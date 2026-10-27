namespace Corvus.Native.Code;

/// <summary>An index known to be unsigned-below <see cref="Count"/> on some path; register ids are the decoder's own, 0 is none.</summary>
/// <param name="SlotBase">When set, the index is in frame slot [SlotBase + SlotDisp] instead of a register.</param>
/// <param name="Default">The bounding branch's out-of-range target; the switched value is index + Bias.</param>
/// <param name="FlagsReg">ARM64: the entry flags come from comparing this register with FlagsImm.</param>
internal readonly record struct IndexBound(int Reg, uint Count, int SlotBase = 0, ulong SlotDisp = 0, uint? Default = null, long Bias = 0,
    int FlagsReg = 0, ulong FlagsImm = 0)
{
    public static readonly IndexBound None = new(0, 0);
    public bool IsKnown => Reg != 0 || SlotBase != 0 || FlagsReg != 0;
}

/// <summary>Facts of one decoded instruction, in the form the analysis loops use. Addresses are RVAs.</summary>
internal struct Insn
{
    public uint Rva;
    public int Length;
    public FlowKind Flow;
    public bool HasTarget;
    /// <summary>Direct branch / call target.</summary>
    public uint Target;
    public bool HasMem;
    public uint MemTarget;
    public bool MemRip;
    public OperandAccess MemAccess;
    public bool HasImm;
    public uint ImmTarget;
    /// <summary>ARM32: a return or indirect jump that runs only when its condition holds; otherwise the next instruction runs.</summary>
    public bool Conditional;
    public uint Next => Rva + (uint)Length;
}

/// <summary>A switch dispatch matched at an indirect jump; the switched value is table index + <see cref="Bias"/>.</summary>
/// <param name="BaseAssumed">The image base register is set outside the run; every target must lie in the function's unwind ranges.</param>
internal sealed record SwitchMatch(uint TableRva, int EntrySize, bool Absolute, bool RelativeToTable, uint Count, uint? IndexTableRva, uint IndexTableCount, bool BaseAssumed)
{
    /// <summary>The bounding branch's out-of-range target; null when an and-mask bounds the index.</summary>
    public uint? Default { get; init; }
    public long Bias { get; init; }
    public bool BoundByMask { get; init; }
    /// <summary>x86 PE: no compare bounds the index; the count is the run of relocated entries (values not exact).</summary>
    public bool BoundByRelocations { get; init; }
    /// <summary>ARM64: targets are <see cref="Base"/> + (entry &lt;&lt; <see cref="Shift"/>), the entry sign-extended when <see cref="Signed"/>.</summary>
    public uint? Base { get; init; }
    public int Shift { get; init; }
    public bool Signed { get; init; }
    /// <summary>ARM32: the index selects a branch in a run, target = <see cref="Base"/> + (index &lt;&lt; <see cref="Shift"/>).</summary>
    public bool Direct { get; init; }
    /// <summary>When set, every target lies within this many bytes of the dispatch.</summary>
    public uint Window { get; init; }

    /// <summary>The reason when the instructions before an indirect jump are no table dispatch at all.</summary>
    public const string NoDispatch = "no recognized table dispatch";
}

/// <summary>Decodes one instruction set over an image's code, keeping run state for switch matching; one per thread.</summary>
internal interface ICodeDecoder
{
    /// <summary>The image has 64-bit pointers.</summary>
    bool Is64 { get; }

    /// <summary>Starts the walk of a new function (forgets what was learned about the previous one).</summary>
    void BeginFunction() { }

    /// <summary>Starts the walk of the function at <paramref name="start"/> (ARM32: decodes in that function's state).</summary>
    void BeginFunction(uint start) => BeginFunction();

    /// <summary>Starts a new linear run; <paramref name="incoming"/> is a bound known on entry.</summary>
    void BeginRun(IndexBound incoming);

    /// <summary>Decodes the instruction at <paramref name="rva"/>; false when the address is not in executable code.</summary>
    bool Decode(uint rva, out Insn insn);

    /// <summary>Decodes at <paramref name="rva"/>, which the caller knows is inside <paramref name="region"/>.</summary>
    void Decode(ImageCode.Region region, uint rva, out Insn insn);

    /// <summary>Decodes at any mapped address (data included); false when nothing is mapped there.</summary>
    bool DecodeMapped(uint rva, out Insn insn);

    /// <summary>After a conditional jump (the last instruction): the index bounds on its taken and fall-through paths.</summary>
    void ConditionalBounds(out IndexBound taken, out IndexBound fallThrough);

    /// <summary>The switch table dispatch ending at the last instruction (an indirect jump), or null with the reason.</summary>
    SwitchMatch? MatchSwitch(out string reason);

    /// <summary>The last instruction is one compiled user-mode code does not contain: decoding it means the bytes are data.</summary>
    bool LastIsImplausible(bool strict = true);

    /// <summary>The last instruction has a displacement compiled code would not produce at <paramref name="rva"/>.</summary>
    bool LastHasImplausibleDisplacement(uint rva);

    /// <summary>The code at <paramref name="rva"/> is alignment padding (never followed as code after a noreturn call).</summary>
    bool IsPadding(ImageCode.Region region, uint rva);

    /// <summary>The import slot when the code at <paramref name="rva"/> is a stub that only jumps through it.</summary>
    uint? ThunkSlot(uint rva, Func<uint, bool> isImportSlot);
}

/// <summary>The decoder for an image's instruction set.</summary>
internal static class CodeDecoders
{
    /// <param name="code">Executable code for <see cref="ICodeDecoder.Decode(uint, out Insn)"/>; null when only DecodeMapped is used.</param>
    /// <param name="sortedRelocations">x86: relocations inside code (operand checks); ARM: every relocated pointer location.</param>
    /// <param name="armModes">ARM32: the instruction state per function (a new one from the image when null).</param>
    public static ICodeDecoder Create(INativeImage image, ImageCode? code, uint[] sortedRelocations, IReadOnlySet<uint>? importSlots = null,
        (uint Start, uint End)[]? dataInCode = null, Arm32Modes? armModes = null) => image.Arch switch
    {
        NativeArch.X86 or NativeArch.X64 => new X86Decoder(image, code, sortedRelocations),
        NativeArch.Arm64 => new Arm64Decoder(image, code, sortedRelocations, importSlots, dataInCode),
        NativeArch.Arm => new Arm32Decoder(image, code, sortedRelocations, armModes ?? new Arm32Modes(image), importSlots, dataInCode),
        _ => throw new NotSupportedException(InstructionSets.For(image).Reason),
    };
}
