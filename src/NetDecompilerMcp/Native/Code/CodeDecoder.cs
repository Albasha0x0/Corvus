namespace NetDecompilerMcp.Native.Code;

/// <summary>
/// An index known to be below <see cref="Count"/> (unsigned) on some path: register <see cref="Reg"/>, or with
/// <see cref="SlotBase"/> set the frame slot [SlotBase + SlotDisp]. Registers are the decoder's own ids; 0 is none.
/// <see cref="Default"/> is where the bounding branch goes for an index out of range; the switched value is index + <see cref="Bias"/>.
/// <see cref="FlagsReg"/>: the flags on entry come from comparing that register with <see cref="FlagsImm"/> (ARM64, where a
/// bounding branch can follow the compare in another block).
/// </summary>
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

/// <summary>
/// A switch dispatch matched at an indirect jump. <see cref="BaseAssumed"/>: a register used as the image base is set
/// outside the run (hoisted by the compiler); the caller must confirm the table by requiring every target inside the
/// function's own unwind ranges. <see cref="Default"/>: the bounding branch's out-of-range target (null when an and-mask
/// bounds the index, <see cref="BoundByMask"/>); the switched value is table index + <see cref="Bias"/>.
/// </summary>
internal sealed record SwitchMatch(uint TableRva, int EntrySize, bool Absolute, bool RelativeToTable, uint Count, uint? IndexTableRva, uint IndexTableCount, bool BaseAssumed)
{
    public uint? Default { get; init; }
    public long Bias { get; init; }
    public bool BoundByMask { get; init; }
    /// <summary>ARM64: targets are <see cref="Base"/> + (entry &lt;&lt; <see cref="Shift"/>), the entry sign-extended when <see cref="Signed"/>.</summary>
    public uint? Base { get; init; }
    public int Shift { get; init; }
    public bool Signed { get; init; }

    /// <summary>The reason when the instructions before an indirect jump are no table dispatch at all.</summary>
    public const string NoDispatch = "no recognized table dispatch";
}

/// <summary>
/// Decoding of one instruction set over the code of an image, keeping what the current linear run needs to match
/// switch dispatches and bounds. One instance per thread.
/// </summary>
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

    /// <summary>The import slot when the code at <paramref name="rva"/> is a stub that only jumps through it (x86 jmp [slot]; ARM64 PLT and Mach-O stubs).</summary>
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
        _ => throw new NotSupportedException(InstructionSets.For(image.Arch).Reason),
    };
}
