using Iced.Intel;

namespace NetDecompilerMcp.Native.Code;

/// <summary>Names and comments for addresses (RVAs) shown in disassembly.</summary>
public interface ICodeSymbols
{
    /// <summary>A name for the address: import "module!name", export, function, or null.</summary>
    string? NameAt(uint rva);
    /// <summary>A comment for an address an instruction refers to (a quoted string), or null.</summary>
    string? CommentFor(uint rva);
}

/// <summary>One disassembled instruction.</summary>
public sealed record DisasmLine(uint Rva, ulong Address, string Bytes, string Text, string? Comment, InstructionFacts Facts);

/// <summary>
/// Disassembly at any mapped address: MASM syntax (Iced) for x86 / x64, ARM syntax (AsmArm64) for ARM64. Branch, memory
/// and immediate targets are shown by name when the symbols know one; x86 immediates only when they are confirmed
/// addresses (relocated, or in a relocation-free x86 image an absolute push / mov into a section). ARM64 addresses formed
/// by ADRP pairs and loads through import slots are named in the comment.
/// </summary>
public sealed class NativeDisassembler
{
    private readonly INativeImage _image;
    private readonly ICodeSymbols? _symbols;
    private readonly X86Decoder? _decoder;
    private readonly MasmFormatter? _formatter;
    private readonly Resolver? _resolver;
    private readonly StringOutput _output = new();
    private readonly Arm64Decoder? _arm;
    private readonly AsmArm64.Arm64InstructionFormattingOptions _armOptions = new() { UseUppercaseHex = true };
    private readonly char[] _armText = new char[256];

    private sealed class Resolver(INativeImage image) : ISymbolResolver
    {
        public ICodeSymbols? Symbols;
        public IReadOnlyDictionary<uint, string>? Labels;
        public Insn Current;

        public bool TryGetSymbol(in Instruction instruction, int operand, int instructionOperand, ulong address, int addressSize, out SymbolResult symbol)
        {
            symbol = default;
            ulong va = address;
            if (image.Arch == NativeArch.X86) va &= 0xFFFFFFFF;
            if (va < image.ImageBase || va - image.ImageBase >= image.SizeOfImage) return false;
            uint rva = (uint)(va - image.ImageBase);
            bool confirmed = (Current.HasTarget && Current.Target == rva) || (Current.HasMem && Current.MemTarget == rva) || (Current.HasImm && Current.ImmTarget == rva);
            if (!confirmed) return false;
            string? name = null;
            if (Labels != null && Labels.TryGetValue(rva, out var label)) name = label;
            name ??= Symbols?.NameAt(rva);
            if (name == null) return false;
            symbol = new SymbolResult(address, name);
            return true;
        }
    }

    /// <exception cref="NotSupportedException">The image is not x86, x64 or ARM64.</exception>
    public NativeDisassembler(INativeImage image, ICodeSymbols? symbols = null) : this(image, symbols, SortedRelocations(image)) { }

    internal NativeDisassembler(INativeImage image, ICodeSymbols? symbols, uint[] sortedRelocations)
    {
        _image = image;
        _symbols = symbols;
        if (image.Arch == NativeArch.Arm64)
        {
            _arm = new Arm64Decoder(image, null, sortedRelocations);
            return;
        }
        if (image.Arch is not (NativeArch.X86 or NativeArch.X64))
            throw new NotSupportedException(InstructionSets.For(image.Arch).Reason);
        _decoder = new X86Decoder(image, null, sortedRelocations);
        _resolver = new Resolver(image) { Symbols = symbols };
        _formatter = new MasmFormatter(_resolver);
        _formatter.Options.UppercaseHex = true;
        _formatter.Options.SpaceAfterOperandSeparator = true;
        _formatter.Options.RipRelativeAddresses = false;
        _formatter.Options.ShowBranchSize = false;
        _formatter.Options.BranchLeadingZeros = false;
        _formatter.Options.LeadingZeros = false;
        _formatter.Options.FirstOperandCharIndex = 7;
    }

    private static uint[] SortedRelocations(INativeImage image)
    {
        var relocs = image.RelocationRvas.ToArray();
        Array.Sort(relocs);
        return relocs;
    }

    /// <summary>The instruction at <paramref name="rva"/>, or null when nothing is mapped there.</summary>
    public DisasmLine? DecodeOne(uint rva, IReadOnlyDictionary<uint, string>? labels = null)
    {
        _arm?.BeginRun(IndexBound.None);
        return Next(rva, labels);
    }

    /// <summary>The instruction at <paramref name="rva"/>, continuing the current run (ARM64 keeps ADRP pairs across lines).</summary>
    private DisasmLine? Next(uint rva, IReadOnlyDictionary<uint, string>? labels)
    {
        Insn insn;
        if (_arm != null ? !_arm.DecodeMapped(rva, out insn) : !_decoder!.DecodeMapped(rva, out insn)) return null;
        return Line(in insn, labels);
    }

    /// <summary>
    /// Linear disassembly from <paramref name="rva"/>: at most <paramref name="maxInstructions"/>, stopping before
    /// <paramref name="end"/> and after an invalid instruction.
    /// </summary>
    public List<DisasmLine> Disassemble(uint rva, int maxInstructions, uint end = uint.MaxValue, IReadOnlyDictionary<uint, string>? labels = null)
    {
        var lines = new List<DisasmLine>();
        _arm?.BeginRun(IndexBound.None);
        while (lines.Count < maxInstructions && rva < end)
        {
            var line = Next(rva, labels);
            if (line == null) break;
            lines.Add(line);
            if (line.Facts.Flow == FlowKind.Invalid) break;
            rva += (uint)line.Facts.Length;
        }
        return lines;
    }

    private DisasmLine Line(in Insn insn, IReadOnlyDictionary<uint, string>? labels)
    {
        var bytes = new byte[insn.Length];
        int n = _image.Read(insn.Rva, bytes);
        string hex = Convert.ToHexString(bytes, 0, n);
        string text;
        if (insn.Flow == FlowKind.Invalid) text = "(bad)";
        else if (_arm != null) text = FormatArm64(in insn, labels);
        else
        {
            _resolver!.Current = insn;
            _resolver.Labels = labels;
            _formatter!.Format(in _decoder!.Last, _output);
            text = _output.ToStringAndReset();
        }
        string? comment = null;
        if (_symbols != null)
        {
            if (insn.HasMem) comment = _symbols.CommentFor(insn.MemTarget);
            if (comment == null && insn.HasImm) comment = _symbols.CommentFor(insn.ImmTarget);
        }
        if (_arm != null && comment == null && insn.Flow != FlowKind.Invalid && (insn.HasMem || insn.HasImm))
        {
            // the address an ADRP pair or a load through a slot forms is not in the operand text
            uint at = insn.HasMem ? insn.MemTarget : insn.ImmTarget;
            comment = labels?.GetValueOrDefault(at) ?? _symbols?.NameAt(at) ?? $"0x{_image.ImageBase + at:X}";
        }
        return new DisasmLine(insn.Rva, _image.ImageBase + insn.Rva, hex, text, comment, Facts(in insn));
    }

    /// <summary>ARM syntax with the mnemonic padded like the x86 listing; labels (branch, ADR, ADRP, literal) by name or address.</summary>
    private string FormatArm64(in Insn insn, IReadOnlyDictionary<uint, string>? labels)
    {
        var i = _arm!.Last;
        ulong pc = _image.ImageBase + insn.Rva;
        bool page = i.Id == AsmArm64.Arm64InstructionId.ADRP_only_pcreladdr;
        var image = _image;
        var symbols = _symbols;
        bool Label(long offset, Span<char> destination, out int written)
        {
            ulong va = (page ? pc & ~0xFFFUL : pc) + (ulong)offset;
            string? name = null;
            if (!page && va >= image.ImageBase && va - image.ImageBase < image.SizeOfImage)
            {
                uint rva = (uint)(va - image.ImageBase);
                name = labels?.GetValueOrDefault(rva) ?? symbols?.NameAt(rva);
            }
            var s = name ?? $"0x{va:X}";
            written = 0;
            if (s.Length > destination.Length) return false;
            s.AsSpan().CopyTo(destination);
            written = s.Length;
            return true;
        }
        if (!i.TryFormat(_armOptions, _armText, out int n, Label)) return i.ToString();
        var text = _armText.AsSpan(0, n);
        int space = text.IndexOf(' ');
        return space < 0 ? text.ToString() : string.Concat(text[..space].ToString().PadRight(6), " ", text[(space + 1)..].ToString());
    }

    internal static InstructionFacts Facts(in Insn i) => new(
        i.Rva, i.Length, i.Flow,
        i.HasTarget ? i.Target : null,
        i.HasMem ? i.MemTarget : null,
        i.HasMem && i.MemRip,
        i.HasMem ? i.MemAccess : OperandAccess.None,
        i.HasImm ? i.ImmTarget : null);
}
