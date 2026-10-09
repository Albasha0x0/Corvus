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
/// MASM-syntax disassembly (Iced) of x86 / x64 code at any mapped address. Branch, memory and immediate targets
/// are shown by name when the symbols know one; immediates only when they are confirmed addresses (relocated, or
/// in a relocation-free x86 image an absolute push / mov into a section).
/// </summary>
public sealed class NativeDisassembler
{
    private readonly INativeImage _image;
    private readonly ICodeSymbols? _symbols;
    private readonly X86Decoder _decoder;
    private readonly MasmFormatter _formatter;
    private readonly Resolver _resolver;
    private readonly StringOutput _output = new();

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

    /// <exception cref="NotSupportedException">The image is not x86 or x64.</exception>
    public NativeDisassembler(INativeImage image, ICodeSymbols? symbols = null) : this(image, symbols, SortedRelocations(image)) { }

    internal NativeDisassembler(INativeImage image, ICodeSymbols? symbols, uint[] sortedRelocations)
    {
        if (image.Arch is not (NativeArch.X86 or NativeArch.X64))
            throw new NotSupportedException(InstructionSets.For(image.Arch).Reason);
        _image = image;
        _symbols = symbols;
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
        if (!_decoder.DecodeMapped(rva, out var insn)) return null;
        return Line(in insn, labels);
    }

    /// <summary>
    /// Linear disassembly from <paramref name="rva"/>: at most <paramref name="maxInstructions"/>, stopping before
    /// <paramref name="end"/> and after an invalid instruction.
    /// </summary>
    public List<DisasmLine> Disassemble(uint rva, int maxInstructions, uint end = uint.MaxValue, IReadOnlyDictionary<uint, string>? labels = null)
    {
        var lines = new List<DisasmLine>();
        while (lines.Count < maxInstructions && rva < end)
        {
            var line = DecodeOne(rva, labels);
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
        else
        {
            _resolver.Current = insn;
            _resolver.Labels = labels;
            _formatter.Format(in _decoder.Last, _output);
            text = _output.ToStringAndReset();
        }
        string? comment = null;
        if (_symbols != null)
        {
            if (insn.HasMem) comment = _symbols.CommentFor(insn.MemTarget);
            if (comment == null && insn.HasImm) comment = _symbols.CommentFor(insn.ImmTarget);
        }
        return new DisasmLine(insn.Rva, _image.ImageBase + insn.Rva, hex, text, comment, Facts(in insn));
    }

    internal static InstructionFacts Facts(in Insn i) => new(
        i.Rva, i.Length, i.Flow,
        i.HasTarget ? i.Target : null,
        i.HasMem ? i.MemTarget : null,
        i.HasMem && i.MemRip,
        i.HasMem ? i.MemAccess : OperandAccess.None,
        i.HasImm ? i.ImmTarget : null);
}
