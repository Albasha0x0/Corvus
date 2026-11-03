using Iced.Intel;

namespace Corvus.Native.Dump.Rebuild;

/// <summary>Shows the first instructions of a changed x86 or x64 code range.</summary>
public static class CodeChangeText
{
    /// <summary>Suffix of the text when decoding began at the range start.</summary>
    public const string FromRangeStart = "(from the range start)";

    private const int MaxInstructions = 3;

    private sealed class Namer(Func<ulong, string?> name) : ISymbolResolver
    {
        public bool TryGetSymbol(in Instruction instruction, int operand, int instructionOperand,
            ulong address, int addressSize, out SymbolResult symbol)
        {
            symbol = default;
            var text = name(address);
            if (text == null) return false;
            symbol = new SymbolResult(address, text);
            return true;
        }
    }

    /// <summary>
    /// Returns up to 3 instructions of <paramref name="memory"/> as MASM text joined with
    /// <c>; </c>, or null when the machine is not x86 or x64, the buffers do not differ, or
    /// nothing decodes. <paramref name="address"/> is the address of buffer offset 0 and the
    /// range starts at the first byte where the buffers differ. A non-negative
    /// <paramref name="knownStart"/> is an instruction start at or before the range; the file
    /// is decoded from it to find the instruction holding the range start. A negative one
    /// decodes from the range start and the text ends with <see cref="FromRangeStart"/>.
    /// Invalid bytes end the text; targets are named through <paramref name="name"/>.
    /// </summary>
    public static string? Describe(ReadOnlySpan<byte> memory, ReadOnlySpan<byte> file, ulong address,
        NativeArch machine, int knownStart, Func<ulong, string?> name)
    {
        if (machine is not (NativeArch.X86 or NativeArch.X64) || memory.IsEmpty) return null;
        int diff = 0;
        int common = Math.Min(memory.Length, file.Length);
        while (diff < common && memory[diff] == file[diff]) diff++;
        if (diff == memory.Length && diff == file.Length) return null;
        if (diff >= memory.Length) return null;

        int bits = machine == NativeArch.X64 ? 64 : 32;
        bool exact = knownStart >= 0 && knownStart <= diff && knownStart < file.Length;
        int start = diff;
        if (exact)
        {
            var fileBytes = file.ToArray();
            int at = knownStart;
            while (at <= diff && at < fileBytes.Length)
            {
                var scan = Decoder.Create(bits,
                    new ByteArrayCodeReader(fileBytes, at, fileBytes.Length - at), address + (ulong)at);
                scan.Decode(out var step);
                if (step.IsInvalid) break;
                if (at + step.Length > diff) { start = at; break; }
                at += step.Length;
            }
        }

        var memBytes = memory.ToArray();
        var decoder = Decoder.Create(bits,
            new ByteArrayCodeReader(memBytes, start, memBytes.Length - start), address + (ulong)start);
        var formatter = new MasmFormatter(new Namer(name));
        formatter.Options.UppercaseHex = true;
        formatter.Options.SpaceAfterOperandSeparator = true;
        formatter.Options.RipRelativeAddresses = false;
        formatter.Options.ShowBranchSize = false;
        formatter.Options.BranchLeadingZeros = false;
        formatter.Options.LeadingZeros = false;
        var output = new StringOutput();
        var parts = new List<string>();
        while (parts.Count < MaxInstructions && decoder.IP < address + (ulong)memBytes.Length)
        {
            decoder.Decode(out var insn);
            if (insn.IsInvalid) break;
            output.Reset();
            formatter.Format(in insn, output);
            parts.Add(output.ToStringAndReset());
        }
        if (parts.Count == 0) return null;
        var text = string.Join("; ", parts);
        return exact ? text : text + " " + FromRangeStart;
    }
}
