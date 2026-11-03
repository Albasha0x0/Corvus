using System.Buffers.Binary;
using AsmArm64;
using Iced.Intel;

namespace Corvus.Native.Dump.Rebuild;

/// <summary>Shows the first instructions of a changed x86, x64 or ARM64 code range.</summary>
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
    /// <c>; </c>, or null when the machine is not x86, x64 or ARM64, the buffers do not differ, or
    /// nothing decodes. <paramref name="address"/> is the address of buffer offset 0 and the
    /// range starts at the first byte where the buffers differ. A non-negative
    /// <paramref name="knownStart"/> is an instruction start at or before the range; the file
    /// is decoded from it to find the instruction holding the range start. A negative one
    /// decodes from the range start and the text ends with <see cref="FromRangeStart"/>.
    /// ARM64 instructions are 4 bytes: decoding starts at the range start rounded down to 4
    /// and <paramref name="knownStart"/> is ignored. Invalid bytes end the text; targets are
    /// named through <paramref name="name"/>.
    /// </summary>
    public static string? Describe(ReadOnlySpan<byte> memory, ReadOnlySpan<byte> file, ulong address,
        NativeArch machine, int knownStart, Func<ulong, string?> name)
    {
        if (machine is not (NativeArch.X86 or NativeArch.X64 or NativeArch.Arm64) || memory.IsEmpty)
            return null;
        int diff = 0;
        int common = Math.Min(memory.Length, file.Length);
        while (diff < common && memory[diff] == file[diff]) diff++;
        if (diff == memory.Length && diff == file.Length) return null;
        if (diff >= memory.Length) return null;
        if (machine == NativeArch.Arm64) return DescribeArm64(memory, address, diff, name);

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

    private static string? DescribeArm64(ReadOnlySpan<byte> memory, ulong address, int diff,
        Func<ulong, string?> name)
    {
        // Aligned by address, so a buffer that starts mid-word still lands on a boundary.
        int start = Math.Max(0, diff - (int)((address + (ulong)diff) & 3));
        var options = new Arm64InstructionFormattingOptions { UseUppercaseHex = true };
        var text = new char[128];
        var parts = new List<string>();
        for (int at = start; parts.Count < MaxInstructions && at + 4 <= memory.Length; at += 4)
        {
            ulong pc = address + (ulong)at;
            var insn = Arm64Instruction.Decode(BinaryPrimitives.ReadUInt32LittleEndian(memory[at..]));
            bool page = insn.Id == Arm64InstructionId.ADRP_only_pcreladdr;
            bool Label(long offset, Span<char> destination, out int written)
            {
                ulong target = (page ? pc & ~0xFFFUL : pc) + (ulong)offset;
                var s = (page ? null : name(target)) ?? $"0x{target:X}";
                written = 0;
                if (s.Length > destination.Length) return false;
                s.CopyTo(destination);
                written = s.Length;
                return true;
            }
            if (!insn.TryFormat(options, text, out int n, Label)) break;
            parts.Add(new string(text, 0, n));
        }
        return parts.Count == 0 ? null : string.Join("; ", parts);
    }
}