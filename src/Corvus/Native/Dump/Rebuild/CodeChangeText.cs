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

    private const string NoStartSuffix = ", no instruction start known before the range";

    /// <summary>Returns the text of a changed range of <paramref name="bytes"/> bytes that is not shown as code.</summary>
    public static string NoStart(int bytes) => $"bytes changed: {bytes} bytes{NoStartSuffix}";

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
    /// <c>; </c>, or null when the machine is not x86, x64 or ARM64, the buffers do not differ
    /// from <paramref name="rangeStart"/> on, or nothing decodes. <paramref name="address"/> is the
    /// address of buffer offset 0; the range starts at the first byte at or after
    /// <paramref name="rangeStart"/> where the buffers differ. Instructions are shown while they
    /// start before <paramref name="rangeEnd"/>, the buffer end when negative; later bytes only
    /// complete the last instruction.
    /// </summary>
    /// <remarks>
    /// Without an anchor the text is code only when decoding from the range start reaches whole
    /// instructions to the range end and the file bytes over the range decode too; otherwise it is
    /// <see cref="NoStart"/>. Invalid first bytes return null.
    /// A non-negative <paramref name="knownStart"/> is the offset in the buffers of an instruction
    /// start at or before the range; the file is decoded from it to find the instruction holding
    /// the range start. A negative one, a start at or past the end of the file, file bytes that do
    /// not decode, or memory that differs between that instruction and the range decode from the
    /// range start, and the text ends with <see cref="FromRangeStart"/>. ARM64 instructions are
    /// 4 bytes: decoding starts at the range start rounded down to 4 and
    /// <paramref name="knownStart"/> is ignored. Invalid bytes end the text; targets are named
    /// through <paramref name="name"/>.
    /// </remarks>
    public static string? Describe(ReadOnlySpan<byte> memory, ReadOnlySpan<byte> file, ulong address,
        NativeArch machine, int knownStart, Func<ulong, string?> name, int rangeStart = 0, int rangeEnd = -1)
    {
        if (machine is not (NativeArch.X86 or NativeArch.X64 or NativeArch.Arm64) || memory.IsEmpty)
            return null;
        int diff = Math.Max(rangeStart, 0);
        int common = Math.Min(memory.Length, file.Length);
        while (diff < common && memory[diff] == file[diff]) diff++;
        if (diff == memory.Length && diff == file.Length) return null;
        if (diff >= memory.Length) return null;
        if (machine == NativeArch.Arm64) return DescribeArm64(memory, address, diff, rangeEnd < 0 ? memory.Length : rangeEnd, name);

        int bits = machine == NativeArch.X64 ? 64 : 32;
        bool exact = false;
        int start = diff;
        if (knownStart >= 0 && knownStart <= diff && knownStart < file.Length)
        {
            var fileBytes = file.ToArray();
            int at = knownStart;
            while (at <= diff && at < fileBytes.Length)
            {
                var scan = Decoder.Create(bits,
                    new ByteArrayCodeReader(fileBytes, at, fileBytes.Length - at), address + (ulong)at);
                scan.Decode(out var step);
                if (step.IsInvalid) break;
                if (at + step.Length > diff)
                {
                    exact = memory[at..diff].SequenceEqual(file[at..diff]);
                    if (exact) start = at;
                    break;
                }
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
        int end = Math.Min(rangeEnd < 0 ? memBytes.Length : rangeEnd, memBytes.Length);
        bool whole = true;
        while (decoder.IP < address + (ulong)end)
        {
            decoder.Decode(out var insn);
            if (insn.IsInvalid) { whole = false; break; }
            if (parts.Count >= MaxInstructions && !exact) continue;
            if (parts.Count >= MaxInstructions) break;
            output.Reset();
            formatter.Format(in insn, output);
            parts.Add(output.ToStringAndReset());
        }
        if (parts.Count == 0) return null;
        var text = string.Join("; ", parts);
        if (exact) return text;
        if (!whole || !Decodes(file, bits, address, start, end)) return NoStart(end - start);
        return text + " " + FromRangeStart;
    }

    // True when the file bytes of [start, end) decode as whole instructions;
    // bytes past the file are not checked.
    private static bool Decodes(ReadOnlySpan<byte> file, int bits, ulong address, int start, int end)
    {
        end = Math.Min(end, file.Length);
        if (start >= end) return true;
        var bytes = file.ToArray();
        var decoder = Decoder.Create(bits, new ByteArrayCodeReader(bytes, start, bytes.Length - start), address + (ulong)start);
        while (decoder.IP < address + (ulong)end)
        {
            decoder.Decode(out var insn);
            if (insn.IsInvalid) return false;
        }
        return true;
    }

    private static string? DescribeArm64(ReadOnlySpan<byte> memory, ulong address, int diff, int end,
        Func<ulong, string?> name)
    {
        // Aligned by address, so a buffer that starts mid-word still lands on a boundary.
        int start = Math.Max(0, diff - (int)((address + (ulong)diff) & 3));
        var options = new Arm64InstructionFormattingOptions { UseUppercaseHex = true };
        var text = new char[128];
        var parts = new List<string>();
        for (int at = start; parts.Count < MaxInstructions && at < end && at + 4 <= memory.Length; at += 4)
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