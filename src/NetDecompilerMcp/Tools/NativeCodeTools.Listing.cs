using System.Text;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Code;
using static NetDecompilerMcp.Tools.ToolSupport;

namespace NetDecompilerMcp.Tools;

/// <summary>disassemble: boundary and data warnings, data-aware linear listings with resynchronization, and gaps between a function's blocks.</summary>
public sealed partial class NativeCodeTools
{
    // Jump table entries rendered one per line before "...".
    private const int MaxTableLines = 64;

    /// <summary>The warning for a listing that starts at <paramref name="rva"/>, or null when it is an instruction start in a known function.</summary>
    internal static string? StartWarning(AddressClassifier classifier, uint rva, CancellationToken ct)
    {
        var c = classifier.Classify(rva, ct);
        var image = classifier.Index.Image;
        string Va(uint r) => NativeAddress.Va(image, r);
        switch (c.Status)
        {
            case AddressStatus.MidInstruction:
                var covering = classifier.Index.CreateDisassembler().DecodeOne(c.InstructionStart!.Value)?.Text;
                return $"warning: {Va(rva)} is inside the instruction at {Va(c.InstructionStart.Value)}{(covering != null ? $" ({covering})" : "")}; " +
                       $"decoding from here desynchronizes - use address={Va(c.InstructionStart.Value)}";
            case AddressStatus.Data:
                var item = c.Item!;
                return $"warning: {Va(rva)} is in {(item.Kind == "section" ? "the data section" : "a " + item.Kind.Replace('_', ' '))} {item.Text} ({Va(item.Start)}-{Va(item.End)})";
            case AddressStatus.NotInFunction:
                return $"note: no function contains {Va(rva)}";
            case AddressStatus.Unmapped:
                return $"warning: {Va(rva)} is {(c.Section != null ? "in uninitialized data (bss), shown as zeros" : "in no section")}";
            case AddressStatus.Invalid:
                return $"warning: the bytes at {Va(rva)} do not decode";
            default:
                return null;
        }
    }

    /// <summary>
    /// Linear listing from <paramref name="rva"/> of at most <paramref name="max"/> lines: known data items (strings, pointers, IAT slots,
    /// switch tables) are rendered as data and skipped; landing inside a known instruction resynchronizes to the next instruction start.
    /// </summary>
    internal static void AppendLinear(StringBuilder sb, NativeCodeIndex index, AddressClassifier classifier, uint rva, int max, List<string> warnings, CancellationToken ct)
    {
        var image = index.Image;
        string Va(uint r) => NativeAddress.Va(image, r);
        var disassembler = index.CreateDisassembler();
        uint at = rva;
        for (int lines = 0; lines < max && at < image.SizeOfImage;)
        {
            ct.ThrowIfCancellationRequested();
            var owner = index.FunctionAt(at);
            if (owner != null && at != owner.Start)
            {
                var c = classifier.Classify(at, ct);
                if (c.Status == AddressStatus.MidInstruction)
                {
                    uint resume = at == rva ? c.InstructionStart!.Value : c.InstructionStart!.Value + (uint)c.InstructionLength;
                    var note = $"desync: {Va(at)} is inside the instruction at {Va(c.InstructionStart.Value)}; resynchronized to {Va(resume)}";
                    sb.AppendLine("; " + note);
                    if (at != rva) warnings.Add(note);
                    at = resume;
                    continue;
                }
            }
            if (owner == null && classifier.DataItemAt(at, null, ct) is { Kind: "string" or "pointer" or "iat_slot" or "jump_table" or "index_table" } item)
            {
                lines += AppendData(sb, index, item, at, max - lines);
                at = item.End;
                continue;
            }
            var line = disassembler.DecodeOne(at);
            if (line == null) break;
            if (owner != null && at == owner.Start && at != rva) sb.AppendLine($"{owner.Name}:");
            sb.AppendLine(Line(line));
            lines++;
            if (line.Facts.Flow == FlowKind.Invalid) break;
            at += (uint)line.Facts.Length;
        }
    }

    /// <summary>Data lines for <paramref name="item"/> from <paramref name="from"/>; returns the number of lines.</summary>
    private static int AppendData(StringBuilder sb, NativeCodeIndex index, DataItem item, uint from, int max)
    {
        var image = index.Image;
        string Va(uint r) => NativeAddress.Va(image, r);
        uint size = item.End - from;
        var bytes = new byte[Math.Min(size, 4096u)];
        int n = image.Read(from, bytes);
        string Hex(int offset, int count) => Convert.ToHexString(bytes, offset, Math.Max(0, Math.Min(count, n - offset)));
        string Row(uint at, string hex, string text) => $"  {image.ImageBase + at:X}  {hex,-24} {text}";
        string pointer = image.Is64Bit ? "dq" : "dd";
        switch (item.Kind)
        {
            case "string":
                bool wide = index.StringAt(item.Start) is { Encoding: StringEncoding.Utf16 };
                sb.AppendLine(Row(from, Hex(0, 8) + (size > 8 ? "..." : ""), $"{(wide ? "du" : "db")} {item.Text},0" + (from != item.Start ? $"  ; tail of the string at {Va(item.Start)}" : "")));
                return 1;
            case "pointer":
                sb.AppendLine(Row(from, Hex(0, (int)size), $"{pointer} " + (item.Text.StartsWith("pointer to ", StringComparison.Ordinal) ? "offset " + item.Text["pointer to ".Length..] : "?  ; " + item.Text)));
                return 1;
            case "iat_slot":
                sb.AppendLine(Row(from, Hex(0, (int)size), $"{pointer} ?  ; IAT slot of {item.Text}"));
                return 1;
            case "jump_table":
            {
                int lines = 0;
                sb.AppendLine($"; {item.Text}");
                for (uint at = from; at + 4 <= item.End && lines < Math.Min(max, MaxTableLines); at += 4, lines++)
                {
                    int o = (int)(at - from);
                    if (o + 4 > n) break;
                    uint entry = BitConverter.ToUInt32(bytes, o);
                    // x64 tables hold RVAs, x86 tables absolute addresses
                    uint target = image.Is64Bit ? entry : (uint)(entry - image.ImageBase);
                    sb.AppendLine(Row(at, Hex(o, 4), $"dd {(image.Is64Bit ? "rva " : "offset ")}{index.NameAt(target) ?? $"loc_{target:X}"}"));
                }
                if (from + (uint)lines * 4 < item.End) sb.AppendLine($"; ... {(item.End - from) / 4 - (uint)lines} more entries to {Va(item.End)}");
                return Math.Max(1, lines);
            }
            default:
            {
                int lines = 0;
                for (uint at = from; at < item.End && lines < Math.Min(max, MaxTableLines); at += 16, lines++)
                {
                    int o = (int)(at - from);
                    if (o >= n) break;
                    int count = (int)Math.Min(16, item.End - at);
                    sb.AppendLine(Row(at, Hex(o, count), "db " + string.Join(", ", bytes.Skip(o).Take(Math.Min(count, n - o)).Select(b => b.ToString()))));
                }
                return Math.Max(1, lines);
            }
        }
    }

    /// <summary>A function's blocks in address order with their labels, and a comment line for each gap between blocks.</summary>
    internal static void AppendFunction(StringBuilder sb, NativeCodeIndex index, AddressClassifier classifier, NativeFunction fn, int max,
        IReadOnlyDictionary<uint, string> calls, List<string> warnings, CancellationToken ct)
    {
        string? pending = null;
        uint end = 0;
        var listing = index.DisassembleFunction(fn, max, out bool truncated, ct);
        foreach (var (label, line) in listing)
        {
            if (label != null) pending = label.EndsWith(':') ? label : label + ":";
            if (line == null) continue;
            if (end != 0 && line.Rva > end)
            {
                var gap = $"gap {NativeAddress.Va(index.Image, end)}-{NativeAddress.Va(index.Image, line.Rva)} ({line.Rva - end} bytes): {Gap(index, classifier, fn, end, line.Rva, ct)}";
                sb.AppendLine("; " + gap);
                if (!gap.EndsWith("padding", StringComparison.Ordinal)) warnings.Add(gap);
            }
            if (pending != null) { sb.AppendLine(pending); pending = null; }
            sb.AppendLine(Line(line, calls));
            end = line.Rva + (uint)line.Facts.Length;
        }
        if (truncated) sb.AppendLine($"; truncated at {Plural(max, "instruction")}");
    }

    /// <summary>What lies between two blocks of <paramref name="fn"/>: a switch table, padding, another function's code, or unreached bytes.</summary>
    private static string Gap(NativeCodeIndex index, AddressClassifier classifier, NativeFunction fn, uint start, uint end, CancellationToken ct)
    {
        if (index.FunctionAt(start) is { } other && other != fn) return $"code of {other.Name}";
        if (classifier.DataItemAt(start, null, ct) is { } item && item.Kind is not ("section" or "pe_directory"))
            return $"{item.Kind.Replace('_', ' ')}: {item.Text}";
        var bytes = new byte[Math.Min(end - start, 4096u)];
        int n = index.Image.Read(start, bytes);
        if (n > 0 && bytes.AsSpan(0, n).IndexOfAnyExcept((byte)0xCC) < 0) return "int3 padding";
        if (n > 0 && AllNops(bytes.AsSpan(0, n).ToArray(), index.Image.Is64Bit)) return "nop padding";
        if (n > 0 && bytes.AsSpan(0, n).IndexOfAnyExcept((byte)0) < 0) return "zero padding";
        return "unreached code or data";
    }

    /// <summary>The bytes decode as nothing but nop / int3 instructions (multi-byte nops included).</summary>
    private static bool AllNops(byte[] bytes, bool is64)
    {
        var decoder = Iced.Intel.Decoder.Create(is64 ? 64 : 32, new Iced.Intel.ByteArrayCodeReader(bytes));
        while (decoder.IP < (ulong)bytes.Length)
        {
            decoder.Decode(out var insn);
            if (insn.IsInvalid || insn.Mnemonic is not (Iced.Intel.Mnemonic.Nop or Iced.Intel.Mnemonic.Int3)) return false;
        }
        return true;
    }
}
