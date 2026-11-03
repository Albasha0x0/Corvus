using Corvus.Native.Diff;
using Iced.Intel;

namespace Corvus.Native.Dump.Rebuild;

/// <summary>One changed range as the grouping reads it, independent of the service that listed it.</summary>
public sealed record ChangeShapeInput(string Module, string Section, string Kind, ulong Address, int Length,
    byte[] MemoryBytes, NativeArch Machine, string? TargetKind);

/// <summary>Changed ranges that share a shape; first and last address are the lowest and highest member.</summary>
public sealed record ChangeGroup(string Key, string Shape, int Count, ulong FirstAddress, ulong LastAddress,
    long TotalBytes, int FirstIndex);

/// <summary>Groups changed ranges by instruction shape, so repeated stubs report once.</summary>
public static class ChangePatterns
{
    /// <summary>
    /// Returns groups in address order of their first row; empty input gives an empty list.
    /// Code decodes on x86, x64 and ARM64 with immediates, displacements and branch targets masked;
    /// other machines, and code that does not decode, group by length.
    /// </summary>
    public static IReadOnlyList<ChangeGroup> Group(IReadOnlyList<ChangeShapeInput> rows)
    {
        var groups = new Dictionary<string, Acc>(StringComparer.Ordinal);
        for (int i = 0; i < rows.Count; i++)
        {
            var row = rows[i];
            string? target = row.Kind == "data" && row.TargetKind is not null ? TargetGroup(row.TargetKind) : null;
            string shape = target is null ? Shape(row) : TargetShape(target);
            string key = target is not null
                ? $"{row.Module}|{row.Section}|data|{target}"
                : $"{row.Module}|{row.Section}|{row.Kind}|{shape}" + (row.TargetKind is { } t ? $"|{t}" : "");
            if (!groups.TryGetValue(key, out var acc)) groups[key] = acc = new Acc(key, shape, row.Address, i);
            acc.Add(row.Address, row.Length, i);
        }
        return groups.Values
            .OrderBy(a => a.First).ThenBy(a => a.FirstIndex)
            .Select(a => new ChangeGroup(a.Key, a.Shape, a.Count, a.First, a.Last, a.Total, a.FirstIndex))
            .ToList();
    }

    // Reduces a known target to its module; unbacked, committed memory and not
    // a pointer stay whole.
    private static string TargetGroup(string targetKind)
    {
        if (targetKind is "unbacked" or "committed memory" or "not a pointer") return targetKind;
        int bang = targetKind.IndexOf('!');
        if (bang > 0) return targetKind[..bang];
        int plus = targetKind.LastIndexOf("+0x", StringComparison.Ordinal);
        return plus > 0 ? targetKind[..plus] : targetKind;
    }

    private static string TargetShape(string target) => target switch
    {
        "not a pointer" => "values that are not pointers",
        "unbacked" => "pointers into unbacked memory",
        "committed memory" => "pointers into committed memory",
        _ => $"pointers into {target}",
    };

    private sealed class Acc(string key, string shape, ulong first, int index)
    {
        public string Key { get; } = key;
        public string Shape { get; } = shape;
        public ulong First { get; private set; } = first;
        public ulong Last { get; private set; } = first;
        public int FirstIndex { get; private set; } = index;
        public int Count { get; private set; }
        public long Total { get; private set; }

        public void Add(ulong address, int length, int index)
        {
            Count++;
            Total += length;
            if (address < First || address == First && index < FirstIndex) { First = address; FirstIndex = index; }
            if (address > Last) Last = address;
        }
    }

    private static string Shape(ChangeShapeInput row)
    {
        if (row.Kind != "code") return $"{row.Kind} {row.Length} bytes";
        int length = Math.Min(row.Length, row.MemoryBytes.Length);
        if (length <= 0) return $"unread {row.Length} bytes";
        var bytes = row.MemoryBytes.AsSpan(0, length);
        string? text = row.Machine switch
        {
            NativeArch.X86 => DecodeX86(bytes, 32, row.Address),
            NativeArch.X64 => DecodeX86(bytes, 64, row.Address),
            NativeArch.Arm64 => DecodeArm64(bytes, row.Address),
            _ => null,
        };
        return text ?? $"undecoded {row.Length} bytes";
    }

    private static string? DecodeX86(ReadOnlySpan<byte> bytes, int bitness, ulong address)
    {
        var array = bytes.ToArray();
        var reader = new ByteArrayCodeReader(array);
        var decoder = Decoder.Create(bitness, reader, address, DecoderOptions.None);
        var formatter = new IntelFormatter(new FormatterOptions());
        var output = new MaskedOutput();
        var parts = new List<string>();
        while (reader.CanReadByte)
        {
            decoder.Decode(out var instruction);
            if (instruction.IsInvalid) break;
            output.Clear();
            formatter.Format(in instruction, output);
            parts.Add(output.ToString());
        }
        if (parts.Count == 0) return null;
        int rest = array.Length - reader.Position;
        if (rest > 0) parts.Add($"{rest} undecoded bytes");
        return string.Join("; ", parts);
    }

    private static string? DecodeArm64(ReadOnlySpan<byte> bytes, ulong address)
    {
        var layout = new RawLayout(RawArch.Find("arm64"), address, 0);
        var image = new RawCodeImage(bytes.ToArray(), "change", layout);
        var decoder = new MaskedDecoder(image);
        var list = new List<MaskedInsn>();
        decoder.Decode(0, (uint)bytes.Length, list);
        if (list.Count == 0) return null;
        var parts = list.Select(i => string.Join(' ', Enumerable.Range(0, i.Length)
            .Select(b => i.IsWild(b) ? "??" : i.Bytes[b].ToString("x2")))).ToList();
        int rest = bytes.Length - (int)list[^1].End;
        if (rest > 0) parts.Add($"{rest} undecoded bytes");
        return string.Join("; ", parts);
    }

    // Writes an instruction with every number replaced by N.
    private sealed class MaskedOutput : FormatterOutput
    {
        private readonly System.Text.StringBuilder _text = new();

        public void Clear() => _text.Clear();

        public override void Write(string text, FormatterTextKind kind)
            => _text.Append(kind is FormatterTextKind.Number
                or FormatterTextKind.LabelAddress
                or FormatterTextKind.FunctionAddress ? "N" : text);

        public override string ToString() => _text.ToString();
    }
}
