using System.Buffers.Binary;
using System.Text.Json;

namespace Corvus.Core.Models;

/// <summary>
/// A safetensors file: the JSON header (tensor name, dtype, shape, data offsets) and its __metadata__, checked as the
/// safetensors library checks it: offsets contiguous from zero, each tensor's size equal to its shape times its dtype.
/// </summary>
public sealed class Safetensors
{
    // The library's own limit on the header (safetensors::tensor::MAX_HEADER_SIZE).
    public const long MaxHeader = 100_000_000;

    /// <summary>A tensor: <see cref="Begin"/> and <see cref="End"/> are relative to the data after the header.</summary>
    public sealed record Tensor(string Name, string Dtype, IReadOnlyList<long> Shape, long Begin, long End);

    public long HeaderSize { get; private init; }
    public IReadOnlyDictionary<string, string> Metadata { get; private init; } = new Dictionary<string, string>();
    /// <summary>The tensors in data order.</summary>
    public IReadOnlyList<Tensor> Tensors { get; private init; } = [];
    /// <summary>Where the format's rules are broken: gaps, overlaps, sizes, the data's end against the file's.</summary>
    public IReadOnlyList<string> Issues { get; private init; } = [];

    // Bits per element, as safetensors::Dtype::bitsize names them.
    private static readonly Dictionary<string, int> Bits = new(StringComparer.Ordinal)
    {
        ["BOOL"] = 8, ["F4"] = 4, ["F6_E2M3"] = 6, ["F6_E3M2"] = 6, ["U8"] = 8, ["I8"] = 8, ["F8_E5M2"] = 8, ["F8_E4M3"] = 8, ["F8_E8M0"] = 8,
        ["I16"] = 16, ["U16"] = 16, ["F16"] = 16, ["BF16"] = 16, ["I32"] = 32, ["U32"] = 32, ["F32"] = 32, ["C64"] = 64, ["F64"] = 64,
        ["I64"] = 64, ["U64"] = 64,
    };

    /// <summary>The first bytes hold a header length below the file's and a JSON object after it.</summary>
    public static bool Looks(ReadOnlySpan<byte> head, long length)
    {
        if (head.Length < 10) return false;
        ulong n = BinaryPrimitives.ReadUInt64LittleEndian(head);
        return n >= 2 && n <= MaxHeader && (long)n <= length - 8 && head[8] == '{';
    }

    /// <summary>The bits per element of <paramref name="dtype"/>; null for a dtype the format does not define.</summary>
    public static int? BitsOf(string dtype) => Bits.TryGetValue(dtype, out var b) ? b : null;

    /// <summary>Reads the header from <paramref name="s"/> (positioned at the file's start); throws <see cref="InvalidDataException"/> when it is not one.</summary>
    public static Safetensors Read(Stream s, long length)
    {
        Span<byte> size = stackalloc byte[8];
        s.ReadExactly(size);
        ulong n = BinaryPrimitives.ReadUInt64LittleEndian(size);
        if (n > MaxHeader || (long)n > length - 8) throw new InvalidDataException($"the header length {n:N0} is over the limit or the file");
        var json = new byte[n];
        s.ReadExactly(json);
        JsonDocument doc;
        try { doc = JsonDocument.Parse(json); }
        catch (JsonException ex) { throw new InvalidDataException($"the header is not JSON: {ex.Message}"); }
        using (doc)
        {
            if (doc.RootElement.ValueKind != JsonValueKind.Object) throw new InvalidDataException("the header is not a JSON object");
            var metadata = new Dictionary<string, string>(StringComparer.Ordinal);
            var tensors = new List<Tensor>();
            var issues = new List<string>();
            foreach (var p in doc.RootElement.EnumerateObject())
            {
                if (p.Name == "__metadata__")
                {
                    if (p.Value.ValueKind == JsonValueKind.Object)
                        foreach (var m in p.Value.EnumerateObject())
                            metadata[m.Name] = m.Value.ValueKind == JsonValueKind.String ? m.Value.GetString()! : m.Value.GetRawText();
                    continue;
                }
                var t = p.Value;
                if (t.ValueKind != JsonValueKind.Object || !t.TryGetProperty("dtype", out var dt) || dt.ValueKind != JsonValueKind.String ||
                    !t.TryGetProperty("shape", out var sh) || sh.ValueKind != JsonValueKind.Array ||
                    !t.TryGetProperty("data_offsets", out var off) || off.ValueKind != JsonValueKind.Array || off.GetArrayLength() != 2)
                {
                    issues.Add($"{p.Name}: not a tensor entry (dtype, shape, data_offsets)");
                    continue;
                }
                var shape = new List<long>();
                foreach (var d in sh.EnumerateArray()) shape.Add(d.TryGetInt64(out var v) && v >= 0 ? v : -1);
                if (!off[0].TryGetInt64(out var begin) || !off[1].TryGetInt64(out var end) || begin < 0 || end < begin)
                {
                    issues.Add($"{p.Name}: invalid data offsets");
                    continue;
                }
                tensors.Add(new Tensor(p.Name, dt.GetString()!, shape, begin, end));
            }
            tensors.Sort((a, b) => a.Begin != b.Begin ? a.Begin.CompareTo(b.Begin) : string.CompareOrdinal(a.Name, b.Name));
            long at = 0, data = length - 8 - (long)n;
            foreach (var t in tensors)
            {
                if (t.Begin != at) issues.Add(t.Begin > at ? $"{t.Name}: starts at {t.Begin:N0}, after a gap from {at:N0}" : $"{t.Name}: overlaps the tensor before it");
                at = Math.Max(at, t.End);
                if (BitsOf(t.Dtype) is not { } bits) issues.Add($"{t.Name}: unknown dtype {t.Dtype}");
                else if (t.Shape.Any(d => d < 0)) issues.Add($"{t.Name}: invalid shape");
                else
                {
                    var bytes = Elements(t.Shape) * bits;
                    if (bytes % 8 != 0 || bytes / 8 != t.End - t.Begin) issues.Add($"{t.Name}: {t.End - t.Begin:N0} bytes for {Elements(t.Shape):N0} {t.Dtype} elements");
                }
            }
            if (at != data) issues.Add(at > data ? $"the tensors end at {at:N0}, past the data's {data:N0} bytes" : $"{data - at:N0} bytes after the last tensor");
            return new Safetensors { HeaderSize = (long)n, Metadata = metadata, Tensors = tensors, Issues = issues };
        }
    }

    /// <summary>The element count of <paramref name="shape"/>; 1 for a scalar.</summary>
    public static System.Numerics.BigInteger Elements(IReadOnlyList<long> shape)
    {
        System.Numerics.BigInteger n = 1;
        foreach (var d in shape) n *= d;
        return n;
    }
}
