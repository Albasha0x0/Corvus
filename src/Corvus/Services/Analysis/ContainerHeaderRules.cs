using System.Buffers.Binary;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Code;

namespace Corvus.Services.Analysis;

/// <summary>Reports container headers in a native image; a cut body is partial.</summary>
// Layout: magic (4 ASCII), length (u32, counted from byte 8), count (1-256),
// then ascending u32 entry offsets from the magic. Magic is read at 4-byte
// aligned offsets. The body must reach 7.5 bits per byte.
internal sealed class ContainerHeaderRules : ISurveyRuleProvider
{
    private const int MaxLocations = 5;
    private const int MaxEntries = 256;
    private const int MinBody = 600;
    private const int MaxReferences = 3;
    private const double BodyEntropy = 7.5;

    public IReadOnlyCollection<string> Kinds => ["container"];

    public IEnumerable<Features.Rule> Rules =>
    [
        new("transformed file container headers", "crypto", [["container:header"]]),
    ];

    private static readonly System.Buffers.SearchValues<byte> MagicBytes =
        System.Buffers.SearchValues.Create(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_"u8);

    public Evidence? Evaluate(SurveySubject subject, string feature, CancellationToken ct)
    {
        if (subject.Native is not { } index || feature != "container:header") return null;
        var image = index.Image;
        var sections = new List<(NativeSection Section, byte[] Bytes)>();
        foreach (var (section, size) in CryptoConstantRules.Plan(image))
        {
            var bytes = new byte[size];
            int read = image.Read(section.Rva, bytes);
            sections.Add((section, read == size ? bytes : bytes[..read]));
        }

        var headers = new List<(NativeSection Section, int At, Header Found)>();
        foreach (var (section, bytes) in sections)
            for (int at = 0; at + 12 <= bytes.Length; at += 4)
            {
                ct.ThrowIfCancellationRequested();
                if (bytes.AsSpan(at, 4).IndexOfAnyExcept(MagicBytes) >= 0) continue;
                if (Read(bytes, at) is { } found) headers.Add((section, at, found));
            }
        if (headers.Count == 0) return null;
        // Header bytes of detected containers are not loader references.
        var owned = headers
            .Select(h => (Start: h.Section.Rva + (uint)h.At, Length: (uint)(12 + 4 * h.Found.Entries.Length)))
            .ToList();
        var locations = headers.Take(MaxLocations)
            .Select(h => Describe(index, sections, owned, h.Section, h.At, h.Found, ct))
            .ToList();
        return new Evidence(feature, headers.Count, locations);
    }

    private sealed record Header(string Magic, uint Declared, long Available, int[] Entries, double Entropy);

    private static Header? Read(byte[] bytes, int at)
    {
        uint declared = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(at + 4));
        uint entries = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(at + 8));
        if (entries is 0 or > MaxEntries || declared < 4 + 4 * entries + MinBody) return null;
        int tableEnd = at + 12 + 4 * (int)entries;
        if (tableEnd > bytes.Length) return null;
        var offsets = new int[entries];
        uint previous = 0;
        for (int i = 0; i < entries; i++)
        {
            uint offset = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(at + 12 + 4 * i));
            if (offset < 12 + 4 * entries || offset >= (long)declared + 8 || offset < previous) return null;
            offsets[i] = (int)offset;
            previous = offset;
        }
        long bodyEnd = Math.Min((long)at + 8 + declared, bytes.Length);
        if (bodyEnd - tableEnd < MinBody) return null;
        double entropy = Blob.Entropy(bytes.AsSpan(tableEnd, (int)(bodyEnd - tableEnd)));
        if (entropy < BodyEntropy) return null;
        return new Header(System.Text.Encoding.ASCII.GetString(bytes, at, 4), declared, bodyEnd - at - 8, offsets, entropy);
    }

    private static string Describe(
        NativeCodeIndex index,
        List<(NativeSection Section, byte[] Bytes)> sections,
        List<(uint Start, uint Length)> owned,
        NativeSection section, int at, Header h, CancellationToken ct)
    {
        var image = index.Image;
        uint rva = section.Rva + (uint)at;
        var magic = System.Text.Encoding.ASCII.GetBytes(h.Magic);
        var reversed = magic.Reverse().ToArray();
        var references = new List<string>();
        int total = 0;
        foreach (var (other, bytes) in sections)
            foreach (var pattern in magic.SequenceEqual(reversed) ? new[] { magic } : [magic, reversed])
                for (int from = 0; from < bytes.Length;)
                {
                    int found = bytes.AsSpan(from).IndexOf(pattern);
                    if (found < 0) break;
                    uint hit = other.Rva + (uint)(from + found);
                    from += found + 4;
                    ct.ThrowIfCancellationRequested();
                    if (owned.Any(o => hit >= o.Start && hit < o.Start + o.Length)) continue;
                    total++;
                    if (references.Count < MaxReferences)
                        references.Add(index.FunctionAt(hit) is { } f ? Format.Within(f.Name, f.Start, hit) : $"{NativeAddress.Va(image, hit)} in {other.Name}");
                }
        var entries = string.Join(", +0x", h.Entries.Select(o => o.ToString("X")));
        var text = $"container '{h.Magic}' @{NativeAddress.Va(image, rva)} in {section.Name}: " +
                   $"declared length {h.Declared}, body entropy {h.Entropy:F2}, entries at +0x{entries}";
        if (total == 0) text += ", loader references unknown (none found)";
        else
        {
            text += $", magic referenced at {string.Join(", ", references)}";
            if (total > references.Count) text += $" and {total - references.Count} more";
        }
        if (h.Available < h.Declared)
            text += $" (partial: {h.Available} of {h.Declared} declared bytes are in the section)";
        return text;
    }
}
