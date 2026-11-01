using System.Buffers.Binary;
using System.Collections.Immutable;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Code;
using Corvus.Tools;

namespace Corvus.Services.Analysis;

/// <summary>Reports container headers in a native image; a cut body is partial.</summary>
// Layout: magic (4 ASCII), length (u32, counted from byte 8), count (1-256),
// then ascending u32 entry offsets from the magic. Magic is read at 4-byte
// aligned offsets. The body must reach 7.5 bits per byte.
internal sealed class ContainerHeaderRules : ISurveyRuleProvider
{
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
        var locations = headers.Take(Evidence.MaxLocations)
            .Select(h => Describe(index, sections, owned, h.Section, h.At, h.Found, ct))
            .ToList();
        return new Evidence(feature, headers.Count, locations);
    }

    private sealed record Header(string Magic, uint Declared, long Available, int[] Entries, double Entropy);

    /// <summary>
    /// Describes the container header at the start of <paramref name="data"/>; null when
    /// shorter than 12 bytes or the layout does not hold. A body under 600 bytes is named partial.
    /// </summary>
    internal static string? DescribeLayout(byte[] data)
    {
        if (data.Length < 12 || data.AsSpan(0, 4).IndexOfAnyExcept(MagicBytes) >= 0) return null;
        if (Read(data, 0, decoded: true) is not { } h) return null;
        var text = $"container header '{h.Magic}', {h.Entries.Length} entries, declared length {h.Declared}";
        long body = h.Available - 4 - 4 * h.Entries.Length;
        return body < MinBody ? $"{text} (range holds only {body} of the {MinBody} body bytes needed to confirm)" : text;
    }

    // Decoded ranges skip the body entropy test and accept a short body.
    private static Header? Read(byte[] bytes, int at, bool decoded = false)
    {
        uint declared = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(at + 4));
        uint entries = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(at + 8));
        if (entries is 0 or > MaxEntries || declared < 4 + 4 * entries + (decoded ? 0 : MinBody)) return null;
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
        if (!decoded && bodyEnd - tableEnd < MinBody) return null;
        double entropy = decoded ? 0 : Blob.Entropy(bytes.AsSpan(tableEnd, (int)(bodyEnd - tableEnd)));
        if (!decoded && entropy < BodyEntropy) return null;
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
        var loaders = new Dictionary<uint, NativeFunction>();
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
                    var loader = index.LabelFunctionAt(hit);
                    if (loader is not null) loaders.TryAdd(loader.Start, loader);
                    if (references.Count < MaxReferences)
                        references.Add(loader is { } f
                            ? Format.Within(f.Name, f.Start, hit)
                            : $"{NativeAddress.Va(image, hit)} in {other.Name}");
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
        var read = loaders.Values.OrderBy(l => l.Start).Take(MaxReferences).ToList();
        if (loaders.Count > read.Count)
            text += $", read {read.Count} of {loaders.Count} loaders";
        var summaries = new List<CryptoAttribution.Found>();
        foreach (var loader in read)
        {
            ct.ThrowIfCancellationRequested();
            summaries.Add(CryptoAttribution.Summary(index, loader, ct));
        }
        var algorithms = summaries.SelectMany(x => x.Algorithms).ToImmutableSortedSet(StringComparer.Ordinal);
        var modes = summaries.Select(x => x.Mode).OfType<string>().ToImmutableSortedSet(StringComparer.Ordinal);
        if (algorithms.Count > 0)
            text += $", loader transform {string.Join(", ", algorithms)}" +
                    (modes.Count > 0 ? $" mode {string.Join(", ", modes)}" : ", mode not determined");

        // Ranges are file offsets for unpack_container; a cut container ends
        // its last entry at the section.
        long end = Math.Min((long)at + 8 + h.Declared, at + 8 + h.Available) - at;
        long Stop(int i) => Math.Min(i + 1 < h.Entries.Length ? h.Entries[i + 1] : end, end);
        string Range(int i) => h.Entries[i] >= end
            ? $"+0x{h.Entries[i]:X} outside the section"
            : $"+0x{h.Entries[i]:X} length {Math.Max(0, Stop(i) - h.Entries[i])}";
        text += $"; entry ranges {string.Join(", ", Enumerable.Range(0, Math.Min(h.Entries.Length, MaxReferences)).Select(Range))}" +
                (h.Entries.Length > MaxReferences ? $" and {h.Entries.Length - MaxReferences} more" : "");
        if (h.Available < h.Declared)
            text += $" (partial: {h.Available} of {h.Declared} declared bytes are in the section)";

        // Offset arithmetic is in long; an offset outside the section's raw
        // bytes or the file is not offered. RawOffset is read as the file
        // offset of the section start in every image format.
        long first = (long)section.RawOffset + at + h.Entries[0];
        bool inFile = h.Entries[0] < end && first < (long)section.RawOffset + section.RawSize
            && (image.FileSize == 0 || first < image.FileSize);
        long entryLength = Math.Max(0, Stop(0) - h.Entries[0]);
        var calls = new List<string>();
        if (inFile && entryLength > 0)
        {
            string mode = modes.Count == 1 && modes.Single() is "ECB" or "CBC" ? $" mode={modes.Single().ToLowerInvariant()}" : "";
            foreach (var name in Supported(summaries))
                calls.Add($"unpack_container path={image.Path} algorithm={name}{mode} " +
                          $"parameterFile=<json with key, iv, offset={first}, length={entryLength}>");
        }
        if (calls.Count > 0)
            text += ". Next: " + string.Join(" or ", calls) + " verifies entry 0";
        return text;
    }

    // The unpack_container algorithms the loaders' ciphers map to; an AES
    // key size other than 128 bits, or one not determined, maps to none.
    private static IEnumerable<string> Supported(List<CryptoAttribution.Found> summaries)
    {
        var all = summaries.SelectMany(x => x.Algorithms).ToList();
        if (all.Any(a => a.StartsWith("AES", StringComparison.Ordinal))
            && summaries.Where(x => x.Algorithms.Any(a => a.StartsWith("AES", StringComparison.Ordinal)))
                .All(x => x.AesKeyBits == 128))
            yield return "aes-128";
        if (all.Any(a => a.StartsWith("Blowfish", StringComparison.Ordinal)))
            yield return "blowfish";
    }
}
