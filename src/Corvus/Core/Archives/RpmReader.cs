using System.Buffers.Binary;
using System.Text;

namespace Corvus.Core.Archives;

/// <summary>
/// RPM packages (lead, signature header, header, payload): the package fields and the file list as the header records
/// them, with modes, owners, link targets and digests; the payload decompressed and read as cpio for the file contents;
/// the install scriptlets under scripts/. A file the header lists but the payload omits (%ghost) is noted as such.
/// </summary>
internal sealed class RpmReader : IContainerReader
{
    private const int MaxEntries = 1_000_000;

    public string Kind => "rpm package";

    public bool Accepts(ReadOnlySpan<byte> data, string name) => data.Length >= 96 && data.StartsWith((ReadOnlySpan<byte>)[0xED, 0xAB, 0xEE, 0xDB]);

    /// <summary>A header's tags: the value of each, decoded by its type (strings, string arrays, integer arrays, binary).</summary>
    internal sealed class Header(Dictionary<int, object> tags)
    {
        public string? String(int tag) => tags.GetValueOrDefault(tag) switch { string s => s, string[] { Length: > 0 } a => a[0], _ => null };
        public string[] Strings(int tag) => tags.GetValueOrDefault(tag) switch { string[] a => a, string s => [s], _ => [] };
        public long[] Numbers(int tag) => tags.GetValueOrDefault(tag) as long[] ?? [];
        public long? Number(int tag) => Numbers(tag) is { Length: > 0 } n ? n[0] : null;
        public bool Has(int tag) => tags.ContainsKey(tag);
        public IEnumerable<int> Tags => tags.Keys;
    }

    /// <summary>
    /// Reads a header structure at <paramref name="at"/> (magic 8E AD E8, index entries, data store); <paramref name="end"/>
    /// is the offset after it. Throws <see cref="InvalidDataException"/> on a damaged header.
    /// </summary>
    internal static Header ReadHeader(ReadOnlySpan<byte> d, int at, out int end)
    {
        if (at > d.Length - 16 || !d[at..].StartsWith((ReadOnlySpan<byte>)[0x8E, 0xAD, 0xE8])) throw new InvalidDataException($"no header at 0x{at:X}");
        int count = BinaryPrimitives.ReadInt32BigEndian(d[(at + 8)..]), size = BinaryPrimitives.ReadInt32BigEndian(d[(at + 12)..]);
        int index = at + 16;
        if (count < 0 || count > MaxEntries || size < 0 || (long)index + 16L * count + size > d.Length) throw new InvalidDataException($"the header at 0x{at:X} runs past the file");
        int store = index + 16 * count;
        end = store + size;
        var tags = new Dictionary<int, object>();
        for (int i = 0; i < count; i++)
        {
            var e = d.Slice(index + 16 * i, 16);
            int tag = BinaryPrimitives.ReadInt32BigEndian(e), type = BinaryPrimitives.ReadInt32BigEndian(e[4..]);
            int offset = BinaryPrimitives.ReadInt32BigEndian(e[8..]), n = BinaryPrimitives.ReadInt32BigEndian(e[12..]);
            if (offset < 0 || offset > size || n < 0) throw new InvalidDataException($"tag {tag} points past its header");
            var data = d.Slice(store + offset, size - offset);
            tags[tag] = type switch
            {
                1 or 2 => Ints(data, n, 1),
                3 => Ints(data, n, 2),
                4 => Ints(data, n, 4),
                5 => Ints(data, n, 8),
                6 => Strings(data, 1)[0],
                8 or 9 => Strings(data, n),
                7 => data[..Math.Min(n, data.Length)].ToArray(),
                _ => Array.Empty<long>(),
            };
        }
        return new Header(tags);
    }

    private static long[] Ints(ReadOnlySpan<byte> d, int n, int width)
    {
        if ((long)n * width > d.Length) throw new InvalidDataException("an integer array runs past its header");
        var v = new long[n];
        for (int i = 0; i < n; i++)
            v[i] = width switch
            {
                1 => d[i],
                2 => BinaryPrimitives.ReadUInt16BigEndian(d[(2 * i)..]),
                4 => BinaryPrimitives.ReadUInt32BigEndian(d[(4 * i)..]),
                _ => BinaryPrimitives.ReadInt64BigEndian(d[(8 * i)..]),
            };
        return v;
    }

    private static string[] Strings(ReadOnlySpan<byte> d, int n)
    {
        var v = new string[n];
        for (int i = 0; i < n; i++)
        {
            int z = d.IndexOf((byte)0);
            if (z < 0) throw new InvalidDataException("a string runs past its header");
            v[i] = Encoding.UTF8.GetString(d[..z]);
            d = d[(z + 1)..];
        }
        return v;
    }

    // Header tags (rpmtag.h).
    private const int Name = 1000, Version = 1001, Release = 1002, Epoch = 1003, Summary = 1004, BuildTime = 1006, BuildHost = 1007, License = 1014,
        Arch = 1022, OldFileNames = 1027, FileSizes = 1028, FileModes = 1030, FileDigests = 1035, FileLinkTos = 1036, FileFlags = 1037,
        FileUserName = 1039, FileGroupName = 1040, SourceRpm = 1044, ProvideName = 1047, RequireName = 1049, DirIndexes = 1116, BaseNames = 1117,
        DirNames = 1118, PayloadFormat = 1124, PayloadCompressor = 1125, LongFileSizes = 5008, FileDigestAlgo = 5011;

    private static readonly (int Tag, int Program, string Name)[] Scriptlets =
        [(1023, 1085, "preinstall"), (1024, 1086, "postinstall"), (1025, 1087, "preuninstall"), (1026, 1088, "postuninstall"), (1079, 1091, "verify"), (1151, 1153, "pretrans"), (1152, 1154, "posttrans")];

    private static readonly Dictionary<long, string> DigestAlgorithms = new() { [1] = "MD5", [2] = "SHA-1", [8] = "SHA-256", [9] = "SHA-384", [10] = "SHA-512", [11] = "SHA-224" };

    // Signature header tags.
    private static readonly (int Tag, string Name)[] Signatures = [(267, "DSA"), (268, "RSA"), (269, "SHA-1"), (273, "SHA-256"), (278, "SHA3-256"), (1002, "PGP"), (1004, "MD5"), (1005, "GPG")];

    public ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        Header signature, header;
        int payloadAt;
        try
        {
            signature = ReadHeader(data, 96, out int sigEnd);
            // The signature header is padded to a multiple of 8 bytes.
            header = ReadHeader(data, (sigEnd + 7) & ~7, out payloadAt);
        }
        catch (InvalidDataException ex) { throw new ToolError(ErrorCode.MalformedInput, $"{name}: not a readable rpm package: {ex.Message}"); }
        bool source = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(6)) == 1;
        var notes = new List<string>();
        var items = new List<ExtractedItem>();

        // The payload's contents, by path.
        var contents = new Dictionary<string, ExtractedItem>(StringComparer.Ordinal);
        string compressor = header.String(PayloadCompressor) ?? "gzip", format = header.String(PayloadFormat) ?? "cpio";
        if (format != "cpio") notes.Add($"payload format {format} is not read");
        else
        {
            try
            {
                var cpio = Payload(compressor, data.AsSpan(payloadAt), limits);
                var inner = new CpioReader().Open(cpio, name, allFiles: true, limits, ct);
                foreach (var item in inner.Items) contents[item.Name] = item;
                notes.AddRange(inner.Notes.Select(n => "payload: " + n));
            }
            catch (InvalidDataException ex) { notes.Add($"payload ({compressor}): {ex.Message}"); }
        }

        var entries = new List<ContainerEntry>();
        var paths = Paths(header);
        long[] sizes = header.Numbers(LongFileSizes) is { Length: > 0 } l ? l : header.Numbers(FileSizes), modes = header.Numbers(FileModes), flags = header.Numbers(FileFlags);
        string[] digests = header.Strings(FileDigests), links = header.Strings(FileLinkTos), users = header.Strings(FileUserName), groups = header.Strings(FileGroupName);
        string algorithm = DigestAlgorithms.GetValueOrDefault(header.Number(FileDigestAlgo) ?? 1, "digest");
        int ghosts = 0;
        for (int i = 0; i < paths.Count; i++)
        {
            ct.ThrowIfCancellationRequested();
            string path = paths[i].TrimStart('/');
            long mode = At(modes, i);
            bool ghost = (At(flags, i) & 0x40) != 0;
            var detail = new List<string>();
            if (At(users, i) is { Length: > 0 } user) detail.Add($"{user}:{At(groups, i)}");
            if ((mode & 0xF000) == 0x4000) detail.Add("directory");
            if ((mode & 0xF000) == 0xA000 && At(links, i) is { Length: > 0 } target) detail.Add($"symbolic link to {target}");
            if (At(digests, i) is { Length: > 0 } digest) detail.Add($"{algorithm} {digest}");
            if ((At(flags, i) & 1) != 0) detail.Add("configuration file");
            if (ghost) { detail.Add("not in the payload (%ghost)"); ghosts++; }
            entries.Add(new ContainerEntry(path, At(sizes, i), string.Join("; ", detail)) { Mode = Convert.ToString(mode & 0xFFF, 8) });
            if ((mode & 0xF000) == 0x8000 && !ghost && contents.TryGetValue(path, out var item) && (allFiles || Containers.IsInteresting(path)))
            {
                if (items.Count >= limits.MaxItems) { notes.Add("Stopped: the extraction limit was reached."); break; }
                items.Add(item with { Origin = "rpm payload" });
            }
        }
        foreach (var (tag, program, script) in Scriptlets)
        {
            if (header.String(tag) is not { Length: > 0 } body) continue;
            string interpreter = header.String(program) ?? "/bin/sh";
            items.Add(new ExtractedItem("scripts/" + script, Encoding.UTF8.GetBytes(body), $"{script} scriptlet ({interpreter})"));
            entries.Add(new ContainerEntry("scripts/" + script, Encoding.UTF8.GetByteCount(body), $"scriptlet run by {interpreter}"));
        }

        string epoch = header.Number(Epoch) is { } e ? $"{e}:" : "";
        string nevra = $"{header.String(Name)}-{epoch}{header.String(Version)}-{header.String(Release)}.{(source ? "src" : header.String(Arch))}";
        var summary = new StringBuilder($"{(source ? "source" : "binary")} rpm {nevra}");
        if (header.String(Summary) is { } s) summary.Append($": {s}");
        if (header.String(License) is { } lic) summary.Append($"; license {lic}");
        if (header.String(BuildHost) is { } host) summary.Append($"; built on {host}");
        if (header.Number(BuildTime) is { } time) summary.Append($" at {DateTimeOffset.FromUnixTimeSeconds(time):yyyy-MM-dd HH:mm:ss} UTC");
        summary.Append($"; {paths.Count:N0} file(s)" + (ghosts > 0 ? $" ({ghosts} not in the payload)" : "") + $", payload {format} compressed with {compressor}");
        summary.Append($"; requires {header.Strings(RequireName).Length}, provides {header.Strings(ProvideName).Length}");
        if (!source && header.String(SourceRpm) is { } srpm) summary.Append($"; source package {srpm}");
        var signed = Signatures.Where(t => signature.Has(t.Tag)).Select(t => t.Name).ToList();
        summary.Append(signed.Count > 0 ? $"; signature header: {string.Join(", ", signed)}" : "; signature header empty");
        notes.Insert(0, summary.Append('.').ToString());
        return new ContainerContents(Kind, items, notes) { Entries = entries };
    }

    private static byte[] Payload(string compressor, ReadOnlySpan<byte> payload, AnalysisLimits limits) => compressor switch
    {
        "none" or "" => payload.ToArray(),
        "gzip" or "bzip2" or "xz" or "lzma" or "zstd" => Firmware.FsCodec.DecodeStream(compressor, payload, limits.MaxTotalBytes),
        _ => throw new InvalidDataException($"compressor {compressor} is not read"),
    };

    /// <summary>Each file's path: dirname + basename (rpm 4.0 on), or the old full names.</summary>
    internal static List<string> Paths(Header h)
    {
        var bases = h.Strings(BaseNames);
        if (bases.Length == 0) return [.. h.Strings(OldFileNames)];
        var dirs = h.Strings(DirNames);
        var index = h.Numbers(DirIndexes);
        var paths = new List<string>(bases.Length);
        for (int i = 0; i < bases.Length; i++)
            paths.Add((i < index.Length && index[i] >= 0 && index[i] < dirs.Length ? dirs[index[i]] : "") + bases[i]);
        return paths;
    }

    private static long At(long[] a, int i) => i < a.Length ? a[i] : 0;

    private static string? At(string[] a, int i) => i < a.Length ? a[i] : null;
}
