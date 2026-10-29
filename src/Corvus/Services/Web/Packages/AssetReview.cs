using System.Buffers.Binary;
using System.Text.RegularExpressions;

namespace Corvus.Services.Web.Packages;

public static partial class PackageReview
{
    private const int MinTrailingBytes = 1024;

    private static readonly Regex AssetFile = new(@"\.(?:png|jpe?g|gif|wav|ttf|otf|woff2?|ttc|otc)$", RegexOptions.IgnoreCase | RegexOptions.NonBacktracking);

    private static readonly Regex CodeFile = new(@"\.(?:js|mjs|cjs|py)$", RegexOptions.NonBacktracking);

    /// <summary>Images, sounds and fonts with 1 KiB or more past their format's end that the package's own code names; empty when none.</summary>
    // Installers and editors append metadata, so trailing bytes no code names
    // are left out.
    private static List<PackageFinding> AssetTrailingData(PackageFiles files, PackageReport report, List<string> notes, CancellationToken ct)
    {
        var trailing = new List<(string Path, string Format, long End, long After)>();
        var notChecked = new List<string>();
        foreach (var path in files.Paths.Where(p => AssetFile.IsMatch(p) && !p.Contains("node_modules/", StringComparison.Ordinal)).Order(StringComparer.Ordinal))
        {
            ct.ThrowIfCancellationRequested();
            if (files.Bytes(path) is not { } bytes) continue;
            if (bytes.AsSpan().StartsWith("wOF2"u8) || bytes.AsSpan().StartsWith("ttcf"u8)) { notChecked.Add(path); continue; }
            if (FormatEnd(bytes) is not { } end || bytes.Length - end.End < MinTrailingBytes) continue;
            trailing.Add((path, end.Format, end.End, bytes.Length - end.End));
        }
        var findings = new List<PackageFinding>();
        if (trailing.Count == 0 && notChecked.Count == 0) return findings;
        var code = Capped(files, [.. files.Paths.Where(p => CodeFile.IsMatch(p) && !p.Contains("node_modules/", StringComparison.Ordinal)).Order(StringComparer.Ordinal)]);
        long read = 0;
        var texts = new List<(string Path, string Text)>();
        foreach (var path in code)
        {
            if (read > MaxScannedSourceBytes) { notes.Add($"asset references: code past the first {MaxScannedSourceBytes >> 20} MiB not searched, from {path}"); break; }
            if (files.Text(path) is not { } text) continue;
            read += text.Length;
            texts.Add((path, text));
        }
        List<string> Naming(string asset)
        {
            var name = asset[(asset.LastIndexOf('/') + 1)..];
            var literal = new Regex($@"[""'`](?:[^""'`\r\n]*[/\\])?{Regex.Escape(name)}[""'`]", RegexOptions.NonBacktracking);
            return texts.Where(t => literal.IsMatch(t.Text)).Select(t => t.Path).ToList();
        }
        // Their compressed or multi-font layout is not walked, so a named one is
        // unknown rather than clean.
        var named = notChecked.Where(a => Naming(a).Count > 0).ToList();
        if (named.Count > 0) notes.Add($"{named.Count} named assets not checked: WOFF2 or font collection ({string.Join(", ", named.Take(5))})");
        foreach (var asset in trailing)
        {
            var refs = Naming(asset.Path);
            if (refs.Count == 0) continue;
            var install = refs.FirstOrDefault(r => RunsAtInstall(report, r));
            var by = install ?? refs[0];
            findings.Add(new PackageFinding("package/asset-trailing-data", install != null ? "noteworthy" : "review", "binary",
                $"{asset.Path}: {asset.Format} data ends at byte {asset.End:N0}, {asset.After:N0} bytes follow; named in {by}" + (install != null ? ", which runs at install" : ""), asset.Path));
        }
        return findings;
    }

    /// <summary>True when an install-time script's command names <paramref name="path"/>'s file.</summary>
    private static bool RunsAtInstall(PackageReport report, string path)
    {
        var name = path[(path.LastIndexOf('/') + 1)..];
        return report.Scripts.Any(s => s.AtInstall && s.Command.Contains(name, StringComparison.Ordinal));
    }

    /// <summary>The format and the offset where its own structure ends; null for an unknown, truncated or malformed file.</summary>
    internal static (string Format, long End)? FormatEnd(byte[] b)
    {
        try
        {
            if (b.AsSpan().StartsWith((byte[])[0x89, (byte)'P', (byte)'N', (byte)'G', 0x0D, 0x0A, 0x1A, 0x0A])) return PngEnd(b) is { } png ? ("PNG", png) : null;
            if (b is [0xFF, 0xD8, 0xFF, ..]) return JpegEnd(b) is { } jpeg ? ("JPEG", jpeg) : null;
            if (b.AsSpan().StartsWith("GIF8"u8)) return GifEnd(b) is { } gif ? ("GIF", gif) : null;
            if (b.Length >= 12 && b.AsSpan().StartsWith("RIFF"u8) && b.AsSpan(8).StartsWith("WAVE"u8)) return ("RIFF", 8L + BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(4)));
            if (b.AsSpan().StartsWith("wOFF"u8)) return WoffEnd(b) is { } woff ? ("WOFF", woff) : null;
            if (b is [0, 1, 0, 0, ..] || b.AsSpan().StartsWith("OTTO"u8) || b.AsSpan().StartsWith("true"u8)) return SfntEnd(b) is { } sfnt ? ("font", sfnt) : null;
        }
        catch (Exception ex) when (ex is ArgumentOutOfRangeException or IndexOutOfRangeException) { }
        return null;
    }

    private static long? PngEnd(byte[] b)
    {
        for (long at = 8; at + 12 <= b.Length;)
        {
            long next = at + 12 + BinaryPrimitives.ReadUInt32BigEndian(b.AsSpan((int)at));
            if (b.AsSpan((int)at + 4, 4).SequenceEqual("IEND"u8)) return next;
            at = next;
        }
        return null;
    }

    // Segment lengths skip embedded thumbnails; entropy-coded data ends at a
    // marker other than a stuffed 0x00 or a restart.
    private static long? JpegEnd(byte[] b)
    {
        int at = 2;
        while (at + 2 <= b.Length)
        {
            if (b[at] != 0xFF) return null;
            byte marker = b[at + 1];
            if (marker == 0xFF) { at++; continue; }
            if (marker == 0xD9) return at + 2;
            if (marker is >= 0xD0 and <= 0xD7 or 0x01) { at += 2; continue; }
            at += 2 + BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(at + 2));
            if (marker != 0xDA) continue;
            while (at + 1 < b.Length && !(b[at] == 0xFF && b[at + 1] is not 0x00 and not (>= 0xD0 and <= 0xD7))) at++;
        }
        return null;
    }

    private static long? GifEnd(byte[] b)
    {
        int at = 13 + ((b[10] & 0x80) != 0 ? 3 << ((b[10] & 7) + 1) : 0);
        while (at < b.Length)
        {
            switch (b[at])
            {
                case 0x3B: return at + 1;
                case 0x21: at += 2; break;
                case 0x2C: at += 10 + ((b[at + 9] & 0x80) != 0 ? 3 << ((b[at + 9] & 7) + 1) : 0) + 1; break;
                default: return null;
            }
            // Data sub-blocks: a length byte each, ending at a zero length.
            while (b[at] != 0) at += b[at] + 1;
            at++;
        }
        return null;
    }

    private static long? SfntEnd(byte[] b)
    {
        int tables = BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(4));
        long end = 12 + 16L * tables;
        for (int i = 0; i < tables; i++)
        {
            var record = b.AsSpan(12 + 16 * i);
            end = Math.Max(end, (long)BinaryPrimitives.ReadUInt32BigEndian(record[8..]) + BinaryPrimitives.ReadUInt32BigEndian(record[12..]));
        }
        // Tables are padded to 4 bytes.
        return (end + 3) & ~3L;
    }

    private static long? WoffEnd(byte[] b)
    {
        int tables = BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(12));
        long end = 44 + 20L * tables;
        for (int i = 0; i < tables; i++)
        {
            var record = b.AsSpan(44 + 20 * i);
            end = Math.Max(end, (long)BinaryPrimitives.ReadUInt32BigEndian(record[4..]) + BinaryPrimitives.ReadUInt32BigEndian(record[8..]));
        }
        // Metadata and private data blocks follow the tables.
        end = Math.Max(end, (long)BinaryPrimitives.ReadUInt32BigEndian(b.AsSpan(24)) + BinaryPrimitives.ReadUInt32BigEndian(b.AsSpan(28)));
        end = Math.Max(end, (long)BinaryPrimitives.ReadUInt32BigEndian(b.AsSpan(36)) + BinaryPrimitives.ReadUInt32BigEndian(b.AsSpan(40)));
        return (end + 3) & ~3L;
    }
}
