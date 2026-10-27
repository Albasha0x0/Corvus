using System.Buffers.Binary;
using System.Text;
using Corvus.Core.Firmware;

namespace Corvus.Core.Archives;

/// <summary>AppImage (type 2) and snap packages: squashfs files, with notes naming the package and AppImage sections.</summary>
internal static class LinuxAppPackages
{
    /// <summary>Paths a squashfs read always extracts: snap.yaml and a desktop entry at the root.</summary>
    public static bool Metadata(string path) => path == "meta/snap.yaml" || (!path.Contains('/') && path.EndsWith(".desktop", StringComparison.Ordinal));

    /// <summary>The AppImage type (1 or 2) from the ELF identification bytes, or 0.</summary>
    public static int AppImageType(ReadOnlySpan<byte> b) =>
        b.Length >= 64 && b.StartsWith((ReadOnlySpan<byte>)[0x7F, 0x45, 0x4C, 0x46]) && b[8] == (byte)'A' && b[9] == (byte)'I' && b[10] is 1 or 2 ? b[10] : 0;

    /// <summary>A type 2 AppImage's squashfs offset (the end of the runtime's section headers), or -1.</summary>
    public static long Payload(ReadOnlySpan<byte> b)
    {
        if (AppImageType(b) != 2 || b[5] != 1) return -1;
        long end = b[4] == 2
            ? (long)Math.Min(BinaryPrimitives.ReadUInt64LittleEndian(b[0x28..]), int.MaxValue) + BinaryPrimitives.ReadUInt16LittleEndian(b[0x3A..]) * (long)BinaryPrimitives.ReadUInt16LittleEndian(b[0x3C..])
            : BinaryPrimitives.ReadUInt32LittleEndian(b[0x20..]) + BinaryPrimitives.ReadUInt16LittleEndian(b[0x2E..]) * (long)BinaryPrimitives.ReadUInt16LittleEndian(b[0x30..]);
        return end > 0 && end <= b.Length - 96 && SquashfsReader.Looks(b[(int)end..]) ? end : -1;
    }

    public static ContainerContents OpenAppImage(byte[] data, long payload, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        var fs = SquashfsReader.Read(new FsSource(new MemoryStream(data, writable: false), payload, data.Length - payload, name), allFiles, limits, ct);
        var sections = Sections(data);
        var note = new StringBuilder($"AppImage type 2: a {(data[4] == 2 ? 64 : 32)}-bit runtime of {payload:N0} bytes, squashfs at 0x{payload:X}");
        if (Text(sections, ".upd_info") is { Length: > 0 } update) note.Append($"; update information {update}");
        note.Append(sections.TryGetValue(".sha256_sig", out var sig) ? sig.AsSpan().ContainsAnyExcept((byte)0) ? $"; signed ({Text(sections, ".sha256_sig")!.Length:N0}-byte signature)" : "; not signed" : "; no signature section");
        if (Desktop(fs) is { } desktop) note.Append($"; {desktop}");
        fs.Notes.Insert(0, note.Append('.').ToString());
        return fs with { Kind = "AppImage" };
    }

    /// <summary>The squashfs contents named as a snap when meta/snap.yaml is present; otherwise unchanged.</summary>
    public static ContainerContents Snap(ContainerContents fs)
    {
        if (fs.Items.FirstOrDefault(i => i.Name == "meta/snap.yaml") is not { } yaml) return fs;
        var top = new Dictionary<string, string>(StringComparer.Ordinal);
        var apps = new List<string>();
        bool inApps = false;
        foreach (var raw in Encoding.UTF8.GetString(yaml.Bytes).Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            if (line.Length == 0 || line.TrimStart().StartsWith('#')) continue;
            if (!char.IsWhiteSpace(line[0]))
            {
                int colon = line.IndexOf(':');
                if (colon <= 0) { inApps = false; continue; }
                string key = line[..colon];
                inApps = key == "apps";
                top[key] = line[(colon + 1)..].Trim().Trim('\'', '"');
            }
            // An app is a key indented one level under apps:.
            else if (inApps && line.Length > 2 && line[..2] == "  " && !char.IsWhiteSpace(line[2]) && line.TrimEnd().EndsWith(':')) apps.Add(line.Trim().TrimEnd(':'));
        }
        var note = new StringBuilder($"snap {top.GetValueOrDefault("name", "?")} {top.GetValueOrDefault("version", "")}".TrimEnd());
        if (top.GetValueOrDefault("summary") is { Length: > 0 } summary) note.Append($": {summary}");
        foreach (var key in new[] { "base", "grade", "confinement" })
            if (top.GetValueOrDefault(key) is { Length: > 0 } v) note.Append($"; {key} {v}");
        if (apps.Count > 0) note.Append($"; apps {string.Join(", ", apps)}");
        fs.Notes.Insert(0, note.Append('.').ToString());
        return fs with { Kind = "snap package" };
    }

    // The desktop entry at the root: its name, command, icon and version.
    private static string? Desktop(ContainerContents fs)
    {
        if (fs.Items.FirstOrDefault(i => !i.Name.Contains('/') && i.Name.EndsWith(".desktop", StringComparison.Ordinal)) is not { } entry) return null;
        var keys = new Dictionary<string, string>(StringComparer.Ordinal);
        bool main = false;
        foreach (var raw in Encoding.UTF8.GetString(entry.Bytes).Split('\n'))
        {
            var line = raw.Trim();
            if (line.StartsWith('[')) { main = line == "[Desktop Entry]"; continue; }
            int eq = line.IndexOf('=');
            if (main && eq > 0) keys.TryAdd(line[..eq], line[(eq + 1)..]);
        }
        var parts = new List<string>();
        foreach (var (key, label) in new[] { ("Exec", "command"), ("Icon", "icon"), ("X-AppImage-Version", "version") })
            if (keys.GetValueOrDefault(key) is { Length: > 0 } v) parts.Add($"{label} {v}");
        return $"desktop entry {entry.Name}: {keys.GetValueOrDefault("Name", "?")}" + (parts.Count > 0 ? $" ({string.Join(", ", parts)})" : "");
    }

    private static string? Text(Dictionary<string, byte[]> sections, string name) =>
        sections.TryGetValue(name, out var b) ? Encoding.UTF8.GetString(b).TrimEnd('\0') : null;

    // Section contents by name, from the section headers and their string table; empty on a damaged table.
    private static Dictionary<string, byte[]> Sections(byte[] d)
    {
        var result = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        bool wide = d[4] == 2;
        long shoff = wide ? (long)Math.Min(BinaryPrimitives.ReadUInt64LittleEndian(d.AsSpan(0x28)), int.MaxValue) : BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan(0x20));
        int size = BinaryPrimitives.ReadUInt16LittleEndian(d.AsSpan(wide ? 0x3A : 0x2E)), count = BinaryPrimitives.ReadUInt16LittleEndian(d.AsSpan(wide ? 0x3C : 0x30));
        int strings = BinaryPrimitives.ReadUInt16LittleEndian(d.AsSpan(wide ? 0x3E : 0x32));
        if (size < (wide ? 64 : 40) || strings >= count || shoff + (long)size * count > d.Length) return result;
        (long Offset, long Size, int Name) Header(int i)
        {
            var h = d.AsSpan((int)(shoff + (long)size * i), size);
            return wide
                ? ((long)Math.Min(BinaryPrimitives.ReadUInt64LittleEndian(h[0x18..]), long.MaxValue), (long)Math.Min(BinaryPrimitives.ReadUInt64LittleEndian(h[0x20..]), long.MaxValue), (int)BinaryPrimitives.ReadUInt32LittleEndian(h))
                : (BinaryPrimitives.ReadUInt32LittleEndian(h[0x10..]), BinaryPrimitives.ReadUInt32LittleEndian(h[0x14..]), (int)BinaryPrimitives.ReadUInt32LittleEndian(h));
        }
        var table = Header(strings);
        if (table.Offset < 0 || table.Size < 0 || table.Offset + table.Size > d.Length) return result;
        var names = d.AsSpan((int)table.Offset, (int)table.Size);
        for (int i = 0; i < count; i++)
        {
            var (offset, length, name) = Header(i);
            if (name < 0 || name >= names.Length || offset < 0 || length < 0 || length > 1 << 20 || offset + length > d.Length) continue;
            int z = names[name..].IndexOf((byte)0);
            string key = Encoding.ASCII.GetString(z < 0 ? names[name..] : names.Slice(name, z));
            result.TryAdd(key, d.AsSpan((int)offset, (int)length).ToArray());
        }
        return result;
    }
}
