using System.Text;

namespace Corvus.Core.Archives;

/// <summary>
/// ar archives (System V / GNU and BSD member names): static libraries list their object files, and a Debian package
/// (deb(5): debian-binary, control.tar.*, data.tar.*) is laid out as dpkg-deb --raw-extract writes it, data at the root
/// and the control files under DEBIAN/, with the control fields noted.
/// </summary>
internal sealed class ArReader : IContainerReader
{
    private const int MaxMembers = 100_000;

    public string Kind => "ar archive";

    public bool Accepts(ReadOnlySpan<byte> data, string name) => data.StartsWith("!<arch>\n"u8);

    public ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        var members = Members(data, name, ct);
        if (members.Count > 0 && members[0].Name == "debian-binary") return Debian(data, members, name, allFiles, limits, ct);
        var items = new List<ExtractedItem>();
        var entries = new List<ContainerEntry>();
        var notes = new List<string>();
        foreach (var (member, at, size) in members)
        {
            if (member is "/" or "/SYM64/" or "__.SYMDEF" or "__.SYMDEF SORTED") { notes.Add($"symbol table ({size:N0} bytes)"); continue; }
            entries.Add(new ContainerEntry(member, size));
            if (items.Count < limits.MaxItems) items.Add(new ExtractedItem(member, data.AsSpan(at, size).ToArray(), "ar member"));
        }
        if (entries.Count > items.Count) notes.Add($"{entries.Count - items.Count} of {entries.Count} members not extracted (the item limit).");
        return new ContainerContents(Kind, items, notes) { Entries = entries };
    }

    /// <summary>Each member's name and data range; GNU long names come from the "//" member, BSD ones ("#1/len") precede the data.</summary>
    private static List<(string Name, int At, int Size)> Members(byte[] data, string name, CancellationToken ct)
    {
        var members = new List<(string, int, int)>();
        byte[]? longNames = null;
        int p = 8;
        while (p + 60 <= data.Length)
        {
            ct.ThrowIfCancellationRequested();
            if (data[p + 58] != '`' || data[p + 59] != '\n') throw Malformed(name, $"no member header at 0x{p:X}");
            if (!int.TryParse(Encoding.ASCII.GetString(data, p + 48, 10).Trim(), out int size) || size < 0 || size > data.Length - p - 60)
                throw Malformed(name, $"the member at 0x{p:X} runs past the end");
            string raw = Encoding.ASCII.GetString(data, p, 16).TrimEnd(' ');
            int at = p + 60, length = size;
            string member;
            if (raw == "//") { longNames = data.AsSpan(at, size).ToArray(); member = raw; }
            else if (raw.StartsWith("#1/", StringComparison.Ordinal) && int.TryParse(raw[3..], out int n) && n >= 0 && n <= size)
            {
                member = Encoding.UTF8.GetString(data, at, n).TrimEnd('\0');
                at += n;
                length -= n;
            }
            else if (raw.Length > 1 && raw[0] == '/' && int.TryParse(raw[1..], out int offset))
            {
                if (longNames == null || offset < 0 || offset >= longNames.Length) throw Malformed(name, $"long name /{offset} has no entry in the name table");
                int end = longNames.AsSpan(offset).IndexOf((byte)'\n');
                member = Encoding.UTF8.GetString(longNames, offset, end < 0 ? longNames.Length - offset : end).TrimEnd('/');
            }
            else member = raw is "/" or "/SYM64/" ? raw : raw.TrimEnd('/');
            if (raw != "//") members.Add((member, at, length));
            if (members.Count > MaxMembers) throw Malformed(name, $"more than {MaxMembers:N0} members");
            p += 60 + size + (size & 1);
        }
        return members;
    }

    private ContainerContents Debian(byte[] data, List<(string Name, int At, int Size)> members, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        var items = new List<ExtractedItem>();
        var entries = new List<ContainerEntry>();
        var notes = new List<string>();
        string format = Encoding.ASCII.GetString(data, members[0].At, Math.Min(members[0].Size, 16)).Trim();
        string? control = null;
        foreach (var (member, at, size) in members.Skip(1))
        {
            bool isControl = member.StartsWith("control.tar", StringComparison.Ordinal);
            if (!isControl && !member.StartsWith("data.tar", StringComparison.Ordinal)) { notes.Add($"member {member} ({size:N0} bytes) is not part of the package layout; not read"); continue; }
            var tar = Tar(data.AsSpan(at, size).ToArray(), member, name, limits);
            if (tar == null) { notes.Add($"{member}: compression not read"); continue; }
            ContainerContents inner;
            try { inner = new ArchiveReader().Open(tar, member, allFiles || isControl, limits, ct); }
            catch (ToolError ex) when (ex.Code == ErrorCode.MalformedInput) { notes.Add($"{member}: {ex.Message}"); continue; }
            string prefix = isControl ? "DEBIAN/" : "";
            foreach (var e in inner.Entries ?? [])
                if (Path(e.Path) is { Length: > 0 } path) entries.Add(e with { Path = prefix + path });
            foreach (var item in inner.Items)
            {
                if (Path(item.Name) is not { Length: > 0 } path) continue;
                if (isControl && path == "control") control = Encoding.UTF8.GetString(item.Bytes);
                if (isControl || items.Count < limits.MaxItems) items.Add(item with { Name = prefix + path, Origin = $"debian package {member}" });
            }
            notes.AddRange(inner.Notes.Select(n => $"{member}: {n}"));
        }
        notes.Insert(0, control != null ? Fields(control) + $" (format {format})" : $"debian package format {format}: no control file");
        return new ContainerContents("debian package", items, notes) { Entries = entries };
    }

    /// <summary>The member as a tar: gzip, xz and plain tar are left to <see cref="ArchiveReader"/>, zstd is expanded here; null for another compression.</summary>
    private static byte[]? Tar(byte[] member, string memberName, string name, AnalysisLimits limits)
    {
        if (!member.AsSpan().StartsWith((ReadOnlySpan<byte>)[0x28, 0xB5, 0x2F, 0xFD]))
            return memberName.EndsWith(".zst", StringComparison.Ordinal) || !new ArchiveReader().Accepts(member, memberName) ? null : member;
        try
        {
            using var z = new ZstdSharp.DecompressionStream(new MemoryStream(member, writable: false));
            return Blob.ReadBounded(z, limits.MaxItemBytes) ?? throw new ToolError(ErrorCode.LimitExceeded, $"{name}: {memberName} decompresses past the {limits.MaxItemBytes:N0}-byte item limit.", "raise the limits");
        }
        catch (Exception ex) when (ex is IOException or ZstdSharp.ZstdException) { throw Malformed(name, $"{memberName} is unreadable zstd data ({ex.Message})"); }
    }

    /// <summary>A tar path as dpkg writes it ("./usr/bin/x") relative to the package root; empty for the root itself.</summary>
    private static string Path(string path) => path.StartsWith("./", StringComparison.Ordinal) ? path[2..] : path.TrimStart('/');

    /// <summary>"debian package name version (architecture): depends ...; description" from the control file (deb-control(5)).</summary>
    private static string Fields(string control)
    {
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in control.Split('\n'))
        {
            if (line.Length == 0) continue;
            if (line[0] is ' ' or '\t') continue; // continuation lines of a multi-line field
            int colon = line.IndexOf(':');
            if (colon <= 0) continue;
            fields.TryAdd(line[..colon].Trim(), line[(colon + 1)..].Trim());
        }
        string F(string key) => fields.GetValueOrDefault(key) ?? "";
        var text = $"debian package {F("Package")} {F("Version")} ({F("Architecture")})";
        if (F("Depends") is { Length: > 0 } depends) text += $": depends {depends}";
        if (F("Description") is { Length: > 0 } description) text += $"; {description}";
        return text.Length > 1000 ? text[..1000] + "..." : text;
    }

    private static ToolError Malformed(string name, string what) => new(ErrorCode.MalformedInput, $"{name}: not a readable ar archive: {what}.");
}
