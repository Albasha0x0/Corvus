using System.Text;
using Corvus.Core.Archives;

namespace Corvus.Core.Installers;

/// <summary>A file the package installs: its key, install path, size, component and the cabinet that holds it (null when stored outside the package).</summary>
internal sealed record MsiFile(string Key, string Path, long Size, string? Component, int Sequence, string? Cabinet);

/// <summary>A custom action decoded from its type bits: what it runs (DLL, EXE, JScript, VBScript, ...), from where, and how.</summary>
internal sealed record MsiCustomAction(string Action, int Type, string Kind, string SourceKind, string? Source, string? Target, string Execution, IReadOnlyList<string> Sequences)
{
    /// <summary>Runs as LocalSystem: deferred without impersonation.</summary>
    public bool System => (Type & 0x400) != 0 && (Type & 0x800) != 0;
}

/// <summary>What a Windows Installer package does: properties, files, cabinets, custom actions and when they run, registry, services.</summary>
internal sealed class MsiPackage
{
    public required MsiDatabase Database { get; init; }
    public Dictionary<string, string> Properties { get; private set; } = [];
    public Dictionary<string, string> Summary { get; private set; } = [];
    public List<MsiFile> Files { get; } = [];
    public List<MsiCustomAction> CustomActions { get; } = [];
    public List<string> Notes { get; } = [];

    public static MsiPackage Read(byte[] data, string name, CancellationToken ct)
    {
        var p = new MsiPackage { Database = MsiDatabase.Read(data, name, ct) };
        p.Properties = p.Database.Properties();
        p.Summary = SummaryInformation(p.Database);
        p.ReadFiles();
        p.ReadCustomActions();
        p.Notes.AddRange(p.Database.Notes);
        return p;
    }

    private static string? S(Dictionary<string, object?> r, string c) => r.GetValueOrDefault(c) as string;
    private static int? I(Dictionary<string, object?> r, string c) => r.GetValueOrDefault(c) as int?;

    /// <summary>The long name of a "short|long" name, without its source part ("target:source").</summary>
    public static string LongName(string? value)
    {
        if (string.IsNullOrEmpty(value)) return "";
        var target = value.Split(':')[0];
        return target.Contains('|') ? target[(target.IndexOf('|') + 1)..] : target;
    }

    /// <summary>The system folders a package names by property, written as their usual path (as msiextract writes them).</summary>
    private static readonly Dictionary<string, string> StandardFolders = new(StringComparer.Ordinal)
    {
        ["ProgramFilesFolder"] = "Program Files", ["ProgramFiles64Folder"] = "Program Files", ["ProgramFiles6432Folder"] = "Program Files",
        ["CommonFilesFolder"] = "Program Files/Common Files", ["CommonFiles64Folder"] = "Program Files/Common Files", ["WindowsFolder"] = "Windows",
        ["SystemFolder"] = "Windows/System32", ["System64Folder"] = "Windows/System32", ["System16Folder"] = "Windows/System", ["FontsFolder"] = "Windows/Fonts",
        ["TempFolder"] = "Temp", ["AppDataFolder"] = "AppData/Roaming", ["LocalAppDataFolder"] = "AppData/Local", ["CommonAppDataFolder"] = "ProgramData",
        ["DesktopFolder"] = "Desktop", ["StartMenuFolder"] = "Start Menu", ["ProgramMenuFolder"] = "Start Menu/Programs",
        ["StartupFolder"] = "Start Menu/Programs/Startup", ["PersonalFolder"] = "Documents", ["FavoritesFolder"] = "Favorites", ["SendToFolder"] = "SendTo",
        ["TemplateFolder"] = "Templates", ["NetHoodFolder"] = "NetHood", ["PrintHoodFolder"] = "PrintHood", ["RecentFolder"] = "Recent", ["AdminToolsFolder"] = "Administrative Tools",
    };

    /// <summary>Install paths of the Directory table: each entry's long target name under its parent; TARGETDIR (and other roots) by key.</summary>
    public Dictionary<string, string> Directories()
    {
        var parent = new Dictionary<string, string?>(StringComparer.Ordinal);
        var names = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var r in Database.Table("Directory")?.Records() ?? [])
        {
            if (S(r, "Directory") is not { } key) continue;
            parent[key] = S(r, "Directory_Parent");
            names[key] = LongName(S(r, "DefaultDir"));
        }
        var paths = new Dictionary<string, string>(StringComparer.Ordinal);
        string Resolve(string key, int depth)
        {
            if (paths.TryGetValue(key, out var known)) return known;
            if (StandardFolders.TryGetValue(key, out var standard)) return paths[key] = standard;
            if (depth > 64 || !names.TryGetValue(key, out var name)) return key;
            var up = parent.GetValueOrDefault(key);
            // A root (no parent, or itself) is named by its key, as SourceDir for TARGETDIR.
            string path = string.IsNullOrEmpty(up) || up == key ? (key == "TARGETDIR" ? "SourceDir" : key)
                : name is "." or "" ? Resolve(up, depth + 1) : Resolve(up, depth + 1) + "/" + name;
            return paths[key] = path;
        }
        foreach (var key in names.Keys) Resolve(key, 0);
        return paths;
    }

    private void ReadFiles()
    {
        var dirs = Directories();
        var componentDir = (Database.Table("Component")?.Records() ?? []).Where(r => S(r, "Component") != null)
            .GroupBy(r => S(r, "Component")!).ToDictionary(g => g.Key, g => S(g.First(), "Directory_"), StringComparer.Ordinal);
        var media = (Database.Table("Media")?.Records() ?? []).Select(r => (Last: I(r, "LastSequence") ?? 0, Cabinet: S(r, "Cabinet"))).OrderBy(m => m.Last).ToList();
        foreach (var r in Database.Table("File")?.Records() ?? [])
        {
            if (S(r, "File") is not { } key) continue;
            var component = S(r, "Component_");
            var dir = component != null && componentDir.GetValueOrDefault(component) is { } d ? dirs.GetValueOrDefault(d, d) : "SourceDir";
            int sequence = I(r, "Sequence") ?? 0;
            var cabinet = media.FirstOrDefault(m => m.Last >= sequence).Cabinet;
            Files.Add(new MsiFile(key, dir + "/" + LongName(S(r, "FileName")), I(r, "FileSize") ?? 0, component, sequence, cabinet));
        }
    }

    private static readonly Dictionary<int, (string Kind, string Source)> Bases = new()
    {
        [1] = ("DLL", "Binary"), [2] = ("EXE", "Binary"), [5] = ("JScript", "Binary"), [6] = ("VBScript", "Binary"),
        [17] = ("DLL", "File"), [18] = ("EXE", "File"), [21] = ("JScript", "File"), [22] = ("VBScript", "File"),
        [34] = ("EXE", "Directory"), [37] = ("JScript", "inline"), [38] = ("VBScript", "inline"), [50] = ("EXE", "Property"),
        [53] = ("JScript", "Property"), [54] = ("VBScript", "Property"), [19] = ("error message", "none"), [35] = ("set directory", "Directory"),
        [51] = ("set property", "Property"), [7] = ("nested install", "substorage"), [23] = ("nested install", "source"), [39] = ("nested install", "product code"),
    };

    private void ReadCustomActions()
    {
        var sequences = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        foreach (var table in new[] { "InstallExecuteSequence", "InstallUISequence", "AdminExecuteSequence", "AdvtExecuteSequence" })
            foreach (var r in Database.Table(table)?.Records() ?? [])
                if (S(r, "Action") is { } action)
                {
                    if (!sequences.TryGetValue(action, out var list)) sequences[action] = list = [];
                    var condition = S(r, "Condition");
                    list.Add($"{table} {I(r, "Sequence")}{(string.IsNullOrEmpty(condition) ? "" : $" if {condition}")}");
                }
        foreach (var r in Database.Table("CustomAction")?.Records() ?? [])
        {
            if (S(r, "Action") is not { } action || I(r, "Type") is not { } type) continue;
            var (kind, source) = Bases.GetValueOrDefault(type & 0x3F, ($"type {type & 0x3F}", "?"));
            string execution = (type & 0x400) == 0 ? "immediate" : (type & 0x100) != 0 ? "rollback" : (type & 0x200) != 0 ? "commit" : "deferred";
            if ((type & 0x400) != 0) execution += (type & 0x800) != 0 ? ", as LocalSystem" : ", as the user";
            if ((type & 0x40) != 0) execution += ", errors ignored";
            if ((type & 0x80) != 0) execution += ", asynchronous";
            if ((type & 0x2000) != 0) execution += ", target hidden from the log";
            CustomActions.Add(new MsiCustomAction(action, type, kind, source, S(r, "Source"), S(r, "Target"), execution, sequences.GetValueOrDefault(action) ?? []));
        }
    }

    /// <summary>The \x05SummaryInformation property set: title, subject, author, keywords, template (platform;languages), revision (package code), creating application, and the word count's source flags.</summary>
    private static Dictionary<string, string> SummaryInformation(MsiDatabase db)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        var s = db.StreamData("\u0005SummaryInformation", 1 << 20);
        if (s == null || s.Length < 48) return result;
        try
        {
            int setAt = (int)System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(s.AsSpan(44));
            int count = (int)System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(s.AsSpan(setAt + 4));
            var names = new Dictionary<int, string> { [2] = "title", [3] = "subject", [4] = "author", [5] = "keywords", [6] = "comments", [7] = "template", [8] = "lastSavedBy", [9] = "revision", [12] = "created", [13] = "saved", [14] = "pageCount", [15] = "wordCount", [18] = "application", [19] = "security" };
            for (int i = 0; i < Math.Min(count, 64); i++)
            {
                int id = (int)System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(s.AsSpan(setAt + 8 + i * 8));
                int at = setAt + (int)System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(s.AsSpan(setAt + 12 + i * 8));
                if (!names.TryGetValue(id, out var name) || at + 8 > s.Length) continue;
                int vt = System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(s.AsSpan(at));
                switch (vt)
                {
                    case 30: // VT_LPSTR
                        int len = (int)System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(s.AsSpan(at + 4));
                        if (len > 0 && at + 8 + len <= s.Length) result[name] = Encoding.Latin1.GetString(s, at + 8, len).TrimEnd('\0');
                        break;
                    case 3 or 2: result[name] = System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(s.AsSpan(at + 4)).ToString(System.Globalization.CultureInfo.InvariantCulture); break;
                    case 64:
                        long ft = System.Buffers.Binary.BinaryPrimitives.ReadInt64LittleEndian(s.AsSpan(at + 4));
                        if (ft > 0 && ft < DateTime.MaxValue.ToFileTimeUtc()) result[name] = DateTime.FromFileTimeUtc(ft).ToString("u", System.Globalization.CultureInfo.InvariantCulture);
                        break;
                }
            }
            if (result.TryGetValue("wordCount", out var wc) && int.TryParse(wc, out var flags))
                result["source"] = ((flags & 2) != 0 ? "compressed files" : "uncompressed files") + ((flags & 1) != 0 ? ", short names" : "") + ((flags & 4) != 0 ? ", administrative image" : "");
        }
        catch (ArgumentOutOfRangeException) { result["damaged"] = "the summary information runs past its stream"; }
        return result;
    }

    /// <summary>The bytes of the embedded cabinet a Media row names ("#name"), or null for an external one.</summary>
    public byte[]? EmbeddedCabinet(string? cabinet, long max) => cabinet is ['#', .. var stream] ? Database.StreamData(stream, max) : null;

    /// <summary>A Binary-table stream by its key.</summary>
    public byte[]? Binary(string key, long max) => Database.StreamData("Binary." + key, max);

    public static string ScriptExtension(string kind) => kind switch { "JScript" => ".js", "VBScript" => ".vbs", _ => ".txt" };
}

/// <summary>Windows Installer packages as containers: files by install path, Binary/ and CustomAction/, plus tables/ and streams/ with allFiles.</summary>
internal sealed class MsiReader : IContainerReader
{
    public string Kind => "msi";

    public bool Accepts(ReadOnlySpan<byte> data, string name) => MsiDatabase.Looks(data);

    public ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        var p = MsiPackage.Read(data, name, ct);
        var db = p.Database;
        var items = new List<ExtractedItem>();
        var entries = new List<ContainerEntry>();
        var notes = new List<string>(p.Notes);
        long total = 0;
        var byKey = p.Files.GroupBy(f => f.Key).ToDictionary(g => g.Key, g => g.First(), StringComparer.Ordinal);
        var extracted = new HashSet<string>(StringComparer.Ordinal);
        foreach (var cabinet in p.Files.Select(f => f.Cabinet).Where(c => c is ['#', ..]).Distinct())
        {
            ct.ThrowIfCancellationRequested();
            byte[]? bytes;
            try { bytes = p.EmbeddedCabinet(cabinet, limits.MaxItemBytes); }
            catch (ToolError ex) when (ex.Code == ErrorCode.LimitExceeded) { notes.Add(ex.Message); continue; }
            if (bytes == null || !Cabinet.Looks(bytes)) { notes.Add($"embedded cabinet {cabinet}: not found or not a cabinet"); continue; }
            var cab = CabinetReader.Contents(Cabinet.Read(bytes, cabinet!), allFiles, limits, ct, "",
                f => byKey.TryGetValue(f.Name, out var mf) ? mf.Path : "unknown/" + f.Name);
            foreach (var f in Cabinet.Read(bytes, cabinet!).Files) extracted.Add(f.Name);
            items.AddRange(cab.Items);
            entries.AddRange(cab.Entries!);
            notes.AddRange(cab.Notes.Select(n => $"{cabinet}: {n}"));
            total += cab.Items.Sum(i => (long)i.Bytes.Length);
        }
        int outside = 0;
        foreach (var f in p.Files.Where(f => !extracted.Contains(f.Key)))
        {
            entries.Add(new ContainerEntry(f.Path, f.Size, f.Cabinet != null ? $"in external cabinet {f.Cabinet}" : "stored beside the package"));
            outside++;
        }
        if (outside > 0) notes.Add($"{outside} file(s) are not inside the package (external cabinets or uncompressed source files): listed, not extracted");
        foreach (var key in (db.Table("Binary")?.Rows ?? []).Select(r => r[0] as string).Where(k => k != null))
        {
            var bytes = p.Binary(key!, limits.MaxItemBytes);
            if (bytes == null) continue;
            ArchiveItems.Take(items, entries, "Binary table", $"Binary/{key}{BinaryExtension(p, key!, bytes)}", bytes, true, limits, ref total);
        }
        foreach (var ca in p.CustomActions.Where(c => c.SourceKind == "inline" && c.Target != null))
            ArchiveItems.Take(items, entries, "custom action script", $"CustomAction/{ca.Action}{MsiPackage.ScriptExtension(ca.Kind)}", Encoding.UTF8.GetBytes(ca.Target!), true, limits, ref total);
        if (allFiles)
        {
            foreach (var t in db.Tables.Values)
                ArchiveItems.Take(items, entries, "table", $"tables/{t.Name}.tsv", Encoding.UTF8.GetBytes(Tsv(t)), true, limits, ref total);
            foreach (var (streamName, entry) in db.Streams.Where(s => !s.Key.StartsWith('!') && !s.Key.StartsWith("Binary.", StringComparison.Ordinal)))
            {
                if (p.Files.Any(f => f.Cabinet == "#" + streamName)) continue;
                byte[] bytes;
                try { bytes = db.File.Read(entry, limits.MaxItemBytes); }
                catch (ToolError ex) when (ex.Code == ErrorCode.LimitExceeded) { notes.Add(ex.Message); continue; }
                ArchiveItems.Take(items, entries, "installer stream", "streams/" + Documents.CompoundFileReader.StreamPath(streamName), bytes, true, limits, ref total);
            }
        }
        if (p.CustomActions.Count > 0)
            notes.Add($"{p.CustomActions.Count} custom action(s), {p.CustomActions.Count(c => c.Kind is "DLL" or "EXE" or "JScript" or "VBScript")} running code; summarize_file view=installer says what each runs and when.");
        return new ContainerContents($"Windows Installer {db.Kind}", items, notes) { Entries = entries };
    }

    /// <summary>The extension of a Binary-table stream: the script language of the custom action that runs it, else from its content.</summary>
    public static string BinaryExtension(MsiPackage p, string key, byte[] bytes) =>
        p.CustomActions.FirstOrDefault(c => c.SourceKind == "Binary" && c.Source == key && c.Kind is "JScript" or "VBScript") is { } script
            ? MsiPackage.ScriptExtension(script.Kind) : Extension(bytes);

    private static string Extension(byte[] b)
    {
        var kind = Blob.Identify(b);
        if (kind is "native PE" or ".NET assembly" or "NativeAOT executable") return PeImage.TryParse(b)?.IsDll == true ? ".dll" : ".exe";
        return kind switch { "cab" => ".cab", "zip" => ".zip", "ole (msi/doc/xls)" => ".ole", "png" => ".png", "ico" => ".ico", "gif" => ".gif", "jpeg" => ".jpg", "text" => ".txt", _ => "" };
    }

    public static string Tsv(MsiTable t)
    {
        var sb = new StringBuilder();
        sb.AppendLine(string.Join('\t', t.Columns));
        foreach (var r in t.Rows) sb.AppendLine(string.Join('\t', r.Select(v => v?.ToString()?.Replace('\t', ' ').Replace("\r", "\\r", StringComparison.Ordinal).Replace("\n", "\\n", StringComparison.Ordinal) ?? "")));
        return sb.ToString();
    }
}
