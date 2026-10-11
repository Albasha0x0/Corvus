using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Core.Mobile;

namespace NetDecompilerMcp.Services.Mobile;

/// <summary>
/// An Android package written as a Gradle project skeleton: settings and build files from the manifest, the manifest and
/// resources decoded to XML (resource files at their canonical res/ paths, the resource table as values XML per
/// configuration), assets, jniLibs, other Java resources, and the code as Java through JADX when it is configured, else
/// smali. Signature files are left out.
/// </summary>
public sealed partial class AndroidProjectExport(DexService dex, JavaDecompilerService java)
{
    public sealed record Result(string Directory, int Files, string Sources, int Classes, int SourceFailures, IReadOnlyList<string> Notes);

    public static bool IsPackagePath(string value)
    {
        var ext = Path.GetExtension(value.Trim());
        return ext.Equals(".apk", StringComparison.OrdinalIgnoreCase) || ext.Equals(".aab", StringComparison.OrdinalIgnoreCase)
               || ext.Equals(".apks", StringComparison.OrdinalIgnoreCase) || ext.Equals(".xapk", StringComparison.OrdinalIgnoreCase)
               || ext.Equals(".apkm", StringComparison.OrdinalIgnoreCase);
    }

    public async Task<Result> Export(string path, string outputDirectory, Action<int, int, string>? progress, CancellationToken ct)
    {
        var dir = SafeFile.FullPath(outputDirectory);
        Directory.CreateDirectory(dir);
        if (Directory.EnumerateFileSystemEntries(dir).Any())
            throw new ToolError(ErrorCode.Conflict, $"Output directory is not empty: {dir}. Choose an empty or new directory.");
        var notes = new List<string>();
        int files = 0;
        void Write(string relative, byte[] bytes)
        {
            SafeFile.WriteUnderRoot(dir, relative, bytes, overwrite: false);
            files++;
        }
        void Text(string relative, string text) => Write(relative, Encoding.UTF8.GetBytes(text));

        string package;
        using (var p = AndroidPackage.Open(path))
        {
            var res = p.Resources;
            var manifest = AndroidManifestSummary.Of(p.Manifest, res);
            package = manifest.Package;
            Text("settings.gradle", $"rootProject.name = \"{Escape(package.Length > 0 ? package : Path.GetFileNameWithoutExtension(path))}\"\ninclude ':app'\n");
            Text("build.gradle", "plugins {\n    id 'com.android.application' version '8.5.2' apply false\n}\n");
            Text("app/build.gradle", BuildFile(manifest));
            Text("app/src/main/AndroidManifest.xml", p.Manifest.ToXml(res == null ? null : res.Name));

            // resource files at their canonical paths (shrunk builds rename them), the table as values XML
            var canonical = new Dictionary<string, string>(StringComparer.Ordinal);
            if (res != null)
            {
                var rows = res.Rows.ToList();
                foreach (var r in rows.Where(r => r.ValueType == "file"))
                    canonical.TryAdd(r.Value, $"res/{r.Type}{(r.Config.Length > 0 ? "-" + r.Config : "")}/{r.Name}{FileExtension(r.Value)}");
                foreach (var (relative, xml) in ValuesXml(rows, notes)) Text("app/src/main/" + relative, xml);
            }
            else notes.Add("The package has no resource table: no values XML.");
            bool proto = p.Kind == "aab";
            foreach (var entry in p.Entries.ToList())
            {
                ct.ThrowIfCancellationRequested();
                string? target = entry switch
                {
                    "AndroidManifest.xml" or "resources.arsc" or "resources.pb" => null,
                    _ when entry.StartsWith("classes", StringComparison.Ordinal) && entry.EndsWith(".dex", StringComparison.Ordinal) => null,
                    _ when entry.StartsWith("META-INF/", StringComparison.Ordinal) && IsSignatureFile(entry) => null,
                    _ when entry.EndsWith('/') => null,
                    _ when entry.StartsWith("res/", StringComparison.Ordinal) => "app/src/main/" + canonical.GetValueOrDefault(entry, entry),
                    _ when entry.StartsWith("assets/", StringComparison.Ordinal) => "app/src/main/" + entry,
                    _ when entry.StartsWith("lib/", StringComparison.Ordinal) && entry.Count(c => c == '/') == 2 => "app/src/main/jniLibs/" + entry["lib/".Length..],
                    _ => "app/src/main/resources/" + entry,
                };
                if (target == null) continue;
                byte[] bytes;
                try { bytes = p.Read(entry) ?? []; }
                catch (ToolError ex) { notes.Add($"{entry}: not exported ({ex.Message})."); continue; }
                if (entry.StartsWith("res/", StringComparison.Ordinal) && entry.EndsWith(".xml", StringComparison.OrdinalIgnoreCase) && (proto || AxmlDocument.IsAxml(bytes)))
                {
                    try
                    {
                        var doc = proto ? AabProto.ReadXml(bytes) : AxmlDocument.Read(bytes);
                        bytes = Encoding.UTF8.GetBytes(doc.ToXml(res == null ? null : res.Name));
                    }
                    catch (ToolError ex) { notes.Add($"{entry}: kept compiled ({ex.Message})."); }
                }
                try { Write(target, bytes); }
                catch (ToolError ex) { notes.Add($"{entry}: not written ({ex.Message})."); }
            }
        }

        var (sources, classes, failures) = await Sources(path, dir, Write, notes, progress, ct).ConfigureAwait(false);
        return new Result(dir, files, sources, classes, failures, notes);
    }

    /// <summary>One Java file per top-level class through JADX, else one smali file per class.</summary>
    private async Task<(string Kind, int Classes, int Failures)> Sources(string path, string dir, Action<string, byte[]> write, List<string> notes,
        Action<int, int, string>? progress, CancellationToken ct)
    {
        DexIndex index;
        try { index = dex.Index(path, ct); }
        catch (ToolError ex)
        {
            notes.Add($"No code exported: {ex.Message}");
            return ("none", 0, 0);
        }
        var all = index.Classes.Keys.Order(StringComparer.Ordinal).ToList();
        // Minified classes may differ only in case (a and A), which share one file on Windows and macOS.
        var used = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        int renamed = 0;
        string FileFor(string folder, string cls, string extension)
        {
            var stem = $"app/src/main/{folder}/{cls[1..^1]}";
            var relative = stem + extension;
            for (int n = 2; !used.Add(relative); n++) relative = $"{stem}_{n}{extension}";
            if (!relative.EndsWith("/" + cls[1..^1].Split('/')[^1] + extension, StringComparison.Ordinal)) renamed++;
            return relative;
        }
        var topLevel = all.Where(d => Outer(d) is not { } outer || !index.Classes.ContainsKey(outer)).ToList();
        bool useJava = true;
        int done = 0, failures = 0;
        foreach (var cls in topLevel)
        {
            ct.ThrowIfCancellationRequested();
            progress?.Invoke(done++, topLevel.Count, cls);
            string text;
            try { text = await java.Decompile(path, cls, smaliFallback: true, ct).ConfigureAwait(false); }
            catch (ToolError ex) when (ex.Code == ErrorCode.ProviderUnavailable && done == 1)
            {
                notes.Add($"Sources are smali: {ex.Message}");
                useJava = false;
                break;
            }
            catch (ToolError ex)
            {
                failures++;
                text = $"// {cls}: not decompiled ({ex.Message})\n";
            }
            write(FileFor("java", cls, ".java"), Encoding.UTF8.GetBytes(StripHeader(text)));
        }
        if (useJava)
        {
            CaseNote();
            return ("java", topLevel.Count, failures);
        }

        done = 0;
        used.Clear();
        renamed = 0;
        foreach (var cls in all)
        {
            ct.ThrowIfCancellationRequested();
            progress?.Invoke(done++, all.Count, cls);
            string smali;
            try { smali = dex.Disassemble(path, cls, annotated: false, ct); }
            catch (ToolError ex)
            {
                failures++;
                smali = $"# {cls}: not disassembled ({ex.Message})\n";
            }
            write(FileFor("smali", cls, ".smali"), Encoding.UTF8.GetBytes(smali));
        }
        CaseNote();
        notes.Add("Gradle does not build smali: app/src/main/smali is the code to read, or to rebuild with a smali assembler.");
        return ("smali", all.Count, failures);

        void CaseNote()
        {
            if (renamed > 0) notes.Add($"{renamed} class(es) differ from another only in letter case and are written as Name_2 (Name_3, ...) beside it.");
        }
    }

    private static string? Outer(string descriptor)
    {
        int dollar = descriptor.LastIndexOf('$');
        return dollar > descriptor.LastIndexOf('/') && dollar > 1 ? descriptor[..dollar] + ";" : null;
    }

    /// <summary>The decompiler's first line names the class and engine; the file starts at the source.</summary>
    private static string StripHeader(string text) =>
        text.StartsWith("// L", StringComparison.Ordinal) && text.IndexOf('\n') is var nl and > 0 ? text[(nl + 1)..] : text;

    private static bool IsSignatureFile(string entry)
    {
        var name = Path.GetFileName(entry);
        return name.Equals("MANIFEST.MF", StringComparison.OrdinalIgnoreCase) || name.EndsWith(".SF", StringComparison.OrdinalIgnoreCase)
               || name.EndsWith(".RSA", StringComparison.OrdinalIgnoreCase) || name.EndsWith(".EC", StringComparison.OrdinalIgnoreCase)
               || name.EndsWith(".DSA", StringComparison.OrdinalIgnoreCase);
    }

    private static string FileExtension(string path)
    {
        var name = Path.GetFileName(path);
        return name.EndsWith(".9.png", StringComparison.OrdinalIgnoreCase) ? ".9.png" : Path.GetExtension(name);
    }

    private static string BuildFile(AndroidManifestSummary m)
    {
        static string Int(int? v, int fallback) => (v ?? fallback).ToString(CultureInfo.InvariantCulture);
        int target = m.TargetSdk ?? m.CompileSdk ?? 34;
        var sb = new StringBuilder("plugins {\n    id 'com.android.application'\n}\n\nandroid {\n");
        sb.Append($"    namespace '{Escape(m.Package)}'\n");
        sb.Append($"    compileSdk {Int(m.CompileSdk ?? target, 34)}\n\n    defaultConfig {{\n");
        sb.Append($"        applicationId '{Escape(m.Package)}'\n");
        sb.Append($"        minSdk {Int(m.MinSdk, 21)}\n        targetSdk {Int(target, 34)}\n");
        if (m.VersionCode is { } code && long.TryParse(code, out _)) sb.Append($"        versionCode {code}\n");
        if (m.VersionName is { } name) sb.Append($"        versionName '{Escape(name)}'\n");
        sb.Append("    }\n}\n");
        return sb.ToString();
    }

    private static string Escape(string s) => s.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("'", "\\'", StringComparison.Ordinal).Replace("\"", "\\\"", StringComparison.Ordinal);

    /// <summary>The resource table's values as res/values[-config]/&lt;type&gt;s.xml; file resources are written as files instead.</summary>
    internal static IEnumerable<(string Path, string Xml)> ValuesXml(List<ResourceRow> rows, List<string> notes)
    {
        int skipped = 0;
        foreach (var byConfig in rows.Where(r => r.ValueType != "file").GroupBy(r => r.Config).OrderBy(g => g.Key, StringComparer.Ordinal))
        {
            var folder = byConfig.Key.Length == 0 ? "values" : "values-" + byConfig.Key;
            foreach (var byType in byConfig.GroupBy(r => r.Type).OrderBy(g => g.Key, StringComparer.Ordinal))
            {
                var sb = new StringBuilder("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<resources>\n");
                int written = 0;
                foreach (var r in byType.OrderBy(r => r.Id))
                {
                    if (Element(r) is { } element) { sb.Append(element); written++; }
                    else skipped++;
                }
                sb.Append("</resources>\n");
                if (written > 0) yield return ($"res/{folder}/{FileName(byType.Key)}.xml", sb.ToString());
            }
        }
        if (skipped > 0) notes.Add($"{skipped} resource value(s) (attribute definitions and other compiled-only kinds) have no values XML.");
    }

    private static string FileName(string type) => type switch
    {
        "string" or "color" or "dimen" or "integer" or "bool" or "id" or "style" or "array" or "plurals" or "fraction" or "drawable" => type + "s",
        _ => type,
    };

    private static string? Element(ResourceRow r)
    {
        string name = Xml(r.Name);
        if (r.ValueType != "bag")
            return r.Type switch
            {
                "id" => $"    <item type=\"id\" name=\"{name}\" />\n",
                "string" => $"    <string name=\"{name}\">{(r.ValueType == "string" ? AndroidString(r.Value, literal: true) : Xml(r.Value))}</string>\n",
                "color" or "dimen" or "integer" or "bool" or "fraction" or "drawable" => $"    <{r.Type} name=\"{name}\">{Xml(r.Value)}</{r.Type}>\n",
                "attr" => null,
                _ => $"    <item type=\"{Xml(r.Type)}\" name=\"{name}\">{Xml(r.Value)}</item>\n",
            };
        var items = Bag(r.Value, out var parent);
        var sb = new StringBuilder();
        switch (r.Type)
        {
            case "style":
                sb.Append($"    <style name=\"{name}\"{(parent != null ? $" parent=\"{Xml(parent)}\"" : "")}>\n");
                foreach (var (k, v) in items) sb.Append($"        <item name=\"{Xml(k)}\">{Xml(v)}</item>\n");
                sb.Append("    </style>\n");
                return sb.ToString();
            case "array":
                sb.Append($"    <array name=\"{name}\">\n");
                foreach (var (_, v) in items) sb.Append($"        <item>{AndroidString(v)}</item>\n");
                sb.Append("    </array>\n");
                return sb.ToString();
            case "plurals":
                sb.Append($"    <plurals name=\"{name}\">\n");
                foreach (var (k, v) in items) sb.Append($"        <item quantity=\"{Xml(k)}\">{AndroidString(v)}</item>\n");
                sb.Append("    </plurals>\n");
                return sb.ToString();
            default:
                return null;
        }
    }

    /// <summary>A bag's "parent=...; key=value; ..." text as its parent and items.</summary>
    private static List<(string Key, string Value)> Bag(string value, out string? parent)
    {
        parent = null;
        var items = new List<(string, string)>();
        foreach (var part in value.Split("; ", StringSplitOptions.RemoveEmptyEntries))
        {
            int eq = part.IndexOf('=');
            if (eq <= 0) continue;
            var (k, v) = (part[..eq], part[(eq + 1)..]);
            if (k == "parent" && items.Count == 0 && parent == null) parent = v;
            else items.Add((k, v));
        }
        return items;
    }

    private static string Xml(string s) => s.Replace("&", "&amp;", StringComparison.Ordinal).Replace("<", "&lt;", StringComparison.Ordinal)
        .Replace(">", "&gt;", StringComparison.Ordinal).Replace("\"", "&quot;", StringComparison.Ordinal);

    /// <summary>A string resource as aapt reads it back: XML escaped, quotes and apostrophes escaped, a leading @ or ? escaped.</summary>
    private static string AndroidString(string s, bool literal = false)
    {
        if (!literal && ReferenceText().IsMatch(s)) return Xml(s); // a bag item's reference, not text

        var text = Xml(s).Replace("\\", "\\\\", StringComparison.Ordinal).Replace("'", "\\'", StringComparison.Ordinal)
            .Replace("&quot;", "\\\"", StringComparison.Ordinal).Replace("\n", "\\n", StringComparison.Ordinal);
        return text.StartsWith('@') || text.StartsWith('?') ? "\\" + text : text;
    }

    [GeneratedRegex(@"^[@?]([a-z]+:)?[a-z]+/[A-Za-z0-9_.]+$|^@null$|^@0x[0-9a-f]{8}$")]
    private static partial Regex ReferenceText();
}
