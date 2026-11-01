using System.Globalization;
using System.Text;
using System.Xml;
using Corvus.Core;
using Corvus.Core.Documents;
using Corvus.Services.Web.Scripts;

namespace Corvus.Services.Analysis;

/// <summary>view=shell: the targets of shell, installer description and management console files, checked for local handlers and network shares.</summary>
internal sealed class ShellFileView : IFileSummaryView
{
    /// <summary>A target the file names: Field is where it was read, Kind what it starts or reaches; null Kind is a plain target.</summary>
    public sealed record Target(string Field, string Value, string? Kind);

    /// <summary>Format names the file kind; SnapIns lists the CLSIDs of a console file's snap-ins; null for other kinds and for a console file that is not well-formed (see Notes), empty when it has none.</summary>
    public sealed record Facts(string Format, IReadOnlyList<Target> Targets, IReadOnlyList<string> Notes, IReadOnlyList<string>? SnapIns = null);

    public string Name => "shell";

    private const long MaxFile = 4L << 20;

    private const int MaxTargets = 500;

    public FileView? Inspect(FileInput file, CancellationToken ct)
    {
        if (file.Length > MaxFile || file.Streamed) return null;
        var ext = Path.GetExtension(file.Path).ToLowerInvariant();
        var isDesktopIni = Path.GetFileName(file.Path).Equals("desktop.ini", StringComparison.OrdinalIgnoreCase);
        if (!isDesktopIni && ext is not (".url" or ".scf" or ".inf" or ".reg" or ".appinstaller" or ".library-ms" or ".searchconnector-ms" or ".msc")) return null;
        var text = ScriptText.Decode(file.Bytes, out _);
        var notes = new List<string>();
        var snapIns = new List<string>();
        var commands = new List<string>();
        var targets = isDesktopIni ? ReadIni(text, DesktopIniKeys)
            : ext switch
            {
                ".url" => ReadUrl(text),
                ".scf" => ReadIni(text, ScfKeys),
                ".inf" => ReadInf(text, notes),
                ".reg" => ReadReg(text, notes),
                ".appinstaller" => ReadXml(text, notes, ct, appInstaller: true),
                ".msc" => ReadConsole(text, notes, snapIns, commands, ct),
                _ => ReadXml(text, notes, ct),
            };
        var format = isDesktopIni ? "Folder settings file" : ext switch
        {
            ".url" => "Internet shortcut",
            ".scf" => "Explorer command file",
            ".inf" => "Setup information file",
            ".reg" => "Registry script",
            ".appinstaller" => "App installer file",
            ".library-ms" => "Library description",
            ".msc" => "Management console",
            _ => "Search connector description",
        };
        bool consoleRead = ext == ".msc" && notes.Count == 0;
        if (targets.Count > MaxTargets)
        {
            notes.Add($"listed {MaxTargets} of {targets.Count} targets");
            targets = targets.Take(MaxTargets).ToList();
        }
        if (targets.Count == 0 && notes.Count == 0 && !consoleRead) notes.Add("no target found; view=script reads the file as text");
        var highlights = new List<string> { $"{format}: {(targets.Count == 0 ? "no target" : string.Join("; ", targets.Take(3).Select(t => t.Value)))}." };
        highlights.AddRange(targets.Where(t => t.Kind != null).Take(3).Select(t => $"{t.Field} is a {t.Kind}: {t.Value}."));
        if (consoleRead && snapIns.Count > 0) highlights.Add($"Snap-ins: {string.Join(", ", snapIns.Take(5))}.");
        var findings = new List<Finding>(LocalHandlerTargets.Scan(targets.Select(t => (t.Value, t.Field)), "shortcut"));
        findings.AddRange(FindingRules.FromLaunchers(Launchers.MatchAll(commands), "shell"));
        return new FileView(new Facts(format, targets, notes, consoleRead ? snapIns : null), highlights) { Findings = findings };
    }

    // An .scf Command value is a shell command id, not a program path.
    private static readonly HashSet<string> ScfKeys = new(StringComparer.OrdinalIgnoreCase) { "IconFile" };

    private static readonly HashSet<string> DesktopIniKeys = new(StringComparer.OrdinalIgnoreCase)
        { "IconFile", "IconResource", "LocalizedResourceName", "InfoTip" };

    // Microsoft Learn INF general syntax: these keys name sections whose lines
    // are command lines run by the install section.
    private static readonly HashSet<string> InfCommandKeys = new(StringComparer.OrdinalIgnoreCase)
        { "RunPreSetupCommands", "RunPostSetupCommands" };

    private static readonly HashSet<string> InfRegisterKeys = new(StringComparer.OrdinalIgnoreCase)
        { "RegisterDlls", "UnregisterDlls" };

    /// <summary>Lists the values of the named keys of an INI-style text; a handler or share value reports its kind.</summary>
    private static List<Target> ReadIni(string text, HashSet<string> keys)
    {
        var list = new List<Target>();
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            int eq = line.IndexOf('=');
            if (eq <= 0 || line[0] is '[' or ';') continue;
            var key = line[..eq].Trim();
            var value = line[(eq + 1)..].Trim();
            if (value.Length > 0 && keys.Contains(key)) list.Add(new Target(key, value, LocalHandlerTargets.Match(value)));
        }
        return list;
    }

    private static Dictionary<string, List<string>> ReadSections(string text)
    {
        var sections = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        List<string>? current = null;
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line[0] == ';') continue;
            if (line[0] == '[' && line.EndsWith(']'))
            {
                var name = line[1..^1];
                if (!sections.TryGetValue(name, out current)) sections[name] = current = [];
                continue;
            }
            current?.Add(line);
        }
        return sections;
    }

    /// <summary>Lists the command lines, module registrations and autostart values of the sections an .inf file names; a missing section is noted.</summary>
    private static List<Target> ReadInf(string text, List<string> notes)
    {
        var list = new List<Target>();
        var sections = ReadSections(text);
        List<string> Named(string key, string names)
        {
            var lines = new List<string>();
            foreach (var name in names.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
            {
                if (sections.TryGetValue(name.Trim('"'), out var body)) lines.AddRange(body);
                else notes.Add($"section [{name}] named by {key} is not in the file; its entries are unknown");
            }
            return lines;
        }
        foreach (var body in sections.Values.ToList())
            foreach (var line in body)
            {
                int eq = line.IndexOf('=');
                if (eq <= 0) continue;
                var key = line[..eq].Trim();
                var value = line[(eq + 1)..].Trim();
                if (InfCommandKeys.Contains(key))
                    foreach (var cmd in Named(key, value)) list.Add(new Target(key, cmd, LocalHandlerTargets.Match(cmd) ?? "command"));
                else if (InfRegisterKeys.Contains(key))
                    foreach (var reg in Named(key, value)) list.Add(new Target(key, reg, LocalHandlerTargets.Match(reg) ?? "module registration"));
                else if (key.Equals("AddReg", StringComparison.OrdinalIgnoreCase))
                    foreach (var entry in Named(key, value))
                    {
                        var f = entry.Split(',', 5, StringSplitOptions.TrimEntries);
                        if (f.Length == 5 && f[4].Length > 0 && RegistryValueMatters(f[1], f[2]))
                            list.Add(new Target($@"{f[0]}\{f[1]}\{f[2]}", f[4].Trim('"'), "autostart value"));
                    }
            }
        return list;
    }

    // Run and RunOnce values start programs; under the other keys only the
    // named values do.
    private static bool RegistryValueMatters(string key, string name)
    {
        if (!InstallerFileView.Autostart.Any(a => key.Contains(a, StringComparison.OrdinalIgnoreCase))) return false;
        if (key.Contains(@"\currentcontrolset\services", StringComparison.OrdinalIgnoreCase))
            return name.Equals("ImagePath", StringComparison.OrdinalIgnoreCase) || name.Equals("ServiceDll", StringComparison.OrdinalIgnoreCase);
        if (key.Contains(@"\winlogon", StringComparison.OrdinalIgnoreCase))
            return name is "Shell" or "Userinit" or "Taskman";
        if (key.Contains(@"\image file execution options", StringComparison.OrdinalIgnoreCase))
            return name.Equals("Debugger", StringComparison.OrdinalIgnoreCase);
        if (key.Contains(@"\active setup", StringComparison.OrdinalIgnoreCase))
            return name.Equals("StubPath", StringComparison.OrdinalIgnoreCase);
        return true;
    }

    /// <summary>Lists the string and expandable-string values of autostart keys in a .reg text; other value types are counted in the notes; deleted keys are skipped.</summary>
    private static List<Target> ReadReg(string text, List<string> notes)
    {
        var list = new List<Target>();
        string? key = null;
        int undecoded = 0;
        foreach (var line in JoinContinuations(text))
        {
            if (line.StartsWith('['))
            {
                var name = line.Trim('[', ']');
                key = name.StartsWith('-') ? null : name;
                continue;
            }
            if (key is null || line.Length == 0 || (line[0] != '"' && line[0] != '@')) continue;
            int i = 0;
            string valueName = "(Default)";
            if (line[0] == '@') i = 1;
            else if (!TryReadQuoted(line, ref i, out valueName)) continue;
            if (i >= line.Length || line[i] != '=') continue;
            if (!RegistryValueMatters(key, valueName)) continue;
            var data = line[(i + 1)..].Trim();
            string? value = null;
            int p = 0;
            if (data.StartsWith('"')) TryReadQuoted(data, ref p, out value);
            else if (data.StartsWith("hex(2):", StringComparison.OrdinalIgnoreCase)) value = DecodeHex(data[7..]);
            else undecoded++;
            if (!string.IsNullOrEmpty(value)) list.Add(new Target($@"{key}\{valueName}", value, "autostart value"));
        }
        if (undecoded > 0) notes.Add($"{undecoded} non-string value(s) under autostart keys are not decoded; view=script reads the file as text");
        return list;
    }

    // A line ending in a backslash continues on the next line (hex data).
    private static List<string> JoinContinuations(string text)
    {
        var lines = new List<string>();
        var pending = new StringBuilder();
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            if (pending.Length > 0) line = line.TrimStart();
            if (line.EndsWith('\\') && !line.StartsWith('[')) { pending.Append(line, 0, line.Length - 1); continue; }
            lines.Add(pending.Append(line).ToString());
            pending.Clear();
        }
        return lines;
    }

    private static bool TryReadQuoted(string s, ref int i, out string value)
    {
        var sb = new StringBuilder();
        value = "";
        if (i >= s.Length || s[i] != '"') return false;
        for (i++; i < s.Length; i++)
        {
            if (s[i] == '\\' && i + 1 < s.Length) { sb.Append(s[++i]); continue; }
            if (s[i] == '"') { i++; value = sb.ToString(); return true; }
            sb.Append(s[i]);
        }
        return false;
    }

    private static string? DecodeHex(string hex)
    {
        var bytes = new List<byte>();
        foreach (var part in hex.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
        {
            if (!byte.TryParse(part, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var b)) return null;
            bytes.Add(b);
        }
        return Encoding.Unicode.GetString(bytes.ToArray()).TrimEnd('\0');
    }

    private static List<Target> ReadUrl(string text)
    {
        var list = new List<Target>();
        bool inSection = false;
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            if (line.StartsWith('[')) { inSection = line.Equals("[InternetShortcut]", StringComparison.OrdinalIgnoreCase); continue; }
            if (!inSection) continue;
            int eq = line.IndexOf('=');
            if (eq <= 0) continue;
            var key = line[..eq].Trim();
            var value = line[(eq + 1)..].Trim();
            if (value.Length > 0 && (key.Equals("URL", StringComparison.OrdinalIgnoreCase) || key.Equals("IconFile", StringComparison.OrdinalIgnoreCase)))
                list.Add(new Target(key, value, LocalHandlerTargets.Match(value)));
        }
        return list;
    }

    // Microsoft Learn Library Description Schema and Search Connector
    // Description Schema: simpleLocation holds url.
    // Microsoft Learn App Installer file reference: Uri attributes name the
    // installer file, the main package or bundle and each dependency.
    private static List<Target> ReadXml(string text, List<string> notes, CancellationToken ct, bool appInstaller = false)
    {
        var list = new List<Target>();
        try
        {
            using var reader = XmlReader.Create(new StringReader(text), new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = MaxFile });
            var doc = new XmlDocument { XmlResolver = null };
            doc.Load(reader);
            if (appInstaller)
            {
                foreach (XmlElement el in doc.SelectNodes("//*[@Uri]")!)
                {
                    ct.ThrowIfCancellationRequested();
                    if (el.LocalName is not ("AppInstaller" or "MainPackage" or "MainBundle" or "Package" or "Bundle")) continue;
                    var value = el.GetAttribute("Uri").Trim();
                    if (value.Length == 0) continue;
                    var kind = LocalHandlerTargets.Match(value);
                    if (kind == null && Uri.TryCreate(value, UriKind.Absolute, out var uri) && uri.Scheme != Uri.UriSchemeHttps) kind = "unencrypted location";
                    list.Add(new Target($"{el.LocalName}/Uri", value, kind));
                }
                foreach (XmlElement setting in doc.GetElementsByTagName("UpdateSettings"))
                    foreach (var child in setting.ChildNodes.OfType<XmlElement>())
                        list.Add(new Target($"UpdateSettings/{child.LocalName}", child.InnerText.Trim() is { Length: > 0 } t ? t : "set", "update setting"));
                return list;
            }
            foreach (XmlElement loc in doc.GetElementsByTagName("simpleLocation"))
            {
                ct.ThrowIfCancellationRequested();
                foreach (XmlElement url in loc.GetElementsByTagName("url"))
                {
                    var value = url.InnerText.Trim();
                    if (value.Length == 0) continue;
                    var kind = LocalHandlerTargets.Match(value);
                    if (kind == null && (value.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || value.StartsWith("https://", StringComparison.OrdinalIgnoreCase)))
                        kind = "network location (WebDAV)";
                    list.Add(new Target("simpleLocation/url", value, kind));
                }
            }
        }
        catch (XmlException) { notes.Add("the file is not well-formed XML; its targets are unknown; view=script reads it as text"); }
        return list;
    }

    // A console file (MMC_ConsoleFile) is XML; its target elements are read by name.
    private static List<Target> ReadConsole(string text, List<string> notes, List<string> snapIns, List<string> commands, CancellationToken ct)
    {
        var list = new List<Target>();
        try
        {
            using var reader = XmlReader.Create(new StringReader(text), new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = MaxFile });
            var doc = new XmlDocument { XmlResolver = null };
            doc.Load(reader);
            foreach (XmlElement el in doc.GetElementsByTagName("*"))
            {
                ct.ThrowIfCancellationRequested();
                switch (el.LocalName.ToLowerInvariant())
                {
                    case "snapin":
                        var clsid = Attr(el, "CLSID");
                        if (clsid.Length > 0 && !snapIns.Contains(clsid)) snapIns.Add(clsid);
                        break;
                    case "task":
                        var command = Part(el, "Command");
                        if (command.Length == 0) break;
                        var line = $"{command} {Part(el, "Params")}".Trim();
                        commands.Add(line);
                        list.Add(new Target("Task/Command", line, LocalHandlerTargets.Match(command) ?? LocalHandlerTargets.Match(Part(el, "Params"))));
                        break;
                    case "string":
                        var value = el.InnerText.Trim();
                        var kind = ConsoleKind(value);
                        if (kind != null) list.Add(new Target("StringTable", value, kind));
                        break;
                }
            }
        }
        catch (XmlException) { notes.Add("the file is not well-formed XML; its snap-ins and tasks are unknown"); }
        return list;
    }

    // Attribute names match ignoring case. A task may write a value as an
    // attribute or a child element; both forms are read because the layout is unconfirmed.
    private static string Attr(XmlElement el, string name)
    {
        foreach (XmlAttribute a in el.Attributes)
            if (a.LocalName.Equals(name, StringComparison.OrdinalIgnoreCase)) return a.Value.Trim();
        return "";
    }

    private static string Part(XmlElement task, string name)
    {
        foreach (XmlElement el in task.GetElementsByTagName("*").Cast<XmlElement>().Prepend(task))
        {
            var value = Attr(el, name);
            if (value.Length == 0 && el.LocalName.Equals(name, StringComparison.OrdinalIgnoreCase) && el != task) value = el.InnerText.Trim();
            if (value.Length > 0) return value;
        }
        return "";
    }

    private static string? ConsoleKind(string value)
    {
        bool res = value.Contains("res://", StringComparison.OrdinalIgnoreCase);
        bool script = value.Contains("javascript:", StringComparison.OrdinalIgnoreCase);
        if (res && script) return "resource reference with a script URL";
        if (res) return "resource reference (res://)";
        if (script) return "script URL";
        return LocalHandlerTargets.Match(value);
    }
}
