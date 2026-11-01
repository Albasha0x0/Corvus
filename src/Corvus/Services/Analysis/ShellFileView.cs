using System.Xml;
using Corvus.Core;
using Corvus.Core.Documents;
using Corvus.Services.Web.Scripts;

namespace Corvus.Services.Analysis;

/// <summary>view=shell: the targets of a .url, .library-ms, .searchConnector-ms or .msc file, checked for local handlers and network shares.</summary>
internal sealed class ShellFileView : IFileSummaryView
{
    /// <summary>A target the file names: Field is where it was read, Kind what it starts or reaches; null Kind is a plain target.</summary>
    public sealed record Target(string Field, string Value, string? Kind);

    /// <summary>Format names the file kind; SnapIns lists the CLSIDs of a console file's snap-ins; null for other kinds and for a console file that is not well-formed (see Notes), empty when it has none.</summary>
    public sealed record Facts(string Format, IReadOnlyList<Target> Targets, IReadOnlyList<string> Notes, IReadOnlyList<string>? SnapIns = null);

    public string Name => "shell";

    private const long MaxFile = 4L << 20;

    public FileView? Inspect(FileInput file, CancellationToken ct)
    {
        if (file.Length > MaxFile || file.Streamed) return null;
        var ext = Path.GetExtension(file.Path).ToLowerInvariant();
        if (ext is not (".url" or ".library-ms" or ".searchconnector-ms" or ".msc")) return null;
        var text = ScriptText.Decode(file.Bytes, out _);
        var notes = new List<string>();
        var snapIns = new List<string>();
        var commands = new List<string>();
        var targets = ext switch
        {
            ".url" => ReadUrl(text),
            ".msc" => ReadConsole(text, notes, snapIns, commands, ct),
            _ => ReadXml(text, notes, ct),
        };
        var format = ext switch { ".url" => "Internet shortcut", ".library-ms" => "Library description", ".msc" => "Management console", _ => "Search connector description" };
        var highlights = new List<string> { $"{format}: {(targets.Count == 0 ? "no target" : string.Join("; ", targets.Take(3).Select(t => t.Value)))}." };
        highlights.AddRange(targets.Where(t => t.Kind != null).Take(3).Select(t => $"{t.Field} is a {t.Kind}: {t.Value}."));
        bool consoleRead = ext == ".msc" && notes.Count == 0;
        if (consoleRead && snapIns.Count > 0) highlights.Add($"Snap-ins: {string.Join(", ", snapIns.Take(5))}.");
        var findings = new List<Finding>(LocalHandlerTargets.Scan(targets.Select(t => (t.Value, t.Field)), "shortcut"));
        findings.AddRange(FindingRules.FromLaunchers(Launchers.MatchAll(commands), "shell"));
        return new FileView(new Facts(format, targets, notes, consoleRead ? snapIns : null), highlights) { Findings = findings };
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
    private static List<Target> ReadXml(string text, List<string> notes, CancellationToken ct)
    {
        var list = new List<Target>();
        try
        {
            using var reader = XmlReader.Create(new StringReader(text), new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = MaxFile });
            var doc = new XmlDocument { XmlResolver = null };
            doc.Load(reader);
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
        catch (XmlException) { notes.Add("the file is not well-formed XML; its targets are unknown"); }
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
