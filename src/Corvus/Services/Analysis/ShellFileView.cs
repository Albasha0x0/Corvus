using System.Xml;
using Corvus.Core;
using Corvus.Services.Web.Scripts;

namespace Corvus.Services.Analysis;

/// <summary>view=shell: the targets of a .url, .library-ms or .searchConnector-ms file, checked for local handlers and network shares.</summary>
internal sealed class ShellFileView : IFileSummaryView
{
    /// <summary>A target the file names: Field is where it was read, Kind what it starts or reaches; null Kind is a plain target.</summary>
    public sealed record Target(string Field, string Value, string? Kind);

    public sealed record Facts(string Format, IReadOnlyList<Target> Targets, IReadOnlyList<string> Notes);

    public string Name => "shell";

    private const long MaxFile = 4L << 20;

    public FileView? Inspect(FileInput file, CancellationToken ct)
    {
        if (file.Length > MaxFile || file.Streamed) return null;
        var ext = Path.GetExtension(file.Path).ToLowerInvariant();
        if (ext is not (".url" or ".library-ms" or ".searchconnector-ms")) return null;
        var text = ScriptText.Decode(file.Bytes, out _);
        var notes = new List<string>();
        var targets = ext == ".url" ? ReadUrl(text) : ReadXml(text, notes, ct);
        var format = ext switch { ".url" => "Internet shortcut", ".library-ms" => "Library description", _ => "Search connector description" };
        var highlights = new List<string> { $"{format}: {(targets.Count == 0 ? "no target" : string.Join("; ", targets.Take(3).Select(t => t.Value)))}." };
        highlights.AddRange(targets.Where(t => t.Kind != null).Take(3).Select(t => $"{t.Field} is a {t.Kind}: {t.Value}."));
        return new FileView(new Facts(format, targets, notes), highlights) { Findings = LocalHandlerTargets.Scan(targets.Select(t => (t.Value, t.Field)), "shortcut") };
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
}
