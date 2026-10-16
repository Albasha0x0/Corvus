using System.ComponentModel;
using System.Text;
using System.Text.RegularExpressions;
using Corvus.Services.Web.Scripts;

namespace Corvus.Services.Analysis;

/// <summary>
/// view=script: a PowerShell, batch, VBScript / VBA or JavaScript file (or the script blocks of an .hta, .wsf or .html
/// page) read with its transformation layers peeled to plain text by a bounded evaluator; nothing runs. The plain text
/// pages by character offset. The overview reads a JavaScript file only when it shows signs of a transformation.
/// </summary>
internal sealed class ScriptFileView : IFileSummaryView
{
    private const int MaxText = 8 << 20, OverviewText = 2 << 20, Window = 24_000, LayerText = 2_000;

    public sealed record Layer(int Depth, string Language, string Via, int Chars,
        [property: Description("The layer's text as decoded, to its first 2,000 characters.")] string Text);

    public sealed record Facts(string Language, IReadOnlyList<Layer> Layers,
        [property: Description("Transformations undone besides layers.")] IReadOnlyList<string>? Recovered, int Folded,
        [property: Description("Commands, methods and objects the script calls, with constant arguments.")] IReadOnlyList<string>? Calls,
        int PlainChars, long Offset, long? Next,
        [property: Description("The plain text from offset: peeled layers in place, constants folded.")] string Plain,
        bool Complete, IReadOnlyList<string>? Notes);

    public string Name => "script";

    public FileView? Inspect(FileInput file, CancellationToken ct)
    {
        bool asked = file.Options.Wants(Name);
        if (file.Length > MaxText || !asked && file.Length > OverviewText || file.Streamed) return null;
        if (file.Kind is not ("text" or "data")) return null;
        var bytes = file.Bytes;
        if (bytes.Length == 0 || bytes.AsSpan(0, Math.Min(bytes.Length, 4096)).IndexOf((byte)0) >= 0 && !(bytes.Length > 1 && bytes[1] == 0)) return null;
        var text = ScriptText.Decode(bytes, out _);
        if (!ScriptText.Printable(text)) return null;
        var ext = Path.GetExtension(file.Path).ToLowerInvariant();
        ScriptReading reading;
        if (ext is ".hta" or ".wsf" or ".html" or ".htm" or ".sct" or ".wsc" || ext == "" && Regex.IsMatch(text, @"<script\b[^>]*\blanguage\s*=", RegexOptions.IgnoreCase))
        {
            if (Blocks(text) is not { Count: > 0 } blocks) return null;
            reading = ReadBlocks(blocks, ct, asked);
        }
        else
        {
            var language = ScriptReader.Detect(file.Path, text);
            if (language == null) return null;
            // a JavaScript file in the overview: only with signs of a transformation (decoders, eval layers, packers)
            if (language == "javascript" && !asked && !Regex.IsMatch(text.Length > 200_000 ? text[..200_000] : text,
                    @"\b_0x[0-9a-f]{4,6}\b|\beval\s*\(|\bnew\s+Function\s*\(|\bFunction\s*\(\s*(?:atob|unescape|String\.fromCharCode)|\}\('|\\x[0-9a-f]{2}\\x[0-9a-f]{2}|\bActiveXObject\b"))
                return null;
            reading = ScriptReader.Read(text, language, ct, asked ? 4_000 : 1_500);
        }
        if (!asked && reading.Layers.Count == 0 && reading.Recovered.Count == 0 && reading.Folded == 0 && reading.Language == "javascript") return null;
        long offset = Math.Clamp(file.Options.Offset, 0, reading.Plain.Length);
        var window = reading.Plain.Substring((int)offset, (int)Math.Min(Window, reading.Plain.Length - offset));
        long? next = offset + window.Length < reading.Plain.Length ? offset + window.Length : null;
        var notes = reading.Notes.ToList();
        if (next != null) notes.Add($"{reading.Plain.Length:N0} characters of plain text; offset={next} reads on");
        var facts = new Facts(reading.Language,
            reading.Layers.Select(l => new Layer(l.Depth, l.Language, l.Via, l.Text.Length, l.Text.Length > LayerText ? l.Text[..LayerText] : l.Text)).ToList(),
            reading.Recovered.Count > 0 ? reading.Recovered : null, reading.Folded, reading.Calls.Count > 0 ? reading.Calls : null,
            reading.Plain.Length, offset, next, window, reading.Complete, notes.Count > 0 ? notes : null);
        return new FileView(facts, Highlights(reading));
    }

    private static List<string> Highlights(ScriptReading r)
    {
        var name = r.Language switch { "powershell" => "PowerShell", "batch" => "Batch", "vbscript" => "VBScript", "javascript" => "JavaScript", _ => r.Language };
        var sb = new StringBuilder($"{name} script");
        if (r.Layers.Count > 0)
            sb.Append($": {r.Layers.Count} transformation layer(s) peeled ({string.Join("; ", r.Layers.Take(3).Select(l => $"{l.Language} via {l.Via}"))}{(r.Layers.Count > 3 ? "; ..." : "")})");
        if (r.Recovered.Count > 0) sb.Append(r.Layers.Count > 0 ? ", " : ": ").Append(string.Join(", ", r.Recovered)).Append(" undone");
        if (r.Layers.Count == 0 && r.Recovered.Count == 0) sb.Append($": {r.Folded} constant expression(s) folded");
        sb.Append("; view=script shows the plain text.");
        var list = new List<string> { sb.ToString() };
        if (r.Calls.Count > 0) list.Add("Script calls worth reviewing: " + string.Join("; ", r.Calls.Take(8)) + (r.Calls.Count > 8 ? "; ..." : "") + ".");
        return list;
    }

    private sealed record Block(string Language, string Text);

    /// <summary>The script blocks of an HTML application, Windows Script File or page, with their languages.</summary>
    private static List<Block> Blocks(string text)
    {
        var list = new List<Block>();
        foreach (Match m in Regex.Matches(text, @"<script\b([^>]*)>(.*?)</script\s*>", RegexOptions.IgnoreCase | RegexOptions.Singleline, TimeSpan.FromSeconds(2)))
        {
            var attributes = m.Groups[1].Value;
            var body = m.Groups[2].Value;
            if (Regex.IsMatch(attributes, @"\bsrc\s*=", RegexOptions.IgnoreCase) || body.Trim().Length == 0) continue;
            var lang = Regex.Match(attributes, @"\b(?:language|type)\s*=\s*[""']?(?:text/)?([\w.]+)", RegexOptions.IgnoreCase).Groups[1].Value.ToLowerInvariant();
            var language = lang switch
            {
                "vbscript" or "vbs" or "vbscript.encode" => "vbscript",
                "" or "javascript" or "jscript" or "js" or "ecmascript" or "jscript.encode" => "javascript",
                _ => null,
            };
            if (language == null) continue;
            body = Regex.Replace(body, @"^\s*<!\[CDATA\[|\]\]>\s*$|^\s*<!--|-->\s*$", "");
            list.Add(new Block(language, body));
        }
        return list;
    }

    private static ScriptReading ReadBlocks(List<Block> blocks, CancellationToken ct, bool asked)
    {
        var plain = new StringBuilder();
        var layers = new List<ScriptLayer>();
        var calls = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        var notes = new List<string>();
        var recovered = new SortedSet<string>(StringComparer.Ordinal);
        int folded = 0;
        bool complete = true;
        foreach (var b in blocks.Take(64))
        {
            var r = ScriptReader.Read(b.Text, b.Language, ct, asked ? 2_000 : 750);
            plain.Append($"<script language=\"{b.Language}\">").Append(r.Plain).Append("</script>\n");
            layers.AddRange(r.Layers);
            calls.UnionWith(r.Calls);
            notes.AddRange(r.Notes.Where(n => !notes.Contains(n)));
            recovered.UnionWith(r.Recovered);
            folded += r.Folded;
            complete &= r.Complete;
        }
        var language = blocks.Select(b => b.Language).Distinct().Count() == 1 ? blocks[0].Language : "mixed";
        return new ScriptReading(language, plain.ToString(), layers, folded, calls.ToList(), notes) { Complete = complete, Recovered = recovered.ToList() };
    }
}
