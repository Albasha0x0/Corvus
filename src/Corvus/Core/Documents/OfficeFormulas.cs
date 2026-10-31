using System.IO.Compression;
using System.Text.RegularExpressions;
using System.Xml;

namespace Corvus.Core.Documents;

/// <summary>Word fields, Excel DDE links and formulas, and altChunk parts of an OOXML package, read as text; nothing is run or updated.</summary>
internal static partial class OfficeFormulas
{
    private const string WordNs = "http://schemas.openxmlformats.org/wordprocessingml/2006/main";
    private const int MaxFields = 2000, MaxFormulaFindings = 1000, MaxDepth = 3;
    private const long MaxChunk = 64L << 20;

    // Field code names: Microsoft Learn, "Field codes in Word".
    private static readonly string[] ListedFields = ["HYPERLINK", "INCLUDETEXT", "INCLUDEPICTURE"];

    /// <summary>Adds the fields, DDE links, formulas and altChunk findings of <paramref name="zip"/> to <paramref name="doc"/>, paths under <paramref name="prefix"/>.</summary>
    public static void Read(ZipArchive zip, string prefix, OfficeDocument doc, int depth, CancellationToken ct)
    {
        foreach (var entry in zip.Entries)
        {
            ct.ThrowIfCancellationRequested();
            var name = entry.FullName;
            try
            {
                if (IsWordPart(name)) ReadWordFields(entry, prefix + name, doc, ct);
                else if (name.StartsWith("xl/externalLinks/", StringComparison.OrdinalIgnoreCase) && name.EndsWith(".xml", StringComparison.OrdinalIgnoreCase)) ReadDdeLinks(entry, prefix + name, doc);
            }
            catch (XmlException ex) { doc.Notes.Add($"{prefix}{name}: not well-formed XML: {ex.Message}"); }
            catch (ToolError ex) when (ex.Code is ErrorCode.MalformedInput or ErrorCode.LimitExceeded) { doc.Notes.Add(ex.Message); }
        }
        ReadSheets(zip, prefix, doc, ct);
        if (depth < MaxDepth) ReadChunks(zip, prefix, doc, depth, ct);
    }

    private static bool IsWordPart(string name) =>
        name.StartsWith("word/", StringComparison.OrdinalIgnoreCase) && name.EndsWith(".xml", StringComparison.OrdinalIgnoreCase)
        && name[5..] is var leaf && !leaf.Contains('/') && (leaf.StartsWith("header", StringComparison.OrdinalIgnoreCase) || leaf.StartsWith("footer", StringComparison.OrdinalIgnoreCase)
            || leaf.Equals("document.xml", StringComparison.OrdinalIgnoreCase) || leaf.Equals("footnotes.xml", StringComparison.OrdinalIgnoreCase) || leaf.Equals("endnotes.xml", StringComparison.OrdinalIgnoreCase));

    private static XmlReader Open(ZipArchiveEntry entry, out Stream stream)
    {
        if (entry.Length > MaxChunk) throw new ToolError(ErrorCode.LimitExceeded, $"{entry.FullName} is over {MaxChunk >> 20} MiB.");
        stream = entry.Open();
        return XmlReader.Create(stream, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null });
    }

    private sealed class OpenField
    {
        public readonly System.Text.StringBuilder Code = new();
        public bool InCode = true;
    }

    private static void ReadWordFields(ZipArchiveEntry entry, string part, OfficeDocument doc, CancellationToken ct)
    {
        using var reader = Open(entry, out var stream);
        using var _ = stream;
        var open = new Stack<OpenField>();
        int fields = 0, steps = 0;
        while (!reader.EOF)
        {
            if ((++steps & 0xFFF) == 0) ct.ThrowIfCancellationRequested();
            if (reader.NodeType == XmlNodeType.Element)
            {
                switch (reader.LocalName)
                {
                    case "fldChar":
                        var kind = reader.GetAttribute("fldCharType", WordNs) ?? reader.GetAttribute("fldCharType");
                        if (kind == "begin") open.Push(new OpenField());
                        else if (kind == "separate" && open.Count > 0) open.Peek().InCode = false;
                        else if (kind == "end" && open.Count > 0)
                        {
                            var code = open.Pop().Code.ToString();
                            if (++fields <= MaxFields) Field(code, part, doc);
                        }
                        break;
                    case "instrText":
                        var text = reader.ReadElementContentAsString();
                        if (open.Count > 0 && open.Peek().InCode) open.Peek().Code.Append(text);
                        continue;
                    case "fldSimple":
                        if ((reader.GetAttribute("instr", WordNs) ?? reader.GetAttribute("instr")) is { } instr && ++fields <= MaxFields) Field(instr, part, doc);
                        break;
                }
            }
            reader.Read();
        }
        if (fields > MaxFields) doc.Notes.Add($"{part}: fields read up to {MaxFields:N0} of {fields:N0}");
    }

    /// <summary>Classifies one field instruction: DDE and DDEAUTO are DDE fields, HYPERLINK, INCLUDETEXT and INCLUDEPICTURE are listed, others are skipped.</summary>
    internal static void Field(string instruction, string part, OfficeDocument doc)
    {
        var code = instruction.Trim();
        int end = 0;
        while (end < code.Length && !char.IsWhiteSpace(code[end])) end++;
        var name = code[..end].ToUpperInvariant();
        if (name is "DDE" or "DDEAUTO")
        {
            doc.Active.Add(new MacroFinding("Dde", Clip(code), name == "DDEAUTO"
                ? "a DDEAUTO field, which asks another program to run a command when the document opens"
                : "a DDE field, which asks another program to run a command when it updates") { Location = part });
            return;
        }
        if (Array.IndexOf(ListedFields, name) < 0) return;
        var target = FirstArgument(code[end..]);
        bool remote = name != "HYPERLINK" && Remote(target);
        doc.Active.Add(new MacroFinding(remote ? "RemoteField" : "Field", Clip(code), remote ? $"a {name} field with a remote target" : $"a {name} field") { Location = part });
        if (name == "HYPERLINK" && target.Length > 0) doc.Targets.Add((target, part));
    }

    // Field code paths double their backslashes, so both spellings are checked.
    private static bool Remote(string target) =>
        target.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || target.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
        || new[] { target, target.Replace(@"\\", @"\") }.Any(t => HandlerTargets.Match(t) is { } m && (m == "file:// target" || m.StartsWith("UNC", StringComparison.Ordinal)));

    private static string FirstArgument(string rest)
    {
        rest = rest.TrimStart();
        if (rest.StartsWith('"'))
        {
            int close = rest.IndexOf('"', 1);
            return close < 0 ? rest[1..] : rest[1..close];
        }
        int end = 0;
        while (end < rest.Length && !char.IsWhiteSpace(rest[end])) end++;
        return rest[..end];
    }

    private static string Clip(string s) => s.Length > 300 ? s[..300] + "..." : s;

    private static void ReadDdeLinks(ZipArchiveEntry entry, string part, OfficeDocument doc)
    {
        using var reader = Open(entry, out var stream);
        using var _ = stream;
        while (reader.Read())
            if (reader.NodeType == XmlNodeType.Element && reader.LocalName == "ddeLink")
                doc.Active.Add(new MacroFinding("Dde", $"{reader.GetAttribute("ddeService")}|{reader.GetAttribute("ddeTopic")}",
                    "a DDE link, which asks another program for data or to run a command when the workbook updates") { Location = part });
    }

    private static void ReadSheets(ZipArchive zip, string prefix, OfficeDocument doc, CancellationToken ct)
    {
        var sheets = zip.Entries.Where(e => e.FullName.StartsWith("xl/worksheets/", StringComparison.OrdinalIgnoreCase) && e.FullName.EndsWith(".xml", StringComparison.OrdinalIgnoreCase)).ToList();
        if (sheets.Count == 0) return;
        var names = SheetNames(zip);
        int found = 0;
        foreach (var sheet in sheets)
        {
            var label = names.GetValueOrDefault(sheet.FullName) ?? Path.GetFileNameWithoutExtension(sheet.Name);
            try
            {
                using var reader = Open(sheet, out var stream);
                using var _ = stream;
                string cell = "";
                int steps = 0;
                while (!reader.EOF)
                {
                    if ((++steps & 0xFFF) == 0) ct.ThrowIfCancellationRequested();
                    if (reader.NodeType == XmlNodeType.Element)
                    {
                        if (reader.LocalName == "c") cell = reader.GetAttribute("r") ?? "";
                        else if (reader.LocalName == "f" && !reader.IsEmptyElement)
                        {
                            var formula = reader.ReadElementContentAsString();
                            found += Formula(formula, prefix + sheet.FullName, $"{label}!{cell}", doc);
                            if (found >= MaxFormulaFindings) { doc.Notes.Add($"{prefix}{sheet.FullName}: formulas read up to {MaxFormulaFindings:N0} findings"); return; }
                            continue;
                        }
                    }
                    reader.Read();
                }
            }
            catch (XmlException ex) { doc.Notes.Add($"{prefix}{sheet.FullName}: not well-formed XML: {ex.Message}"); }
            catch (ToolError ex) when (ex.Code is ErrorCode.MalformedInput or ErrorCode.LimitExceeded) { doc.Notes.Add(ex.Message); }
        }
    }

    private static Dictionary<string, string> SheetNames(ZipArchive zip)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            if (zip.GetEntry("xl/workbook.xml") is not { } workbook) return map;
            var targets = XlmMacros.Relationships(zip, "xl/_rels/workbook.xml.rels");
            foreach (XmlElement s in XlmMacros.Load(workbook).GetElementsByTagName("sheet"))
                if (targets.GetValueOrDefault(s.GetAttribute("id", "http://schemas.openxmlformats.org/officeDocument/2006/relationships")) is { } target)
                    map["xl/" + target.TrimStart('/').Replace("xl/", "", StringComparison.OrdinalIgnoreCase)] = s.GetAttribute("name");
        }
        // Sheet names are a label; the part name stands in when the workbook is unreadable.
        catch (Exception ex) when (ex is ToolError or XmlException) { }
        return map;
    }

    /// <summary>Classifies one worksheet formula by the functions it calls and a DDE reference; returns how many findings it added.</summary>
    internal static int Formula(string formula, string part, string cell, OfficeDocument doc)
    {
        int added = 0;
        var location = $"{part}:{cell}";
        if (DdeReference().Match(formula) is { Success: true } dde)
        {
            doc.Active.Add(new MacroFinding("Dde", Clip(dde.Value), "a formula reference to a DDE service and topic") { Location = location });
            added++;
        }
        foreach (Match m in Call().Matches(formula))
        {
            var function = m.Groups[1].Value.ToUpperInvariant();
            if (function == "HYPERLINK")
            {
                var target = HyperlinkTarget().Match(formula) is { Success: true } t ? t.Groups[1].Value.Replace("\"\"", "\"") : "";
                doc.Active.Add(new MacroFinding("LinkFormula", Clip(formula), target.Length > 0 ? "a HYPERLINK formula" : "a HYPERLINK formula with a computed target") { Location = location });
                if (target.Length > 0) doc.Targets.Add((target, location));
            }
            else
                doc.Active.Add(new MacroFinding("Formula", Clip(formula), function == "WEBSERVICE"
                    ? "a WEBSERVICE formula, which requests a URL when the workbook calculates"
                    : $"a {function} formula, which calls a function in a library") { Location = location });
            added++;
        }
        return added;
    }

    private static void ReadChunks(ZipArchive zip, string prefix, OfficeDocument doc, int depth, CancellationToken ct)
    {
        if (zip.GetEntry("word/_rels/document.xml.rels") is not { } rels) return;
        XmlDocument xml;
        try { xml = XlmMacros.Load(rels); }
        catch (ToolError) { return; }
        foreach (XmlElement r in xml.GetElementsByTagName("Relationship"))
        {
            var type = r.GetAttribute("Type");
            if (!type.EndsWith("/aFChunk", StringComparison.Ordinal) || string.Equals(r.GetAttribute("TargetMode"), "External", StringComparison.OrdinalIgnoreCase)) continue;
            ct.ThrowIfCancellationRequested();
            var target = r.GetAttribute("Target");
            var path = target.StartsWith('/') ? target[1..] : "word/" + target;
            var entry = zip.GetEntry(path);
            if (entry == null) { doc.Notes.Add($"{prefix}{path}: altChunk target is not in the package"); continue; }
            if (entry.Length > MaxChunk) { doc.Notes.Add($"{prefix}{path}: over {MaxChunk >> 20} MiB, not read"); continue; }
            try { Chunk(ReadAll(entry), prefix + path, doc, depth, ct); }
            catch (ToolError ex) when (ex.Code is ErrorCode.MalformedInput or ErrorCode.LimitExceeded) { doc.Notes.Add($"{prefix}{path}: {ex.Message}"); }
        }
    }

    private static byte[] ReadAll(ZipArchiveEntry e)
    {
        using var s = e.Open();
        using var ms = new MemoryStream();
        s.CopyTo(ms);
        return ms.ToArray();
    }

    private static void Chunk(byte[] data, string path, OfficeDocument doc, int depth, CancellationToken ct)
    {
        if (RtfObjects.Looks(data) || Blob.Identify(data) == "zip")
        {
            var sub = OfficeDocument.Read(data, Path.GetFileName(path), ct, depth + 1);
            if (sub == null) { doc.Notes.Add($"{path}: altChunk is not a readable document"); return; }
            foreach (var f in sub.Findings) doc.Active.Add(f with { Location = f.Location == null ? path : $"{path}/{f.Location}" });
            foreach (var (target, where) in sub.Targets) doc.Targets.Add((target, $"{path}/{where}"));
            doc.Notes.AddRange(sub.Notes.Select(n => $"{path}: {n}"));
            return;
        }
        var html = new List<string>();
        if (MailMessage.LooksLikeMime(data))
            html.AddRange(MailMessage.ReadMime(data, path, AnalysisLimits.Default, ct).Bodies.Where(b => b.Name == "html").Select(b => b.Text));
        else html.Add(TextDecoding.Decode(data, out _));
        foreach (var text in html)
            foreach (var (target, where) in HandlerTargets.FromHtml(text))
            {
                doc.Targets.Add((target, $"{path} {where}"));
                if (target.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || target.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                    doc.Active.Add(new MacroFinding("IOC", target, "an address in an altChunk part") { Location = path });
            }
    }

    // Function names: Microsoft Support, "WEBSERVICE function" and "CALL function".
    [GeneratedRegex(@"\b(WEBSERVICE|CALL|REGISTER|HYPERLINK)\s*\(", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.NonBacktracking)]
    private static partial Regex Call();

    [GeneratedRegex(@"HYPERLINK\s*\(\s*""((?:[^""]|"""")*)""", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.NonBacktracking)]
    private static partial Regex HyperlinkTarget();

    [GeneratedRegex(@"[A-Za-z_][A-Za-z0-9_.]*\|'[^']*'!", RegexOptions.CultureInvariant | RegexOptions.NonBacktracking)]
    private static partial Regex DdeReference();
}
