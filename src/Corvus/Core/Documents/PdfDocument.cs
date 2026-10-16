using System.Text;
using System.Text.RegularExpressions;

namespace Corvus.Core.Documents;

/// <summary>An action of a PDF: its kind (JavaScript, Launch, URI, SubmitForm, GoToR, ...), what runs it and its target.</summary>
internal sealed record PdfAction(int Object, string Type, string Trigger, string? Target);

/// <summary>A JavaScript action's or XFA script's code.</summary>
internal sealed record PdfScript(int Object, string Trigger, string Code);

/// <summary>A file embedded in a PDF (an /EmbeddedFile stream) under its file specification's name.</summary>
internal sealed record PdfEmbeddedFile(int Object, string Name, string? Description, byte[] Bytes);

/// <summary>A pdfid keyword: how often it occurs in the file's bytes and how many of those were written with #xx escapes.</summary>
internal sealed record PdfKeywordCount(string Keyword, int Count, int Escaped);

/// <summary>
/// The active content of a PDF: actions with what triggers them (document open, page and field events, annotations,
/// document-level scripts), JavaScript and XFA scripts with noteworthy calls, launched programs, URIs, embedded files, and
/// pdfid's keyword counts over the raw bytes. Nothing is rendered or run.
/// </summary>
internal sealed class PdfDocument
{
    public required PdfFile File { get; init; }
    public List<PdfAction> Actions { get; } = [];
    public List<PdfScript> Scripts { get; } = [];
    public List<PdfEmbeddedFile> Files { get; } = [];
    public List<(int Object, byte[] Xml)> Xfa { get; } = [];
    public List<PdfKeywordCount> Keywords { get; private set; } = [];
    public List<MacroFinding> Findings { get; } = [];
    public List<string> UndecodedFilters { get; } = [];

    /// <summary>pdfid's default keywords.</summary>
    public static readonly string[] PdfidKeywords =
        ["obj", "endobj", "stream", "endstream", "xref", "trailer", "startxref", "/Page", "/Encrypt", "/ObjStm", "/JS", "/JavaScript", "/AA", "/OpenAction",
         "/AcroForm", "/JBIG2Decode", "/RichMedia", "/Launch", "/EmbeddedFile", "/XFA"];

    private const long MaxStream = 256L << 20;

    /// <summary>The last documents read, by their bytes: summarize_file's view and its container walk read the same array.</summary>
    private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<byte[], PdfDocument> Recent = [];

    public static PdfDocument Read(byte[] data, string name, CancellationToken ct)
    {
        if (Recent.TryGetValue(data, out var known)) return known;
        var doc = new PdfDocument { File = PdfFile.Read(data, name, ct) };
        doc.Keywords = Pdfid(data);
        doc.Analyze(ct);
        Recent.AddOrUpdate(data, doc);
        return doc;
    }

    /// <summary>pdfid's count: words of letters and digits after the header, a name's #xx escapes decoded, matched case-sensitively; plus /Colors over 2^24.</summary>
    public static List<PdfKeywordCount> Pdfid(byte[] data)
    {
        var index = new Dictionary<string, int>(StringComparer.Ordinal);
        for (int k = 0; k < PdfidKeywords.Length; k++) index[PdfidKeywords[k]] = k;
        var lookup = index.GetAlternateLookup<ReadOnlySpan<char>>();
        var count = new int[PdfidKeywords.Length];
        var escaped = new int[PdfidKeywords.Length];
        int colorsOver = 0;
        // the word with a leading '/' slot; words longer than any keyword are only measured
        Span<char> word = stackalloc char[16];
        int length = 0;
        bool hex = false, slash = false, afterColors = false, digits = true;
        long number = 0;
        int header = data.AsSpan(0, Math.Min(data.Length, 1024)).IndexOf("%PDF-"u8);
        int i = header >= 0 ? header + 8 : 0;
        void Update(Span<char> word)
        {
            if (length == 0) return;
            if (length < word.Length)
            {
                var key = slash ? word[..(length + 1)] : word[1..(length + 1)];
                if (lookup.TryGetValue(key, out var k)) { count[k]++; if (hex) escaped[k]++; }
                if (slash) afterColors = key.SequenceEqual("/Colors");
            }
            else if (slash) afterColors = false;
            length = 0;
            hex = false;
            digits = true;
            number = 0;
        }
        word[0] = '/';
        for (; i < data.Length; i++)
        {
            byte c = data[i];
            bool alnum = c is >= (byte)'a' and <= (byte)'z' or >= (byte)'A' and <= (byte)'Z' or >= (byte)'0' and <= (byte)'9';
            if (!alnum && slash && c == '#' && i + 2 < data.Length && PdfLexer.HexValue(data[i + 1]) >= 0 && PdfLexer.HexValue(data[i + 2]) >= 0)
            {
                c = (byte)(PdfLexer.HexValue(data[i + 1]) * 16 + PdfLexer.HexValue(data[i + 2]));
                hex = true;
                i += 2;
                alnum = true;
            }
            if (alnum)
            {
                if (length + 1 < word.Length) word[length + 1] = (char)c;
                length++;
                digits &= c is >= (byte)'0' and <= (byte)'9';
                if (digits && number < 1L << 40) number = number * 10 + (c - '0');
                continue;
            }
            if (slash && c == '#') { Update(word); continue; }
            if (afterColors && !slash && length > 0 && digits && number > 1 << 24) colorsOver++;
            Update(word);
            slash = c == '/';
        }
        Update(word);
        var list = PdfidKeywords.Select((k, n) => new PdfKeywordCount(k, count[n], escaped[n])).ToList();
        list.Add(new PdfKeywordCount("/Colors > 2^24", colorsOver, 0));
        return list;
    }

    private static readonly Dictionary<string, string> Triggers = new(StringComparer.Ordinal)
    {
        ["OpenAction"] = "document opens", ["A"] = "link, outline item or field activated", ["Next"] = "after another action",
        ["O"] = "page or annotation opens", ["C"] = "page closes or field recalculated", ["E"] = "pointer enters annotation", ["X"] = "pointer exits annotation",
        ["D"] = "mouse button down", ["U"] = "mouse button up", ["Fo"] = "annotation gets focus", ["Bl"] = "annotation loses focus", ["PO"] = "annotation's page opens",
        ["PC"] = "annotation's page closes", ["PV"] = "annotation's page visible", ["PI"] = "annotation's page invisible", ["K"] = "keystroke in a field",
        ["F"] = "field formatted", ["V"] = "field validated", ["WC"] = "document will close", ["WS"] = "document will save", ["DS"] = "document saved",
        ["WP"] = "document will print", ["DP"] = "document printed",
    };

    private void Analyze(CancellationToken ct)
    {
        var pdf = File;
        // who refers to each object, by key: the trigger of an action stored as its own object
        var referrers = new Dictionary<int, (int From, string Key)>();
        var embeddedNames = new Dictionary<int, (string Name, string? Description)>();
        var documentScripts = new HashSet<int>();
        foreach (var o in pdf.Current)
        {
            ct.ThrowIfCancellationRequested();
            Walk(o.Value, o.Number, "", 0, (from, key, r) => referrers.TryAdd(r.Number, (from, key)));
            // file specifications with embedded files, at any depth (often inline in a name tree)
            Dicts(o.Value, 0, d =>
            {
                if (pdf.Resolve(d["EF"]) is not PdfDict ef) return;
                var name = pdf.Text(d["UF"], o) is { Length: > 0 } uf ? uf : pdf.Text(d["F"], o);
                foreach (var e in ef.Entries)
                    if (e.Value is PdfRef r) embeddedNames.TryAdd(r.Number, (name, pdf.Text(d["Desc"], o) is { Length: > 0 } desc ? desc : null));
            });
        }
        // document-level scripts: the /JavaScript name tree under the catalog's /Names
        if (pdf.Resolve(pdf.Trailer?["Root"]) is PdfDict catalog && pdf.Resolve(catalog["Names"]) is PdfDict names && pdf.Resolve(names["JavaScript"]) is PdfDict tree)
            foreach (var r in NameTreeValues(tree, 0)) if (r is PdfRef rr) documentScripts.Add(rr.Number);

        foreach (var o in pdf.Current)
        {
            ct.ThrowIfCancellationRequested();
            var trigger = documentScripts.Contains(o.Number) ? "document-level script (runs on open)"
                : referrers.TryGetValue(o.Number, out var by) ? Describe(by.From, by.Key) : "not referenced";
            FindActions(o, o.Value, "", trigger, 0);
            if (o.Stream != null && o.Dict is { } sd)
            {
                bool embedded = sd.Name("Type") == "EmbeddedFile" || embeddedNames.ContainsKey(o.Number);
                if (embedded)
                {
                    var bytes = pdf.Decoded(o, out var stopped, MaxStream);
                    if (stopped != null) UndecodedFilters.Add($"object {o.Number}: {stopped}");
                    var (name, desc) = embeddedNames.GetValueOrDefault(o.Number, ($"embedded_{o.Number}", null));
                    Files.Add(new PdfEmbeddedFile(o.Number, name.Length > 0 ? name : $"embedded_{o.Number}", desc, bytes));
                }
            }
            if (o.Dict is { } ad && pdf.Resolve(ad["XFA"]) is { } xfa) ReadXfa(xfa);
        }
        foreach (var (obj, xml) in Xfa)
        {
            var text = Encoding.UTF8.GetString(xml);
            foreach (Match m in Regex.Matches(text, @"<script\b[^>]*>(.*?)</script>", RegexOptions.Singleline | RegexOptions.IgnoreCase, TimeSpan.FromSeconds(5)))
                Scripts.Add(new PdfScript(obj, "XFA form script", System.Net.WebUtility.HtmlDecode(m.Groups[1].Value)));
        }
        Scan();
    }

    private void ReadXfa(PdfValue xfa)
    {
        var parts = xfa is PdfArray a ? a.Items.Where(i => i is PdfRef).Cast<PdfRef>() : xfa is PdfRef r0 ? [r0] : [];
        foreach (var r in parts.Distinct())
            if (File.Get(r.Number) is { Stream: not null } s && !Xfa.Any(x => x.Object == r.Number))
                Xfa.Add((r.Number, File.Decoded(s, out _, MaxStream)));
    }

    private static string Describe(int from, string key)
    {
        var last = key.Split('/')[^1];
        var meaning = Triggers.GetValueOrDefault(last);
        return $"object {from} /{key}" + (meaning != null ? $" ({meaning})" : "");
    }

    private static void Dicts(PdfValue v, int depth, Action<PdfDict> visit)
    {
        if (depth > 32) return;
        if (v is PdfDict d)
        {
            visit(d);
            foreach (var e in d.Entries) Dicts(e.Value, depth + 1, visit);
        }
        else if (v is PdfArray a) foreach (var i in a.Items) Dicts(i, depth + 1, visit);
    }

    /// <summary>Every reference in a value with the key path that holds it.</summary>
    private static void Walk(PdfValue v, int from, string path, int depth, Action<int, string, PdfRef> found)
    {
        if (depth > 32) return;
        switch (v)
        {
            case PdfRef r: found(from, path.TrimStart('/'), r); break;
            case PdfDict d: foreach (var e in d.Entries) Walk(e.Value, from, path + "/" + e.Key, depth + 1, found); break;
            case PdfArray a: foreach (var i in a.Items) Walk(i, from, path, depth + 1, found); break;
        }
    }

    private IEnumerable<PdfValue> NameTreeValues(PdfDict node, int depth)
    {
        if (depth > 32) yield break;
        if (File.Resolve(node["Names"]) is PdfArray pairs)
            for (int i = 1; i < pairs.Items.Count; i += 2) yield return pairs.Items[i];
        if (File.Resolve(node["Kids"]) is PdfArray kids)
            foreach (var k in kids.Items)
                if (File.Resolve(k) is PdfDict kid)
                    foreach (var v in NameTreeValues(kid, depth + 1)) yield return v;
    }

    /// <summary>Actions in a value: the object's own dictionary (triggered by its referrer) or dictionaries held inline under a key path.</summary>
    private void FindActions(PdfObject owner, PdfValue v, string path, string referrer, int depth)
    {
        if (depth > 16 || v is not PdfDict d) return;
        var trigger = path.Length == 0 ? referrer : Describe(owner.Number, path);
        var type = d.Name("S") ?? (d["JS"] != null ? "JavaScript" : null);
        if (type != null && (d.Name("Type") is null or "Action"))
        {
            string? target = type switch
            {
                "JavaScript" => null,
                "Launch" => LaunchTarget(d, owner),
                "URI" => File.Text(d["URI"], owner),
                "SubmitForm" or "GoToR" or "GoToE" or "ImportData" => FileSpec(d["F"], owner),
                "Named" => d.Name("N"),
                _ => null,
            };
            if (type is not ("GoTo" or "Named" or "SetOCGState" or "Thread") || target != null)
                Actions.Add(new PdfAction(owner.Number, type, trigger, target));
            if (type == "JavaScript") Scripts.Add(new PdfScript(owner.Number, trigger, ScriptText(d["JS"], owner)));
        }
        foreach (var e in d.Entries)
            if (e.Value is PdfDict child && e.Key is not ("Parent" or "P" or "Kids" or "Resources"))
                FindActions(owner, child, path.Length == 0 ? e.Key : path + "/" + e.Key, referrer, depth + 1);
    }

    private string ScriptText(PdfValue? js, PdfObject owner)
    {
        if (js is PdfRef r && File.Get(r.Number) is { Stream: not null } s)
        {
            var bytes = File.Decoded(s, out var stopped, MaxStream);
            if (stopped != null) UndecodedFilters.Add($"object {r.Number}: {stopped}");
            return new PdfString(bytes).Text;
        }
        return File.Text(js, owner);
    }

    private string? LaunchTarget(PdfDict d, PdfObject owner)
    {
        if (File.Resolve(d["Win"]) is PdfDict win)
        {
            var file = File.Text(win["F"], owner);
            var parameters = File.Text(win["P"], owner);
            return parameters.Length > 0 ? $"{file} {parameters}" : file;
        }
        return FileSpec(d["F"], owner);
    }

    private string? FileSpec(PdfValue? f, PdfObject owner)
    {
        var v = File.Resolve(f);
        if (v is PdfString) return File.Text(f, owner);
        if (v is PdfDict spec) return File.Text(spec["UF"], owner) is { Length: > 0 } uf ? uf : File.Text(spec["F"], owner);
        return null;
    }

    private static readonly (string Pattern, string Description)[] ScriptRules =
    [
        (@"\beval\s*\(", "runs code built at run time"),
        (@"\bunescape\s*\(", "decodes %u-escaped data, often shellcode"),
        (@"String\.fromCharCode", "builds strings from character codes"),
        (@"\butil\.printf\s*\(", "util.printf, an old overflow target"),
        (@"Collab\.(collectEmailInfo|getIcon)", "Collab API, an old overflow target"),
        (@"media\.newPlayer", "media.newPlayer, an old use-after-free target"),
        (@"spell\.customDictionaryOpen", "spell.customDictionaryOpen, an old overflow target"),
        (@"\bgetAnnots\s*\(", "reads annotations, a place to hide data"),
        (@"\bexportDataObject\s*\(", "writes an embedded file to disk and may open it"),
        (@"\blaunchURL\s*\(|\bgetURL\s*\(", "opens a URL"),
        (@"\bsubmitForm\s*\(", "sends form data to a server"),
        (@"\bSOAP\.|\bNet\.HTTP", "network request from the script"),
        (@"\bapp\.setTimeOut\s*\(|\bapp\.setInterval\s*\(", "runs code later"),
        (@"\bapp\.openDoc\s*\(", "opens another document"),
        (@"\butil\.stringFromStream\s*\(", "reads a stream into a string"),
        (@"\bthis\.getField\s*\(|\bgetPageNthWord\s*\(", "reads document text or fields, a place to hide data"),
    ];

    private void Scan()
    {
        foreach (var s in Scripts)
            foreach (var (pattern, description) in ScriptRules)
            {
                var m = Regex.Match(s.Code, pattern, RegexOptions.CultureInvariant, TimeSpan.FromSeconds(5));
                if (!m.Success) continue;
                int line = 1;
                for (int i = 0; i < m.Index; i++) if (s.Code[i] == '\n') line++;
                if (!Findings.Any(f => f.Keyword == m.Value && f.Location?.StartsWith($"object {s.Object}:", StringComparison.Ordinal) == true))
                    Findings.Add(new MacroFinding("Suspicious", m.Value.Trim(), description) { Location = $"object {s.Object}:{line}" });
            }
        foreach (var a in Actions.Where(a => a.Type == "Launch"))
            Findings.Add(new MacroFinding("Suspicious", "Launch", $"starts a program or opens a file: {a.Target}") { Location = $"object {a.Object}" });
        foreach (var a in Actions.Where(a => a.Type == "URI" && a.Target != null).DistinctBy(a => a.Target))
            Findings.Add(new MacroFinding("IOC", a.Target!, "URL") { Location = $"object {a.Object}" });
        foreach (var k in Keywords.Where(k => k.Escaped > 0))
            Findings.Add(new MacroFinding("Suspicious", k.Keyword, $"written with #xx escapes {k.Escaped} time(s), which hides it from plain text search"));
        if (Keywords.FirstOrDefault(k => k.Keyword == "/Colors > 2^24") is { Count: > 0 })
            Findings.Add(new MacroFinding("Suspicious", "/Colors > 2^24", "a color count over 2^24, an old overflow pattern (CVE-2009-3459)"));
    }
}
