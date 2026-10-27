using System.ComponentModel;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Corvus.Services.Web;

/// <summary>Decodes React Server Components (flight) payloads from a raw stream or a page's self.__next_f.push chunks, without running them.</summary>
public static partial class FlightData
{
    /// <summary>A client module reference (an I row): the row, the bundler's module id, its chunk files and the export it names.</summary>
    public sealed record ClientModule(string Row, string Id, IReadOnlyList<string> Chunks, string Name, bool Async);

    /// <summary>The decoded payload: where it came from, row counts by tag, client modules, server actions, hints, errors and the element tree.</summary>
    public sealed record Payload(
        [property: Description("raw, or page (N pushes).")] string Source,
        int Rows,
        [property: Description("Rows by tag: model (JSON), I (client module), H (hint), E (error), T (text), D (debug), W (console), and binary tags.")] IReadOnlyDictionary<string, int> Tags,
        IReadOnlyList<ClientModule> ClientModules,
        [property: Description("Server action ids the payload references, with the row holding each.")] IReadOnlyList<string> Actions,
        IReadOnlyList<string> Hints, IReadOnlyList<string> Errors,
        [property: Description("React elements in the model rows.")] int Elements,
        [property: Description("Elements from row 0 as type(children): host tags, client MODULE#export; bounded.")] string? Tree,
        IReadOnlyList<string> Notes);

    private const int MaxRows = 200_000, MaxTree = 400, MaxDepth = 40;
    // Binary and text rows carry a hexadecimal byte length after the tag: id:Tlen,data.
    private const string LengthTags = "TAaOoUSsLlGgMmVB";

    /// <summary>True when <paramref name="text"/> holds flight data: a page with self.__next_f pushes, or a raw stream starting with a row.</summary>
    public static bool Applies(string text) => text.Contains("self.__next_f.push(", StringComparison.Ordinal) || RawStart().IsMatch(text.AsSpan(0, Math.Min(text.Length, 64)).ToString());

    /// <summary>Decodes <paramref name="text"/>: a page's pushes joined in order, else the text as a raw stream. Null when neither applies.</summary>
    public static Payload? Read(string text, CancellationToken ct)
    {
        var notes = new List<string>();
        string source;
        byte[] stream;
        if (text.Contains("self.__next_f.push(", StringComparison.Ordinal))
        {
            var (bytes, pushes) = Pushes(text, notes);
            if (pushes == 0) return null;
            (stream, source) = (bytes, $"page ({pushes} pushes)");
        }
        else if (RawStart().IsMatch(text.AsSpan(0, Math.Min(text.Length, 64)).ToString())) (stream, source) = (Encoding.UTF8.GetBytes(text), "raw");
        else return null;
        return Decode(stream, source, notes, ct);
    }

    // self.__next_f.push([0]) starts, [1,"chunk"] carries text, [2,"..."] form state, [3,"base64"] a binary chunk.
    private static (byte[] Bytes, int Pushes) Pushes(string html, List<string> notes)
    {
        using var ms = new MemoryStream();
        int pushes = 0;
        foreach (Match m in Push().Matches(html))
        {
            pushes++;
            if (!m.Groups[2].Success) continue;
            string chunk;
            try { chunk = JsonSerializer.Deserialize<string>(m.Groups[2].Value) ?? ""; }
            catch (JsonException) { notes.Add($"push {pushes}: its string does not decode as JSON; skipped"); continue; }
            switch (m.Groups[1].Value)
            {
                case "1": ms.Write(Encoding.UTF8.GetBytes(chunk)); break;
                case "3":
                    try { ms.Write(Convert.FromBase64String(chunk)); }
                    catch (FormatException) { notes.Add($"push {pushes}: a binary chunk that is not base64; skipped"); }
                    break;
                case "2": notes.Add("form state pushed (push type 2); not decoded"); break;
            }
        }
        return (ms.ToArray(), pushes);
    }

    private static Payload Decode(byte[] s, string source, List<string> notes, CancellationToken ct)
    {
        var tags = new SortedDictionary<string, int>(StringComparer.Ordinal);
        var models = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        var modules = new List<ClientModule>();
        var hints = new List<string>();
        var errors = new List<string>();
        int rows = 0, i = 0;
        while (i < s.Length && rows < MaxRows)
        {
            if ((rows & 0xFFF) == 0) ct.ThrowIfCancellationRequested();
            if (s[i] == '\n') { i++; continue; }
            int colon = Array.IndexOf(s, (byte)':', i, Math.Min(16, s.Length - i));
            if (colon < 0 || colon == i || !IsHex(s, i, colon)) { notes.Add($"byte {i}: not a row (id:TAG data); the rest is not read"); break; }
            var id = Encoding.ASCII.GetString(s, i, colon - i);
            int p = colon + 1;
            string tag = "";
            if (p < s.Length && s[p] is >= (byte)'A' and <= (byte)'Z' or >= (byte)'a' and <= (byte)'z' && LooksTagged(s, p))
            {
                tag = ((char)s[p]).ToString();
                p++;
            }
            rows++;
            if (tag.Length == 1 && LengthTags.Contains(tag[0]))
            {
                int comma = Array.IndexOf(s, (byte)',', p, Math.Min(16, s.Length - p));
                if (comma < 0 || !int.TryParse(Encoding.ASCII.GetString(s, p, comma - p), System.Globalization.NumberStyles.HexNumber, null, out var len) || len < 0)
                { notes.Add($"row {id}: tag {tag} without a byte length; the rest is not read"); break; }
                tags[tag] = tags.GetValueOrDefault(tag) + 1;
                i = Math.Min(s.Length, comma + 1 + len);
                if (comma + 1 + len > s.Length) notes.Add($"row {id}: {len} bytes announced, {s.Length - comma - 1} present (cut)");
                continue;
            }
            int end = Array.IndexOf(s, (byte)'\n', p);
            if (end < 0) end = s.Length;
            var data = Encoding.UTF8.GetString(s, p, end - p);
            i = end + 1;
            var key = tag.Length == 0 ? "model" : tag;
            if (tag == "H" && data.Length > 0) { hints.Add(Hint(data)); key = "H"; }
            tags[key] = tags.GetValueOrDefault(key) + 1;
            JsonElement json;
            try { json = JsonDocument.Parse(tag == "H" ? data[1..] : data).RootElement.Clone(); }
            catch (JsonException) { if (tag is "" or "I" or "E") notes.Add($"row {id}: {key} data is not JSON"); continue; }
            switch (tag)
            {
                case "": models[id] = json; break;
                case "I": if (Module(id, json) is { } m) modules.Add(m); break;
                case "E": errors.Add(Error(id, json)); break;
            }
        }
        if (rows >= MaxRows) notes.Add($"only the first {MaxRows:N0} rows are read");
        var actions = new SortedSet<string>(StringComparer.Ordinal);
        int elements = 0;
        foreach (var (id, json) in models) Walk(json, id, actions, ref elements, 0);
        string? tree = null;
        // Row ids are unique in a stream; a repeated one keeps its first module.
        var byRow = new Dictionary<string, ClientModule>(StringComparer.Ordinal);
        foreach (var m in modules) byRow.TryAdd(m.Row, m);
        if (models.TryGetValue("0", out var root))
        {
            int nodes = 0;
            tree = string.Join(", ", Tree(root, models, byRow, ref nodes, 0, []));
            if (nodes >= MaxTree) notes.Add($"tree cut at {MaxTree} elements");
        }
        else if (models.Count > 0) notes.Add("no row 0: the payload is a part of a stream, the tree is not drawn");
        return new Payload(source, rows, tags, modules, [.. actions], hints, errors, elements, tree, notes);
    }

    // A tag letter is followed by data, never by the end of the row: "1:I[...]", "2:T1a,..."; a JSON row starts with [ { " or a literal.
    private static bool LooksTagged(byte[] s, int p) =>
        p + 1 < s.Length && !(s[p] is (byte)'t' or (byte)'f' or (byte)'n' && JsonLiteral(s, p));

    private static bool JsonLiteral(byte[] s, int p)
    {
        foreach (var lit in new[] { "true", "false", "null" })
            if (p + lit.Length <= s.Length && Encoding.ASCII.GetString(s, p, lit.Length) == lit && (p + lit.Length == s.Length || s[p + lit.Length] == '\n')) return true;
        return false;
    }

    private static bool IsHex(byte[] s, int from, int to)
    {
        for (int k = from; k < to; k++)
            if (!Uri.IsHexDigit((char)s[k])) return false;
        return true;
    }

    // [id, chunks, name, async?] since React 19; {id, chunks, name, async} before.
    private static ClientModule? Module(string row, JsonElement json)
    {
        string? id = null, name = null;
        JsonElement chunks = default;
        bool isAsync = false;
        if (json.ValueKind == JsonValueKind.Array && json.GetArrayLength() >= 3)
        {
            id = Text(json[0]);
            chunks = json[1];
            name = Text(json[2]);
            isAsync = json.GetArrayLength() > 3 && json[3].ValueKind is JsonValueKind.Number or JsonValueKind.True;
        }
        else if (json.ValueKind == JsonValueKind.Object)
        {
            id = json.TryGetProperty("id", out var v) ? Text(v) : null;
            if (json.TryGetProperty("chunks", out var c)) chunks = c;
            name = json.TryGetProperty("name", out var n) ? Text(n) : null;
            isAsync = json.TryGetProperty("async", out var a) && a.ValueKind == JsonValueKind.True;
        }
        if (id == null) return null;
        var list = chunks.ValueKind == JsonValueKind.Array ? chunks.EnumerateArray().Select(Text).OfType<string>().ToList() : [];
        // Webpack lists chunk ids and files in pairs; the files are what a reader can find in the build.
        var files = list.Where(c => c.Contains('/') || c.EndsWith(".js", StringComparison.Ordinal) || c.EndsWith(".css", StringComparison.Ordinal)).ToList();
        return new ClientModule(row, id, files.Count > 0 ? files : list, name ?? "", isAsync);
    }

    private static string? Text(JsonElement e) => e.ValueKind switch
    {
        JsonValueKind.String => e.GetString(),
        JsonValueKind.Number => e.GetRawText(),
        _ => null,
    };

    // H rows: a hint code letter, then JSON. L preloads, D dns-prefetch, C preconnect, S stylesheet, X script, M module.
    private static string Hint(string data)
    {
        var code = data[0] switch { 'L' => "preload", 'D' => "dns-prefetch", 'C' => "preconnect", 'S' => "stylesheet", 'X' => "script", 'M' => "modulepreload", 'm' => "modulescript", var c => "hint " + c };
        try
        {
            var json = JsonDocument.Parse(data[1..]).RootElement;
            var first = json.ValueKind == JsonValueKind.Array && json.GetArrayLength() > 0 ? Text(json[0]) : Text(json);
            var kind = json.ValueKind == JsonValueKind.Array && json.GetArrayLength() > 1 ? Text(json[1]) : null;
            return $"{code} {first}{(kind != null ? " as " + kind : "")}";
        }
        catch (JsonException) { return code; }
    }

    private static string Error(string row, JsonElement json)
    {
        string? Get(string k) => json.ValueKind == JsonValueKind.Object && json.TryGetProperty(k, out var v) ? Text(v) : null;
        return $"row {row}: {Get("message") ?? "(message not sent)"}{(Get("digest") is { } d ? $" (digest {d})" : "")}";
    }

    // Elements are ["$", type, key, props, ...]; server references are objects with id and bound, or "$h" strings to such rows.
    private static void Walk(JsonElement e, string row, SortedSet<string> actions, ref int elements, int depth)
    {
        if (depth > 200) return;
        switch (e.ValueKind)
        {
            case JsonValueKind.Array:
                if (IsElement(e)) elements++;
                foreach (var c in e.EnumerateArray()) Walk(c, row, actions, ref elements, depth + 1);
                break;
            case JsonValueKind.Object:
                if (e.TryGetProperty("id", out var id) && id.ValueKind == JsonValueKind.String && e.TryGetProperty("bound", out _)) actions.Add($"{id.GetString()} (row {row})");
                foreach (var p in e.EnumerateObject()) Walk(p.Value, row, actions, ref elements, depth + 1);
                break;
        }
    }

    private static bool IsElement(JsonElement e) => e.GetArrayLength() >= 4 && e[0].ValueKind == JsonValueKind.String && e[0].GetString() == "$";

    // Elements as type(children, ...): host tags by name, client components by module and export, references followed.
    private static List<string> Tree(JsonElement e, Dictionary<string, JsonElement> models, Dictionary<string, ClientModule> modules, ref int nodes, int depth, HashSet<string> seen)
    {
        var found = new List<string>();
        if (nodes >= MaxTree || depth > MaxDepth) return found;
        switch (e.ValueKind)
        {
            case JsonValueKind.Array when IsElement(e):
            {
                nodes++;
                var type = e[1].ValueKind == JsonValueKind.String ? e[1].GetString()! : "?";
                var children = new List<string>();
                if (e[3].ValueKind == JsonValueKind.Object)
                    foreach (var p in e[3].EnumerateObject()) children.AddRange(Tree(p.Value, models, modules, ref nodes, depth + 1, seen));
                found.Add(TypeName(type, models, modules) + (children.Count > 0 ? "(" + string.Join(", ", children) + ")" : ""));
                break;
            }
            case JsonValueKind.Array:
                foreach (var c in e.EnumerateArray()) found.AddRange(Tree(c, models, modules, ref nodes, depth, seen));
                break;
            case JsonValueKind.Object:
                foreach (var p in e.EnumerateObject()) found.AddRange(Tree(p.Value, models, modules, ref nodes, depth, seen));
                break;
            case JsonValueKind.String when e.GetString() is { Length: > 1 } r && Reference(r) is { } target && models.TryGetValue(target, out var m) && seen.Add(target):
                found.AddRange(Tree(m, models, modules, ref nodes, depth, seen));
                break;
        }
        return found;
    }

    // A client module by id and export (none: the module itself); a symbol row ("$Sreact.fragment") by its name.
    private static string TypeName(string type, Dictionary<string, JsonElement> models, Dictionary<string, ClientModule> modules)
    {
        if (Reference(type) is not { } row) return type;
        if (modules.TryGetValue(row, out var m)) return $"client {m.Id}{(m.Name.Length > 0 ? "#" + m.Name : "")}";
        if (models.TryGetValue(row, out var v) && v.ValueKind == JsonValueKind.String && v.GetString() is { } sym && sym.StartsWith("$S", StringComparison.Ordinal)) return sym[2..];
        return "ref " + type;
    }

    // "$L1" lazy, "$1" model, "$@1" promise rows; "$$" escapes a dollar, "$S" names a symbol.
    private static string? Reference(string r)
    {
        if (r.Length < 2 || r[0] != '$') return null;
        var body = r.StartsWith("$L", StringComparison.Ordinal) || r.StartsWith("$@", StringComparison.Ordinal) ? r[2..] : r[1..];
        return body.Length > 0 && body.All(Uri.IsHexDigit) ? body : null;
    }

    // self.__next_f.push(...) or the bootstrap (self.__next_f=self.__next_f||[]).push(...).
    [GeneratedRegex("""(?:self\.__next_f|\(\s*self\.__next_f\s*=\s*self\.__next_f\s*\|\|\s*\[\]\s*\))\.push\(\[\s*(\d+)\s*(?:,\s*("(?:[^"\\]|\\.)*")\s*)?\]\)""")]
    private static partial Regex Push();

    [GeneratedRegex("^[0-9a-f]{1,8}:[A-Za-z\\[{\"]")]
    private static partial Regex RawStart();
}
