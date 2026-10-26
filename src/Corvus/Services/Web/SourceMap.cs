using System.Text;
using System.Text.Json;
using Corvus.Core;

namespace Corvus.Services.Web;

/// <summary>One mapping segment: generated position (0-based line, UTF-16 column) to an original source position and name.</summary>
public readonly record struct MapSegment(int Line, int Column, int Source, int OriginalLine, int OriginalColumn, int Name);

/// <summary>
/// A v3 source map (ECMA-426). <c>mappings</c> is decoded lazily: base64 VLQ fields are relative to the previous segment,
/// so a checkpoint (position and the running values) is kept every <see cref="CheckpointEvery"/> segments; a lookup
/// decodes at most that many. Indexed maps (<c>sections</c>) are read section by section.
/// </summary>
public sealed class SourceMap
{
    public const int CheckpointEvery = 1024;
    /// <summary>Largest map decoded.</summary>
    public const long MaxBytes = 256L * 1024 * 1024;

    private readonly string _mappings;
    private readonly List<Checkpoint> _checkpoints = [];
    private readonly List<(int Line, int Column, SourceMap Map)>? _sections;

    public IReadOnlyList<string> Sources { get; }
    public IReadOnlyList<string?> SourcesContent { get; }
    public IReadOnlyList<string> Names { get; }
    public IReadOnlyList<string> Issues => _issues;
    public int SegmentCount { get; private set; }
    private readonly List<string> _issues = [];

    private readonly record struct Checkpoint(int Position, int Line, int Column, int Source, int OriginalLine, int OriginalColumn, int Name, int Index);

    public static SourceMap Parse(ReadOnlySpan<byte> json)
    {
        if (json.Length > MaxBytes) throw new ToolError(ErrorCode.LimitExceeded, $"the source map is {json.Length:N0} bytes; maps up to {MaxBytes:N0} bytes are decoded.");
        // the XSSI guard some servers prepend, and a BOM
        if (json.StartsWith(")]}'"u8)) json = json[(json.IndexOf((byte)'\n') + 1)..];
        if (json.StartsWith((ReadOnlySpan<byte>)[0xEF, 0xBB, 0xBF])) json = json[3..];
        try
        {
            using var doc = JsonDocument.Parse(json.ToArray(), new JsonDocumentOptions { MaxDepth = 64 });
            return new SourceMap(doc.RootElement);
        }
        catch (JsonException ex) { throw new ToolError(ErrorCode.MalformedInput, $"the source map is not valid JSON: {ex.Message}"); }
        // a string value that is not valid UTF-8
        catch (InvalidOperationException ex) { throw new ToolError(ErrorCode.MalformedInput, $"the source map holds invalid text: {ex.Message}"); }
    }

    private SourceMap(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object) throw new ToolError(ErrorCode.MalformedInput, "the source map is not a JSON object.");
        if (root.TryGetProperty("sections", out var sections) && sections.ValueKind == JsonValueKind.Array)
        {
            _sections = [];
            var sources = new List<string>();
            var content = new List<string?>();
            var names = new List<string>();
            foreach (var s in sections.EnumerateArray())
            {
                if (!s.TryGetProperty("offset", out var off) || !s.TryGetProperty("map", out var map))
                {
                    _issues.Add("a section without offset or embedded map (url sections are not loaded)");
                    continue;
                }
                var child = new SourceMap(map);
                _sections.Add((off.GetProperty("line").GetInt32(), off.GetProperty("column").GetInt32(), child));
                sources.AddRange(child.Sources);
                content.AddRange(child.SourcesContent);
                names.AddRange(child.Names);
                SegmentCount += child.SegmentCount;
                _issues.AddRange(child.Issues);
            }
            (Sources, SourcesContent, Names, _mappings) = (sources, content, names, "");
            return;
        }
        string root0 = root.TryGetProperty("sourceRoot", out var sr) && sr.ValueKind == JsonValueKind.String ? sr.GetString() ?? "" : "";
        Sources = Strings(root, "sources").Select(s => Normalize(root0, s ?? "")).ToList();
        SourcesContent = Strings(root, "sourcesContent");
        Names = Strings(root, "names").Select(s => s ?? "").ToList();
        _mappings = root.TryGetProperty("mappings", out var m) && m.ValueKind == JsonValueKind.String ? m.GetString() ?? "" : "";
        Index();
    }

    private static List<string?> Strings(JsonElement root, string name) =>
        root.TryGetProperty(name, out var a) && a.ValueKind == JsonValueKind.Array
            ? a.EnumerateArray().Select(e => e.ValueKind == JsonValueKind.String ? e.GetString() : null).ToList()
            : [];

    /// <summary>webpack://ns/./src/x.ts and similar prefixes reduced to a relative path; never rooted or above its root.</summary>
    internal static string Normalize(string sourceRoot, string source)
    {
        var s = (sourceRoot.Length > 0 && !source.Contains("://") ? sourceRoot.TrimEnd('/') + "/" : "") + source;
        int scheme = s.IndexOf("://", StringComparison.Ordinal);
        if (scheme > 0)
        {
            s = s[(scheme + 3)..];
            // webpack://<namespace>/./src: drop the namespace
            if (s.StartsWith('/')) s = s.TrimStart('/');
            else if (s.IndexOf('/') is var slash and > 0 && source.StartsWith("webpack://", StringComparison.Ordinal)) s = s[(slash + 1)..];
        }
        var parts = new List<string>();
        foreach (var part in s.Replace('\\', '/').Split('/'))
        {
            if (part is "" or ".") continue;
            if (part == "..") { if (parts.Count > 0) parts.RemoveAt(parts.Count - 1); continue; }
            parts.Add(part.Contains(':') ? part.Replace(':', '_') : part);
        }
        return string.Join("/", parts);
    }

    /// <summary>One pass over mappings: counts segments and records checkpoints (values are not kept).</summary>
    private void Index()
    {
        var state = new Checkpoint(0, 0, 0, 0, 0, 0, 0, 0);
        int index = 0;
        foreach (var seg in Decode(state))
        {
            index++;
            if (index % CheckpointEvery == 0) _checkpoints.Add(_last with { Index = index });
        }
        SegmentCount = index;
    }

    private Checkpoint _last;

    /// <summary>Segments from <paramref name="start"/> on; <see cref="_last"/> holds the state after each one.</summary>
    private IEnumerable<MapSegment> Decode(Checkpoint start)
    {
        var s = _mappings;
        int p = start.Position, line = start.Line, column = start.Column, source = start.Source, oline = start.OriginalLine, ocol = start.OriginalColumn, name = start.Name;
        var fields = new int[5];
        while (p < s.Length)
        {
            char c = s[p];
            if (c == ';') { line++; column = 0; p++; continue; }
            if (c == ',') { p++; continue; }
            int n = 0;
            bool bad = false;
            while (p < s.Length && s[p] is not (',' or ';'))
            {
                if (n == 5 || !Vlq(s, ref p, out fields[n])) { bad = true; while (p < s.Length && s[p] is not (',' or ';')) p++; break; }
                n++;
            }
            if (bad || n is not (1 or 4 or 5))
            {
                if (_issues.Count < 20) _issues.Add($"malformed segment at mappings offset {p}");
                continue;
            }
            column += fields[0];
            if (n >= 4) { source += fields[1]; oline += fields[2]; ocol += fields[3]; }
            if (n == 5) name += fields[4];
            _last = new Checkpoint(p, line, column, source, oline, ocol, name, 0);
            yield return new MapSegment(line, column, n >= 4 ? source : -1, n >= 4 ? oline : -1, n >= 4 ? ocol : -1, n == 5 ? name : -1);
        }
    }

    private static bool Vlq(string s, ref int p, out int value)
    {
        int result = 0, shift = 0;
        while (p < s.Length)
        {
            int digit = Base64(s[p++]);
            if (digit < 0 || shift > 30) { value = 0; return false; }
            result |= (digit & 31) << shift;
            shift += 5;
            if ((digit & 32) == 0)
            {
                value = (result & 1) != 0 ? -(result >> 1) : result >> 1;
                return true;
            }
        }
        value = 0;
        return false;
    }

    private static int Base64(char c) => c switch
    {
        >= 'A' and <= 'Z' => c - 'A',
        >= 'a' and <= 'z' => c - 'a' + 26,
        >= '0' and <= '9' => c - '0' + 52,
        '+' => 62,
        '/' => 63,
        _ => -1,
    };

    /// <summary>The segment covering a generated position (0-based line, UTF-16 column): the last one at or before it on that line.</summary>
    public MapSegment? Find(int line, int column)
    {
        if (_sections != null)
        {
            var section = _sections.LastOrDefault(x => x.Line < line || (x.Line == line && x.Column <= column));
            if (section.Map == null) return null;
            int l = line - section.Line, c = l == 0 ? column - section.Column : column;
            return section.Map.Find(l, c) is { } hit ? hit with { Line = line } : null;
        }
        // the last checkpoint before the target, then a forward decode
        int lo = 0, hi = _checkpoints.Count - 1, from = -1;
        while (lo <= hi)
        {
            int mid = (lo + hi) / 2;
            var cp = _checkpoints[mid];
            if (cp.Line < line || (cp.Line == line && cp.Column <= column)) { from = mid; lo = mid + 1; }
            else hi = mid - 1;
        }
        var start = from >= 0 ? _checkpoints[from] : new Checkpoint(0, 0, 0, 0, 0, 0, 0, 0);
        MapSegment? best = null;
        foreach (var seg in Decode(start))
        {
            if (seg.Line > line || (seg.Line == line && seg.Column > column)) break;
            if (seg.Line == line) best = seg;
        }
        return best;
    }

    /// <summary>
    /// The generated positions of source index <paramref name="source"/> at the first original line at or after
    /// <paramref name="line"/> (0-based) that has any, as a debugger moves a breakpoint to the next line with code; null
    /// when no such line is mapped. The whole mapping is decoded.
    /// </summary>
    public (int Line, IReadOnlyList<MapSegment> Segments)? Generated(int source, int line)
    {
        var best = new List<MapSegment>();
        int found = int.MaxValue;
        foreach (var seg in All())
        {
            if (seg.Source != source || seg.OriginalLine < line || seg.OriginalLine > found) continue;
            if (seg.OriginalLine < found) (found, best) = (seg.OriginalLine, []);
            best.Add(seg);
        }
        return best.Count == 0 ? null : (found, best);
    }

    // Every segment in generated order; a section's lines, first-line columns and source indexes are offset into this map's.
    private IEnumerable<MapSegment> All()
    {
        if (_sections == null)
        {
            foreach (var seg in Decode(default)) yield return seg;
            yield break;
        }
        int sources = 0;
        foreach (var (line, column, map) in _sections)
        {
            foreach (var seg in map.All())
                yield return seg with { Line = seg.Line + line, Column = seg.Line == 0 ? seg.Column + column : seg.Column, Source = seg.Source < 0 ? -1 : seg.Source + sources };
            sources += map.Sources.Count;
        }
    }

    /// <summary>The map a JavaScript file names: an inline data: URL, a URL relative to the file, or a sibling .map. Null when none.</summary>
    public static (SourceMap Map, string Location)? Locate(string file, byte[] text)
    {
        var url = MappingUrl(text);
        if (url != null && url.StartsWith("data:", StringComparison.Ordinal))
        {
            int comma = url.IndexOf(',');
            if (comma < 0) return null;
            var meta = url[5..comma];
            var payload = url[(comma + 1)..];
            byte[] json = meta.EndsWith(";base64", StringComparison.Ordinal) ? Convert.FromBase64String(payload) : Encoding.UTF8.GetBytes(Uri.UnescapeDataString(payload));
            return (Parse(json), "inline");
        }
        var dir = Path.GetDirectoryName(file) ?? "";
        // without a comment: a sibling x.js.map, or x.map (jquery.min.js -> jquery.min.map)
        var candidate = url != null && !url.Contains("://") ? Path.Combine(dir, Uri.UnescapeDataString(url.Split('?', '#')[0]))
            : File.Exists(file + ".map") ? file + ".map" : Path.ChangeExtension(file, ".map");
        if (!File.Exists(candidate)) return null;
        var info = new FileInfo(candidate);
        if (info.Length > MaxBytes) throw new ToolError(ErrorCode.LimitExceeded, $"{candidate} is {info.Length:N0} bytes; maps up to {MaxBytes:N0} bytes are decoded.");
        candidate = Path.GetFullPath(candidate);
        return (Parse(File.ReadAllBytes(candidate)), url != null ? candidate : candidate + " (no sourceMappingURL comment)");
    }

    /// <summary>The last //# sourceMappingURL= (or //@, /*# */) in the file, searched from the end without a regex.</summary>
    internal static string? MappingUrl(byte[] text)
    {
        var marker = "sourceMappingURL="u8;
        int at = text.AsSpan().LastIndexOf(marker);
        if (at < 3) return null;
        var before = text.AsSpan(Math.Max(0, at - 4), Math.Min(4, at));
        if (before.IndexOf("//"u8) < 0 && before.IndexOf("/*"u8) < 0) return null;
        int start = at + marker.Length, end = start;
        while (end < text.Length && text[end] is not ((byte)' ' or (byte)'\n' or (byte)'\r' or (byte)'\t' or (byte)'*')) end++;
        return end > start ? Encoding.UTF8.GetString(text, start, end - start) : null;
    }
}
