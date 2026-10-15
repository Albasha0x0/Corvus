using System.Text;
using Corvus.Core;

namespace Corvus.Services.Web;

/// <summary>A bundler or runtime recognized by its signature, with the evidence string and its count.</summary>
public sealed record JsBundler(string Family, string Evidence, int Count);

/// <summary>A located source map: inline, or the .map file read.</summary>
public sealed record JsMapInfo(string Location, int Sources, int WithContent, int Segments, IReadOnlyList<string> Issues);

/// <summary>analyze_js view=summary: what the file is built from, without running it.</summary>
public sealed record JsSummary(long Bytes, int Lines, int LongestLine, IReadOnlyList<JsBundler> Bundlers, JsMapInfo? SourceMap,
    IReadOnlyList<string> Notes) { internal int Banners { get; init; } }

/// <summary>analyze_js view=position: a generated position and the original position it maps to.</summary>
public sealed record JsPosition(string? Source, int? OriginalLine, int? OriginalColumn, string? Name);

/// <summary>analyze_js view=endpoints: a request (or ROUTE), its client, line:column, module and original position.</summary>
public sealed record JsEndpoint(string Verb, string Url, string Client, string Site, string? Module, string? Original);

/// <summary>analyze_js view=source: one original source from the map's sourcesContent, paged by the caller.</summary>
public sealed record JsSource(string Source, int Index, string? Content);

/// <summary>Static facts of JavaScript files: bundler signatures, source maps and positions through them.</summary>
public static class JsAnalysis
{
    public const long MaxFileBytes = 512L * 1024 * 1024;

    // byte signatures of bundler runtimes; the design's AST recognizers refine these into module tables
    private static readonly (string Family, string Evidence)[] Signatures =
    [
        ("webpack", "__webpack_require__"), ("webpack", "__webpack_modules__"), ("webpack", "webpackChunk"), ("webpack", "webpackJsonp"),
        ("esbuild", "__commonJS("), ("esbuild", "__toESM("), ("rollup/vite", "__vitePreload"), ("rollup/vite", "__vite__mapDeps"),
        ("parcel", "parcelRegister("), ("parcel", "parcelRequire"), ("turbopack", "TURBOPACK"), ("browserify", "require,module,exports"),
        ("systemjs", "System.register("), ("metro", "__d(function"), ("amd", "define(["),
    ];

    public static byte[] Read(string path)
    {
        var full = InputFiles.RequireRegularFile(path, "JavaScript file");
        if (!File.Exists(full)) throw Targets.FileNotFound(path);
        var info = new FileInfo(full);
        if (info.Length > MaxFileBytes) throw new ToolError(ErrorCode.LimitExceeded, $"{path} is {info.Length:N0} bytes; files up to {MaxFileBytes:N0} bytes are read.");
        return File.ReadAllBytes(full);
    }

    public static JsSummary Summary(string path)
    {
        var text = Read(path);
        var notes = new List<string>();
        // React Native's Hermes bytecode: compiled, not JavaScript text
        if (text.AsSpan().StartsWith((ReadOnlySpan<byte>)[0xC6, 0x1F, 0xBC, 0x03, 0xC1, 0x03, 0x19, 0x1F]) && text.Length >= 12)
        {
            uint version = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(text.AsSpan(8));
            notes.Add($"Hermes bytecode version {version} (React Native): compiled, not JavaScript text; analyze_js view=functions, decompile and disassemble read its code.");
            return new JsSummary(text.Length, 0, 0, [new JsBundler("hermes", $"bytecode v{version}", 1)], null, notes);
        }
        int lines = 1, longest = 0, start = 0;
        for (int i = 0; i < text.Length; i++)
            if (text[i] == '\n') { lines++; longest = Math.Max(longest, i - start); start = i + 1; }
        longest = Math.Max(longest, text.Length - start);
        var bundlers = Signatures.Select(s => new JsBundler(s.Family, s.Evidence, Count(text, Encoding.UTF8.GetBytes(s.Evidence))))
            .Where(b => b.Count > 0).ToList();
        int banners = Count(text, "/*!"u8.ToArray()) + Count(text, "@license"u8.ToArray());
        JsMapInfo? map = null;
        try
        {
            if (SourceMap.Locate(path, text) is { } found)
                map = new JsMapInfo(found.Location, found.Map.Sources.Count, found.Map.SourcesContent.Count(c => c != null), found.Map.SegmentCount, found.Map.Issues);
        }
        catch (ToolError ex) { notes.Add("source map: " + ex.Message); }
        catch (FormatException ex) { notes.Add("source map: inline data is not base64: " + ex.Message); }
        if (map == null) notes.Add("No source map (no sourceMappingURL and no sibling .map): positions stay generated.");
        if (longest > 100_000) notes.Add($"Minified: the longest line has {longest:N0} bytes.");
        return new JsSummary(text.Length, lines, longest, bundlers, map, notes) { Banners = banners };
    }

    /// <summary>The original position of generated <paramref name="line"/>:<paramref name="column"/> (both 1-based, as editors show them).</summary>
    public static JsPosition Position(string path, int line, int column)
    {
        if (line < 1 || column < 1) throw new ToolError(ErrorCode.InvalidArgument, "line and column are 1-based.", "pass line>=1 and column>=1");
        var map = Map(path);
        if (map.Find(line - 1, column - 1) is not { Source: >= 0 } seg) return new JsPosition(null, null, null, null);
        return new JsPosition(seg.Source < map.Sources.Count ? map.Sources[seg.Source] : null, seg.OriginalLine + 1, seg.OriginalColumn + 1,
            seg.Name >= 0 && seg.Name < map.Names.Count ? map.Names[seg.Name] : null);
    }

    /// <summary>An original source by path (a suffix match) or index, with its content when the map embeds it.</summary>
    public static JsSource Source(string path, string source)
    {
        var map = Map(path);
        int index = int.TryParse(source, out var n) && n >= 0 && n < map.Sources.Count ? n
            : map.Sources.Select((s, i) => (s, i)).Where(x => x.s == source || x.s.EndsWith("/" + source.TrimStart('/'), StringComparison.Ordinal)).Select(x => x.i).DefaultIfEmpty(-1).First();
        if (index < 0)
            throw new ToolError(ErrorCode.NotFound, $"no source '{source}' in the map ({map.Sources.Count} sources).", "analyze_js view=sources lists them");
        return new JsSource(map.Sources[index], index, index < map.SourcesContent.Count ? map.SourcesContent[index] : null);
    }

    /// <summary>The parsed file with its scopes, or a malformed-input error naming why it did not parse.</summary>
    internal static JsProgram Program(string path, CancellationToken ct)
    {
        var notes = new List<string>();
        return JsProgram.Build(Path.GetFileName(path), Encoding.UTF8.GetString(Read(path)), notes, ct)
               ?? throw new ToolError(ErrorCode.MalformedInput, $"{Path.GetFileName(path)} could not be parsed: {string.Join("; ", notes)}");
    }

    /// <summary>The original position of 1-based <paramref name="line"/>:<paramref name="column"/>, or null.</summary>
    internal static string? Original(SourceMap? map, int line, int column) =>
        map?.Find(line - 1, column - 1) is { Source: >= 0 } seg && seg.Source < map.Sources.Count ? $"{map.Sources[seg.Source]}:{seg.OriginalLine + 1}:{seg.OriginalColumn + 1}" : null;

    internal static SourceMap? TryMap(string path)
    {
        try { return SourceMap.Locate(path, Read(path))?.Map; }
        catch (ToolError) { return null; }
        catch (FormatException) { return null; }
    }

    public static SourceMap Map(string path) =>
        SourceMap.Locate(path, Read(path))?.Map ?? throw new ToolError(ErrorCode.NotFound, $"{path} has no source map (no sourceMappingURL and no sibling .map).",
            "positions and original sources need a map; analyze_js view=summary shows what the file holds");

    private static int Count(byte[] text, byte[] needle)
    {
        int n = 0;
        for (int at = 0; at < text.Length && n < 1_000_000; n++)
        {
            int hit = text.AsSpan(at).IndexOf(needle);
            if (hit < 0) break;
            at += hit + needle.Length;
        }
        return n;
    }
}
