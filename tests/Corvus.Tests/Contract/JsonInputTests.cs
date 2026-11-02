using System.IO.Compression;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Corvus.Core;
using Corvus.Core.Models;
using Corvus.Core.Pcap;
using Corvus.Native;
using Corvus.Native.Dump;
using Corvus.Services.Analysis;
using Corvus.Services.Analysis.Dependencies;
using Corvus.Services.Web;

namespace Corvus.Tests;

/// <summary>JSON taken from an analyzed file is read through InputJson, and every reader of it survives hostile bytes.</summary>
public sealed partial class JsonInputTests
{
    private const string Fed = "json-input-feed";

    private const string Direct = "json-input-parse";

    private static string Source => Path.Combine(DocsTests.RepoRoot(), "src", "Corvus");

    private static byte[] Bytes(string s) => Encoding.UTF8.GetBytes(s);

    /// <summary>The seed with the last byte of every string value replaced by 0xFF.</summary>
    private static byte[] InvalidUtf8(byte[] seed)
    {
        var b = (byte[])seed.Clone();
        bool inString = false;
        for (int i = 0; i < b.Length; i++)
        {
            if (b[i] == '\\' && inString) { i++; continue; }
            if (b[i] != '"') continue;
            if (inString && i > 0 && b[i - 1] != '"') b[i - 1] = 0xFF;
            inString = !inString;
        }
        return b;
    }

    private static byte[] Truncated(byte[] seed) => seed[..(seed.Length * 2 / 3)];

    private static byte[] Deep(bool objects, int levels)
    {
        var open = objects ? "{\"a\":" : "[";
        var close = objects ? "}" : "]";
        var sb = new StringBuilder();
        for (int i = 0; i < levels; i++) sb.Append(open);
        sb.Append('1');
        for (int i = 0; i < levels; i++) sb.Append(close);
        return Bytes(sb.ToString());
    }

    private static byte[] Zlib(byte[] data)
    {
        using var output = new MemoryStream();
        using (var z = new ZLibStream(output, CompressionLevel.Fastest, leaveOpen: true)) z.Write(data);
        return output.ToArray();
    }

    private static byte[] Safe(byte[] json)
    {
        var header = new byte[8 + json.Length + 4];
        BitConverter.GetBytes((long)json.Length).CopyTo(header, 0);
        json.CopyTo(header, 8);
        return header;
    }

    private static byte[] ImageArchive(byte[] config)
    {
        using var output = new MemoryStream();
        using (var tar = new System.Formats.Tar.TarWriter(output, System.Formats.Tar.TarEntryFormat.Ustar, leaveOpen: true))
            foreach (var (name, content) in new[] { ("manifest.json", Bytes("""[{"Config":"c.json","RepoTags":["a:1"],"Layers":[]}]""")), ("c.json", config) })
                tar.WriteEntry(new System.Formats.Tar.UstarTarEntry(System.Formats.Tar.TarEntryType.RegularFile, name) { DataStream = new MemoryStream(content) });
        return output.ToArray();
    }

    private static string Temp(byte[] content)
    {
        var path = Path.Combine(Path.GetTempPath(), "corvus-json-" + Guid.NewGuid().ToString("N") + ".json");
        File.WriteAllBytes(path, content);
        return path;
    }

    private static void WithFile(byte[] content, Action<string> read)
    {
        var path = Temp(content);
        try { read(path); }
        finally { File.Delete(path); }
    }

    private static object? Static(Type type, string name, params object?[] args)
    {
        try { return type.GetMethod(name, BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public)!.Invoke(null, args); }
        catch (TargetInvocationException ex) { ExceptionDispatchInfo.Capture(ex.InnerException!).Throw(); throw; }
    }

    /// <summary>The failures a reader reports by design; anything else is unhandled.</summary>
    private static bool Expected(Exception ex) => ex is ToolError or InvalidDataException;

    private static IEnumerable<(string Name, byte[] Bytes)> Hostile(string seed)
    {
        var bytes = Bytes(seed);
        yield return ("invalid UTF-8", InvalidUtf8(bytes));
        yield return ("truncated JSON", Truncated(bytes));
        yield return ("deep array nesting", Deep(false, 20_000));
        yield return ("deep object nesting", Deep(true, 20_000));
        yield return ("empty input", []);
        yield return ("array root", Bytes("""[1,"a",[2],{}]"""));
        yield return ("number root", Bytes("1"));
        yield return ("string root", Bytes("\"s\""));
        yield return ("null root", Bytes("null"));
    }

    private const string DirectParse = @"JsonDocument\.Parse\(|JsonDocument\.ParseValue\(|JsonNode\.Parse\(|JsonSerializer\.Deserialize|new (System\.Text\.Json\.)?Utf8JsonReader\(";

    private static IEnumerable<string> SourcesUsing(string pattern)
    {
        var rx = new Regex(pattern, RegexOptions.CultureInvariant);
        foreach (var file in Directory.EnumerateFiles(Source, "*.cs", SearchOption.AllDirectories))
        {
            var relative = Path.GetRelativePath(Source, file).Replace('\\', '/');
            if (relative == "Core/InputJson.cs") continue;
            if (rx.IsMatch(File.ReadAllText(file))) yield return relative;
        }
    }

    [Fact]
    public void Input_json_with_invalid_utf8_fails_as_a_json_error()
    {
        var invalid = InvalidUtf8(Bytes("""{"a":"bc"}"""));
        Assert.ThrowsAny<JsonException>(() => InputJson.ParseDocument(invalid));
        Assert.ThrowsAny<JsonException>(() => InputJson.RequireUtf8(invalid));
    }

    [Fact]
    public void Input_json_nested_past_the_depth_limit_fails_as_a_json_error()
    {
        Assert.ThrowsAny<JsonException>(() => InputJson.ParseDocument(Deep(false, InputJson.MaxDepth + 1)));
        Assert.ThrowsAny<JsonException>(() => InputJson.ParseDocument(Deep(false, 10_000), new JsonDocumentOptions { MaxDepth = 100_000 }));
        using var ok = InputJson.ParseDocument(Deep(false, InputJson.MaxDepth - 1));
        Assert.Equal(JsonValueKind.Array, ok.RootElement.ValueKind);
    }

    [Fact]
    public void Input_json_cut_short_or_empty_fails_as_a_json_error()
    {
        Assert.ThrowsAny<JsonException>(() => InputJson.ParseDocument(Truncated(Bytes("""{"a":["b","c"]}"""))));
        Assert.ThrowsAny<JsonException>(() => InputJson.ParseDocument(ReadOnlyMemory<byte>.Empty));
    }

    [Fact]
    public void Input_json_in_a_stream_past_the_limit_fails_as_a_json_error()
    {
        var json = Bytes("""{"a":"bcdef"}""");
        Assert.ThrowsAny<JsonException>(() => InputJson.ParseDocument(new MemoryStream(json), json.Length - 1));
        using var ok = InputJson.ParseDocument(new MemoryStream(json), json.Length);
        Assert.Equal("bcdef", ok.RootElement.GetProperty("a").GetString());
    }

    [Fact]
    public void A_reader_string_with_invalid_utf8_fails_as_a_json_error()
    {
        var invalid = InvalidUtf8(Bytes("""{"a":"bc"}"""));
        Assert.ThrowsAny<JsonException>(() =>
        {
            var reader = new Utf8JsonReader(invalid);
            while (reader.Read())
                if (reader.TokenType == JsonTokenType.String) InputJson.GetString(ref reader);
        });
    }

    // Commit 0e92815d: a saved image's JSON with invalid UTF-8 threw from a later GetString.
    [Fact]
    public void Every_reader_of_json_from_an_input_file_survives_hostile_bytes()
    {
        var used = SourcesUsing(@"\bInputJson\.").ToHashSet(StringComparer.Ordinal);
        var unfed = used.Where(f => !Feeds.ContainsKey(f)).ToDictionary(f => f, _ => "reads input JSON through InputJson and has no hostile-bytes feed", StringComparer.Ordinal);
        Ratchet.Check(Fed, "every reader of JSON from an input file is fed invalid UTF-8, truncated JSON and deep nesting", unfed);
        var parsing = SourcesUsing(DirectParse).ToHashSet(StringComparer.Ordinal);
        var stale = Feeds.Keys.Where(f => !used.Contains(f) && !parsing.Contains(f)).ToList();
        Assert.True(stale.Count == 0, "feeds for files that no longer read JSON: " + string.Join(", ", stale));

        var failures = new List<string>();
        foreach (var (file, (seed, read)) in Feeds)
        {
            try { read(Bytes(seed)); }
            catch (Exception ex) when (Expected(ex)) { }
            catch (Exception ex) { failures.Add($"{file}: its valid seed throws {ex.GetType().Name}: {ex.Message}"); }
            foreach (var (name, bytes) in Hostile(seed))
                try { read(bytes); }
                catch (Exception ex) when (Expected(ex)) { }
                catch (Exception ex) { failures.Add($"{file}: {name} throws {ex.GetType().Name}: {ex.Message}"); }
        }
        Assert.True(failures.Count == 0, string.Join("\n", failures));
    }

    [Fact]
    public void Text_with_an_unpaired_surrogate_parses_or_fails_as_a_json_error()
    {
        using var doc = InputJson.ParseDocument("[\"a\ud800b\"]");
        Assert.Equal("a�b", doc.RootElement[0].GetString());
        Assert.ThrowsAny<JsonException>(() => InputJson.ParseDocument("{\"a\":"));
        Assert.Equal("x", InputJson.ParseString("\"x\""));
        Assert.ThrowsAny<JsonException>(() => InputJson.ParseString("1"));
    }

    [Fact]
    public void Json_parsed_without_InputJson_has_a_feed_or_a_listed_exception()
    {
        var direct = SourcesUsing(DirectParse)
            .Where(f => !Feeds.ContainsKey(f))
            .ToDictionary(f => f, _ => "parses JSON outside InputJson: route input-file JSON through InputJson and feed it, or list the file with its reason", StringComparer.Ordinal);
        Ratchet.Check(Direct, "JSON read from an input file goes through InputJson or has a hostile-bytes feed", direct);
    }
}
