using System.Text.Json;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;
using Corvus.Core;

namespace Corvus.Tests;

/// <summary>Real data for tools no family test covers on a real library.</summary>
[Trait("Data", "Real"), Trait("Speed", "Slow")]
public sealed class ToolRealDataTests(Xunit.Abstractions.ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    internal static string Text(CallToolResult r) => string.Concat(r.Content.OfType<TextContentBlock>().Select(b => b.Text));

    /// <summary>A successful call: its text and structured record.</summary>
    internal static async Task<(string Text, JsonElement Record)> Call(McpClient client, string tool, Dictionary<string, object?> args)
    {
        var r = await client.CallToolAsync(tool, args);
        Assert.True(r.IsError != true, $"{tool}: {Text(r)}");
        return (Text(r), r.StructuredContent ?? default);
    }

    private static string Sqlite(string rid, string file) => RealPackages.File("SQLitePCLRaw.lib.e_sqlite3", "2.1.11", "runtimes", rid, "native", file);

    [Theory]
    [InlineData("win-x64", "e_sqlite3.dll", "rcx")]
    [InlineData("linux-x64", "libe_sqlite3.so", "rdi")]
    public async Task Native_reading_tools_answer_on_a_real_PE_and_ELF(string rid, string file, string firstArgument)
    {
        var image = Sqlite(rid, file);
        await using var server = await InProcessServer.StartAsync();
        var c = server.Client;
        Dictionary<string, object?> On(params (string Key, object? Value)[] more) => new[] { ("image", (object?)image) }.Concat(more).ToDictionary(p => p.Item1, p => p.Item2);

        Assert.Contains("sqlite3_open", (await Call(c, "list_exports", On(("filter", "sqlite3_open")))).Text);
        Assert.True((await Call(c, "list_imports", On())).Record.GetProperty("total").GetInt32() > 10);
        Assert.True((await Call(c, "list_functions", On(("limit", 5)))).Record.GetProperty("total").GetInt32() > 1000);
        await Call(c, "list_globals", On(("limit", 5)));
        await Call(c, "list_cpp_classes", On()); // C code: no RTTI classes, but the scan runs over the whole image
        await Call(c, "get_exception_info", On());
        Assert.Contains(rid.StartsWith("win", StringComparison.Ordinal) ? "AMD64" : "X86_64", (await Call(c, "get_pe_info", On())).Text, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("sqlite3_free", (await Call(c, "resolve_address", On(("address", "sqlite3_free")))).Text);
        var bytes = (await Call(c, "read_bytes", On(("address", "sqlite3_free"), ("length", 16)))).Text;
        Assert.Contains("16 bytes", bytes);
        Assert.Contains("unsigned", (await Call(c, "convert_number", new() { ["numbers"] = new[] { "0x" + bytes.Split('\n')[1].Split("  ")[1].Replace(" ", "")[..8] } })).Text);
        Assert.True((await Call(c, "search_bytes", On(("pattern", "SQLite format 3"), ("text", true)))).Record.GetProperty("total").GetInt32() >= 1);
        Assert.True((await Call(c, "search_native_strings", On(("query", "no such table"), ("limit", 5)))).Record.GetProperty("total").GetInt32() >= 1);
        Assert.Contains("sqlite3_free", (await Call(c, "disassemble", On(("address", "sqlite3_free")))).Text);
        Assert.Contains("decoded", (await Call(c, "inspect_instruction", On(("address", "sqlite3_free"), ("limit", 3)))).Text);
        Assert.True((await Call(c, "search_instructions", On(("mnemonic", "^call$"), ("limit", 5)))).Record.GetProperty("items").GetArrayLength() == 5);
        Assert.True((await Call(c, "find_xrefs", On(("address", "sqlite3_free")))).Record.GetProperty("total").GetInt32() >= 1);
        await Call(c, "get_call_arguments", On(("address", "sqlite3_open")));
        await Call(c, "resolve_call_targets", On(("address", "sqlite3_open"), ("scope", "function")));
        // Compact record: the engine note in its own field, no instruction text per site (the text has it), no empty target lists.
        var (targetsText, targets) = await Call(c, "resolve_call_targets", On(("scope", "image")));
        Assert.StartsWith("ours", targets.GetProperty("engine").GetString());
        Assert.False(string.IsNullOrEmpty(targets.GetProperty("engineNote").GetString()));
        Assert.DoesNotContain(targets.GetProperty("notes").EnumerateArray(), n => n.GetString()!.StartsWith("Engine:", StringComparison.Ordinal));
        Assert.All(targets.GetProperty("items").EnumerateArray(), i => Assert.False(i.TryGetProperty("text", out _)));
        // Measured 1.32x (PE) and 1.41x (ELF: import targets carry evidence the text leaves out), from 1.64x.
        int recordTokens = TokenEstimate.Of(targets.GetRawText()), textTokens = TokenEstimate.Of(targetsText);
        Assert.True(recordTokens <= textTokens * 145 / 100, $"record {recordTokens}, text {textTokens}");
        Assert.Contains($"of {firstArgument}", (await Call(c, "trace_native_values", On(("address", "sqlite3_open"), ("location", firstArgument)))).Text);
        Assert.Contains("sqlite3_open", (await Call(c, "native_call_tree", On(("function", "sqlite3_open"), ("depth", 2)))).Text);
        Assert.Contains("== callers", (await Call(c, "analyze_native_function", On(("address", "sqlite3_open")))).Text);
        Assert.Contains("sqlite3_open", (await Call(c, "trace_native_feature", On(("query", "sqlite3_open")))).Text);
        await Call(c, "find_similar_functions", On(("address", "sqlite3_open"), ("limit", 5)));
        await Call(c, "find_virtual_calls", On(("limit", 5)));
        var summary = await c.CallToolAsync("summarize_build", new Dictionary<string, object?> { ["path"] = image });
        Assert.True(summary.IsError == true && Text(summary).Contains("not_a_build", StringComparison.Ordinal), Text(summary)); // a real native library is no build
    }

    /// <summary>Every find_similar_functions view keeps its rows in items: a walk by nextOffset sees each of total once.</summary>
    [Theory]
    [InlineData("similar")]
    [InlineData("duplicates")]
    [InlineData("clusters")]
    public async Task Similar_function_views_page_their_rows_in_items(string view)
    {
        var image = Sqlite("win-x64", "e_sqlite3.dll");
        await using var server = await InProcessServer.StartAsync();
        // view=similar asks about the first duplicate group's first member, which has look-alikes
        string? address = null;
        if (view == "similar")
            address = (await Call(server.Client, "find_similar_functions", new() { ["image"] = image, ["view"] = "duplicates", ["limit"] = 1 }))
                .Record.GetProperty("items")[0].GetProperty("functions")[0].GetProperty("address").GetString();
        int limit = address != null ? 1 : 5;
        var rows = new List<string>();
        int? total = null, offset = 0;
        for (int calls = 0; offset is int at; calls++)
        {
            Assert.True(calls < 200, "nextOffset does not end");
            var args = new Dictionary<string, object?> { ["image"] = image, ["view"] = view, ["offset"] = at, ["limit"] = limit };
            if (address != null) (args["address"], args["minScore"]) = (address, 0.3);
            var (_, record) = await Call(server.Client, "find_similar_functions", args);
            Assert.False(record.TryGetProperty("groups", out _));
            Assert.Equal(at, record.GetProperty("offset").GetInt32());
            total ??= record.GetProperty("total").GetInt32();
            Assert.Equal(total, record.GetProperty("total").GetInt32());
            var items = record.GetProperty("items").EnumerateArray().Select(e => e.GetRawText()).ToList();
            rows.AddRange(items);
            offset = record.TryGetProperty("nextOffset", out var next) ? next.GetInt32() : null;
            Assert.Equal(offset != null, record.GetProperty("hasMore").GetBoolean());
            Assert.True(offset == null || offset == at + items.Count, $"nextOffset {offset} after {items.Count} rows at {at}");
        }
        Assert.True(total > limit, $"{view}: {total} rows, too few to page");
        Assert.Equal(total, rows.Count);
        Assert.Equal(rows.Count, rows.Distinct().Count());
    }

    /// <summary>The runtime's compression assembly: its declarations bind to a runtime native library, which the runtime itself resolves.</summary>
    [Fact]
    public async Task Verify_native_imports_classifies_a_runtime_assembly()
    {
        var lib = RealPackages.File("Microsoft.NETCore.App.Runtime.linux-arm64", "10.0.11", "runtimes", "linux-arm64", "lib", "net10.0", "System.IO.Compression.dll");
        await using var server = await InProcessServer.StartAsync();
        var (text, record) = await Call(server.Client, "verify_native_imports", new() { ["assembly"] = lib, ["platform"] = "linux" });
        Assert.True(record.GetProperty("declarations").GetInt32() > 5, text);
        Assert.Contains("libSystem.IO.Compression.Native!CompressionNative_Inflate", text);
        Assert.DoesNotContain("dll_not_found", text);
    }

    /// <summary>HarfBuzzSharp ships its PDB: names, symbols and a struct layout from a real compiler's output.</summary>
    [Fact]
    public async Task Pdb_tools_read_a_matching_real_pdb()
    {
        var dll = RealPackages.File("HarfBuzzSharp.NativeAssets.Win32", "14.2.0", "runtimes", "win-x64", "native", "libHarfBuzzSharp.dll");
        var pdb = RealPackages.File("HarfBuzzSharp.NativeAssets.Win32", "14.2.0", "runtimes", "win-x64", "native", "libHarfBuzzSharp.pdb");
        using var work = new TempDir();
        await using var client = await McpProtocolTests.StartServerInAsync(work.Path);
        Assert.Contains("matches the image", (await Call(client, "load_pdb", new() { ["image"] = dll, ["path"] = pdb })).Text);
        Assert.Contains("hb_buffer_create", (await Call(client, "search_pdb_symbols", new() { ["image"] = "libHarfBuzzSharp.dll", ["query"] = "hb_buffer_create" })).Text);
        var (typeText, type) = await Call(client, "get_native_type", new() { ["image"] = "libHarfBuzzSharp.dll", ["name"] = "hb_glyph_info_t" });
        Assert.Contains("codepoint", typeText);
        // Compact record: false, zero and empty fields are left out.
        Assert.False(type.GetProperty("type").TryGetProperty("forwardOnly", out _));
        Assert.False(type.TryGetProperty("candidates", out _));
        // Measured 1.37-1.48x (one row object per field; the text is a table).
        foreach (var name in new[] { "hb_glyph_info_t", "hb_segment_properties_t", "hb_feature_t" })
        {
            var (t, r) = await Call(client, "get_native_type", new() { ["image"] = "libHarfBuzzSharp.dll", ["name"] = name });
            int textTokens = TokenEstimate.Of(t), recordTokens = TokenEstimate.Of(r.GetRawText());
            output.WriteLine($"get_native_type {name}: text {textTokens}, record {recordTokens} tokens");
            Assert.True(recordTokens <= textTokens * 155 / 100, $"{name}: record {recordTokens}, text {textTokens}");
        }
    }

    /// <summary>Workspace, notes and session tools on a real library, in a server with its own notes folder.</summary>
    [Fact]
    public async Task Workspace_notes_and_session_tools_work_on_a_real_library()
    {
        var lib = RealPackages.Lib("Newtonsoft.Json", "13.0.4", "netstandard2.0", "Newtonsoft.Json.dll");
        using var work = new TempDir();
        await using var c = await McpProtocolTests.StartServerInAsync(work.Path);
        Assert.Contains("netstandard2.0", (await Call(c, "add_search_directory", new() { ["directory"] = Path.GetDirectoryName(lib) })).Text);
        await Call(c, "load_assembly", new() { ["path"] = lib });
        Assert.Contains("Newtonsoft.Json", (await Call(c, "list_assemblies", new())).Text);
        Assert.Contains("Reloaded", (await Call(c, "reload_assembly", new() { ["assembly"] = "Newtonsoft.Json" })).Text);
        var note = (await Call(c, "record_note", new() { ["text"] = "parses JSON text", ["anchor"] = "Newtonsoft.Json:Newtonsoft.Json.Linq.JToken::Parse(string)" })).Record;
        Assert.Equal("dotnet", note.GetProperty("anchor").GetProperty("kind").GetString());
        await Call(c, "update_note", new() { ["id"] = note.GetProperty("id").GetString(), ["expectedRevision"] = 1, ["status"] = "confirmed" });
        Assert.Contains("parses JSON text", (await Call(c, "list_notes", new() { ["anchor"] = "Newtonsoft.Json", ["status"] = "all" })).Text);
        var session = Path.Combine(work.Path, "work.session.json");
        Assert.Equal(1, (await Call(c, "save_session", new() { ["outputPath"] = session })).Record.GetProperty("notes").GetInt32());
        Assert.Contains("already_loaded", (await Call(c, "load_session", new() { ["path"] = session })).Text);
        Assert.Contains("version", (await Call(c, "server_status", new())).Text);
        Assert.Contains("Unloaded", (await Call(c, "unload_assembly", new() { ["assembly"] = "Newtonsoft.Json" })).Text);
    }
}
