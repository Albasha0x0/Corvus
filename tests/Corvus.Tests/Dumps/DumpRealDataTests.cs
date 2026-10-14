using System.Diagnostics;
using System.Text.Json;
using Microsoft.CodeAnalysis;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;
using Corvus.Core;
using Corvus.Mcp;

namespace Corvus.Tests;

/// <summary>
/// The dumps, live, Il2Cpp and NativeAOT tools over stdio on real data (F-DM acceptance): a full-memory .NET Framework dump
/// written by a probe compiled here, a running child process, the NativeAOT-compiled ilc of the ILCompiler pack and
/// CoreLib; every default page within its class budget per part, list walks that rebuild the whole.
/// </summary>
[Trait("Speed", "Slow")]
[Trait("Data", "Real")]
public sealed class DumpRealDataTests(Xunit.Abstractions.ITestOutputHelper output) : IAsyncLifetime
{
    private readonly TempDir _dir = new();
    private McpClient _client = null!;

    private static string Ilc => RealPackages.File("runtime.win-x64.Microsoft.DotNet.ILCompiler", "10.0.11", "tools", "ilc.exe");
    private static string CoreLib => RealPackages.File("Microsoft.NETCore.App.Runtime.linux-arm64", "10.0.11", "runtimes", "linux-arm64", "lib", "net10.0", "System.Private.CoreLib.dll");

    public async Task InitializeAsync() => _client = await McpProtocolTests.StartServerAsync(null, null, ["--no-watch"]);

    public async Task DisposeAsync()
    {
        await _client.DisposeAsync();
        _dir.Dispose();
    }

    private async Task<(string Text, JsonElement Record)> Call(string tool, Dictionary<string, object?> args)
    {
        var r = await _client.CallToolAsync(tool, args);
        var text = string.Concat(r.Content.OfType<TextContentBlock>().Select(b => b.Text));
        Assert.True(r.IsError != true, $"{tool}: {text[..Math.Min(500, text.Length)]}");
        var raw = r.StructuredContent!.Value.GetRawText();
        int t = TokenEstimate.Of(text), s = TokenEstimate.Of(raw), limit = OutputClasses.Budget(ToolContract.Of(tool).Output) * 105 / 100;
        output.WriteLine($"{tool}({string.Join(", ", args.Where(a => a.Key is not ("dump" or "image" or "path" or "text")).Select(a => $"{a.Key}={a.Value}"))}): text {t}, record {s}");
        Assert.True(t <= limit && s <= limit, $"{tool}: text {t}, record {s}, over {limit}");
        return (text, JsonDocument.Parse(raw).RootElement.Clone());
    }

    private string FrameworkDump()
    {
        var exe = FrameworkDumpRealTests.Build(_dir, Platform.X64);
        return FrameworkDumpRealTests.Dump(exe, _dir.File("fx-x64.dmp"));
    }

    [Fact]
    public async Task DumpToolsFitTheirBudgetsOnAFullMemoryDump()
    {
        if (!OperatingSystem.IsWindows()) return;
        var dump = FrameworkDump();
        var (summary, record) = await Call("open_minidump", new() { ["path"] = dump });
        Assert.Contains("Exception", summary);
        Assert.True(record.GetProperty("counts").GetProperty("fullMemory").GetBoolean());
        const string module = "ntdll.dll";
        foreach (var view in new[] { "modules", "threads", "memory", "unloaded" })
        {
            var (_, list) = await Call("open_minidump", new() { ["path"] = dump, ["view"] = view });
            Assert.Equal(view, list.GetProperty("view").GetString());
        }
        var (_, stack) = await Call("dump_stack", new() { ["dump"] = dump });
        Assert.Contains(stack.GetProperty("items").EnumerateArray(), f => f.GetProperty("kind").GetString() == "managed");
        // G2-B7: array and generic rows have no TypeDef, so no token (never the nil row 0x02000000)
        var (_, stats) = await Call("dump_heap", new() { ["dump"] = dump, ["mode"] = "stats", ["limit"] = 200 });
        var rows = stats.GetProperty("items").EnumerateArray().ToList();
        Assert.Contains(rows, r => r.GetProperty("type").GetString()!.EndsWith("[]", StringComparison.Ordinal));
        Assert.All(rows.Where(r => r.GetProperty("type").GetString()!.EndsWith("[]", StringComparison.Ordinal)), r => Assert.False(r.TryGetProperty("token", out _)));
        Assert.All(rows, r => Assert.NotEqual("0x02000000", r.TryGetProperty("token", out var t) ? t.GetString() : null));
        Assert.Contains(rows, r => r.TryGetProperty("token", out _));
        var (_, arrays) = await Call("dump_heap", new() { ["dump"] = dump, ["mode"] = "objects", ["type"] = "System.Object[]" });
        var (_, array) = await Call("dump_object", new() { ["dump"] = dump, ["address"] = arrays.GetProperty("items")[0].GetProperty("address").GetString() });
        Assert.False(array.TryGetProperty("token", out _));
        var (_, objects) = await Call("dump_heap", new() { ["dump"] = dump, ["mode"] = "objects", ["type"] = "System.String" });
        var address = objects.GetProperty("items")[0].GetProperty("address").GetString();
        var (_, str) = await Call("dump_object", new() { ["dump"] = dump, ["address"] = address });
        Assert.StartsWith("0x02", str.GetProperty("token").GetString());
        await Call("bucket_minidumps", new() { ["folder"] = _dir.Path });

        // 64 KiB of a module walks in pages that rebuild the whole read
        var hex = new System.Text.StringBuilder();
        int pages = 0;
        int? at = 0;
        while (at is { } offset)
        {
            var (_, page) = await Call("read_dump_memory", new() { ["dump"] = dump, ["address"] = module, ["length"] = 65536, ["offset"] = offset });
            hex.Append(page.GetProperty("code").GetString());
            at = page.TryGetProperty("nextOffset", out var n) ? n.GetInt32() : null;
            pages++;
        }
        output.WriteLine($"read_dump_memory: 64 KiB in {pages} pages");
        Assert.Equal(65536 * 2, hex.Length);
        Assert.InRange(pages, 15, 40);

        var text = string.Concat(Enumerable.Repeat("System.InvalidOperationException: sample-probe\r\n   at FxProbe.Program.Inner()\r\n   at FxProbe.Program.Main(String[] args)\r\n", 60));
        var (_, symbolized) = await Call("symbolize_stack_text", new() { ["text"] = text });
        Assert.True(symbolized.GetProperty("hasMore").GetBoolean());
    }

    [Fact]
    public async Task InspectProcessViewsFitTheirBudgets()
    {
        if (!OperatingSystem.IsWindows()) return;
        var exe = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "findstr.exe");
        using var child = Process.Start(new ProcessStartInfo(exe, "x") { RedirectStandardInput = true, RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true })!;
        try
        {
            foreach (var view in new[] { "summary", "modules", "regions", "threads", "stacks" })
            {
                var (_, r) = await Call("inspect_process", new() { ["process"] = child.Id.ToString(), ["view"] = view });
                Assert.True(r.GetProperty("detached").GetBoolean());
            }
        }
        finally
        {
            child.Kill();
            child.WaitForExit(10_000);
        }
    }

    [Fact]
    public async Task NativeAotViewsUseRowsAndFit()
    {
        foreach (var view in new[] { "summary", "sections", "types", "methods", "strings", "statics" })
        {
            var (_, r) = await Call("get_nativeaot_info", new() { ["image"] = Ilc, ["view"] = view });
            if (view != "summary") Assert.True(r.GetProperty("total").GetInt32() > 0, view);
        }
        var (_, type) = await Call("get_nativeaot_info", new() { ["image"] = Ilc, ["view"] = "type", ["query"] = "System.String" });
        Assert.Contains(type.GetProperty("items").EnumerateArray(), i => i.GetProperty("kind").GetString() == "slot");
    }

    [Fact]
    public async Task CppBindingPagesFit()
    {
        var (text, record) = await Call("generate_cpp_binding", new() { ["type"] = "System.String", ["assembly"] = CoreLib });
        Assert.Contains("struct", text);
        Assert.True(record.TryGetProperty("nextOffset", out _));
    }

    /// <summary>A real Il2CppDumper dump: get_il2cpp_info, find_method_by_address and export_il2cpp_symbols records; apply_il2cpp_names with the binary.</summary>
    [RequiresRealDataFact(RealData.Il2CppStringsDir)]
    public async Task Il2CppRecordsOnARealDump()
    {
        var dir = RealData.Path(RealData.Il2CppStringsDir);
        foreach (var dll in Directory.EnumerateFiles(dir, "*.dll", SearchOption.AllDirectories).Take(400))
            await _client.CallToolAsync("load_assembly", new Dictionary<string, object?> { ["path"] = dll });
        var (_, info) = await Call("get_il2cpp_info", new() { ["symbol"] = "UnityEngine.Object" });
        Assert.NotEmpty(info.GetProperty("members").EnumerateArray());
        var rva = info.GetProperty("members").EnumerateArray().Select(m => m.TryGetProperty("rva", out var v) ? v.GetString() : null).First(v => v != null);
        var (_, lookup) = await Call("find_method_by_address", new() { ["address"] = rva, ["kind"] = "rva" });
        Assert.NotEmpty(lookup.GetProperty("items").EnumerateArray());
        var (_, export) = await Call("export_il2cpp_symbols", new() { ["outputDirectory"] = _dir.File("il2cpp"), ["formats"] = "header" });
        Assert.NotEmpty(export.GetProperty("files").EnumerateArray());
        if (Directory.EnumerateFiles(dir, "GameAssembly.dll", SearchOption.AllDirectories).FirstOrDefault() is { } binary)
        {
            var (_, names) = await Call("apply_il2cpp_names", new() { ["image"] = binary });
            Assert.True(names.GetProperty("functions").GetInt32() > 0);
        }
    }
}
