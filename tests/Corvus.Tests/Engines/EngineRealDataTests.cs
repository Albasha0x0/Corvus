using ModelContextProtocol.Client;
using Xunit.Abstractions;
using static Corvus.Tests.ToolRealDataTests;

namespace Corvus.Tests;

/// <summary>
/// S12.3 real data for the engine tools: IDA and Ghidra on a small production DLL of the ILCompiler package
/// (jitinterface_x64.dll), each through a server of its own; skipped when the engine is absent.
/// </summary>
[Trait("Data", "Real"), Trait("Speed", "Slow")]
public sealed class EngineRealDataTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    /// <summary>A copy in this test's folder, so the engine's database lands beside it and never in the package folder.</summary>
    private string Image()
    {
        var copy = _dir.File("jitinterface_x64.dll");
        if (!File.Exists(copy)) File.Copy(RealPackages.File("runtime.win-x64.Microsoft.DotNet.ILCompiler", "10.0.11", "tools", "jitinterface_x64.dll"), copy);
        return copy;
    }

    private async Task<string> Log(McpClient c, string tool, Dictionary<string, object?> args)
    {
        var (text, _) = await Call(c, tool, args);
        output.WriteLine($"== {tool}\n{text}");
        return text;
    }

    [IdaFact]
    public async Task Ida_tools_work_on_a_real_dll()
    {
        var image = Image();
        await using var c = await McpProtocolTests.StartServerInAsync(_dir.Path, "--ida-scripting");
        var (_, exports) = await Call(c, "list_exports", new() { ["image"] = image });
        var function = exports.GetProperty("items")[0].GetProperty("name").GetString()!;
        Dictionary<string, object?> On(params (string Key, object? Value)[] more) =>
            new[] { ("image", (object?)image), ("engine", "ida") }.Concat(more).ToDictionary(p => p.Item1, p => p.Item2);

        Assert.Contains("arg_0", await Log(c, "get_native_frame", On(("function", function))));
        Assert.Contains("IDA", await Log(c, "get_engine_status", new() { ["image"] = image }));
        Assert.Contains("types", await Log(c, "list_native_types", On(("limit", 5))));
        Assert.Contains("corvus_probe", await Log(c, "declare_native_types", On(("declarations", "struct corvus_probe { int count; char *name; };"))));
        Assert.Contains("void *p", await Log(c, "set_native_type", On(("address", function), ("type", "int __fastcall f(void *p)"))));
        Assert.Contains("context", await Log(c, "set_native_local", On(("function", function), ("local", "p"), ("newName", "context"))));
        await Log(c, "set_native_operand", On(("address", function), ("operand", 0), ("display", "hex")));
        await Log(c, "define_native", On(("address", function), ("kind", "code")));
        await Log(c, "search_decompiled", On(("pattern", "return"), ("maxFunctions", 20), ("limit", 3)));
        await Log(c, "reanalyze_native", On(("from", function)));
        Assert.Contains(function, await Log(c, "ida_python", On(("code", "import idc\nprint(idc.get_func_name(idc.get_name_ea_simple('" + function + "')))"))));
        await Log(c, "export_engine_database", On(("outputPath", _dir.File("jit.i64"))));
        await Log(c, "set_native_stack_var", On(("function", function), ("variable", "arg_0"), ("newName", "saved_rbx")));
    }

    [GhidraFact]
    public async Task Ghidra_tools_work_on_a_real_dll()
    {
        var image = Image();
        await using var c = await McpProtocolTests.StartServerInAsync(_dir.Path, "--ghidra-scripting");
        var (_, exports) = await Call(c, "list_exports", new() { ["image"] = image });
        var function = exports.GetProperty("items")[0].GetProperty("name").GetString()!;
        Assert.Contains("returned to the caller", await Log(c, "emulate_native", new() { ["image"] = image, ["address"] = function, ["maxInstructions"] = 1000, ["stubs"] = "*=0", ["engine"] = "ghidra" }));
        Assert.Contains("jitinterface_x64.dll", await Log(c, "ghidra_script", new() { ["image"] = image, ["code"] = "println(currentProgram.getName());", ["engine"] = "ghidra" }));
        // the same source again reuses its compiled bundle: compilation is most of a first run
        var script = new Dictionary<string, object?> { ["image"] = image, ["code"] = "println(\"functions \" + currentProgram.getFunctionManager().getFunctionCount());", ["engine"] = "ghidra" };
        var clock = System.Diagnostics.Stopwatch.StartNew();
        await Log(c, "ghidra_script", script);
        var first = clock.Elapsed;
        clock.Restart();
        await Log(c, "ghidra_script", script);
        output.WriteLine($"script first {first.TotalMilliseconds:0} ms, repeat {clock.Elapsed.TotalMilliseconds:0} ms");
        Assert.True(clock.Elapsed < first / 2, $"repeat {clock.Elapsed} not under half of the first {first}");
        // installed scripts: one of Ghidra's, and one from the user folder with arguments
        await Log(c, "ghidra_script", new() { ["image"] = image, ["name"] = "CountSymbolsScript.java", ["engine"] = "ghidra" });
        var userScripts = Directory.CreateDirectory(Path.Combine(Corvus.Native.Providers.DataFolder.Root, "ghidra_scripts")).FullName;
        File.WriteAllText(Path.Combine(userScripts, "EchoArgs.java"),
            "import ghidra.app.script.GhidraScript;\npublic class EchoArgs extends GhidraScript {\n    @Override\n    public void run() throws Exception { println(\"args \" + String.join(\"|\", getScriptArgs())); }\n}\n");
        Assert.Contains("args a|b c", await Log(c, "ghidra_script", new() { ["image"] = image, ["name"] = "EchoArgs", ["args"] = new[] { "a", "b c" }, ["engine"] = "ghidra" }));
        var python = await c.CallToolAsync("ghidra_script", new Dictionary<string, object?> { ["image"] = image, ["name"] = "Example.py", ["engine"] = "ghidra" });
        Assert.Contains("unsupported", string.Concat(python.Content.OfType<ModelContextProtocol.Protocol.TextContentBlock>().Select(b => b.Text)));
        var pcode = await Log(c, "decompile_native", new() { ["image"] = image, ["address"] = function, ["view"] = "pcode", ["engine"] = "ghidra" });
        Assert.Contains("block 0", pcode);
        Assert.Contains("RETURN", pcode);
    }
}
