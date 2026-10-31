using ModelContextProtocol.Client;
using Xunit.Abstractions;
using static Corvus.Tests.ToolRealDataTests;

namespace Corvus.Tests;

/// <summary>
/// A test folder, a copy of jitinterface_x64.dll of the ILCompiler package and
/// logged tool calls.
/// </summary>
public abstract class EngineRealDataTestBase(ITestOutputHelper output) : IDisposable
{
    private protected readonly TempDir _dir = new();
    private protected readonly TestPhases _phases = new(output);

    private protected ITestOutputHelper Output => output;

    public void Dispose() => _dir.Dispose();

    /// <summary>A copy in this test's folder, so the engine never reads the package folder.</summary>
    private protected string Image()
    {
        var copy = _dir.File("jitinterface_x64.dll");
        if (!File.Exists(copy)) File.Copy(RealPackages.File("runtime.win-x64.Microsoft.DotNet.ILCompiler", "10.0.11", "tools", "jitinterface_x64.dll"), copy);
        return copy;
    }

    private protected async Task<string> Log(McpClient c, string tool, Dictionary<string, object?> args)
    {
        var (text, _) = await _phases.Run(tool, () => Call(c, tool, args));
        output.WriteLine($"== {tool}\n{text}");
        return text;
    }
}

/// <summary>
/// IDA on jitinterface_x64.dll of the ILCompiler package through its own
/// server; skipped when absent.
/// </summary>
[Trait("Data", "Real"), Trait("Speed", "Slow")]
public sealed class EngineRealDataTests(ITestOutputHelper output) : EngineRealDataTestBase(output)
{
    [IdaFact]
    public async Task Ida_tools_work_on_a_real_dll()
    {
        var image = Image();
        // The edits are saved into the database, so an own cache keeps the next run from a renamed frame.
        await using var c = await _phases.Run("server start", () => McpProtocolTests.StartServerAsync(_dir.Path, null, ["--ida-scripting"],
            new Dictionary<string, string?> { [Corvus.Native.Providers.AnalysisCache.RootVariable] = _dir.File("cache") }));
        var (_, exports) = await _phases.Run("list_exports", () => Call(c, "list_exports", new() { ["image"] = image }));
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
}

/// <summary>
/// Ghidra on jitinterface_x64.dll of the ILCompiler package through its own
/// server; skipped when absent.
/// </summary>
[Trait("Data", "Real"), Trait("Speed", "Slow")]
public sealed class EngineRealDataGhidraTests(ITestOutputHelper output) : EngineRealDataTestBase(output)
{
    [GhidraFact]
    [Trait(PerfBudget.Trait, PerfBudget.Timing)]
    public async Task Ghidra_tools_work_on_a_real_dll()
    {
        var image = Image();
        await using var c = await _phases.Run("server start", () => McpProtocolTests.StartServerInAsync(_dir.Path, "--ghidra-scripting"));
        var (_, exports) = await _phases.Run("list_exports", () => Call(c, "list_exports", new() { ["image"] = image }));
        var function = exports.GetProperty("items")[0].GetProperty("name").GetString()!;
        Assert.Contains("returned to the caller", await Log(c, "emulate_native", new() { ["image"] = image, ["address"] = function, ["maxInstructions"] = 1000, ["stubs"] = "*=0", ["engine"] = "ghidra" }));
        Assert.Contains("jitinterface_x64.dll", await Log(c, "ghidra_script", new() { ["image"] = image, ["code"] = "println(currentProgram.getName());", ["engine"] = "ghidra" }));
        // The same source again reuses its compiled bundle: compilation is most of a first run.
        var script = new Dictionary<string, object?> { ["image"] = image, ["code"] = "println(\"functions \" + currentProgram.getFunctionManager().getFunctionCount());", ["engine"] = "ghidra" };
        // The worker writes a script's source next to its classes each time it
        // compiles it (ScriptOps.compile), under its own home.
        // Regression for the eece1727 push run, which read the cache folder.
        var key = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes((string)script["code"]!)))[..16];
        var clock = System.Diagnostics.Stopwatch.StartNew();
        await Log(c, "ghidra_script", script);
        var first = clock.Elapsed;
        var source = GhidraScriptSource.Path(key);
        var compiled = File.GetLastWriteTimeUtc(source);
        clock.Restart();
        await Log(c, "ghidra_script", script);
        Assert.True(File.Exists(source), source);
        Assert.Equal(compiled, File.GetLastWriteTimeUtc(source));
        PerfBudget.AtMost("engines/ghidra-script-repeat-share", clock.Elapsed / first, 0.5, "of-first", Output, $"repeat {clock.Elapsed.TotalMilliseconds:0} ms, first {first.TotalMilliseconds:0} ms");
        // Installed scripts: one of Ghidra's, and one from the user folder with arguments.
        await Log(c, "ghidra_script", new() { ["image"] = image, ["name"] = "CountSymbolsScript.java", ["engine"] = "ghidra" });
        var userScripts = Directory.CreateDirectory(Path.Combine(Corvus.Native.Providers.DataFolder.Root, "ghidra_scripts")).FullName;
        File.WriteAllText(Path.Combine(userScripts, "EchoArgs.java"),
            "import ghidra.app.script.GhidraScript;\npublic class EchoArgs extends GhidraScript {\n    @Override\n    public void run() throws Exception { println(\"args \" + String.join(\"|\", getScriptArgs())); }\n}\n");
        Assert.Contains("args a|b c", await Log(c, "ghidra_script", new() { ["image"] = image, ["name"] = "EchoArgs", ["args"] = new[] { "a", "b c" }, ["engine"] = "ghidra" }));
        var python = await c.CallToolAsync("ghidra_script", new Dictionary<string, object?> { ["image"] = image, ["name"] = "Example.py", ["engine"] = "ghidra" });
        // Without a PyGhidra Python the workers run in a plain JVM.
        if (Environment.GetEnvironmentVariable(Corvus.Native.Providers.Ghidra.GhidraOptions.PythonVariable) is not { Length: > 0 })
            Assert.Contains("CORVUS_GHIDRA_PYTHON", string.Concat(python.Content.OfType<ModelContextProtocol.Protocol.TextContentBlock>().Select(b => b.Text)));
        var pcode = await Log(c, "decompile_native", new() { ["image"] = image, ["address"] = function, ["view"] = "pcode", ["engine"] = "ghidra" });
        Assert.Contains("block 0", pcode);
        Assert.Contains("RETURN", pcode);
    }

    /// <summary>With CORVUS_GHIDRA_PYTHON (a Python with PyGhidra) the worker runs under PyGhidra: Python code and installed .py scripts run in it.</summary>
    [RequiresRealDataFact("CORVUS_GHIDRA_DIR", "CORVUS_GHIDRA_PYTHON")]
    public async Task Ghidra_python_scripts_run_under_pyghidra()
    {
        var image = Image();
        await using var c = await _phases.Run("server start", () => McpProtocolTests.StartServerInAsync(_dir.Path, "--ghidra-scripting"));
        var clock = System.Diagnostics.Stopwatch.StartNew();
        var text = await Log(c, "ghidra_script", new()
        {
            ["image"] = image, ["language"] = "python", ["engine"] = "ghidra",
            ["code"] = "fm = currentProgram.getFunctionManager()\nprint('python', currentProgram.getName(), fm.getFunctionCount() > 0)",
        });
        Output.WriteLine($"first python script {clock.ElapsedMilliseconds} ms (worker start and analysis included)");
        Assert.Contains("python jitinterface_x64.dll True", text);
        var userScripts = Directory.CreateDirectory(Path.Combine(Corvus.Native.Providers.DataFolder.Root, "ghidra_scripts")).FullName;
        File.WriteAllText(Path.Combine(userScripts, "echo_args.py"), "print('args ' + '|'.join(getScriptArgs()))\n");
        Assert.Contains("args a|b c", await Log(c, "ghidra_script", new() { ["image"] = image, ["name"] = "echo_args.py", ["args"] = new[] { "a", "b c" }, ["engine"] = "ghidra" }));
        // Java still runs in the same worker.
        Assert.Contains("jitinterface_x64.dll", await Log(c, "ghidra_script", new() { ["image"] = image, ["code"] = "println(currentProgram.getName());", ["engine"] = "ghidra" }));
    }
}

/// <summary>Where a Ghidra worker writes a compiled script's source.</summary>
internal static class GhidraScriptSource
{
    /// <summary>The source of the script with this key under the worker folder (the extension-set folder of the worker root, else the cache folder).</summary>
    internal static string Path(string key)
    {
        var name = $"UserScript_{key}.java";
        var workerRoot = Environment.GetEnvironmentVariable(Corvus.Native.Providers.Ghidra.GhidraOptions.WorkerDirectoryVariable);
        if (workerRoot is not { Length: > 0 })
            return System.IO.Path.Combine(Corvus.Native.Providers.AnalysisCache.DefaultRoot, "ghidra", "home", "scripts", key, name);
        foreach (var set in Directory.Exists(workerRoot) ? Directory.GetDirectories(workerRoot) : [])
            if (System.IO.Path.Combine(set, "home", "scripts", key, name) is var path && File.Exists(path)) return path;
        return System.IO.Path.Combine(workerRoot, "*", "home", "scripts", key, name);
    }
}
