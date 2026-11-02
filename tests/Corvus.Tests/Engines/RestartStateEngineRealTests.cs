using Xunit.Abstractions;
using static Corvus.Tests.ToolRealDataTests;

namespace Corvus.Tests;

/// <summary>A script, a reanalysis and an export are read again from the engine database by a second server process on the same analysis cache.</summary>
[Trait("Data", "Real"), Trait("Speed", "Slow")]
public sealed class RestartStateEngineRealTests(ITestOutputHelper output) : EngineRealDataTestBase(output)
{
    private Dictionary<string, string?> Cache => new() { [Corvus.Native.Providers.AnalysisCache.RootVariable] = _dir.File("cache") };

    [IdaFact]
    public async Task Ida_script_and_reanalysis_effects_survive_a_restart()
    {
        var image = Image();
        string function;
        await using (var a = await McpProtocolTests.StartServerAsync(_dir.Path, null, ["--ida-scripting"], Cache))
        {
            var (_, exports) = await Call(a, "list_exports", new() { ["image"] = image });
            function = exports.GetProperty("items")[0].GetProperty("name").GetString()!;
            await Log(a, "ida_python", new() { ["image"] = image, ["engine"] = "ida", ["persist"] = true,
                ["code"] = $"import idc\nidc.set_name(idc.get_name_ea_simple('{function}'), 'restart_probe')" });
            await Log(a, "reanalyze_native", new() { ["image"] = image, ["engine"] = "ida", ["from"] = function });
            await Log(a, "get_engine_status", new() { ["image"] = image, ["waitSeconds"] = 600 });
        }
        await using var b = await McpProtocolTests.StartServerAsync(_dir.Path, null, ["--ida-scripting"], Cache);
        Assert.Contains("restart_probe", await Log(b, "ida_python", new() { ["image"] = image, ["engine"] = "ida",
            ["code"] = "import idc\nprint(idc.get_name(idc.get_name_ea_simple('restart_probe')))" }));
        Assert.Contains("\"reusedDatabase\":true", (await Call(b, "get_engine_status", new() { ["image"] = image })).Record.GetRawText().Replace(" ", ""));
        var export = _dir.File("restart.i64");
        await Log(b, "export_engine_database", new() { ["image"] = image, ["engine"] = "ida", ["outputPath"] = export });
        Assert.True(new FileInfo(export).Length > 0);
    }

    [GhidraFact]
    public async Task Ghidra_script_and_reanalysis_effects_survive_a_restart()
    {
        var image = Image();
        string function;
        await using (var a = await McpProtocolTests.StartServerAsync(_dir.Path, null, ["--ghidra-scripting"], Cache))
        {
            var (_, functions) = await Call(a, "list_functions", new() { ["image"] = image, ["engine"] = "ghidra", ["limit"] = 1 });
            function = functions.GetProperty("items")[0].GetProperty("address").GetString()!;
            await Log(a, "ghidra_script", new() { ["image"] = image, ["engine"] = "ghidra",
                ["code"] = $"getFunctionAt(toAddr(\"{function}\")).setName(\"restart_probe\", ghidra.program.model.symbol.SourceType.USER_DEFINED);" });
            await Log(a, "reanalyze_native", new() { ["image"] = image, ["engine"] = "ghidra", ["from"] = function });
            await Log(a, "get_engine_status", new() { ["image"] = image, ["waitSeconds"] = 600 });
        }
        await using var b = await McpProtocolTests.StartServerAsync(_dir.Path, null, ["--ghidra-scripting"], Cache);
        Assert.Contains("restart_probe", await Log(b, "ghidra_script", new() { ["image"] = image, ["engine"] = "ghidra",
            ["code"] = $"println(getFunctionAt(toAddr(\"{function}\")).getName());" }));
        Assert.Contains("\"reusedDatabase\":true", (await Call(b, "get_engine_status", new() { ["image"] = image })).Record.GetRawText().Replace(" ", ""));
        var export = _dir.File("restart.gzf");
        await Log(b, "export_engine_database", new() { ["image"] = image, ["engine"] = "ghidra", ["outputPath"] = export });
        Assert.True(new FileInfo(export).Length > 0);
    }
}
