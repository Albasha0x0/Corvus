using Corvus.Core;
using Corvus.Native.Providers.Ghidra;
using Corvus.Services;
using Xunit.Abstractions;
using static Corvus.Tests.ToolRealDataTests;

namespace Corvus.Tests;

/// <summary>A Ghidra archive (.gzf) as an input: its original file loads, Ghidra opens the archive without analysis, a different file is refused.</summary>
public sealed class PackedDatabaseTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    // a private analysis cache: another class's server may hold the shared project of the same DLL
    private Dictionary<string, string?> Cache => new() { [Corvus.Native.Providers.AnalysisCache.RootVariable] = _dir.File("cache") };

    [Fact]
    public void A_file_other_than_the_recorded_one_is_refused()
    {
        var file = _dir.File("app.dll");
        File.WriteAllBytes(file, [1, 2, 3]);
        var e = Assert.Throws<ToolError>(() => PackedDatabaseInput.Verify("app.gzf", new GhidraProvider.ArchiveOriginal("app.dll", new string('0', 64), null, null), file));
        Assert.Equal(ErrorCode.Conflict, e.Code);
        Assert.Contains("load the file the archive was made from", e.Remediation);
    }

    [GhidraFact, Trait("Speed", "Slow")]
    public async Task An_exported_archive_loads_back_and_decompiles_without_analysis()
    {
        var image = _dir.File("jitinterface_x64.dll");
        File.Copy(RealPackages.File("runtime.win-x64.Microsoft.DotNet.ILCompiler", "10.0.11", "tools", "jitinterface_x64.dll"), image);
        var gzf = _dir.File("jit.gzf");
        string function;
        await using (var c = await McpProtocolTests.StartServerAsync(_dir.Path, null, [], Cache))
        {
            await Call(c, "load_assembly", new() { ["path"] = image });
            // an unnamed function: the server has no name of its own there, so the archive's shows
            var (_, functions) = await Call(c, "list_functions", new() { ["image"] = "jitinterface_x64.dll", ["engine"] = "ghidra", ["filter"] = "FUN_", ["limit"] = 1 });
            function = functions.GetProperty("items")[0].GetProperty("address").GetString()!;
            output.WriteLine("rename: " + (await Call(c, "rename_native", new() { ["image"] = "jitinterface_x64.dll", ["address"] = function, ["name"] = "from_the_archive", ["engine"] = "ghidra", ["dryRun"] = false })).Text);
            output.WriteLine((await Call(c, "export_engine_database", new() { ["image"] = "jitinterface_x64.dll", ["outputPath"] = gzf, ["engine"] = "ghidra" })).Text);
        }
        File.Delete(image);
        await using (var c = await McpProtocolTests.StartServerAsync(_dir.Path, null, ["--ghidra-scripting"], Cache))
        {
            var (loaded, _) = await Call(c, "load_assembly", new() { ["path"] = gzf });
            output.WriteLine(loaded);
            Assert.Contains("Ghidra opens the archive", loaded);
            var (code, _) = await Call(c, "decompile_native", new() { ["image"] = "jitinterface_x64.dll", ["address"] = function });
            output.WriteLine(code);
            Assert.Contains("(ghidra)", code);
            // the name lives in the archive's database, not only in the server's notes
            var (name, _) = await Call(c, "ghidra_script", new() { ["image"] = "jitinterface_x64.dll", ["code"] = $"println(getFunctionAt(toAddr(\"{function}\")).getName());" });
            output.WriteLine(name);
            Assert.Contains("from_the_archive", name);
            var (status, s) = await Call(c, "get_engine_status", new() { ["image"] = "jitinterface_x64.dll" });
            output.WriteLine(status);
            Assert.Contains("\"reusedDatabase\":true", s.GetRawText().Replace(" ", ""));
        }
    }

    [GhidraFact, Trait("Speed", "Slow")]
    public async Task A_users_Ghidra_project_opens_from_a_copy_and_stays_unchanged()
    {
        var image = _dir.File("jitinterface_x64.dll");
        File.Copy(RealPackages.File("runtime.win-x64.Microsoft.DotNet.ILCompiler", "10.0.11", "tools", "jitinterface_x64.dll"), image);
        await using (var c = await McpProtocolTests.StartServerAsync(_dir.Path, null, [], Cache))
        {
            await Call(c, "load_assembly", new() { ["path"] = image });
            await Call(c, "list_functions", new() { ["image"] = "jitinterface_x64.dll", ["engine"] = "ghidra", ["limit"] = 1 });
        }
        // a project made by Ghidra stands in for the user's: copied out of the first server's cache, with a lock file of an open session
        var made = Directory.GetFiles(_dir.File("cache"), GhidraSession.ProjectName + ".gpr", SearchOption.AllDirectories).Single();
        var user = Directory.CreateDirectory(_dir.File("user")).FullName;
        File.Copy(made, Path.Combine(user, "corvus.gpr"));
        CopyTree(Path.ChangeExtension(made, ".rep"), Path.Combine(user, "corvus.rep"));
        File.WriteAllText(Path.Combine(user, "corvus.lock"), "");
        File.Delete(image);
        var before = Snapshot(user);
        // a fresh cache: the database can only come from the project
        var fresh = new Dictionary<string, string?> { [Corvus.Native.Providers.AnalysisCache.RootVariable] = _dir.File("cache2") };
        await using (var c = await McpProtocolTests.StartServerAsync(_dir.Path, null, [], fresh))
        {
            var missing = await c.CallToolAsync("load_assembly", new Dictionary<string, object?> { ["path"] = Path.Combine(user, "corvus.gpr"), ["program"] = "/other.dll" });
            Assert.True(missing.IsError);
            Assert.Contains("/jitinterface_x64.dll", Text(missing));
            var (loaded, _) = await Call(c, "load_assembly", new() { ["path"] = Path.Combine(user, "corvus.gpr") });
            output.WriteLine(loaded);
            Assert.Contains("corvus.gpr:/jitinterface_x64.dll, read from a copy", loaded);
            var (code, _) = await Call(c, "decompile_native", new() { ["image"] = "jitinterface_x64.dll", ["address"] = "AllocException" });
            Assert.Contains("(ghidra)", code);
            var (_, s) = await Call(c, "get_engine_status", new() { ["image"] = "jitinterface_x64.dll" });
            Assert.Contains("\"reusedDatabase\":true", s.GetRawText().Replace(" ", ""));
        }
        Assert.Equal(before, Snapshot(user));
    }

    private static void CopyTree(string from, string to)
    {
        foreach (var f in Directory.GetFiles(from, "*", SearchOption.AllDirectories))
        {
            var target = Path.Combine(to, Path.GetRelativePath(from, f));
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            File.Copy(f, target);
        }
    }

    /// <summary>Every file under <paramref name="dir"/> with its size, write time and SHA-256.</summary>
    private static string Snapshot(string dir) => string.Join("\n", Directory.GetFiles(dir, "*", SearchOption.AllDirectories).Order(StringComparer.Ordinal)
        .Select(f => $"{Path.GetRelativePath(dir, f)} {new FileInfo(f).Length} {File.GetLastWriteTimeUtc(f).Ticks} {Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(f)))}"));
}
