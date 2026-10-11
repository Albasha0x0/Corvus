using Corvus.Native;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Ghidra;
using Corvus.Native.Providers.Ida;

namespace Corvus.Tests;

/// <summary>Engine databases saved before the rename (old stamp names, Ghidra project name) reopen without a new analysis.</summary>
[Trait("Speed", "Slow")]
public sealed class EngineRenameMigrationTests
{
    private static readonly NativeOpenOptions Offline = new() { Symbols = SymbolMode.Off };

    [IdaFact]
    public async Task An_IDA_database_with_the_old_node_names_reopens_with_them_renamed()
    {
        using var dir = new TempDir();
        using var provider = new IdaProvider(new IdaProviderOptions { CacheRoot = dir.Path });
        await using (var s = (IdaSession)await provider.OpenAsync(NativeIdaProviderTests.System64, null, Offline))
        {
            // As a database saved before the rename holds them.
            var made = await s.RunScriptAsync("""
                import ida_netnode
                for new, old in (("$ corvus stamps", "$ netdecompilermcp stamps"), ("$ corvus user types", "$ netdecompilermcp user types")):
                    n = ida_netnode.netnode(new, 0, True)
                    n.rename(old)
                ida_netnode.netnode("$ netdecompilermcp stamps", 0, False) != ida_netnode.BADNODE
                """);
            Assert.True(made.Error == null, made.Error);
            Assert.Equal("True", made.Result);
            await s.SaveAsync();
        }
        // The input stamp lives in the stamps node: without the rename the database would not be reused.
        await using (var s = (IdaSession)await provider.OpenAsync(NativeIdaProviderTests.System64, null, Offline))
        {
            Assert.True(s.ReusedDatabase);
            var nodes = await s.RunScriptAsync("""
                import ida_netnode
                tuple(ida_netnode.netnode(name, 0, False) != ida_netnode.BADNODE
                      for name in ("$ corvus stamps", "$ corvus user types", "$ netdecompilermcp stamps", "$ netdecompilermcp user types"))
                """);
            Assert.True(nodes.Error == null, nodes.Error);
            Assert.Equal("(True, True, False, False)", nodes.Result);
        }
    }

    [GhidraFact]
    public async Task A_Ghidra_project_with_the_old_names_reopens_analyzed_with_its_stamps_and_types()
    {
        using var dir = new TempDir();
        var sample = dir.File("input");
        Directory.CreateDirectory(sample);
        sample = Path.Combine(sample, Path.GetFileName(NativeIdaProviderTests.System64));
        File.Copy(NativeIdaProviderTests.System64, sample);
        using var provider = new GhidraProvider(new GhidraProviderOptions { CacheRoot = dir.File("cache") });
        await using (var s = (GhidraSession)await provider.OpenAsync(sample, null, Offline))
        {
            Assert.Equal("complete", (await s.GetEngineInfoAsync()).Analysis);
            // As a project saved before the rename holds them.
            var made = await s.RunJavaAsync("""
                var now = currentProgram.getOptions("Corvus");
                var old = currentProgram.getOptions("NetDecompilerMcp");
                for (String n : now.getOptionNames()) { old.setString("ndm_" + n, now.getString(n, null)); now.removeOption(n); }
                currentProgram.getDataTypeManager().createCategory(new ghidra.program.model.data.CategoryPath("/ndm/classes"));
                println("moved " + old.getOptionNames().size());
                """, 120);
            Assert.True(made.Error == null, made.Error);
            Assert.Contains("moved ", made.Stdout);
            Assert.DoesNotContain("moved 0", made.Stdout);
        }
        var gpr = Assert.Single(Directory.GetFiles(dir.File("cache"), GhidraSession.ProjectName + ".gpr", SearchOption.AllDirectories));
        var project = Path.GetDirectoryName(gpr)!;
        File.Move(gpr, Path.Combine(project, "ndm.gpr"));
        Directory.Move(Path.Combine(project, GhidraSession.ProjectName + ".rep"), Path.Combine(project, "ndm.rep"));

        await using (var s = (GhidraSession)await provider.OpenAsync(sample, null, Offline))
        {
            Assert.True(((INativeDecompilerSession)s).ReusedDatabase);
            Assert.Equal("complete", (await s.GetEngineInfoAsync()).Analysis);
            var state = await s.RunJavaAsync("""
                var types = currentProgram.getDataTypeManager();
                println("analysis=" + currentProgram.getOptions("Corvus").getString("analysis", null));
                println("old=" + currentProgram.getOptions("NetDecompilerMcp").getOptionNames().size());
                println("corvus=" + (types.getCategory(new ghidra.program.model.data.CategoryPath("/corvus/classes")) != null));
                println("ndm=" + (types.getCategory(new ghidra.program.model.data.CategoryPath("/ndm")) != null));
                """, 60);
            Assert.True(state.Error == null, state.Error);
            Assert.Contains("analysis=complete", state.Stdout);
            Assert.Contains("old=0", state.Stdout);
            Assert.Contains("corvus=true", state.Stdout);
            Assert.Contains("ndm=false", state.Stdout);
        }
        Assert.True(File.Exists(Path.Combine(project, GhidraSession.ProjectName + ".gpr")));
        Assert.False(File.Exists(Path.Combine(project, "ndm.gpr")));
    }
}
