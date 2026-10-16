using System.Text.Json.Nodes;
using Corvus.Core;
using Corvus.Mcp;

namespace Corvus.Tests;

/// <summary>The per-tool contract table: complete, consistent with the effects and the catalog, and the profiles of D6, D12 and D14.</summary>
public class ToolContractTests
{
    private static readonly string[] AllTools = Toolsets.Families.SelectMany(f => f.Tools).ToArray();

    /// <summary>D7: these take dryRun and default it to true (the other three that take it already do).</summary>
    private static readonly string[] D7 =
    [
        "rename_symbol", "rename_namespace", "stub_method", "patch_method_csharp", "patch_method_il", "add_members_csharp", "add_types_csharp",
        "simplify_methods", "apply_edits", "migrate_native_names", "rename_native", "comment_native", "patch_bytes", "patch_asm",
    ];

    [Fact]
    public void EveryToolHasOutputAndLatencyClass()
    {
        Assert.Equal(AllTools.Order(StringComparer.Ordinal), ToolContract.Table.Keys.Order(StringComparer.Ordinal));
        Assert.Equal(162, ToolContract.Table.Count);
        foreach (var tool in AllTools)
        {
            var c = ToolContract.Of(tool);
            Assert.Equal(tool, c.Tool);
            Assert.True(Enum.IsDefined(c.Output) && c.Output != OutputClass.Error, $"{tool}: output class");
            Assert.True(Enum.IsDefined(c.Latency), $"{tool}: latency class");
        }
    }

    [Fact]
    public void RowsAgreeWithTheEffects()
    {
        var problems = new List<string>();
        foreach (var c in ToolContract.Table.Values)
        {
            var e = c.Effects;
            if (e.ReadOnly != (c.DryRun == DryRunPolicy.NotApplicable)) problems.Add($"{c.Tool}: read-only {e.ReadOnly} but dryRun policy {c.DryRun}");
            if ((c.DryRun == DryRunPolicy.None) != !string.IsNullOrWhiteSpace(c.DryRunReason)) problems.Add($"{c.Tool}: a reason exactly when it changes something without dryRun");
            if ((c.Output == OutputClass.List) != (c.SortKey != null)) problems.Add($"{c.Tool}: a sort key exactly for lists");
        }
        foreach (var tool in D7.Concat(["migrate_native_patches", "update_to_new_build", "load_session"]))
            if (ToolContract.Of(tool).DryRun != DryRunPolicy.DefaultTrue) problems.Add($"{tool}: D7 dryRun default true");
        foreach (var tool in new[] { "revert_edits", "load_pdb", "apply_il2cpp_names", "install_android_package", "uninstall_android_package", "export_il2cpp_symbols", "get_resource" }
                     .Concat(Toolsets.Families.Single(f => f.Name == "engine").Tools.Where(t => !ToolEffects.Of(t).ReadOnly)))
            if (ToolContract.Of(tool).DryRun != DryRunPolicy.None) problems.Add($"{tool}: no dryRun, with a recorded reason (N12-N14)");
        Assert.True(problems.Count == 0, string.Join("\n", problems));
    }

    [Fact]
    public void DryRunPolicyMatchesTheParameters()
    {
        var schemas = Catalog.OfThisBuild().Tools.ToDictionary(t => (string)t["name"]!, t => t["inputSchema"]!["properties"]!.AsObject());
        var problems = new List<string>();
        foreach (var c in ToolContract.Table.Values)
        {
            bool takes = schemas[c.Tool].ContainsKey("dryRun");
            if (takes != (c.DryRun == DryRunPolicy.DefaultTrue)) problems.Add($"{c.Tool}: takes dryRun {takes}, policy {c.DryRun}");
        }
        Assert.True(problems.Count == 0, string.Join("\n", problems));
    }

    [Fact]
    public void ProfilesHaveTheirSizes()
    {
        var lean = ToolContract.Table.Values.Where(c => c.Lean).Select(c => c.Tool).ToList();
        var core = ToolContract.Table.Values.Where(c => c.Core).Select(c => c.Tool).ToList();
        Assert.Equal(40, lean.Count);
        Assert.Equal(100, core.Count);
        // D12: builds and notes leave core; D14: merged tools; get_engine_status moves to the engine family.
        Assert.DoesNotContain(core, t => Toolsets.FamilyOf(t) is "builds" or "notes" or "engine" or "android" or "dumps" or "live");
        Assert.DoesNotContain(core, t => t is "decompile_type" or "decompile_assembly_attributes" or "find_overrides" or "get_engine_status");
        Assert.Contains("load_assembly", lean);
        Assert.Contains("decompile_native", lean);
    }

    [Fact]
    public void BudgetsAreTheD1Defaults()
    {
        Assert.Equal([6_000, 8_000, 6_000, 4_000, 3_000, 1_000],
            new[] { OutputClass.List, OutputClass.Code, OutputClass.Bytes, OutputClass.Report, OutputClass.Edit, OutputClass.Error }.Select(OutputClasses.Budget));
        Assert.All(Enum.GetValues<OutputClass>(), c => Assert.True(OutputClasses.Budget(c) <= 9_500));
        var unknown = ToolContract.Of("no_such_tool");
        Assert.Equal((OutputClass.Report, LatencyClass.Long), (unknown.Output, unknown.Latency));
    }
}
