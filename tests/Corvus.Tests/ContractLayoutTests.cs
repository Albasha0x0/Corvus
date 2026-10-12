using Corvus.Core;
using Corvus.Mcp;

namespace Corvus.Tests;

/// <summary>Per-tool tables are split by tool family: each family's file lists only that family's tools.</summary>
public class ContractLayoutTests
{
    private static void AssertFamilies<T>(string table, IEnumerable<KeyValuePair<string, T>> byFamily, Func<T, IEnumerable<string>> tools)
    {
        var problems = new List<string>();
        foreach (var (family, rows) in byFamily)
        {
            if (!Toolsets.All.Contains(family)) problems.Add($"{table}: '{family}' is not a family");
            foreach (var tool in tools(rows).Where(t => Toolsets.FamilyOf(t) != family))
                problems.Add($"{table}: {tool} is listed under {family} but belongs to {Toolsets.FamilyOf(tool) ?? "no family"}");
        }
        problems.AddRange(Toolsets.All.Except(byFamily.Select(f => f.Key)).Select(f => $"{table}: no rows for family {f}"));
        Assert.True(problems.Count == 0, string.Join("\n", problems));
    }

    [Fact]
    public void EachFamilyFileListsOnlyItsTools()
    {
        AssertFamilies("ToolEffects", ToolEffects.ByFamily, rows => rows.Keys);
        AssertFamilies("ParameterDomains", ParameterDomains.ByFamily, rows => rows.Keys);
        AssertFamilies("ToolContract", ToolContract.ByFamily, rows => rows.Keys);
        AssertFamilies("ContractSweep.FileWriters", ContractSweep.FileWritersByFamily, rows => rows.Keys);
        Assert.Equal(Toolsets.Families.Sum(f => f.Tools.Length), ToolEffects.Table.Count);
    }
}
