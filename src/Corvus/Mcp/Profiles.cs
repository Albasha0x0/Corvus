using Corvus.Core;

namespace Corvus.Mcp;

/// <summary>Which tools a set of <see cref="Toolsets"/> names registers: whole families, plus the core and lean members of the contract table.</summary>
public static class Profiles
{
    /// <summary>Whether a server started with <paramref name="enabled"/> registers <paramref name="tool"/>; a tool no family lists is kept.</summary>
    public static bool Registers(IReadOnlySet<string> enabled, string tool)
    {
        if (Toolsets.FamilyOf(tool) is not { } family || enabled.Contains(family)) return true;
        var contract = ToolContract.Of(tool);
        return contract.Core && enabled.Contains(Toolsets.CoreName) || contract.Lean && enabled.Contains(Toolsets.Lean);
    }

    /// <summary>Whether a server with these toolsets and whitelist (null: none) registers <paramref name="tool"/>; the session tools stay.</summary>
    public static bool Registers(IReadOnlySet<string> enabled, IReadOnlySet<string>? allowed, string tool) =>
        Registers(enabled, tool) && (allowed == null || allowed.Contains(tool) || Toolsets.FamilyOf(tool) == Toolsets.Session);

    /// <summary>The tools <paramref name="enabled"/> registers, in family order.</summary>
    public static IEnumerable<string> ToolsOf(IReadOnlySet<string> enabled) =>
        Toolsets.Families.SelectMany(f => f.Tools).Where(t => Registers(enabled, t));

    /// <summary>Whether any tool of <paramref name="family"/> is in the core profile.</summary>
    public static bool InCore(Toolsets.Family family) => family.Tools.Any(t => ToolContract.Of(t).Core);
}
