using Corvus.Native.Code;

namespace Corvus.Native.Calls;

/// <summary>Names the open indirect calls of a call-site list from the index's slot resolution.</summary>
internal static class SlotCallNames
{
    /// <summary>The site named after its slot target when the analysis left it open; the site itself otherwise.</summary>
    public static CallSiteInfo Resolve(NativeCodeIndex index, CallSiteInfo site, CancellationToken ct = default) =>
        index.SlotTargets == null || !IsOpen(site) ? site : Apply(site, index.SlotTargets(site.Caller, ct));

    /// <summary>The sites with each open indirect call named after its slot target; the list itself when none is.</summary>
    public static IReadOnlyList<CallSiteInfo> Resolve(NativeCodeIndex index, IReadOnlyList<CallSiteInfo> sites, CancellationToken ct = default)
    {
        if (index.SlotTargets == null || !sites.Any(IsOpen)) return sites;
        var targets = index.SlotTargets(sites.First(IsOpen).Caller, ct);
        return targets.Count == 0 ? sites : [.. sites.Select(s => Apply(s, targets))];
    }

    private static bool IsOpen(CallSiteInfo site) => site.Kind == CalleeKind.Indirect && site.Target == null;

    private static CallSiteInfo Apply(CallSiteInfo site, IReadOnlyDictionary<uint, string> targets) =>
        IsOpen(site) && targets.TryGetValue(site.Rva, out var name) ? site with { Callee = name, Kind = CalleeKind.VirtualExact } : site;
}
