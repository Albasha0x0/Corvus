using Corvus.Native;
using Corvus.Native.Code;

namespace Corvus.Services;

/// <summary>
/// Finds the runtime helpers of an AOT binary: the internal function behind an
/// exported runtime API, the metadata initializer that managed methods call
/// first, and the shared null-reference throw.
/// </summary>
public static class AotRuntimeHelpers
{
    /// <summary>Fewest named functions that must call a function for it to be a shared helper.</summary>
    private const int MinCallers = 3;

    /// <summary>
    /// A helper found at <paramref name="Rva"/>: the name to apply and the
    /// evidence, which is the text applied as its comment.
    /// </summary>
    public sealed record Helper(uint Rva, string Name, string Evidence);

    // Export names are literals matched in the input. Source-derived from the
    // exported runtime API; ranges of runtime versions are not tested.
    private static readonly (string Export, string Name, string Role)[] Exported =
    [
        ("il2cpp_object_new", "Runtime_ObjectNew", "object allocation"),
        ("il2cpp_runtime_class_init", "Runtime_ClassInit", "class init, runs the static constructor once"),
        ("il2cpp_runtime_object_init", "Runtime_ObjectInit", "constructor run"),
        ("il2cpp_raise_exception", "Runtime_RaiseException", "exception throw"),
    ];

    private const string RaiseExport = "il2cpp_raise_exception";

    /// <summary>
    /// Helpers found through <paramref name="native"/>'s exports and call
    /// shapes, ordered by RVA; empty when none match. Addresses in
    /// <paramref name="taken"/> are skipped. An export wrapper that makes
    /// zero or several direct calls names nothing.
    /// </summary>
    public static IReadOnlyList<Helper> Find(INativeImage native, NativeCodeIndex index, IReadOnlySet<uint> taken, CancellationToken ct = default)
    {
        var found = new Dictionary<uint, Helper>();
        var exports = native.Exports.Where(e => e.Name != null && e.ForwardedTo == null).ToDictionary(e => e.Name!, e => e.Rva, StringComparer.Ordinal);
        var exportRvas = exports.Values.ToHashSet();
        var raiseTargets = new List<uint>();

        foreach (var (export, name, role) in Exported)
        {
            ct.ThrowIfCancellationRequested();
            if (!exports.TryGetValue(export, out var rva) || index.FunctionByStart(rva) is not { } wrapper) continue;
            if (export == RaiseExport) raiseTargets.Add(rva);
            // An exported entry that only forwards to one internal function names that function.
            var targets = index.Callees(wrapper, CallEdgeFilter.Direct).Where(c => c.Function != null).Select(c => c.Function!.Start).Distinct().ToList();
            if (targets.Count != 1 || targets[0] == rva || exportRvas.Contains(targets[0]) || taken.Contains(targets[0])) continue;
            if (export == RaiseExport) raiseTargets.Add(targets[0]);
            // Two exports forwarding to one function keep the first table entry.
            found.TryAdd(targets[0], new Helper(targets[0], name, $"{role}; behind export {export}"));
        }

        var skip = taken.Concat(exportRvas).Concat(found.Keys).ToHashSet();
        if (Initializer(index, taken, skip, ct) is { } init)
            found.TryAdd(init.Rva, init);
        skip.UnionWith(found.Keys);
        if (NullThrower(index, taken, raiseTargets, skip, ct) is { } thrower)
            found.TryAdd(thrower.Rva, thrower);
        return [.. found.Values.OrderBy(h => h.Rva)];
    }

    /// <summary>
    /// The function that most named functions call first, when at least half
    /// of them do and at least three: the lazy metadata initializer.
    /// </summary>
    private static Helper? Initializer(NativeCodeIndex index, IReadOnlySet<uint> named, IReadOnlySet<uint> skip, CancellationToken ct)
    {
        var first = new Dictionary<uint, int>();
        int callers = 0;
        foreach (var start in named)
        {
            ct.ThrowIfCancellationRequested();
            if (index.FunctionByStart(start) is not { } f) continue;
            // The lowest call site address is the first call the method makes.
            var call = index.Callees(f, CallEdgeFilter.Direct).Where(c => c.Kind == XrefKind.Call).OrderBy(c => c.From).FirstOrDefault();
            if (call == null) continue;
            callers++;
            if (call.Function == null) continue;
            first[call.Function.Start] = first.GetValueOrDefault(call.Function.Start) + 1;
        }
        var best = first.Where(p => !named.Contains(p.Key) && !skip.Contains(p.Key)).OrderByDescending(p => p.Value).ThenBy(p => p.Key).FirstOrDefault();
        if (best.Value < MinCallers || best.Value * 2 < callers) return null;
        return new Helper(best.Key, "Runtime_InitMetadata", $"metadata lazy init; first call of {best.Value} of {callers} named functions");
    }

    /// <summary>
    /// The function that only calls the exception raise and that at least
    /// three named functions call: the shared null-reference throw.
    /// </summary>
    private static Helper? NullThrower(NativeCodeIndex index, IReadOnlySet<uint> named, IReadOnlyList<uint> raiseTargets, IReadOnlySet<uint> skip, CancellationToken ct)
    {
        var candidates = new Dictionary<uint, NativeFunction>();
        foreach (var target in raiseTargets.Distinct())
        {
            ct.ThrowIfCancellationRequested();
            if (index.FunctionByStart(target) is not { } raise) continue;
            foreach (var site in index.Callers(raise, CallEdgeFilter.Direct))
                if (site.Caller is { } c && !skip.Contains(c.Start)) candidates[c.Start] = c;
        }
        (uint Rva, int Count) best = default;
        foreach (var c in candidates.Values)
        {
            ct.ThrowIfCancellationRequested();
            var callees = index.Callees(c, CallEdgeFilter.Direct).Select(x => x.Function?.Start).Distinct().ToList();
            if (callees.Count != 1 || callees[0] is not { } only || !raiseTargets.Contains(only)) continue;
            int count = index.Callers(c, CallEdgeFilter.Direct).Where(x => x.Caller != null && named.Contains(x.Caller.Start)).Select(x => x.Caller!.Start).Distinct().Count();
            if (count > best.Count || (count == best.Count && count > 0 && c.Start < best.Rva)) best = (c.Start, count);
        }
        if (best.Count < MinCallers) return null;
        return new Helper(best.Rva, "Runtime_ThrowNullReference", $"null-reference throw; only raises the exception, called by {best.Count} named functions");
    }
}
