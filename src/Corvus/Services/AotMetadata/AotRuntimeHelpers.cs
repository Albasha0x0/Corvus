using Iced.Intel;
using Corvus.Native;
using Corvus.Native.Code;

namespace Corvus.Services;

/// <summary>
/// Finds the runtime helpers of an AOT binary: the internal function behind an
/// exported runtime API, the metadata initializer that managed methods call
/// first, the shared null-reference throw and the class setup called before a
/// virtual call.
/// </summary>
public static class AotRuntimeHelpers
{
    /// <summary>Version of the helper rules; a layer saved under an earlier one lacks the helpers added since.</summary>
    public const int Rules = 2;

    /// <summary>Fewest named functions that must call a function for it to be a shared helper.</summary>
    private const int MinCallers = 3;

    /// <summary>Largest code size, in bytes, of a throw stub or a throw wrapper.</summary>
    private const uint StubSize = 0x40;

    /// <summary>Most callers decoded to check a candidate's call sites.</summary>
    private const int MaxSampledCallers = 64;

    /// <summary>Most named functions decoded to find the class setup.</summary>
    private const int MaxScanned = 20000;

    /// <summary>Instructions between the steps of a call-site shape.</summary>
    private const int Window = 8;

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
    /// zero or several direct calls names nothing. Class init and the
    /// constructor run are named from exports only; they have no call-shape
    /// match. <paramref name="note"/> receives a line when a scan bound
    /// leaves a helper unknown.
    /// </summary>
    public static IReadOnlyList<Helper> Find(INativeImage native, NativeCodeIndex index, IReadOnlySet<uint> taken, CancellationToken ct = default, Action<string>? note = null)
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
        if (NullThrower(native, index, taken, raiseTargets, skip, ct) is { } thrower)
            found.TryAdd(thrower.Rva, thrower);
        skip.UnionWith(found.Keys);
        if (ClassSetup(native, index, taken, skip, note, ct) is { } setup)
            found.TryAdd(setup.Rva, setup);
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
            var call = index.Callees(f, CallEdgeFilter.Direct).Where(c => c.Kind is XrefKind.Call or XrefKind.ImportCall).OrderBy(c => c.From).FirstOrDefault();
            if (call == null) continue;
            callers++;
            // An import call or an unresolved target counts as a caller only,
            // so it lowers the share.
            if (call.Kind != XrefKind.Call || call.Function == null) continue;
            first[call.Function.Start] = first.GetValueOrDefault(call.Function.Start) + 1;
        }
        var best = first.Where(p => !named.Contains(p.Key) && !skip.Contains(p.Key)).OrderByDescending(p => p.Value).ThenBy(p => p.Key).FirstOrDefault();
        if (best.Value < MinCallers || best.Value * 2 < callers) return null;
        return new Helper(best.Key, "Runtime_InitMetadata", $"metadata lazy init; first call of {best.Value} of {callers} named functions");
    }

    /// <summary>
    /// The one-call function that raises the null-reference exception and that
    /// at least three named functions call. It calls the exception raise, or a
    /// no-return wrapper that builds and raises the exception; a wrapper
    /// needs at least three callers that reach it through a null check.
    /// </summary>
    private static Helper? NullThrower(INativeImage image, NativeCodeIndex index, IReadOnlySet<uint> named, IReadOnlyList<uint> raiseTargets, IReadOnlySet<uint> skip, CancellationToken ct)
    {
        var raises = raiseTargets.ToHashSet();
        var candidates = new Dictionary<uint, NativeFunction>();
        foreach (var target in raises)
        {
            ct.ThrowIfCancellationRequested();
            if (index.FunctionByStart(target) is not { } raise) continue;
            foreach (var site in index.Callers(raise, CallEdgeFilter.Direct))
                if (site.Caller is { } c && !skip.Contains(c.Start)) candidates[c.Start] = c;
        }
        bool x64 = image.Arch == NativeArch.X64;
        if (x64)
            foreach (var c in index.Functions)
                if (c.Size is > 0 and <= StubSize && !skip.Contains(c.Start)
                    && index.Callers(c, CallEdgeFilter.Direct).Count(x => x.Caller != null && named.Contains(x.Caller.Start)) >= MinCallers)
                    candidates.TryAdd(c.Start, c);

        var wrappers = new Dictionary<uint, bool>();
        (uint Rva, int Count) best = default;
        var wrapped = new List<(uint Rva, int Count, int Checked)>();
        foreach (var c in candidates.Values)
        {
            ct.ThrowIfCancellationRequested();
            var callees = index.Callees(c, CallEdgeFilter.Direct).Select(x => x.Function?.Start).Distinct().ToList();
            if (callees.Count != 1 || callees[0] is not { } only) continue;
            bool viaWrapper = !raises.Contains(only);
            if (viaWrapper && !(x64 && IsRaiseWrapper(image, index, only, wrappers, ct))) continue;
            var callers = index.Callers(c, CallEdgeFilter.Direct).Where(x => x.Caller != null && named.Contains(x.Caller.Start)).Select(x => x.Caller!).DistinctBy(f => f.Start).ToList();
            if (callers.Count < MinCallers) continue;
            if (viaWrapper)
            {
                int nullChecked = NullChecked(image, index, c, callers, ct);
                if (nullChecked >= MinCallers) wrapped.Add((c.Start, callers.Count, nullChecked));
            }
            else if (callers.Count > best.Count || (callers.Count == best.Count && c.Start < best.Rva)) best = (c.Start, callers.Count);
        }
        if (best.Count >= MinCallers)
            return new Helper(best.Rva, "Runtime_ThrowNullReference", $"null-reference throw; only raises the exception, called by {best.Count} named functions");
        // Two wrapped throws reached by null checks are ambiguous, so neither is named.
        if (wrapped.Count != 1) return null;
        var one = wrapped[0];
        return new Helper(one.Rva, "Runtime_ThrowNullReference", $"null-reference throw; raises through a no-return wrapper, reached by null checks in {one.Checked} sampled callers, called by {one.Count} named functions");
    }

    // A small function that never returns, ends in a call and makes at
    // least two.
    private static bool IsRaiseWrapper(INativeImage image, NativeCodeIndex index, uint start, Dictionary<uint, bool> memo, CancellationToken ct)
    {
        if (memo.TryGetValue(start, out var known)) return known;
        bool result = false;
        if (index.FunctionByStart(start) is { Size: > 0 and <= StubSize } f)
        {
            var code = NativeAotCode.Decode(image, index.Ranges(f), ct);
            // Padding after the last call is not part of the body.
            while (code.Count > 0 && code[^1].FlowControl is FlowControl.Exception or FlowControl.Interrupt) code.RemoveAt(code.Count - 1);
            result = code.Count > 0 && code[^1].FlowControl == FlowControl.Call
                && code.Count(i => i.FlowControl == FlowControl.Call) >= 2
                && code.All(i => i.FlowControl is not (FlowControl.Return or FlowControl.IndirectBranch or FlowControl.IndirectCall));
        }
        return memo[start] = result;
    }

    // How many of the first callers branch to a call of the function after
    // test reg,reg.
    private static int NullChecked(INativeImage image, NativeCodeIndex index, NativeFunction thrower, IReadOnlyList<NativeFunction> callers, CancellationToken ct)
    {
        ulong target = image.ImageBase + thrower.Start;
        int checkedCallers = 0;
        foreach (var caller in callers.OrderBy(f => f.Start).Take(MaxSampledCallers))
        {
            var code = NativeAotCode.Decode(image, index.Ranges(caller), ct);
            var branches = new HashSet<ulong>();
            for (int k = 1; k < code.Count; k++)
                if (code[k].Mnemonic == Mnemonic.Je && code[k].Op0Kind == OpKind.NearBranch64 && IsSelfTest(code[k - 1]))
                    branches.Add(code[k].NearBranchTarget);
            if (code.Any(i => i.FlowControl == FlowControl.Call && i.Op0Kind == OpKind.NearBranch64 && i.NearBranchTarget == target && branches.Contains(i.IP)))
                checkedCallers++;
        }
        return checkedCallers;
    }

    private static bool IsSelfTest(in Instruction i) =>
        i.Mnemonic == Mnemonic.Test && i.Op0Kind == OpKind.Register && i.Op1Kind == OpKind.Register && i.Op0Register == i.Op1Register;

    /// <summary>
    /// The function called with a receiver's class pointer right before a
    /// virtual call through the same receiver: <c>mov rcx,[r]</c>, the call,
    /// <c>mov rax,[r]</c>, <c>call [rax+d]</c>. Named when at least three named
    /// functions call it this way and it has at least twice the sites of any
    /// other; at most <see cref="MaxScanned"/> named functions are scanned.
    /// </summary>
    private static Helper? ClassSetup(INativeImage image, NativeCodeIndex index, IReadOnlySet<uint> named, IReadOnlySet<uint> skip, Action<string>? note, CancellationToken ct)
    {
        if (image.Arch != NativeArch.X64) return null;
        var sites = new Dictionary<uint, int>();
        int scanned = 0;
        bool capped = false;
        foreach (var start in named.Order())
        {
            ct.ThrowIfCancellationRequested();
            if (scanned >= MaxScanned) { capped = true; break; }
            if (index.FunctionByStart(start) is not { } f) continue;
            scanned++;
            var code = NativeAotCode.Decode(image, index.Ranges(f), ct);
            var seen = new HashSet<uint>();
            for (int k = 1; k < code.Count; k++)
            {
                if (code[k].FlowControl != FlowControl.Call || code[k].Op0Kind != OpKind.NearBranch64) continue;
                if (!ClassPointerLoad(code[k - 1], out var receiver) || !VirtualCallAfter(code, k, receiver)) continue;
                uint callee = (uint)(code[k].NearBranchTarget - image.ImageBase);
                if (seen.Add(callee)) sites[callee] = sites.GetValueOrDefault(callee) + 1;
            }
        }
        var ranked = sites.Where(p => !named.Contains(p.Key) && !skip.Contains(p.Key) && index.FunctionByStart(p.Key) != null)
            .OrderByDescending(p => p.Value).ThenBy(p => p.Key).Take(2).ToList();
        if (ranked.Count == 0 || ranked[0].Value < MinCallers || (ranked.Count > 1 && ranked[0].Value < ranked[1].Value * 2))
        {
            if (capped) note?.Invoke($"class setup helper unknown: {scanned} of {named.Count} named functions scanned");
            return null;
        }
        return new Helper(ranked[0].Key, "Runtime_ClassSetup", $"class setup; called with the receiver's class pointer before a virtual call in {ranked[0].Value} of {scanned} of {named.Count} named functions scanned");
    }

    // mov rcx,[r] with r another register.
    private static bool ClassPointerLoad(in Instruction i, out Register receiver)
    {
        receiver = Register.None;
        if (i.Mnemonic != Mnemonic.Mov || i.Op0Kind != OpKind.Register || i.Op0Register is not Register.RCX) return false;
        if (i.Op1Kind != OpKind.Memory || i.MemoryIndex != Register.None || i.MemoryDisplacement64 != 0 || i.SegmentPrefix != Register.None) return false;
        if (!i.MemoryBase.IsGPR64() || i.MemoryBase is Register.RIP or Register.RSP || i.MemoryBase == i.Op0Register) return false;
        receiver = i.MemoryBase;
        return true;
    }

    // mov rax,[receiver], then call [rax+d], within the window and with no
    // branch or call between.
    private static bool VirtualCallAfter(List<Instruction> code, int call, Register receiver)
    {
        bool reloaded = false;
        for (int k = call + 1; k < code.Count && k <= call + Window; k++)
        {
            var i = code[k];
            if (reloaded && i.FlowControl == FlowControl.IndirectCall && i.Op0Kind == OpKind.Memory && i.MemoryBase == Register.RAX) return true;
            if (i.FlowControl != FlowControl.Next) return false;
            if (i.Op0Kind == OpKind.Register && i.Op0Register.GetFullRegister() == Register.RAX)
                reloaded = i.Mnemonic == Mnemonic.Mov && i.Op1Kind == OpKind.Memory && i.MemoryBase == receiver && i.MemoryIndex == Register.None && i.MemoryDisplacement64 == 0;
        }
        return false;
    }
}
