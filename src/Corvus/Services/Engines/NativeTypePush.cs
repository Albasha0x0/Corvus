using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Code;
using Corvus.Native.Msvc;
using Corvus.Native.Providers;

namespace Corvus.Services;

/// <summary>Pushes recovered types into an image's engine session: AOT struct layouts and method prototypes, and MSVC
/// RTTI vftable and class structs; a saved stamp skips unchanged pushes.</summary>
public sealed class NativeTypePush(AssemblyWorkspace? workspace = null)
{
    public const string StampKey = "types";
    /// <summary>Most classes and methods sent (larger images keep the first ones in RTTI order).</summary>
    public const int MaxClasses = 20_000, MaxMethods = 200_000;

    private static readonly ConditionalWeakTable<INativeDecompilerSession, State> States = new();

    public sealed record PushResult(int Prototypes, int Classes, TypeBatchResult? Totals, bool AlreadyInDatabase, string Stamp, TimeSpan Elapsed);

    private sealed class State
    {
        public readonly SemaphoreSlim Gate = new(1, 1);
        public object?[]? Inputs;
        public string? Stamp;
        /// <summary>Virtual methods by start and their class, from the last batch (typed in the batch within a time budget, the rest on demand).</summary>
        public Dictionary<uint, string> Owners = [];
        public readonly HashSet<uint> Asked = [];
    }

    /// <summary>Brings the session's types up to date; null when there is nothing to push or nothing changed.</summary>
    public async Task<PushResult?> EnsureAsync(LoadedNative native, INativeDecompilerSession session, CancellationToken ct)
    {
        var state = States.GetValue(session, _ => new State());
        await state.Gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var aot = AotNativeNames.Of(native);
            // A database with PDB types has the real classes, which RTTI outlines would replace.
            var rtti = native.Image.Arch is NativeArch.X86 or NativeArch.X64 or NativeArch.Arm64 or NativeArch.Arm && !NativePdbTypes.Applied(session)
                ? native.GetAnalysis(n => Native.Itanium.CppRtti.Analyze(n.Image, ct)) : null;
            object?[] inputs = [aot, rtti, NativeNameLayers.OfOrNull(native)?.Get(NativeNameSource.Metadata)];
            if (state.Inputs != null && inputs.SequenceEqual(state.Inputs)) return null;

            var clock = System.Diagnostics.Stopwatch.StartNew();
            // Under the workspace read lock, so the dummy assemblies stay loaded; ones unloaded or reloaded since the names were applied are not used.
            var batch = await Task.Run(() => workspace == null ? Build(native, aot, rtti, ct) : workspace.Read(() =>
                Build(native, aot != null && aot.Image.Assemblies.All(workspace.Assemblies.Contains) ? aot : null, rtti, ct)), ct).ConfigureAwait(false);
            if (batch.Prototypes.Count == 0 && batch.Classes.Count == 0 && batch.Declarations == null)
            {
                state.Inputs = inputs;
                return null;
            }
            var stamp = StampOf(batch);
            state.Owners = batch.Methods.GroupBy(m => m.Rva).ToDictionary(g => g.Key, g => g.First().Class);
            if (state.Stamp == stamp)
            {
                state.Inputs = inputs;
                return null;
            }
            if (state.Stamp == null && await session.GetStampAsync(StampKey, ct).ConfigureAwait(false) == stamp)
            {
                (state.Inputs, state.Stamp) = (inputs, stamp);
                return new PushResult(batch.Prototypes.Count, batch.Classes.Count, null, true, stamp, clock.Elapsed);
            }
            var totals = await session.ApplyTypesAsync(batch, StampKey, stamp, save: true, ct).ConfigureAwait(false);
            (state.Inputs, state.Stamp) = (inputs, stamp);
            return new PushResult(batch.Prototypes.Count, batch.Classes.Count, totals, false, stamp, clock.Elapsed);
        }
        finally { state.Gate.Release(); }
    }

    /// <summary>Types a virtual method the last batch deferred with its class as first argument; true when sent.</summary>
    public async Task<bool> EnsureMethodAsync(LoadedNative native, INativeDecompilerSession session, uint start, CancellationToken ct)
    {
        if (!States.TryGetValue(session, out var state)) return false;
        await state.Gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (!state.Owners.TryGetValue(start, out var owner) || !state.Asked.Add(start)) return false;
            await session.ApplyTypesAsync(new NativeTypeBatch(null, [], [], [new NativeMethodOwner(start, owner)], native.Image.Is64Bit ? 8 : 4), cancellationToken: ct)
                .ConfigureAwait(false);
            return true;
        }
        finally { state.Gate.Release(); }
    }

    /// <summary><see cref="EnsureMethodAsync"/> for many functions in one request; returns how many were sent.</summary>
    public async Task<int> EnsureMethodsAsync(LoadedNative native, INativeDecompilerSession session, IEnumerable<uint> starts, CancellationToken ct)
    {
        if (!States.TryGetValue(session, out var state)) return 0;
        await state.Gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var owners = new List<NativeMethodOwner>();
            foreach (var start in starts.Distinct())
                if (state.Owners.TryGetValue(start, out var owner) && state.Asked.Add(start)) owners.Add(new NativeMethodOwner(start, owner));
            if (owners.Count == 0) return 0;
            await session.ApplyTypesAsync(new NativeTypeBatch(null, [], [], owners, native.Image.Is64Bit ? 8 : 4), cancellationToken: ct).ConfigureAwait(false);
            return owners.Count;
        }
        finally { state.Gate.Release(); }
    }

    /// <summary>The stamp of the types last pushed to <paramref name="session"/>, or "" before any push.</summary>
    public static string CurrentStamp(INativeDecompilerSession session) => States.TryGetValue(session, out var s) ? s.Stamp ?? "" : "";

    /// <summary>The batch for an image: AOT header and prototypes, MSVC RTTI classes.</summary>
    internal static NativeTypeBatch Build(LoadedNative native, AotNativeNames.Applied? aot, MsvcRttiResult? rtti, CancellationToken ct)
    {
        string? header = null;
        var prototypes = new List<NativePrototype>();
        if (aot != null)
        {
            // AOT x86 code uses __cdecl; Ghidra's x86 default would be __stdcall.
            AotLayout? layout = new(native.Image.Is64Bit ? 8u : 4u) { Convention = native.Image.Arch == NativeArch.X86 ? "__cdecl" : null };
            AotExporter.LayOut(layout, aot.Image.Assemblies, ct);
            var names = NativeNameLayers.OfOrNull(native)?.Get(NativeNameSource.Metadata)?.Names;
            foreach (var start in aot.Image.Starts)
            {
                ct.ThrowIfCancellationRequested();
                if (start >= native.Image.SizeOfImage || native.Image.SectionAt(start) is not { IsExecutable: true }) continue;
                var (methods, _) = AotNavigator.MethodsSharing(aot.Image, start);
                if (methods.Count == 0) continue;
                // A module replaced since the names were applied needs apply_metadata_names again first.
                if (!ReferenceEquals(methods[0].Method.Module, methods[0].Assembly.Module)) { prototypes.Clear(); layout = null; break; }
                // Prototypes lay out their own types, so the header is written after them.
                prototypes.Add(new NativePrototype(start, AotExporter.Prototype(layout, methods[0].Method, names?.GetValueOrDefault(start) ?? $"f_{start:X}")));
            }
            header = layout != null ? AotExporter.Header(layout) : null;
        }

        var classes = new List<NativeClassType>();
        var owners = new List<NativeMethodOwner>();
        if (rtti != null)
        {
            var polymorphic = rtti.Classes.Where(c => c.Vtables.Count > 0).OrderBy(c => c.Bases.Count).ThenBy(c => c.Name, StringComparer.Ordinal).Take(MaxClasses).ToList();
            var idents = new Dictionary<string, string>(StringComparer.Ordinal);
            var used = new HashSet<string>(StringComparer.Ordinal);
            foreach (var c in polymorphic)
            {
                if (idents.ContainsKey(c.Name)) continue;
                var id = AotLayout.Identifier(c.Name.Replace("::", "__"));
                for (int i = 2; !used.Add(id); i++) id = $"{AotLayout.Identifier(c.Name.Replace("::", "__"))}_{i}";
                idents[c.Name] = id;
            }
            // A virtual method's class is the one every primary-vftable holder derives from at offset 0. Targets in a
            // secondary vftable are skipped, since their this is adjusted.
            var holders = new Dictionary<uint, List<MsvcRttiClass>>();
            var secondary = new HashSet<uint>();
            foreach (var c in polymorphic)
                foreach (var v in c.Vtables)
                    foreach (var s in v.SlotRvas)
                        if (v.Offset != 0) secondary.Add(s);
                        else if (!holders.TryGetValue(s, out var list)) holders[s] = [c];
                        else if (!list.Contains(c)) list.Add(c);
            MsvcRttiClass? OwnerOf(uint slot)
            {
                if (secondary.Contains(slot) || !holders.TryGetValue(slot, out var list)) return null;
                var owner = list.Where(c => list.All(d => ReferenceEquals(d, c) || d.Bases.Any(b => b.Name == c.Name && !b.IsVirtual && b.Mdisp == 0))).ToList();
                return owner.Count == 1 ? owner[0] : null;
            }
            var emitted = new HashSet<string>(StringComparer.Ordinal);
            foreach (var c in polymorphic)
            {
                ct.ThrowIfCancellationRequested();
                // A class with one type descriptor per defining module is emitted once.
                if (!idents.TryGetValue(c.Name, out var id) || !emitted.Add(id)) continue;
                var bases = c.Bases.Where(b => b.Depth == 1 && !b.IsVirtual && b.Mdisp > 0 && idents.ContainsKey(b.Name))
                    .Select(b => new NativeBaseType(idents[b.Name], b.Mdisp)).DistinctBy(b => b.Offset).ToList();
                classes.Add(new NativeClassType(id, c.Vtables.DistinctBy(v => v.Offset).Select(v => new NativeVftableType(v.Offset, v.VftableRva, v.SlotRvas)).ToList(), bases));
                foreach (var v in c.Vtables.Where(v => v.Offset == 0))
                    foreach (var s in v.SlotRvas.Distinct())
                        if (owners.Count < MaxMethods && ReferenceEquals(OwnerOf(s), c) && native.Image.SectionAt(s) is { IsExecutable: true })
                            owners.Add(new NativeMethodOwner(s, id));
            }
        }
        return new NativeTypeBatch(header, prototypes, classes, owners, native.Image.Is64Bit ? 8 : 4);
    }

    /// <summary>SHA-256 of a batch's content.</summary>
    public static string StampOf(NativeTypeBatch batch)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        void Add(string s) => hash.AppendData(Encoding.UTF8.GetBytes(s + "\0"));
        Add(batch.Declarations ?? "");
        foreach (var p in batch.Prototypes) Add($"{p.Rva:X}:{p.Declaration}");
        foreach (var c in batch.Classes)
        {
            Add(c.Name);
            foreach (var v in c.Vftables) Add($"{v.Offset:X}@{v.Rva:X}:{string.Join(",", v.Slots.Select(s => s.ToString("X")))}");
            foreach (var b in c.Bases) Add($"{b.Name}+{b.Offset:X}");
        }
        foreach (var m in batch.Methods) Add($"{m.Rva:X}={m.Class}");
        Add(batch.PointerSize.ToString());
        return Convert.ToHexString(hash.GetHashAndReset());
    }

    /// <summary>One line describing a push for tool output, or null when nothing was pushed.</summary>
    public static string? Describe(PushResult? r) => r switch
    {
        null => null,
        { AlreadyInDatabase: true } => "types: the database already has the current types",
        { Totals: { } t } => $"types: pushed {r.Prototypes} prototype(s) ({t.Typed} applied" + (t.TypeFailures > 0 ? $", {t.TypeFailures} rejected" : "") +
                             (t.DeclarationErrors > 0 ? $", {t.DeclarationErrors} declaration error(s)" : "") + $") and {r.Classes} C++ class(es) " +
                             $"({t.Structs} structs, {t.VftablesTyped} vftables and {t.MethodsTyped} methods typed" +
                             (t.MethodSkips.Count > 0 ? $"; methods left: {string.Join(", ", t.MethodSkips.Select(kv => $"{kv.Value} {kv.Key}"))}" : "") +
                             $") in {r.Elapsed.TotalSeconds:0.0} s",
        _ => null,
    };
}
