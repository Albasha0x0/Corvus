using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Code;
using NetDecompilerMcp.Native.Msvc;
using NetDecompilerMcp.Native.Providers;

namespace NetDecompilerMcp.Services;

/// <summary>
/// Pushes the types the server recovered for an image into its engine session before engine output is shown:
/// <list type="bullet">
/// <item>Il2Cpp (after apply_il2cpp_names, 64-bit): the struct layouts of the dummy assemblies as a C header
/// (<see cref="Il2CppExporter.Header"/>) and each method's C prototype applied to its function.</item>
/// <item>MSVC RTTI: per class with vftables, a vftable struct (slot function pointers, typed from the target's type
/// where the engine has one) and a class struct (vftable pointers at their subobject offsets, base subobjects at
/// theirs; field types beyond that are unknown); the vftables are typed, and virtual methods found in exactly one
/// class's primary vftable get that class as the type of their first argument.</item>
/// </list>
/// One request; a stamp (SHA-256 of the batch) is recorded in the database and saved with it, so a later session on
/// the same database skips the push when nothing changed.
/// </summary>
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
            var il2cpp = Il2CppNativeNames.Of(native);
            var rtti = native.Image.Arch is NativeArch.X86 or NativeArch.X64 ? native.GetAnalysis(n => MsvcRtti.Analyze(n.Image, ct: ct)) : null;
            object?[] inputs = [il2cpp, rtti, NativeNameLayers.OfOrNull(native)?.Get(NativeNameSource.Il2Cpp)];
            if (state.Inputs != null && inputs.SequenceEqual(state.Inputs)) return null;

            var clock = System.Diagnostics.Stopwatch.StartNew();
            // Under the workspace read lock, so the dummy assemblies stay loaded; ones unloaded or reloaded since the names were applied are not used.
            var batch = await Task.Run(() => workspace == null ? Build(native, il2cpp, rtti, ct) : workspace.Read(() =>
                Build(native, il2cpp != null && il2cpp.Image.Assemblies.All(workspace.Assemblies.Contains) ? il2cpp : null, rtti, ct)), ct).ConfigureAwait(false);
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

    /// <summary>
    /// Types the virtual method starting at <paramref name="start"/> with its class (first argument) when the last batch
    /// left it for later (the batch types methods within a time budget); a no-op for other functions. True when sent.
    /// </summary>
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

    /// <summary>
    /// <see cref="EnsureMethodAsync"/> for many functions in one request: the virtual methods among <paramref name="starts"/> the
    /// last batch left for later get their class as the type of their first argument. Returns how many were sent.
    /// </summary>
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

    /// <summary>The batch for an image: Il2Cpp header and prototypes, MSVC RTTI classes.</summary>
    internal static NativeTypeBatch Build(LoadedNative native, Il2CppNativeNames.Applied? il2cpp, MsvcRttiResult? rtti, CancellationToken ct)
    {
        string? header = null;
        var prototypes = new List<NativePrototype>();
        if (il2cpp != null && native.Image.Is64Bit)
        {
            Il2CppLayout? layout = new();
            Il2CppExporter.LayOut(layout, il2cpp.Image.Assemblies, ct);
            var names = NativeNameLayers.OfOrNull(native)?.Get(NativeNameSource.Il2Cpp)?.Names;
            foreach (var start in il2cpp.Image.Starts)
            {
                ct.ThrowIfCancellationRequested();
                if (start >= native.Image.SizeOfImage || native.Image.SectionAt(start) is not { IsExecutable: true }) continue;
                var (methods, _) = Il2CppNavigator.MethodsSharing(il2cpp.Image, start);
                if (methods.Count == 0) continue;
                // methods of a module replaced since the names were applied (reload, reverted edits): apply_il2cpp_names again first
                if (!ReferenceEquals(methods[0].Method.Module, methods[0].Assembly.Module)) { prototypes.Clear(); layout = null; break; }
                // the prototype's own types are laid out on the way, so the header is written after them
                prototypes.Add(new NativePrototype(start, Il2CppExporter.Prototype(layout, methods[0].Method, names?.GetValueOrDefault(start) ?? $"f_{start:X}")));
            }
            header = layout != null ? Il2CppExporter.Header(layout) : null;
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
                var id = Il2CppLayout.Identifier(c.Name.Replace("::", "__"));
                for (int i = 2; !used.Add(id); i++) id = $"{Il2CppLayout.Identifier(c.Name.Replace("::", "__"))}_{i}";
                idents[c.Name] = id;
            }
            // A virtual method's class: of the classes whose primary vftable holds it (a class and the derived classes that
            // inherit the method without overriding it), the one every other derives from at offset 0. Targets also in a
            // secondary vftable are skipped (their this is adjusted).
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
                // a class name with several type descriptors (one per module that defines it) is emitted once
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
