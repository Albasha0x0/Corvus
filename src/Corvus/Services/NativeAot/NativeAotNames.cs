using System.Diagnostics;
using System.Text;
using Corvus.Core;
using Corvus.Native.Annotations;
using Corvus.Native.Code;
using Corvus.Native.NativeAot;

namespace Corvus.Services;

/// <summary>
/// The <see cref="NativeNameSource.NativeAot"/> name layer of a NativeAOT image, built from its own metadata when the
/// code index is first built (no tool call needed) and saved beside the image's annotations like the other imported layers.
/// <para>
/// Naming scheme (the Il2Cpp layer's IDA-safe identifiers, <see cref="NativeName.Identifier"/>): method bodies
/// "Ns_Type__Method" from the stack-trace and invoke maps, commented with the C# form and the other methods folded into the
/// same body; unnamed bodies in a vtable "Ns_Type__BaseMethod" (the overridden method) or "Ns_Type__vslot&lt;k&gt;", unnamed
/// interface implementations "Ns_Type__Method" or "Ns_Type__IFoo_slot&lt;k&gt;"; MethodTables "MT_Ns_Type"; frozen strings
/// "str_&lt;n&gt;" (n in address order) commented with the text, other frozen objects "frozen_&lt;n&gt;"; the module header
/// "__ReadyToRunHeader" and its sections "__&lt;SectionName&gt;"; statics bases "Ns_Type__GCStatics", "Ns_Type__Statics" and
/// "Ns_Type__ThreadStaticsIndex" (or "GCStatics_&lt;n&gt;" and so on when the type is unknown), non-GC static fields
/// "Ns_Type__field" (once the code index is built, "Ns_Type__field_0xN" where code uses one the metadata does not name);
/// interface dispatch cells "__InterfaceDispatchCell_Ns_IFoo__Method". A name already used at another address gets "_&lt;RVA hex&gt;".
/// </para>
/// </summary>
public static class NativeAotNames
{
    /// <summary>Set to 0 to turn off naming NativeAOT images automatically.</summary>
    public const string AutoVariable = "CORVUS_AUTO_NATIVEAOT";
    /// <summary>Saved with the layer; a layer saved by another version of this naming is rebuilt.</summary>
    public const string ReaderIdentity = "nativeaot-names 3";
    /// <summary>Most other folded methods listed in a function's comment.</summary>
    private const int FoldedListed = 8;
    private const int MaxSlotDepth = 64;

    /// <summary>What a build of the layer named.</summary>
    public sealed record Report(int Functions, int FoldedFunctions, int VtableSlots, int InterfaceSlots, int MethodTables, int FrozenStrings, int FrozenObjects, int Suffixed, TimeSpan Elapsed)
    {
        public int Statics { get; init; }
        public int DispatchCells { get; init; }
    }

    /// <summary>The layer's contents: names and comments by RVA, the function starts it contributes, and counts.</summary>
    public sealed record Built(Dictionary<uint, string> Names, Dictionary<uint, string> Comments, uint[] FunctionStarts, Report Report);

    private sealed class Holder
    {
        public readonly object Gate = new();
        public bool Done;
        public NativeAotImage? View;
        public string? Problem;
    }

    /// <summary>The NativeAOT view of <paramref name="native"/>'s current image, located once; null when it has no NativeAOT module header.</summary>
    public static NativeAotImage? View(LoadedNative native, CancellationToken ct = default)
    {
        var holder = native.GetAnalysis(_ => new Holder());
        using (AssemblyWorkspace.Lock(holder.Gate))
        {
            if (holder.Done) return holder.View;
            try { holder.View = NativeAotImage.For(native.Image); }
            catch (ToolError e) { holder.Problem = e.Message; }
            holder.Done = true;
            return holder.View;
        }
    }

    /// <summary>Why the view could not be read, when locating the header failed.</summary>
    public static string? Problem(LoadedNative native) => native.Analysis.TryGetValue(typeof(Holder), out var h) ? ((Holder)h).Problem : null;

    /// <summary>
    /// On the index build thread: sets the nativeaot layer of a NativeAOT image (a saved one of this naming version is kept)
    /// and returns its function starts; null for other images or when turned off by <see cref="AutoVariable"/>.
    /// </summary>
    public static IReadOnlyCollection<uint>? AutoApply(LoadedNative native, NativeCodeService code, CancellationToken ct)
    {
        if (Environment.GetEnvironmentVariable(AutoVariable) == "0") return null;
        var layers = NativeNameLayers.Of(native);
        if (layers.Get(NativeNameSource.NativeAot) is { Info: { SourceIdentity: ReaderIdentity } info }) return info.FunctionStarts ?? [];
        if (View(native, ct) is not { } aot) return null;
        var built = Build(aot, ct);
        layers.Set(new NativeNameLayers.Layer(NativeNameSource.NativeAot, built.Names, built.Comments, $"NativeAOT metadata ({aot.Runtime})",
            new ImportInfo(native.FilePath, ReaderIdentity, DateTime.UtcNow, built.FunctionStarts)), code.Ready(native));
        code.SaveImported(native, NativeNameSource.NativeAot);
        return built.FunctionStarts;
    }

    /// <summary>
    /// Once the code index is built: names the static fields the metadata keeps no names for, "Ns_Type__field_0xN", at each
    /// address code reads, writes or takes inside an owned non-GC statics block; the layer is saved again. Returns the
    /// number of names added, or null for other images or when turned off by <see cref="AutoVariable"/>.
    /// </summary>
    public static int? NameStaticFields(LoadedNative native, NativeCodeService code, NativeCodeIndex index, CancellationToken ct)
    {
        if (Environment.GetEnvironmentVariable(AutoVariable) == "0") return null;
        var layers = NativeNameLayers.Of(native);
        if (layers.Get(NativeNameSource.NativeAot) is not { } layer || View(native, ct) is not { } aot) return null;
        var (names, comments, added) = StaticFieldNames(aot.Statics.Bases, layer.Names, layer.Comments,
            (start, end) => index.RefsToRange(start, end).Where(x => x.Kind is XrefKind.Read or XrefKind.Write or XrefKind.Address).Select(x => x.To), ct);
        if (added == 0) return 0;
        layers.Set(layer with { Names = names, Comments = comments }, index);
        code.SaveImported(native, NativeNameSource.NativeAot);
        return added;
    }

    /// <summary>
    /// The layer's names and comments plus one per address <paramref name="referenced"/> returns inside an owned non-GC
    /// statics block without field metadata (past its base, before the next base, within the block span), and how many it added.
    /// </summary>
    internal static (Dictionary<uint, string> Names, Dictionary<uint, string> Comments, int Added) StaticFieldNames(IReadOnlyList<NativeAotStaticBase> bases,
        IReadOnlyDictionary<uint, string> names, IReadOnlyDictionary<uint, string> comments, Func<uint, uint, IEnumerable<uint>> referenced, CancellationToken ct)
    {
        var outNames = new Dictionary<uint, string>(names);
        var outComments = new Dictionary<uint, string>(comments);
        var used = new HashSet<string>(outNames.Values, StringComparer.Ordinal);
        int added = 0;
        for (int i = 0; i < bases.Count; i++)
        {
            ct.ThrowIfCancellationRequested();
            if (bases[i] is not { Kind: NativeAotStaticsKind.NonGc, Owner: { } owner, Fields.Count: 0 } b) continue;
            uint end = b.Rva + UnnamedStaticsSpan;
            if (i + 1 < bases.Count && bases[i + 1].Rva < end) end = bases[i + 1].Rva;
            foreach (var at in referenced(b.Rva + 1, end).Distinct().Order())
            {
                if (outNames.ContainsKey(at)) continue;
                var name = NativeName.Identifier($"{owner}$$field_0x{at - b.Rva:X}");
                if (!used.Add(name)) used.Add(name = $"{name}_{at:X}");
                outNames[at] = name;
                outComments[at] = $"static of {owner} at +0x{at - b.Rva:X} in its non-GC statics (named from the code that uses it; the metadata keeps no field name)";
                added++;
            }
        }
        return (outNames, outComments, added);
    }

    /// <summary>
    /// Lines describing <paramref name="rva"/> through the image's NativeAOT metadata: the MethodTable, frozen object or named
    /// method body there, else the module section it is in. Empty for other images.
    /// </summary>
    public static List<string> Describe(LoadedNative native, uint rva, CancellationToken ct = default)
    {
        var lines = new List<string>();
        if (View(native, ct) is not { } aot) return lines;
        if (aot.Types.ByRva.TryGetValue(rva, out var mt))
            lines.Add($"NativeAOT MethodTable of {mt.Name} ({mt.Kind}, name from {mt.NameOrigin}); get_nativeaot_info view=type shows its vtable");
        var objects = aot.Frozen.Objects;
        uint header = (uint)aot.Hydrated.PointerSize;
        int lo = 0, hi = objects.Count - 1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >>> 1;
            var o = objects[mid];
            if (rva < o.Rva - header) hi = mid - 1;
            else if (rva >= o.Rva - header + o.Size) lo = mid + 1;
            else
            {
                string what = o.Text != null ? $"String {Il2CppNativeNames.Quote(o.Text)}" : $"{o.TypeName} ({o.Size} bytes)";
                lines.Add(rva == o.Rva ? $"NativeAOT frozen {what}" : $"inside the NativeAOT frozen {what} at rva 0x{o.Rva:X} (+0x{rva - o.Rva:X})");
                break;
            }
        }
        if (aot.Dispatch.CellAt(rva) is { } cell)
            lines.Add($"NativeAOT interface dispatch cell: {cell.Target} (slot {cell.Slot}), {aot.Dispatch.Implementers(cell.Interface, cell.Slot).Count} implementations known; resolve_call_targets lists them at the call");
        if (aot.Statics.At(rva) is { } st)
        {
            var field = st.Fields.LastOrDefault(f => st.Rva + f.Offset <= rva);
            lines.Add(rva == st.Rva ? $"NativeAOT {StaticsComment(st, aot.Hydrated.PointerSize)}"
                : field != null ? $"NativeAOT static {st.Owner}::{field.Name} (+0x{rva - st.Rva - field.Offset:X}) in the non-GC statics at rva 0x{st.Rva:X}"
                // No field name in the metadata: the owner and the offset still say which static it is.
                : $"NativeAOT static {st.Owner ?? "of an unknown type"}::field_0x{rva - st.Rva:X} in the non-GC statics at rva 0x{st.Rva:X}");
        }
        else if (UnnamedStatic(aot.Statics.Bases, rva) is { } owned)
            lines.Add($"NativeAOT static {owned.Owner}::field_0x{rva - owned.Rva:X} in the non-GC statics at rva 0x{owned.Rva:X} (the metadata keeps no field names for it)");
        foreach (var m in aot.Names.Methods.Where(m => m.Rva == rva).Take(Il2CppNativeNames.SharedListed))
            lines.Add($"NativeAOT method {m.Name.Full} (from the {(m.Origin == "invoke" ? "reflection invoke map" : "stack-trace map")}{(m.Hidden ? ", hidden from stack traces" : "")})");
        if (rva == aot.Header.Rva) lines.Add($"NativeAOT module header, ReadyToRun {aot.ReadyToRunVersion} ({aot.Runtime})");
        else if (lines.Count == 0 && aot.Header.Sections.FirstOrDefault(s => s.HasEnd && rva >= s.StartRva && rva < s.EndRva) is { } section)
            lines.Add($"in NativeAOT module section {section.Name} (+0x{rva - section.StartRva:X})");
        return lines;
    }

    /// <summary>Bytes past an owned non-GC statics base without field metadata still read as its fields (statics blocks are small).</summary>
    private const uint UnnamedStaticsSpan = 0x400;

    /// <summary>The owned non-GC statics base, without field metadata, that <paramref name="rva"/> lies just after (before the next base); null otherwise.</summary>
    internal static NativeAotStaticBase? UnnamedStatic(IReadOnlyList<NativeAotStaticBase> bases, uint rva)
    {
        int lo = 0, hi = bases.Count - 1, at = -1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >>> 1;
            if (bases[mid].Rva < rva) { at = mid; lo = mid + 1; } else hi = mid - 1;
        }
        if (at < 0 || bases[at] is not { Kind: NativeAotStaticsKind.NonGc, Owner: not null, Fields.Count: 0 } b || rva - b.Rva >= UnnamedStaticsSpan) return null;
        return at + 1 < bases.Count && bases[at + 1].Rva <= rva ? null : b;
    }

    /// <summary>Names every method body, vtable slot, MethodTable and frozen object of <paramref name="aot"/>.</summary>
    public static Built Build(NativeAotImage aot, CancellationToken ct = default)
    {
        var watch = Stopwatch.StartNew();
        var image = aot.Image;
        var names = new Dictionary<uint, string>();
        var comments = new Dictionary<uint, string>();
        var used = new Dictionary<string, uint>(StringComparer.Ordinal);
        int suffixed = 0;
        void Add(uint rva, string name, string? comment)
        {
            if (names.ContainsKey(rva)) return;
            if (!used.TryAdd(name, rva))
            {
                suffixed++;
                name = $"{name}_{rva:X}";
                used.TryAdd(name, rva);
            }
            names[rva] = name;
            if (comment != null) comments[rva] = comment;
        }
        bool Code(uint rva) => rva < image.SizeOfImage && image.SectionAt(rva) is { IsExecutable: true };

        // Method bodies: the preferred name of each address, the folded others in the comment.
        var maps = aot.Names;
        var byRva = maps.Methods.GroupBy(m => m.Rva).ToDictionary(g => g.Key, g => g.ToList());
        int functions = 0, folded = 0;
        var starts = new List<uint>();
        foreach (var (rva, method) in maps.MethodAt.OrderBy(kv => kv.Key))
        {
            ct.ThrowIfCancellationRequested();
            if (!Code(rva)) continue;
            starts.Add(rva);
            var comment = new StringBuilder(method.Name.Full);
            if (method.Hidden) comment.Append(" (hidden from stack traces)");
            var others = byRva[rva].Select(m => m.Name.Full).Where(n => n != method.Name.Full).Distinct().ToList();
            if (others.Count > 0)
            {
                folded++;
                comment.Append($"\nidentical code, also: {string.Join("; ", others.Take(FoldedListed))}");
                if (others.Count > FoldedListed) comment.Append($" (+{others.Count - FoldedListed} more)");
            }
            Add(rva, NativeName.Identifier($"{method.Name.Owner}$${method.Name.Name}"), comment.ToString());
            functions++;
        }

        var types = aot.Types.ByRva;
        int slots = VtableSlots(types, maps, Code, Add, starts, ct), interfaceSlots = 0;

        // Interface implementations no map named (often in the sealed vtable): after the interface method, learned from the
        // named implementations of the same interface slot ("IEnumerator slot 0" -> MoveNext), else after the slot.
        var implementations = types.Values.Where(t => t.DispatchMap != 0).OrderBy(t => t.NameOrigin == "generated" ? 1 : 0).ThenBy(t => t.Rva)
            .Select(t => (Type: t, Impls: aot.Types.Implementations(t))).ToList();
        string Interface(uint rva) => rva != 0 && types.TryGetValue(rva, out var i) ? i.Name : "interface";
        foreach (var (mt, impls) in implementations)
        {
            ct.ThrowIfCancellationRequested();
            foreach (var impl in impls)
            {
                if (impl.Code == 0 || names.ContainsKey(impl.Code) || !Code(impl.Code)) continue;
                string iface = Interface(impl.Interface);
                string? method = aot.Dispatch.InterfaceMethod(iface, impl.InterfaceSlot);
                Add(impl.Code, NativeName.Identifier($"{mt.Name}$${method ?? $"{Short(iface)}_slot{impl.InterfaceSlot}"}"),
                    $"{mt.Name} implementation of {iface} slot {impl.InterfaceSlot}{(method != null ? $" ({method})" : "")}, vtable slot {impl.ImplSlot}");
                starts.Add(impl.Code);
                interfaceSlots++;
            }
        }

        int methodTables = 0;
        foreach (var mt in types.Values.OrderBy(t => t.Rva))
        {
            ct.ThrowIfCancellationRequested();
            bool generated = mt.NameOrigin == "generated";
            Add(mt.Rva, generated ? $"MT_{mt.Rva:X}" : "MT_" + NativeName.Identifier(mt.Name),
                $"MethodTable of {(generated ? "an unnamed type" : mt.Name)} ({mt.Kind}{(generated ? "" : $", name from {mt.NameOrigin}")})");
            methodTables++;
        }

        int strings = 0, objects = 0;
        foreach (var obj in aot.Frozen.Objects)
        {
            ct.ThrowIfCancellationRequested();
            if (obj.Text != null) Add(obj.Rva, $"str_{strings++}", Il2CppNativeNames.Quote(obj.Text));
            else Add(obj.Rva, $"frozen_{objects++}", $"frozen {obj.TypeName} ({obj.Size} bytes)");
        }
        int statics = 0, unowned = 0;
        foreach (var b in aot.Statics.Bases)
        {
            ct.ThrowIfCancellationRequested();
            string suffix = b.Kind switch { NativeAotStaticsKind.Gc => "GCStatics", NativeAotStaticsKind.NonGc => "Statics", _ => "ThreadStaticsIndex" };
            Add(b.Rva, b.Owner != null ? NativeName.Identifier($"{b.Owner}$${suffix}") : $"{suffix}_{unowned++}", StaticsComment(b, aot.Hydrated.PointerSize));
            if (b.Kind == NativeAotStaticsKind.NonGc)
                foreach (var f in b.Fields.Where(f => f.Offset > 0))
                    Add(b.Rva + f.Offset, NativeName.Identifier($"{b.Owner}$${f.Name}"), $"static {f.Type} {b.Owner}::{f.Name}");
            statics++;
        }
        int cells = 0;
        foreach (var cell in aot.Dispatch.Cells)
        {
            ct.ThrowIfCancellationRequested();
            var impls = aot.Dispatch.Implementers(cell.Interface, cell.Slot);
            Add(cell.Rva, "__InterfaceDispatchCell_" + NativeName.Identifier($"{cell.InterfaceName}$${cell.Method ?? $"slot{cell.Slot}"}"),
                $"interface dispatch cell: {cell.Target} (slot {cell.Slot}); {impls.Count} implementation(s) known" +
                (impls.Count > 0 ? ": " + string.Join(", ", impls.Take(FoldedListed).Select(i => i.TypeName)) + (impls.Count > FoldedListed ? ", …" : "") : ""));
            cells++;
        }
        Add(aot.Header.Rva, "__ReadyToRunHeader", $"NativeAOT module header, ReadyToRun {aot.ReadyToRunVersion} ({aot.Runtime})");
        foreach (var section in aot.Header.Sections.Where(s => s.HasEnd && s.Length > 0))
            Add(section.StartRva, "__" + NativeName.Identifier(section.Name), $"NativeAOT module section {section.Name} ({section.Length} bytes)");

        return new Built(names, comments, starts.Distinct().Order().ToArray(),
            new Report(functions, folded, slots, interfaceSlots, methodTables, strings, objects, suffixed, watch.Elapsed) { Statics = statics, DispatchCells = cells });
    }

    /// <summary>What a statics base holds and how its type is known, with its fields when the metadata keeps them.</summary>
    public static string StaticsComment(NativeAotStaticBase b, int pointerSize)
    {
        string owner = b.Owner != null ? $"{b.Owner}{(b.Origin is "code" ? " (inferred from the code that references it)" : "")}" : "an unknown type";
        var sb = new StringBuilder(b.Kind switch
        {
            NativeAotStaticsKind.Gc => $"GC statics of {owner}: holds the statics object at run time{(b.Size > 0 ? $" ({b.Size} bytes of fields)" : "")}, fields at [slot] + {pointerSize} + offset" +
                                       (b.Preinitialized ? "; preinitialized" : ""),
            NativeAotStaticsKind.NonGc => $"non-GC statics of {owner}",
            _ => $"thread statics index of {owner}: {(b.ThreadIndex is { } i ? $"offset 0x{i:X} in the module's thread-local block" : "unknown offset")}",
        });
        if (b.Fields.Count > 0) sb.Append("; fields: " + string.Join(", ", b.Fields.Select(f => $"{f.Type} {f.Name} +0x{f.Offset:X}")));
        return sb.ToString();
    }

    /// <summary>A type name without its namespace and generic arguments: "System.Collections.Generic.IList&lt;int&gt;" -> "IList".</summary>
    private static string Short(string type)
    {
        int lt = type.IndexOf('<');
        var plain = lt > 0 ? type[..lt] : type;
        return plain[(Math.Max(plain.LastIndexOf('.'), plain.LastIndexOf('+')) + 1)..];
    }

    /// <summary>
    /// Names the unnamed bodies a class introduces in its vtable (slots its base does not share): after the base method the
    /// slot overrides when one up the chain is named, else vslot&lt;k&gt;. Named types first, then by address, so the result is stable.
    /// </summary>
    private static int VtableSlots(IReadOnlyDictionary<uint, NativeAotMethodTable> types, NativeAotNameMaps maps, Func<uint, bool> code,
        Action<uint, string, string?> add, List<uint> starts, CancellationToken ct)
    {
        var slotMethods = new Dictionary<uint, NativeAotMethodName?[]>();
        NativeAotMethodTable? Parent(NativeAotMethodTable mt) =>
            mt.Kind is "class" or "struct" && types.TryGetValue(mt.RelatedType, out var p) && p.Kind == "class" ? p : null;

        // The method in slot k of mt: its own body's name, else the one it inherits or overrides.
        NativeAotMethodName? SlotMethod(NativeAotMethodTable mt, int k, int depth)
        {
            if (!slotMethods.TryGetValue(mt.Rva, out var cache)) slotMethods[mt.Rva] = cache = new NativeAotMethodName?[mt.Vtable.Count];
            if (cache[k] is { } known) return known;
            NativeAotMethodName? found = maps.MethodAt.TryGetValue(mt.Vtable[k], out var m) ? m.Name
                : depth < MaxSlotDepth && Parent(mt) is { } p && k < p.Vtable.Count ? SlotMethod(p, k, depth + 1) : null;
            return cache[k] = found;
        }

        int named = 0;
        var seen = new HashSet<uint>(maps.MethodAt.Keys);
        foreach (var mt in types.Values.Where(t => t.Kind is "class" or "struct").OrderBy(t => t.NameOrigin == "generated" ? 1 : 0).ThenBy(t => t.Rva))
        {
            ct.ThrowIfCancellationRequested();
            var parent = Parent(mt);
            for (int k = 0; k < mt.Vtable.Count; k++)
            {
                uint target = mt.Vtable[k];
                if (target == 0 || !code(target) || parent != null && k < parent.Vtable.Count && parent.Vtable[k] == target) continue;
                if (!seen.Add(target)) continue;
                var overridden = parent != null && k < parent.Vtable.Count ? SlotMethod(parent, k, 0) : null;
                string method = overridden?.Name ?? $"vslot{k}";
                add(target, NativeName.Identifier($"{mt.Name}$${method}"),
                    $"virtual slot {k} of {mt.Name}" + (overridden != null ? $", overrides {overridden.Short}" : ""));
                starts.Add(target);
                named++;
            }
        }
        return named;
    }
}
