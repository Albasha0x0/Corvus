using System.Runtime.CompilerServices;
using System.Text;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Code;
using Corvus.Native.Linking;
using Corvus.Native.Pe;

namespace Corvus.Services;

// Bindings are memoized per set of loaded images; thunk hops are followed at query time once the provider is indexed.
/// <summary>Cross-image navigation: binds imports and P/Invokes to the exports they reach and walks call trees across images.</summary>
public sealed partial class NativeLinkService(AssemblyWorkspace workspace, NativeCodeService code)
{
    public const string Bound = "bound", NotLoaded = "not_loaded", Unresolved = "unresolved";

    /// <summary>Most provider images <see cref="LoadProviders"/> loads in one call.</summary>
    public const int MaxProvidersPerCall = 16;

    private const int MaxDiskImages = 48;
    private const int MaxThunkHops = 4;

    /// <summary>An import or P/Invoke binding: bound (at <see cref="Target"/>+<see cref="Rva"/>), not_loaded, or unresolved with <see cref="Reason"/>.</summary>
    public sealed record Binding(LinkResult Link, string Status, LoadedNative? Target, uint? Rva)
    {
        public string Reason => Status == Unresolved ? Link.Status : "";
        /// <summary>The file the binding ends in (bound or not), or null when unresolved.</summary>
        public string? FinalFile => Link.Final?.File;
    }

    private readonly object _sync = new();
    private readonly Dictionary<string, (PeFile Image, DateTime Stamp, long Length, long Used)> _disk = new(StringComparer.OrdinalIgnoreCase);
    private long _clock;
    private string _stateKey = "";
    private NativeLinker? _linker;
    private Dictionary<string, LoadedNative> _byPath = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConditionalWeakTable<LoadedNative, Binding[]> _imports = new();
    private Dictionary<(LoadedNative, uint), List<(LoadedNative Importer, NativeImport Import)>>? _importers;

    /// <summary>The linker for the current set of loaded images; caches are dropped when that set changes.</summary>
    private NativeLinker Linker()
    {
        var natives = workspace.Natives;
        var key = string.Join("|", natives.Select(n => $"{n.FilePath}@{RuntimeHelpers.GetHashCode(n.Image)}"));
        if (_linker != null && key == _stateKey) return _linker;
        _stateKey = key;
        _byPath = new Dictionary<string, LoadedNative>(StringComparer.OrdinalIgnoreCase);
        foreach (var n in natives) _byPath.TryAdd(n.FilePath, n);
        _imports.Clear();
        _pinvokes.Clear();
        _importers = null;
        var byPath = _byPath;
        return _linker = new NativeLinker(
            path => byPath.TryGetValue(path, out var loaded) ? loaded.Image : OpenFromDisk(path),
            (name, x86) => byPath.Values.FirstOrDefault(n => Path.GetFileName(n.FilePath).Equals(name, StringComparison.OrdinalIgnoreCase)
                                                             && (n.Image.Arch == NativeArch.X86) == x86)?.FilePath);
    }

    private PeFile? OpenFromDisk(string path)
    {
        FileInfo info;
        try
        {
            info = new FileInfo(path);
            if (!info.Exists) return null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException) { return null; }
        if (_disk.TryGetValue(path, out var hit) && hit.Stamp == info.LastWriteTimeUtc && hit.Length == info.Length)
        {
            _disk[path] = hit with { Used = ++_clock };
            return hit.Image;
        }
        PeFile image;
        try { image = PeFile.Open(path); }
        catch (Exception ex) when (ex is ToolError or IOException or UnauthorizedAccessException) { return null; }
        if (_disk.Count >= MaxDiskImages) _disk.Remove(_disk.MinBy(kv => kv.Value.Used).Key);
        _disk[path] = (image, info.LastWriteTimeUtc, info.Length, ++_clock);
        return image;
    }

    /// <summary>The loaded native image with this full path, or null.</summary>
    public LoadedNative? LoadedAt(string? path)
    {
        if (path == null) return null;
        using (AssemblyWorkspace.Lock(_sync))
        {
            Linker();
            return _byPath.GetValueOrDefault(path);
        }
    }

    private static bool IsX86(INativeImage image) => image.Arch == NativeArch.X86;

    /// <summary>The image's code index when it is built (does not wait).</summary>
    public NativeCodeIndex? Index(LoadedNative native) => code.Ready(native);

    /// <summary>Longest wait of <see cref="WarmUp"/>; images still indexing after it are reported as such in results.</summary>
    public static readonly TimeSpan MaxWarmUp = TimeSpan.FromSeconds(30);

    /// <summary>Waits up to <see cref="MaxWarmUp"/> for the code indexes of <paramref name="natives"/> (all when null); failures are skipped.</summary>
    public async Task WarmUp(IEnumerable<LoadedNative>? natives, CancellationToken ct)
    {
        var list = (natives ?? workspace.Natives).Distinct().Where(n => code.Ready(n) == null).ToList();
        if (list.Count == 0) return;
        var all = Task.WhenAll(list.Select(async n =>
        {
            try { await code.Index(n, null, ct); }
            catch (ToolError) { }
        }));
        await Task.WhenAny(all, Task.Delay(MaxWarmUp, ct));
        ct.ThrowIfCancellationRequested();
    }

    /// <summary>Binds one import of <paramref name="importer"/>, following thunks in loaded providers.</summary>
    public Binding BindImport(LoadedNative importer, NativeImport import)
    {
        Binding b;
        using (AssemblyWorkspace.Lock(_sync)) b = Classify(Linker().BindImport(importer.FilePath, IsX86(importer.Image), import));
        return FollowThunks(b);
    }

    /// <summary>Bindings of every import of <paramref name="importer"/>, in import order (thunks not followed).</summary>
    public IReadOnlyList<Binding> BindAll(LoadedNative importer, CancellationToken ct = default)
    {
        using (AssemblyWorkspace.Lock(_sync))
        {
            var linker = Linker();
            if (_imports.TryGetValue(importer, out var cached)) return cached;
            var image = importer.Image;
            var result = new Binding[image.Imports.Count];
            for (int i = 0; i < result.Length; i++)
            {
                ct.ThrowIfCancellationRequested();
                result[i] = Classify(linker.BindImport(importer.FilePath, IsX86(image), image.Imports[i]));
            }
            _imports.AddOrUpdate(importer, result);
            return result;
        }
    }

    /// <summary>Call under <see cref="_sync"/>: bound when the final file is loaded.</summary>
    private Binding Classify(LinkResult link)
    {
        if (link.Final is not { } final) return new Binding(link, Unresolved, null, null);
        return _byPath.TryGetValue(final.File, out var loaded) && final.Rva is { } rva
            ? new Binding(link, Bound, loaded, rva)
            : new Binding(link, NotLoaded, null, null);
    }

    // A thunk into an image that is not loaded adds that hop for display only.
    /// <summary>Follows a bound binding through jump thunks in indexed providers; stays bound to the last loaded code.</summary>
    public Binding FollowThunks(Binding b)
    {
        var current = b;
        for (int i = 0; i < MaxThunkHops && current is { Status: Bound, Target: { } target, Rva: { } rva }; i++)
        {
            if (code.Ready(target)?.FunctionByStart(rva) is not { ThunkImport: { } import } fn || (fn.Flags & FunctionFlags.Thunk) == 0) break;
            LinkResult inner;
            using (AssemblyWorkspace.Lock(_sync)) inner = Linker().BindImport(target.FilePath, IsX86(target.Image), import);
            if (!inner.IsResolved) break;
            var hops = current.Link.Hops.Concat(inner.Hops.Select((h, k) => k == 0 ? h with { Via = "thunk" } : h)).ToList();
            var link = current.Link with { Hops = hops };
            Binding next;
            using (AssemblyWorkspace.Lock(_sync)) next = Classify(inner);
            if (next.Status != Bound) return current with { Link = link };
            current = next with { Link = link };
        }
        return current;
    }

    /// <summary>Every (importer, import) whose binding reaches <paramref name="target"/> at <paramref name="rva"/> directly, thunks excluded.</summary>
    public IReadOnlyList<(LoadedNative Importer, NativeImport Import)> ImportersOf(LoadedNative target, uint rva, CancellationToken ct = default)
    {
        Dictionary<(LoadedNative, uint), List<(LoadedNative, NativeImport)>> map;
        using (AssemblyWorkspace.Lock(_sync))
        {
            Linker();
            map = _importers ??= BuildImporters(ct);
        }
        return map.TryGetValue((target, rva), out var list) ? list : [];
    }

    private Dictionary<(LoadedNative, uint), List<(LoadedNative, NativeImport)>> BuildImporters(CancellationToken ct)
    {
        var map = new Dictionary<(LoadedNative, uint), List<(LoadedNative, NativeImport)>>();
        foreach (var importer in _byPath.Values)
        {
            var bindings = BindAll(importer, ct);
            for (int i = 0; i < bindings.Count; i++)
            {
                if (bindings[i] is not { Status: Bound, Target: { } t, Rva: { } r }) continue;
                if (!map.TryGetValue((t, r), out var list)) map[(t, r)] = list = [];
                list.Add((importer, importer.Image.Imports[i]));
            }
        }
        return map;
    }

    /// <summary>Counts of an image's import bindings: bound, not loaded, and unresolved by reason.</summary>
    public (int Bound, int NotLoaded, Dictionary<string, int> Unresolved) Summary(IReadOnlyList<Binding> bindings)
    {
        int bound = 0, notLoaded = 0;
        var unresolved = new Dictionary<string, int>();
        foreach (var b in bindings)
            switch (b.Status)
            {
                case Bound: bound++; break;
                case NotLoaded: notLoaded++; break;
                default: unresolved[b.Reason] = unresolved.GetValueOrDefault(b.Reason) + 1; break;
            }
        return (bound, notLoaded, unresolved);
    }

    /// <summary>Loads up to <paramref name="max"/> provider files of not-loaded bindings, one level only; returns loaded ids and skipped files.</summary>
    public (List<string> Loaded, List<string> Skipped) LoadProviders(IEnumerable<Binding> bindings, int max)
    {
        var files = bindings.Where(b => b.Status == NotLoaded && b.FinalFile != null).Select(b => b.FinalFile!)
            .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var loaded = new List<string>();
        var skipped = new List<string>();
        foreach (var file in files)
        {
            if (loaded.Count >= max) { skipped.Add(file); continue; }
            try
            {
                var (asm, native) = workspace.LoadAny(file);
                loaded.Add(native?.Id ?? asm?.Id ?? file);
            }
            catch (ToolError ex) { skipped.Add($"{file} ({ex.Message})"); }
        }
        return (loaded, skipped);
    }

    /// <summary>"kernel32.dll!CreateFileW -> KERNELBASE.dll!CreateFileW at 0x180012340 [KERNELBASE.dll]", or the not-loaded / unresolved form.</summary>
    public static string Describe(Binding b)
    {
        var chain = b.Link.Hops.Count > 0 ? b.Link.Chain : b.Link.Module;
        switch (b.Status)
        {
            case Bound:
                var va = NativeAddress.Va(b.Target!.Image, b.Rva!.Value);
                var last = b.Link.Hops[^1];
                return string.Equals(last.File, b.Target.FilePath, StringComparison.OrdinalIgnoreCase)
                    ? $"{chain} at {va} [{b.Target.Id}]"
                    : $"{chain} (code at {va} [{b.Target.Id}] jumps on to {last.Module}, which is not loaded: {last.File})";
            case NotLoaded:
                return $"{chain} in {b.FinalFile} (not loaded)";
            default:
                return $"{b.Link.Module}: unresolved ({b.Reason}): {b.Link.Detail}";
        }
    }

    /// <summary>Name of a function in a tree: its name, address, and the image when it differs from <paramref name="home"/>.</summary>
    private static string FunctionLabel(LoadedNative native, NativeFunction f, LoadedNative? home) =>
        $"{f.Name}  {NativeAddress.Va(native.Image, f.Start)}" + (native != home ? $"  [{native.Id}]" : "");

    /// <summary>A tree node: <see cref="Label"/> is its text line; the other fields are its <see cref="NativeTreeNode"/> row.</summary>
    private sealed record TreeNode(LoadedNative Image, NativeFunction? Function, string Label)
    {
        public List<TreeNode> Children { get; } = [];
        public bool Repeated { get; set; }
        public bool Truncated { get; set; }
        public string? Name { get; init; }
        public uint? Rva { get; init; }
        public string? Edge { get; init; }
        public string? Note { get; init; }
        /// <summary>unresolved or not-loaded.</summary>
        public string? State { get; init; }

        public NativeTreeNode Row(int id, int? parent, int depth, LoadedNative? home)
        {
            var flags = new List<string>();
            if (Repeated) flags.Add("repeated");
            if (Truncated) flags.Add("more");
            if (State != null) flags.Add(State);
            uint? rva = Rva ?? Function?.Start;
            return new NativeTreeNode(id, parent, depth, Name ?? Function?.Name ?? Label, rva is { } r ? NativeAddress.Va(Image.Image, r) : null,
                Image != home ? Image.Id : null, Edge, flags.Count > 0 ? flags : null) { Note = Note };
        }
    }

    /// <summary>The edge name of a call site: call, import, virtual or virtual?.</summary>
    private static string EdgeOf(Native.Code.CallSite site) => site.Kind switch
    {
        XrefKind.VirtualExact => "virtual",
        XrefKind.VirtualPossible => "virtual?",
        XrefKind.ImportCall or XrefKind.ImportJump => "import",
        _ => "call",
    };

    private static string? VirtualNote(NativeCodeIndex index, Native.Code.CallSite site) =>
        site.Kind == XrefKind.VirtualPossible ? $"one of {index.VirtualCalls.SiteAt(site.From)?.TargetCount ?? 0}" : null;

    /// <summary>Writes a caller or callee tree of <paramref name="root"/> across loaded images to <paramref name="sb"/>; returns the node count.</summary>
    /// <param name="rows">Receives the same nodes; top nodes hang under <paramref name="parent"/>; images other than <paramref name="home"/> are named.</param>
    public int AppendTree(StringBuilder sb, LoadedNative native, NativeFunction root, bool callers, int depth, int maxNodes, int indent, bool withRoot,
        CancellationToken ct, CallEdgeFilter edges = CallEdgeFilter.All, List<NativeTreeNode>? rows = null, int? parent = null, LoadedNative? home = null)
    {
        var top = new TreeNode(native, root, FunctionLabel(native, root, native));
        var expanded = new HashSet<(LoadedNative, uint)> { (native, root.Start) };
        int count = 1;
        var queue = new Queue<(TreeNode Node, int Depth)>();
        queue.Enqueue((top, 0));
        while (queue.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            var (n, d) = queue.Dequeue();
            if (n.Function == null) continue;
            var children = callers ? CallerNodes(n, native, ct, edges) : CalleeNodes(n, native, edges);
            if (d >= depth) { if (children.Count > 0) n.Truncated = true; continue; }
            foreach (var child in children)
            {
                if (count >= maxNodes) { n.Truncated = true; break; }
                count++;
                n.Children.Add(child);
                if (child.Function == null) continue;
                if (!expanded.Add((child.Image, child.Function.Start))) { child.Repeated = true; continue; }
                queue.Enqueue((child, d + 1));
            }
        }
        void Write(TreeNode node, int level, int? up)
        {
            sb.Append(new string(' ', level * 2)).Append(node.Label)
              .Append(node.Repeated ? "  (repeated)" : "").Append(node.Truncated ? "  (more not shown)" : "").AppendLine();
            int? id = null;
            if (rows != null)
            {
                id = rows.Count;
                rows.Add(node.Row(rows.Count, up, level, home));
            }
            foreach (var child in node.Children) Write(child, level + 1, id);
        }
        if (withRoot) Write(top, indent, parent);
        else foreach (var child in top.Children) Write(child, indent, parent);
        return count;
    }

    /// <summary>Functions and imports <paramref name="node"/> calls; bound imports become nodes in the provider.</summary>
    private List<TreeNode> CalleeNodes(TreeNode node, LoadedNative home, CallEdgeFilter edges)
    {
        var result = new List<TreeNode>();
        if (code.Ready(node.Image) is not { } index) return result;
        var seen = new HashSet<(LoadedNative?, uint)>();
        foreach (var site in index.Callees(node.Function!, edges))
        {
            if (site.Function is { } fn)
            {
                if (seen.Add((node.Image, fn.Start)))
                    result.Add(new TreeNode(node.Image, fn, FunctionLabel(node.Image, fn, home) + VirtualMark(index, site)) { Edge = EdgeOf(site), Note = VirtualNote(index, site) });
                continue;
            }
            if (site.Import is not { } import || site.Kind is XrefKind.VirtualExact or XrefKind.VirtualPossible)
            {
                if (seen.Add((null, site.Target)))
                    result.Add(new TreeNode(node.Image, null, NativeAddress.Va(node.Image.Image, site.Target) + VirtualMark(index, site))
                        { Name = NativeAddress.Va(node.Image.Image, site.Target), Rva = site.Target, Edge = EdgeOf(site), Note = VirtualNote(index, site), State = "unresolved" });
                continue;
            }
            var b = BindImport(node.Image, import);
            var name = NativeCodeIndex.ImportName(import);
            if (b is { Status: Bound, Target: { } t, Rva: { } rva })
            {
                if (!seen.Add((t, rva))) continue;
                var targetIndex = code.Ready(t);
                var fn2 = targetIndex?.FunctionByStart(rva) ?? targetIndex?.FunctionAt(rva);
                result.Add(fn2 != null
                    ? new TreeNode(t, fn2, $"{name} -> {Describe(b)}" + (fn2.Start != rva ? $" (inside {fn2.Name})" : ""))
                        { Name = name, Rva = rva, Edge = "import", Note = Describe(b) + (fn2.Start != rva ? $" (inside {fn2.Name})" : "") }
                    : new TreeNode(t, null, $"{name} -> {Describe(b)}" + (targetIndex == null ? " (its code index is not built yet)" : " (no function there: data or code not discovered)"))
                        { Name = name, Rva = rva, Edge = "import", Note = Describe(b), State = "unresolved" });
            }
            else if (seen.Add((null, import.SlotRva)))
                result.Add(new TreeNode(node.Image, null, b.Status == NotLoaded ? $"{name} -> {Describe(b)}" : $"{name}  ({Describe(b)})")
                    { Name = name, Rva = import.SlotRva, Edge = "import", Note = Describe(b), State = b.Status == NotLoaded ? "not-loaded" : "unresolved" });
        }
        if (edges == CallEdgeFilter.Virtual) return result;
        AddManagedCallees(result, node, index);
        // Late-bound imports called through a GetProcAddress pointer stored once.
        if (Native.Calls.CallAnalysis.Supports(index)
            && Native.Calls.CallAnalysis.For(index).DynamicImports().CallsByFunction.TryGetValue(node.Function!.Start, out var late))
            foreach (var (_, d) in late.DistinctBy(c => c.Import.FullName))
                result.Add(new TreeNode(node.Image, null, $"{d.FullName}  [dynamic]") { Name = d.FullName, Edge = "dynamic" });
        return result;
    }

    /// <summary>Functions calling <paramref name="node"/>: in its image, and in loaded images through the import bound to it.</summary>
    private List<TreeNode> CallerNodes(TreeNode node, LoadedNative home, CancellationToken ct, CallEdgeFilter edges)
    {
        var result = new List<TreeNode>();
        var seen = new HashSet<(LoadedNative, uint)>();
        if (code.Ready(node.Image) is { } index)
            foreach (var site in index.Callers(node.Function!, edges))
                if (site.Caller is { } caller && seen.Add((node.Image, caller.Start)))
                    result.Add(new TreeNode(node.Image, caller, FunctionLabel(node.Image, caller, home) + VirtualMark(index, site)) { Edge = EdgeOf(site), Note = VirtualNote(index, site) });
        if (edges == CallEdgeFilter.Virtual) return result;
        foreach (var (importer, import) in ImportersOf(node.Image, node.Function!.Start, ct))
        {
            if (code.Ready(importer) is not { } other)
            {
                result.Add(new TreeNode(importer, null, $"[{importer.Id}] imports it as {NativeCodeIndex.ImportName(import)} (its code index is not built yet)")
                    { Name = NativeCodeIndex.ImportName(import), Rva = import.SlotRva, Edge = "import", Note = "its code index is not built yet", State = "unresolved" });
                continue;
            }
            foreach (var (_, caller, _) in SlotUses(other, import))
                if (caller != null && seen.Add((importer, caller.Start)))
                    result.Add(new TreeNode(importer, caller, $"{FunctionLabel(importer, caller, home)}  (calls {NativeCodeIndex.ImportName(import)})")
                        { Edge = "import", Note = "calls " + NativeCodeIndex.ImportName(import) });
        }
        AddManagedCallers(result, node, ct);
        return result;
    }

    /// <summary>"  [virtual]" for a virtual_exact edge, "  [virtual?: one of n]" for a virtual_possible one, "" otherwise.</summary>
    internal static string VirtualMark(NativeCodeIndex index, Native.Code.CallSite site) => site.Kind switch
    {
        XrefKind.VirtualExact => "  [virtual]",
        XrefKind.VirtualPossible => $"  [virtual?: one of {index.VirtualCalls.SiteAt(site.From)?.TargetCount ?? 0}]",
        _ => "",
    };

    /// <summary>Calls and jumps through an import's slot with the function they are in (a jump thunk is its own caller).</summary>
    private static IEnumerable<(CodeXref Ref, NativeFunction? Caller, NativeImport Import)> SlotUses(NativeCodeIndex index, NativeImport import)
    {
        foreach (var x in index.RefsTo(import.SlotRva))
            if (x.Kind is XrefKind.ImportCall or XrefKind.ImportJump)
                yield return (x, index.FunctionAt(x.From), import);
    }

    /// <summary>Call sites in other loaded images that reach <paramref name="rva"/> of <paramref name="target"/> through an import.</summary>
    public List<string> ImportCallSites(LoadedNative target, uint rva, CancellationToken ct)
    {
        var rows = new List<string>();
        foreach (var (importer, import) in ImportersOf(target, rva, ct))
        {
            if (code.Ready(importer) is not { } index)
            {
                rows.Add($"[{importer.Id}] imports it as {NativeCodeIndex.ImportName(import)} (its code index is not built yet: repeat the call)");
                continue;
            }
            var sites = SlotUses(index, import).ToList();
            if (sites.Count == 0) rows.Add($"[{importer.Id}] imports it as {NativeCodeIndex.ImportName(import)}: no call sites found (slot {NativeAddress.Va(importer.Image, import.SlotRva)})");
            foreach (var (x, caller, _) in sites)
                rows.Add($"[{importer.Id}] {NativeAddress.Va(importer.Image, x.From)}  {x.Kind,-10} " +
                         $"{(caller is { } f ? Format.Within(f.Name, f.Start, x.From) : "(no function)")}  via {NativeCodeIndex.ImportName(import)}");
        }
        return rows;
    }
}
