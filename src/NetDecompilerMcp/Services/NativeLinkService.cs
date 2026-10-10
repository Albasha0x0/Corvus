using System.Runtime.CompilerServices;
using System.Text;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Code;
using NetDecompilerMcp.Native.Linking;
using NetDecompilerMcp.Native.Pe;

namespace NetDecompilerMcp.Services;

/// <summary>
/// Cross-image navigation: binds the imports of loaded native images (and P/Invoke declarations of loaded assemblies)
/// to the export they reach, prefers images loaded in the workspace, and walks call trees across image boundaries.
/// Bindings are memoized per workspace state (the set of loaded images); thunk hops (a function that only jumps
/// through an import slot) are followed at query time when the provider's code index is built.
/// </summary>
public sealed partial class NativeLinkService(AssemblyWorkspace workspace, NativeCodeService code)
{
    public const string Bound = "bound", NotLoaded = "not_loaded", Unresolved = "unresolved";

    /// <summary>Most provider images <see cref="LoadProviders"/> loads in one call.</summary>
    public const int MaxProvidersPerCall = 16;

    private const int MaxDiskImages = 48;
    private const int MaxThunkHops = 4;

    /// <summary>
    /// An import or P/Invoke bound to code: <see cref="Status"/> is bound (the code is in <see cref="Target"/> at
    /// <see cref="Rva"/>), not_loaded (resolved to a file that is not loaded: <see cref="LinkResult.Final"/>) or
    /// unresolved (<see cref="Reason"/> says why). <see cref="Link"/> holds every hop, thunks included.
    /// </summary>
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

    // ---- state ----

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
        lock (_sync)
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

    /// <summary>
    /// Waits (at most <see cref="MaxWarmUp"/>) for the code indexes of <paramref name="natives"/> (all loaded images
    /// when null), so thunks and provider functions resolve; failures are skipped.
    /// </summary>
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

    // ---- imports ----

    /// <summary>Binds one import of <paramref name="importer"/>, following thunks in loaded providers.</summary>
    public Binding BindImport(LoadedNative importer, NativeImport import)
    {
        Binding b;
        lock (_sync) b = Classify(Linker().BindImport(importer.FilePath, IsX86(importer.Image), import));
        return FollowThunks(b);
    }

    /// <summary>Bindings of every import of <paramref name="importer"/>, in import order (thunks not followed).</summary>
    public IReadOnlyList<Binding> BindAll(LoadedNative importer, CancellationToken ct = default)
    {
        lock (_sync)
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

    /// <summary>
    /// Continues a bound binding through jump thunks (functions that only jump through an import slot, such as
    /// kernel32!CreateFileW -> KERNELBASE!CreateFileW) while the provider's index is built. The result stays bound to
    /// the last loaded code; a thunk into an image that is not loaded adds that hop for display only.
    /// </summary>
    public Binding FollowThunks(Binding b)
    {
        var current = b;
        for (int i = 0; i < MaxThunkHops && current is { Status: Bound, Target: { } target, Rva: { } rva }; i++)
        {
            if (code.Ready(target)?.FunctionByStart(rva) is not { ThunkImport: { } import } fn || (fn.Flags & FunctionFlags.Thunk) == 0) break;
            LinkResult inner;
            lock (_sync) inner = Linker().BindImport(target.FilePath, IsX86(target.Image), import);
            if (!inner.IsResolved) break;
            var hops = current.Link.Hops.Concat(inner.Hops.Select((h, k) => k == 0 ? h with { Via = "thunk" } : h)).ToList();
            var link = current.Link with { Hops = hops };
            Binding next;
            lock (_sync) next = Classify(inner);
            if (next.Status != Bound) return current with { Link = link };
            current = next with { Link = link };
        }
        return current;
    }

    /// <summary>
    /// Every (importer, import) in the loaded images whose binding reaches <paramref name="target"/> at
    /// <paramref name="rva"/> directly (thunks are code of their own image, reached as calls).
    /// </summary>
    public IReadOnlyList<(LoadedNative Importer, NativeImport Import)> ImportersOf(LoadedNative target, uint rva, CancellationToken ct = default)
    {
        Dictionary<(LoadedNative, uint), List<(LoadedNative, NativeImport)>> map;
        lock (_sync)
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

    /// <summary>
    /// Loads the provider images (final files of not-loaded bindings) of <paramref name="bindings"/>, at most
    /// <paramref name="max"/>; returns the loaded ids and the files left out. Never follows the new images' own imports.
    /// </summary>
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

    // ---- text ----

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

    // ---- cross-image call trees ----

    private sealed record TreeNode(LoadedNative Image, NativeFunction? Function, string Label)
    {
        public List<TreeNode> Children { get; } = [];
        public bool Repeated { get; set; }
        public bool Truncated { get; set; }
    }

    /// <summary>
    /// Callers or callees of <paramref name="root"/> in <paramref name="native"/>, several levels deep and across
    /// loaded images: callees continue from module!import into the provider's function, callers include call sites
    /// in other loaded images that import it. Written to <paramref name="sb"/> from indent <paramref name="indent"/>
    /// (the root line included when <paramref name="withRoot"/>); returns the number of nodes written.
    /// </summary>
    public int AppendTree(StringBuilder sb, LoadedNative native, NativeFunction root, bool callers, int depth, int maxNodes, int indent, bool withRoot,
        CancellationToken ct)
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
            var children = callers ? CallerNodes(n, native, ct) : CalleeNodes(n, native);
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
        void Write(TreeNode node, int level)
        {
            sb.Append(new string(' ', level * 2)).Append(node.Label)
              .Append(node.Repeated ? "  (repeated)" : "").Append(node.Truncated ? "  (more not shown)" : "").AppendLine();
            foreach (var child in node.Children) Write(child, level + 1);
        }
        if (withRoot) Write(top, indent);
        else foreach (var child in top.Children) Write(child, indent);
        return count;
    }

    /// <summary>Functions and imports <paramref name="node"/> calls; bound imports become nodes in the provider.</summary>
    private List<TreeNode> CalleeNodes(TreeNode node, LoadedNative home)
    {
        var result = new List<TreeNode>();
        if (code.Ready(node.Image) is not { } index) return result;
        var seen = new HashSet<(LoadedNative?, uint)>();
        foreach (var site in index.Callees(node.Function!))
        {
            if (site.Function is { } fn)
            {
                if (seen.Add((node.Image, fn.Start))) result.Add(new TreeNode(node.Image, fn, FunctionLabel(node.Image, fn, home)));
                continue;
            }
            if (site.Import is not { } import)
            {
                if (seen.Add((null, site.Target))) result.Add(new TreeNode(node.Image, null, NativeAddress.Va(node.Image.Image, site.Target)));
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
                    : new TreeNode(t, null, $"{name} -> {Describe(b)}" + (targetIndex == null ? " (its code index is not built yet)" : " (no function there: data or code not discovered)")));
            }
            else if (seen.Add((null, import.SlotRva)))
                result.Add(new TreeNode(node.Image, null, b.Status == NotLoaded ? $"{name} -> {Describe(b)}" : $"{name}  ({Describe(b)})"));
        }
        AddManagedCallees(result, node, index);
        return result;
    }

    /// <summary>Functions calling <paramref name="node"/>: in its image, and in loaded images through the import bound to it.</summary>
    private List<TreeNode> CallerNodes(TreeNode node, LoadedNative home, CancellationToken ct)
    {
        var result = new List<TreeNode>();
        var seen = new HashSet<(LoadedNative, uint)>();
        if (code.Ready(node.Image) is { } index)
            foreach (var site in index.Callers(node.Function!))
                if (site.Caller is { } caller && seen.Add((node.Image, caller.Start)))
                    result.Add(new TreeNode(node.Image, caller, FunctionLabel(node.Image, caller, home)));
        foreach (var (importer, import) in ImportersOf(node.Image, node.Function!.Start, ct))
        {
            if (code.Ready(importer) is not { } other)
            {
                result.Add(new TreeNode(importer, null, $"[{importer.Id}] imports it as {NativeCodeIndex.ImportName(import)} (its code index is not built yet)"));
                continue;
            }
            foreach (var (_, caller, _) in SlotUses(other, import))
                if (caller != null && seen.Add((importer, caller.Start)))
                    result.Add(new TreeNode(importer, caller, $"{FunctionLabel(importer, caller, home)}  (calls {NativeCodeIndex.ImportName(import)})"));
        }
        AddManagedCallers(result, node, ct);
        return result;
    }

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
                         $"{(caller is { } f ? $"{f.Name}+0x{x.From - f.Start:X}" : "(no function)")}  via {NativeCodeIndex.ImportName(import)}");
        }
        return rows;
    }
}
