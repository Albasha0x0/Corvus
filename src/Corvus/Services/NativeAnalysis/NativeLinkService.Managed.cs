using System.Runtime.CompilerServices;
using System.Text;
using dnlib.DotNet;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Code;
using Corvus.Native.Linking;

namespace Corvus.Services;

/// <summary>Managed -> native: P/Invoke declarations bound to exports, and native export symbols matched back to them.</summary>
public sealed partial class NativeLinkService
{
    private readonly ConditionalWeakTable<LoadedAssembly, Dictionary<MethodDef, Binding>> _pinvokes = new();

    /// <summary>A native export a symbol names, bound like an import; <see cref="Keys"/> identify the code it reaches.</summary>
    public sealed record NativeTarget(NativeSymbol Symbol, Binding Binding, IReadOnlySet<string> Keys)
    {
        public string Label => Describe(Binding);
    }

    /// <summary>A P/Invoke declaration (or other managed method with a native implementation) bound to native code.</summary>
    public sealed record ManagedLink(LoadedAssembly Assembly, MethodDef Method, Binding Binding, string Kind);

    /// <summary>A [DllImport] method's binding under the runtime's lookup rules, thunks followed; null without an ImplMap.</summary>
    public Binding? BindPInvoke(LoadedAssembly asm, MethodDef method)
    {
        if (method.ImplMap is not { } map) return null;
        Binding b;
        using (AssemblyWorkspace.Lock(_sync))
        {
            var linker = Linker();
            var cache = _pinvokes.GetValue(asm, _ => []);
            if (!cache.TryGetValue(method, out b!)) cache[method] = b = BindPInvokeCore(linker, asm, method, map);
        }
        return FollowThunks(b);
    }

    private Binding BindPInvokeCore(NativeLinker linker, LoadedAssembly asm, MethodDef method, ImplMap map)
    {
        var (module, entry, charSet, callConv) = NativeImportVerifier.Describe(method, map);
        Binding NotChecked(string why) => new(new LinkResult(NativeLinker.NotChecked, module, null, [], why), Unresolved, null, null);
        if (NativeImportVerifier.RuntimeResolved(module) is { } runtime) return NotChecked(runtime);
        if (!OperatingSystem.IsWindows()) return NotChecked("DLL lookup is done on Windows hosts only");
        bool x86 = NativeImportVerifier.IsX86(asm.Module);
        LinkResult link;
        if (entry.StartsWith('#'))
            link = uint.TryParse(entry.AsSpan(1), out var ordinal)
                ? linker.Bind(module, asm.FilePath, x86, null, ordinal, "pinvoke", runtimeFolder: true)
                : new LinkResult(NativeLinker.MissingOrdinal, module, null, [], $"'{entry}' is not an ordinal");
        else
        {
            int? stack = null;
            if (x86 && callConv is "StdCall" or "Winapi")
                try { stack = NativeImportVerifier.StackBytes(method); }
                catch (Exception ex) when (ex is not OperationCanceledException) { stack = null; }
            var candidates = NativeImportVerifier.Candidates(entry, charSet, map.IsNoMangle, stack).Select(c => c.Name).ToList();
            link = linker.BindFirst(module, asm.FilePath, x86, candidates, "pinvoke", runtimeFolder: true).Result;
        }
        if (link.Status == NativeLinker.DllNotFound && NativeImportVerifier.IsRuntimeLibrary(module))
            return NotChecked("a .NET runtime native library linked into the runtime here (no separate DLL)");
        return Classify(link);
    }

    /// <summary>Bindings of every P/Invoke declaration of <paramref name="asm"/>.</summary>
    public IEnumerable<Binding> PInvokeBindings(LoadedAssembly asm)
    {
        foreach (var type in asm.Module.GetTypes())
            foreach (var m in type.Methods)
                if (m.ImplMap != null && BindPInvoke(asm, m) is { } b)
                    yield return b;
    }

    /// <summary>The native code a managed method runs instead of IL (P/Invoke binding or mixed-mode body); null for ordinary methods.</summary>
    public ManagedLink? NativeOf(MethodDef method)
    {
        var asm = workspace.FindByModule(method.Module);
        if (asm == null) return null;
        if (method.ImplMap != null)
            return BindPInvoke(asm, method) is { } b ? new ManagedLink(asm, method, b, "P/Invoke") : null;
        return NativeBody(asm, method);
    }

    /// <summary>Resolves a native symbol to the export (or address) it names; throws NotFound with the reason when it does not resolve.</summary>
    public NativeTarget Resolve(NativeSymbol symbol)
    {
        LinkResult link;
        using (AssemblyWorkspace.Lock(_sync))
        {
            var linker = Linker();
            var loaded = workspace.FindNative(symbol.Image) ?? workspace.FindNative(symbol.Image + ".dll");
            bool x86 = loaded != null && IsX86(loaded.Image);
            string? file = loaded?.FilePath;
            if (file == null)
            {
                var (found, searched) = linker.Locate(symbol.Image, null, x86);
                file = found ?? throw new ToolError(ErrorCode.NotFound, $"No native image '{symbol.Image}' is loaded or found (searched {string.Join("; ", searched)}).",
                    "load it with load_assembly, or name it by its full path: native:C:\\path\\name.dll!Export");
            }
            uint? ordinal = symbol.Export.StartsWith('#') && uint.TryParse(symbol.Export.AsSpan(1), out var o) ? o : null;
            link = linker.Bind(file, null, x86, ordinal == null ? symbol.Export : null, ordinal, "symbol");
            if (!link.IsResolved && loaded != null && link.Status is NativeLinker.MissingExport or NativeLinker.MissingOrdinal
                && Address(loaded, symbol.Export) is { } rva)
                link = new LinkResult(NativeLinker.Resolved, symbol.Image, file, [new LinkHop(file, symbol.Export, 0, rva, null, "address")], "address");
        }
        if (!link.IsResolved)
            throw new ToolError(ErrorCode.NotFound, $"{symbol} does not resolve: {link.Status}: {link.Detail}",
                "list_exports shows the exports; for a loaded image an address or function name works too");
        Binding b;
        using (AssemblyWorkspace.Lock(_sync)) b = Classify(link);
        b = FollowThunks(b);
        var keys = new HashSet<string>(StringComparer.Ordinal) { link.Hops[0].Key };
        if (b.Link.Final is { } final) keys.Add(final.Key);
        return new NativeTarget(symbol, b, keys);
    }

    private uint? Address(LoadedNative native, string text)
    {
        try { return NativeAddress.Parse(native.Image, text, code.Ready(native) is { } index ? index.AddressesOfName : null); }
        catch (ToolError) { return null; }
    }

    /// <summary>Managed methods bound to the code <paramref name="target"/> names: P/Invoke declarations (and native bodies in mixed-mode images).</summary>
    public List<ManagedLink> ManagedLinksTo(NativeTarget target, CancellationToken ct)
    {
        var result = new List<ManagedLink>();
        foreach (var asm in workspace.Assemblies)
            foreach (var type in asm.Module.GetTypes())
                foreach (var m in type.Methods)
                {
                    ct.ThrowIfCancellationRequested();
                    if (m.ImplMap == null && !(m.RVA != 0 && (m.IsNative || m.IsUnmanaged))) continue;
                    if (NativeOf(m) is { } link && link.Binding.Link.Hops.Any(h => target.Keys.Contains(h.Key)))
                        result.Add(link);
                }
        return result;
    }

    /// <summary>Calls through imports naming <paramref name="symbol"/> in every indexed image, loaded provider or not.</summary>
    public List<(LoadedNative Image, NativeImport Import, NativeFunction Caller, uint Site)> ImportCallers(NativeSymbol symbol, CancellationToken ct)
    {
        var result = new List<(LoadedNative, NativeImport, NativeFunction, uint)>();
        foreach (var native in workspace.Natives)
        {
            ct.ThrowIfCancellationRequested();
            if (code.Ready(native) is not { } index) continue;
            foreach (var import in native.Image.Imports)
                if (NativeAddress.ImportMatches(native.Image, import, symbol.Image, symbol.Export))
                    foreach (var c in index.Callers(import))
                        if (c.Caller is { } caller) result.Add((native, import, caller, c.From));
        }
        return result;
    }

    /// <summary>Native call sites of <paramref name="target"/> in every loaded image: direct calls to each hop with code, and calls through bound imports.</summary>
    public List<string> NativeCallSites(NativeTarget target, CancellationToken ct)
    {
        var rows = new List<string>();
        var done = new HashSet<(LoadedNative, uint)>();
        foreach (var hop in target.Binding.Link.Hops)
        {
            if (hop.Rva is not { } rva || LoadedAt(hop.File) is not { } image || !done.Add((image, rva))) continue;
            if (code.Ready(image) is { } index && index.FunctionByStart(rva) is { } fn)
                foreach (var c in index.Callers(fn))
                    rows.Add($"[{image.Id}] {NativeAddress.Va(image.Image, c.From)}  {c.Kind,-10} " +
                             $"{(c.Caller is { } f ? Format.Within(f.Name, f.Start, c.From) : "(no function)")}  calls {fn.Name}");
            rows.AddRange(ImportCallSites(image, rva, ct));
        }
        return rows;
    }

    /// <summary>The native function a bound binding reaches, when its image is indexed.</summary>
    public (LoadedNative Image, NativeFunction Function)? FunctionOf(Binding b) =>
        b is { Status: Bound, Target: { } t, Rva: { } rva } && code.Ready(t) is { } index && (index.FunctionByStart(rva) ?? index.FunctionAt(rva)) is { } fn
            ? (t, fn) : null;

    /// <summary>Callee-tree lines for a method with native code: "native: binding", then its native callees; empty for other methods.</summary>
    public string NativeCallees(MethodDef method, int levels, int indent, int maxNodes, CancellationToken ct, List<NativeTreeNode>? rows = null, int? parent = null)
    {
        if (levels < 1 || NativeOf(method) is not { } link) return "";
        var sb = new StringBuilder();
        var pad = new string(' ', indent * 2);
        sb.Append(pad).Append("native: ").Append(Describe(link.Binding));
        var fn = FunctionOf(link.Binding);
        string? state = link.Binding.Status switch { Bound => fn == null ? "unresolved" : null, NotLoaded => "not-loaded", _ => "unresolved" };
        if (link.Binding.Status == Bound && fn == null)
            sb.Append(code.Ready(link.Binding.Target!) == null ? "  (code index still building: repeat for its callees)" : "  (no function there)");
        sb.AppendLine();
        int? id = null;
        if (rows != null)
        {
            id = rows.Count;
            var b = link.Binding;
            rows.Add(new NativeTreeNode(rows.Count, parent, indent, fn?.Function.Name ?? b.Link.Module,
                b is { Status: Bound, Target: { } t, Rva: { } rva } ? NativeAddress.Va(t.Image, rva) : null, fn?.Image.Id ?? b.Target?.Id,
                link.Kind == "P/Invoke" ? "pinvoke" : "native", state != null ? [state] : null) { Note = Describe(b) });
        }
        if (fn is { } f && levels > 1)
            AppendTree(sb, f.Image, f.Function, callers: false, levels - 1, maxNodes, indent + 1, withRoot: false, ct, rows: rows, parent: id, home: null);
        return sb.ToString();
    }
}
