using Corvus.Core;
using Corvus.Native.Calls;
using Corvus.Native.Code;

namespace Corvus.Services;

/// <summary>
/// The loaded images a value trace crosses into: imports bound to code in a loaded image (thunks followed) and the call
/// sites in other loaded images that reach a function through their imports. Only images whose code index is built and
/// whose instruction set matches are entered (the calling convention must be the same on both sides).
/// </summary>
internal sealed class NativeTraceLinks : ITraceLinks
{
    private readonly NativeLinkService _link;
    private readonly NativeCodeService _code;
    private readonly Dictionary<NativeCodeIndex, LoadedNative> _natives = [];
    private readonly Dictionary<(ITraceHost, uint), (ITraceHost, NativeFunction)?> _providers = [];

    public NativeTraceLinks(AssemblyWorkspace workspace, NativeLinkService link, NativeCodeService code)
    {
        _link = link;
        _code = code;
        var natives = workspace.Read(() => workspace.Natives.ToList());
        foreach (var n in natives)
            if (code.Ready(n) is { } index) _natives.TryAdd(index, n);
        Key = string.Join(",", natives.Select(n => $"{n.Id}:{(code.Ready(n) != null ? 1 : 0)}"));
    }

    public string Key { get; }

    /// <summary>Whether another image could be entered at all (more than one indexed image is loaded).</summary>
    public bool Any => _natives.Count > 1;

    public string ImageOf(ITraceHost host) => _natives.TryGetValue(host.Index, out var n) ? n.Id : Path.GetFileName(host.Index.Image.Path);

    public (ITraceHost Host, NativeFunction Function)? Provider(ITraceHost host, uint slot)
    {
        if (_providers.TryGetValue((host, slot), out var hit)) return hit;
        (ITraceHost, NativeFunction)? result = null;
        if (_natives.TryGetValue(host.Index, out var importer) && host.Index.Image.Imports.FirstOrDefault(i => i.SlotRva == slot) is { } import
            && _link.BindImport(importer, import) is { Status: NativeLinkService.Bound, Target: { } target, Rva: { } rva }
            && _code.Ready(target) is { } index && index.FunctionByStart(rva) is { } f && HostOf(index) is { } other && Compatible(host, other))
            result = (other, f);
        _providers[(host, slot)] = result;
        return result;
    }

    public IReadOnlyList<(ITraceHost Host, uint Site, NativeFunction Caller)> Importers(ITraceHost host, NativeFunction f)
    {
        var result = new List<(ITraceHost, uint, NativeFunction)>();
        if (!_natives.TryGetValue(host.Index, out var target)) return result;
        foreach (var (importer, import) in _link.ImportersOf(target, f.Start))
            if (_code.Ready(importer) is { } index && HostOf(index) is { } other && Compatible(host, other))
                foreach (var c in index.Callers(import))
                    if (c.Caller != null) result.Add((other, c.From, c.Caller));
        return result.DistinctBy(r => (r.Item1, r.Item2)).ToList();
    }

    private ITraceHost? HostOf(NativeCodeIndex index)
    {
        if (!_natives.ContainsKey(index)) return null;
        if (Arm64Trace.Supports(index)) return Arm64Trace.For(index);
        return CallAnalysis.Supports(index) ? CallAnalysis.For(index) : null;
    }

    private static bool Compatible(ITraceHost a, ITraceHost b) => a.GetType() == b.GetType() && a.Is64 == b.Is64;
}
