using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using dnlib.DotNet;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Pe;
using NetDecompilerMcp.Native.ReadyToRun;

namespace NetDecompilerMcp.Services;

/// <summary>
/// Maps the managed methods of a ReadyToRun assembly to their precompiled native code and back. The code is in the
/// assembly itself or, for a component of a composite image, in the composite file next to it. Parsed once per
/// loaded image (composite files once per file); malformed ReadyToRun data becomes a typed error.
/// </summary>
public sealed class ReadyToRunService(AssemblyWorkspace workspace)
{
    private static readonly ConditionalWeakTable<byte[], Lazy<AssemblyCode?>> Cache = new();
    private static readonly ConcurrentDictionary<(string Path, DateTime Stamp), Lazy<(R2RImage Image, R2RCodeMap Map)>> Composites = new();
    private static readonly ConcurrentDictionary<(string Path, DateTime Stamp), Lazy<ModuleDef?>> FileModules = new();

    /// <summary>ReadyToRun facts and code of one loaded assembly.</summary>
    public sealed class AssemblyCode
    {
        private readonly ConcurrentDictionary<int, string> _labels = new();

        internal AssemblyCode(LoadedAssembly assembly, R2RImage header) { Assembly = assembly; Header = header; }

        public LoadedAssembly Assembly { get; }
        /// <summary>The assembly's own ReadyToRun header (for a component: version, flags and owner name only).</summary>
        public R2RImage Header { get; }
        /// <summary>The image holding the code: the assembly, or the composite image of a component.</summary>
        public R2RImage? CodeImage { get; internal set; }
        public R2RCodeMap? Map { get; internal set; }
        public string CodeFile { get; internal set; } = "";
        /// <summary>Component index in the composite image, -1 when the assembly holds its own code.</summary>
        public int Component { get; internal set; } = -1;
        /// <summary>Why there is no code map (a component whose composite image is missing or unreadable).</summary>
        public string? Problem { get; internal set; }
        public R2RNamer Namer { get; internal set; } = null!;
        public R2RSymbols Symbols { get; internal set; } = null!;
        /// <summary>MethodDef rid of this assembly -> its bodies (own code first, then compiled instantiations).</summary>
        public IReadOnlyDictionary<uint, List<R2RBody>> ByMethodDef { get; internal set; } = new Dictionary<uint, List<R2RBody>>();

        /// <summary>The managed name of a body: "Ns.Type::Method(int)" or an instantiation "Ns.List`1&lt;int&gt;::Add(T)".</summary>
        public string Label(R2RBody body) => _labels.GetOrAdd(body.Index, _ =>
        {
            var e = body.Entry;
            try
            {
                if (e.IsInstance)
                    return new R2RSignatures(CodeImage!.View, Namer).Method(new SigReader(CodeImage.View, e.SignatureRva), -1).Name ?? "?";
                int module = e.Component < 0 || e.Component == Component ? 0 : R2RNamer.ComponentModule(e.Component);
                return Namer.Method(module, 0x06000000 | e.MethodDefRid, null, null);
            }
            catch (R2RFormatException ex) { return $"(unreadable method signature: {ex.Message})"; }
        });

        /// <summary>The MethodDef of this assembly a body compiles, or null (another assembly's method, or unresolved).</summary>
        public MethodDef? MethodOf(R2RBody body)
        {
            var e = body.Entry;
            uint rid = 0;
            if (!e.IsInstance && (e.Component < 0 || e.Component == Component)) rid = e.MethodDefRid;
            else if (e.Signature is { IsMethodDef: true } sig && IsOwnModule(sig.TokenModule)) rid = sig.Token & 0x00FFFFFF;
            return rid == 0 ? null : Assembly.Module.ResolveMethod(rid);
        }

        internal bool IsOwnModule(int module) => Component < 0 ? module <= 0 : module == R2RNamer.ComponentModule(Component);
    }

    /// <summary>The assembly's ReadyToRun code, or null when it is not ReadyToRun.</summary>
    /// <exception cref="ToolError">MalformedInput when the ReadyToRun data is corrupt.</exception>
    public AssemblyCode? Get(LoadedAssembly asm, CancellationToken ct = default) => Load(workspace, asm, ct);

    /// <summary>As <see cref="Get"/>, but an Unsupported error when the assembly has no ReadyToRun code.</summary>
    public AssemblyCode Require(LoadedAssembly asm, CancellationToken ct = default)
    {
        var code = Get(asm, ct) ?? throw new ToolError(ErrorCode.Unsupported,
            $"{asm.Id} is not a ReadyToRun image: it carries IL only, no precompiled native code.",
            "decompile_member or get_il read its IL; ReadyToRun images come from crossgen (PublishReadyToRun), e.g. the .NET shared framework's assemblies");
        if (code.Map == null)
            throw new ToolError(ErrorCode.Unsupported, $"{asm.Id} is a component of the composite ReadyToRun image {code.Header.OwnerComposite}; its native code lives there. {code.Problem}",
                $"put {code.Header.OwnerComposite} next to {Path.GetFileName(asm.FilePath)} (it is published alongside it) and retry");
        return code;
    }

    private static AssemblyCode? Load(AssemblyWorkspace workspace, LoadedAssembly asm, CancellationToken ct)
    {
        var lazy = Cache.GetValue(asm.OriginalBytes, _ => new Lazy<AssemblyCode?>(() => Build(workspace, asm, CancellationToken.None)));
        try { return lazy.Value; }
        catch (ToolError)
        {
            Cache.Remove(asm.OriginalBytes); // retry on the next call: the error may come from a missing or changed composite file
            throw;
        }
    }

    private static AssemblyCode? Build(AssemblyWorkspace workspace, LoadedAssembly asm, CancellationToken ct)
    {
        try
        {
            var pe = PeFile.FromBytes(asm.OriginalBytes, asm.FilePath);
            if (R2RImage.FindHeader(pe) == 0) return null;
            var header = R2RImage.Open(pe, ct)!;
            var code = new AssemblyCode(asm, header);
            if (header.IsComponent) OpenComposite(code);
            else
            {
                code.CodeImage = header;
                code.Map = new R2RCodeMap(header);
                code.CodeFile = asm.FilePath;
            }
            var image = code.CodeImage ?? header;
            code.Namer = new R2RNamer(asm.Module, image.ManifestAssemblyRefs, image.IsComposite, name => ResolveModule(workspace, name, code.CodeFile.Length > 0 ? code.CodeFile : asm.FilePath));
            if (code.Map != null)
            {
                code.Symbols = new R2RSymbols(code.Map, code.Namer, code.Label);
                var byMethod = new Dictionary<uint, List<R2RBody>>();
                foreach (var body in code.Map.Bodies)
                {
                    var e = body.Entry;
                    uint rid = 0;
                    if (!e.IsInstance && e.Component == code.Component) rid = e.MethodDefRid;
                    else if (e.Signature is { IsMethodDef: true } sig && code.IsOwnModule(sig.TokenModule)) rid = sig.Token & 0x00FFFFFF;
                    if (rid == 0) continue;
                    if (!byMethod.TryGetValue(rid, out var list)) byMethod[rid] = list = [];
                    if (e.IsInstance) list.Add(body);
                    else list.Insert(0, body);
                }
                code.ByMethodDef = byMethod;
            }
            return code;
        }
        catch (Exception ex) when (ex is R2RFormatException or ArgumentException or IndexOutOfRangeException or OverflowException or InvalidOperationException)
        {
            throw new ToolError(ErrorCode.MalformedInput, $"The ReadyToRun data of {asm.Id} is malformed: {ex.Message}");
        }
    }

    /// <summary>Finds the composite image named by a component's header next to it and selects the component's methods.</summary>
    private static void OpenComposite(AssemblyCode code)
    {
        var owner = code.Header.OwnerComposite;
        var dir = Path.GetDirectoryName(code.Assembly.FilePath);
        if (string.IsNullOrEmpty(owner) || dir == null || owner.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
        {
            code.Problem = "The component names no composite image.";
            return;
        }
        var path = Path.Combine(dir, owner);
        if (!File.Exists(path))
        {
            code.Problem = $"{owner} is not next to it ({dir}).";
            return;
        }
        var key = (Path.GetFullPath(path), File.GetLastWriteTimeUtc(path));
        var lazy = Composites.GetOrAdd(key, k => new Lazy<(R2RImage, R2RCodeMap)>(() =>
        {
            var pe = PeFile.Open(k.Path);
            var image = R2RImage.Open(pe) ?? throw new R2RFormatException($"{owner} has no ReadyToRun header");
            return (image, new R2RCodeMap(image));
        }));
        (R2RImage Image, R2RCodeMap Map) composite;
        try { composite = lazy.Value; }
        catch (Exception ex) when (ex is R2RFormatException or ToolError)
        {
            Composites.TryRemove(key, out _);
            code.Problem = $"{owner} is unreadable: {ex.Message}";
            return;
        }
        var name = code.Assembly.AssemblyName;
        var component = composite.Image.Components.FirstOrDefault(c => string.Equals(c.Name, name, StringComparison.OrdinalIgnoreCase));
        if (component == null)
        {
            code.Problem = $"{owner} lists no component named {name}.";
            return;
        }
        code.CodeImage = composite.Image;
        code.Map = composite.Map;
        code.CodeFile = key.Item1;
        code.Component = component.Index;
    }

    /// <summary>A referenced assembly's module: a loaded assembly of that name, else the file found next to the image or in the framework.</summary>
    private static ModuleDef? ResolveModule(AssemblyWorkspace workspace, string name, string requesterPath)
    {
        var loaded = workspace.Assemblies.FirstOrDefault(a => string.Equals(a.AssemblyName, name, StringComparison.OrdinalIgnoreCase));
        if (loaded != null) return loaded.Module;
        var file = workspace.FindAssemblyFile(name, requesterPath);
        if (file == null) return null;
        var key = (Path.GetFullPath(file), File.GetLastWriteTimeUtc(file));
        return FileModules.GetOrAdd(key, k => new Lazy<ModuleDef?>(() =>
        {
            try { return ModuleDefMD.Load(File.ReadAllBytes(k.Path)); }
            catch (Exception ex) when (ex is IOException or BadImageFormatException or UnauthorizedAccessException) { return null; }
        })).Value;
    }

    /// <summary>
    /// One line for get_assembly_info: version, machine, methods with code and the composite layout; null when the
    /// assembly is not ReadyToRun. Never throws.
    /// </summary>
    public static string? Summary(AssemblyWorkspace workspace, LoadedAssembly asm)
    {
        AssemblyCode? code;
        try { code = Load(workspace, asm, CancellationToken.None); }
        catch (ToolError ex) { return $"ReadyToRun: unreadable ({ex.Message})"; }
        if (code == null) return null;
        var h = code.Header;
        var head = $"ReadyToRun: version {h.MajorVersion}.{h.MinorVersion}, {h.MachineName}{(h.TargetOs != "Windows" ? " " + h.TargetOs : "")}";
        if (code.Map == null) return $"{head}, component of composite image {h.OwnerComposite} (not found: {code.Problem}); get_r2r_code needs that file";
        int own = code.ByMethodDef.Count;
        int bodies = code.ByMethodDef.Values.Sum(l => l.Count);
        var layout = code.Component >= 0
            ? $"component {code.Component} of composite image {Path.GetFileName(code.CodeFile)} (code there)"
            : code.CodeImage!.IsComposite ? "composite" : "not composite";
        return $"{head}, {own} methods with native code ({bodies} bodies incl. generic instantiations), {layout}; get_r2r_code / find_r2r_method show it";
    }
}
