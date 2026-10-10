using dnlib.DotNet;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Native.ReadyToRun;

/// <summary>
/// Names ReadyToRun signature tokens through dnlib modules. Module index 0 (and -1, the default context) is the
/// image's own module; in a single-assembly image 1..N are its AssemblyRef rows and higher indices continue with the
/// manifest metadata's AssemblyRef rows; in a composite image index i + <see cref="CompositeBias"/> is the manifest's row i (the components first).
/// Unresolvable tokens are named "[assembly]0x0A000123". Thread-safe.
/// </summary>
public sealed class R2RNamer : IR2RNames
{
    private readonly ModuleDef? _own;
    private readonly IReadOnlyList<string> _ownRefs;
    private readonly IReadOnlyList<string> _manifest;
    private readonly bool _composite;
    private readonly Func<string, ModuleDef?> _resolve;
    private readonly Dictionary<int, ModuleDef?> _modules = new();

    public R2RNamer(ModuleDef? own, IReadOnlyList<string> manifest, bool composite, Func<string, ModuleDef?> resolve)
    {
        _own = own;
        _manifest = manifest;
        _composite = composite;
        _resolve = resolve;
        var refs = new List<string>();
        if (own is ModuleDefMD md)
            for (uint rid = 1; rid <= md.TablesStream.AssemblyRefTable.Rows; rid++)
                refs.Add(md.ResolveAssemblyRef(rid)?.Name?.String ?? "?");
        _ownRefs = refs;
    }

    /// <summary>
    /// Module index of manifest row 0 in a composite image (observed with crossgen2 for .NET 10: signatures of
    /// System.Private.CoreLib methods use index 90 where CoreLib is manifest row 88).
    /// </summary>
    public const int CompositeBias = 2;

    /// <summary>The module index of component <paramref name="component"/> of a composite image (components lead the manifest).</summary>
    public static int ComponentModule(int component) => component + CompositeBias;

    /// <summary>The assembly a module index names, or null for the image's own module and unknown indices.</summary>
    public string? AssemblyNameAt(int index)
    {
        if (index <= 0) return null;
        if (_composite) return index - CompositeBias < _manifest.Count && index >= CompositeBias ? _manifest[index - CompositeBias] : null;
        if (index <= _ownRefs.Count) return _ownRefs[index - 1];
        int m = index - _ownRefs.Count - 1;
        return m < _manifest.Count ? _manifest[m] : null;
    }

    public ModuleDef? ModuleAt(int index)
    {
        if (index <= 0) return _own;
        lock (_modules)
        {
            if (_modules.TryGetValue(index, out var cached)) return cached;
            var name = AssemblyNameAt(index);
            ModuleDef? module = null;
            if (name != null)
            {
                module = _own?.Assembly?.Name.String.Equals(name, StringComparison.OrdinalIgnoreCase) == true ? _own : null;
                try { module ??= _resolve(name); }
                catch (Exception ex) when (ex is IOException or BadImageFormatException or UnauthorizedAccessException) { }
            }
            return _modules[index] = module;
        }
    }

    private string Unresolved(int module, uint token) => $"[{(module <= 0 ? "self" : AssemblyNameAt(module) ?? $"module {module}")}]0x{token:X8}";

    private T? Resolve<T>(int module, uint token) where T : class
    {
        var m = ModuleAt(module);
        if (m == null) return null;
        try { return m.ResolveToken(token) as T; }
        catch (Exception ex) when (ex is not OutOfMemoryException) { return null; }
    }

    public string Type(int module, uint token) =>
        Resolve<ITypeDefOrRef>(module, token)?.FullName ?? Unresolved(module, token);

    public string Method(int module, uint token, string? owner, IReadOnlyList<string>? methodArgs)
    {
        var m = Resolve<IMethod>(module, token);
        if (m == null) return Unresolved(module, token) + (methodArgs != null ? $"<{string.Join(", ", methodArgs)}>" : "");
        var args = methodArgs != null ? $"<{string.Join(", ", methodArgs)}>" : "";
        return $"{owner ?? m.DeclaringType?.FullName}::{m.Name}{args}({Format.ParameterTypes(m.MethodSig)})";
    }

    public string Field(int module, uint token, string? owner)
    {
        var f = Resolve<IField>(module, token);
        return f == null ? Unresolved(module, token) : $"{owner ?? f.DeclaringType?.FullName}::{f.Name}";
    }

    public string UserString(int module, uint offset)
    {
        if (ModuleAt(module) is not ModuleDefMD md) return Unresolved(module, 0x70000000 | offset);
        try { return "\"" + Format.Escape(Format.Clip(md.USStream.ReadNoNull(offset), 80)) + "\""; }
        catch (Exception ex) when (ex is not OutOfMemoryException) { return Unresolved(module, 0x70000000 | offset); }
    }
}
