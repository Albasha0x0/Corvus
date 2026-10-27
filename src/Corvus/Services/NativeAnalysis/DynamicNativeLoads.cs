using System.ComponentModel;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Corvus.Core;

namespace Corvus.Services;

/// <summary>A place where an assembly loads native code at run time instead of through a static [DllImport].</summary>
public sealed record DynamicNativeLoad(
    [property: Description("native_library_load (NativeLibrary.Load/TryLoad), native_library_get_export (NativeLibrary.GetExport/TryGetExport), " +
                           "dll_import_resolver (NativeLibrary.SetDllImportResolver), load_library (a LoadLibrary/dlopen P/Invoke), " +
                           "get_proc_address (a GetProcAddress/dlsym P/Invoke), delegate_for_function_pointer (Marshal.GetDelegateForFunctionPointer).")] string Kind,
    [property: Description("The method containing the call.")] string Method,
    [property: Description("IL offset of the call.")] string IlOffset,
    [property: Description("The library name passed, when it is a constant (null otherwise).")] string? Library,
    [property: Description("The export name passed (or, for a delegate, looked up in the same method), when it is a constant.")] string? Export);

/// <summary>Finds run-time native loading in IL (NativeLibrary, LoadLibrary/dlopen P/Invokes, delegates), with constant names recovered.</summary>
public static class DynamicNativeLoads
{
    private const int MaxResults = 2000;
    private const int MaxBackward = 32;

    public static (List<DynamicNativeLoad> Loads, bool Truncated) Find(ModuleDef module, CancellationToken ct) =>
        Find(module.GetTypes().ToList(), (types, visit) =>
        {
            foreach (var t in types)
            {
                ct.ThrowIfCancellationRequested();
                if (!visit(t)) break;
            }
        });

    /// <param name="each">Visits the types in order until the visitor returns false (e.g. in short lock sections).</param>
    public static (List<DynamicNativeLoad> Loads, bool Truncated) Find(IReadOnlyList<TypeDef> types, Action<IReadOnlyList<TypeDef>, Func<TypeDef, bool>> each)
    {
        var loads = new List<DynamicNativeLoad>();
        bool truncated = false;
        // Per call target, not per call site; a stub never declares a P/Invoke, so missing references are not stubbed.
        var kinds = new Dictionary<IMethod, string?>();
        each(types, type =>
        {
            using var noStubs = AssemblyWorkspace.WithoutStubs();
            foreach (var method in type.Methods)
            {
                CilBody? body;
                try { body = method.HasBody ? method.Body : null; }
                // An unreadable body is skipped.
                catch (Exception ex) when (ex is not OperationCanceledException) { continue; }
                if (body == null) continue;
                var inMethod = new List<DynamicNativeLoad>();
                var instructions = body.Instructions;
                for (int i = 0; i < instructions.Count; i++)
                {
                    var ins = instructions[i];
                    if (ins.OpCode.Code is not (Code.Call or Code.Callvirt) || ins.Operand is not IMethod target) continue;
                    if (!kinds.TryGetValue(target, out var kind)) kinds[target] = kind = Classify(target);
                    if (kind == null) continue;
                    string? library = null, export = null;
                    int args = ArgumentCount(target);
                    try
                    {
                        if (kind is "native_library_load" or "load_library")
                            library = ConstantArgument(instructions, body.Variables, i, args, 0);
                        else if (kind is "native_library_get_export" or "get_proc_address")
                            export = ConstantArgument(instructions, body.Variables, i, args, 1);
                    }
                    // Malformed operands leave the name unknown.
                    catch (Exception ex) when (ex is not OperationCanceledException) { }
                    inMethod.Add(new DynamicNativeLoad(kind, Format.MemberLabel(method), $"IL_{ins.Offset:x4}", library, export));
                }
                if (inMethod.Count == 0) continue;
                // A library loaded once in the method is where its exports and delegates come from.
                var libraries = inMethod.Where(l => l.Library != null).Select(l => l.Library).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
                var exports = inMethod.Where(l => l.Export != null).Select(l => l.Export).Distinct(StringComparer.Ordinal).ToList();
                foreach (var load in inMethod)
                {
                    var item = load;
                    if (item.Kind is "native_library_get_export" or "get_proc_address" && item.Library == null && libraries.Count == 1)
                        item = item with { Library = libraries[0] };
                    if (item.Kind == "delegate_for_function_pointer" && exports.Count == 1)
                        item = item with { Export = exports[0], Library = libraries.Count == 1 ? libraries[0] : null };
                    loads.Add(item);
                    if (loads.Count >= MaxResults)
                    {
                        truncated = true;
                        return false;
                    }
                }
            }
            return true;
        });
        return (loads, truncated);
    }

    private static string? Classify(IMethod target)
    {
        var typeName = target.DeclaringType?.FullName;
        var name = target.Name.String;
        if (typeName == "System.Runtime.InteropServices.NativeLibrary")
            return name switch
            {
                "Load" or "TryLoad" => "native_library_load",
                "GetExport" or "TryGetExport" => "native_library_get_export",
                "SetDllImportResolver" => "dll_import_resolver",
                _ => null,
            };
        if (typeName == "System.Runtime.InteropServices.Marshal" && name == "GetDelegateForFunctionPointer")
            return "delegate_for_function_pointer";
        MethodDef? def;
        try { def = target.ResolveMethodDef(); }
        catch (Exception ex) when (ex is not OperationCanceledException) { def = null; }
        if (def?.ImplMap is not { } map) return null;
        var entry = map.Name?.String is { Length: > 0 } n ? n : def.Name.String;
        return entry switch
        {
            "LoadLibrary" or "LoadLibraryA" or "LoadLibraryW" or "LoadLibraryEx" or "LoadLibraryExA" or "LoadLibraryExW" or "LoadPackagedLibrary" or "dlopen"
                => "load_library",
            "GetProcAddress" or "dlsym" => "get_proc_address",
            _ => null,
        };
    }

    private static int ArgumentCount(IMethod method) => method.MethodSig is { } sig ? sig.Params.Count + (sig.HasThis ? 1 : 0) : 0;

    /// <summary>The string constant pushed as argument <paramref name="index"/>, found by walking back over straight-line code; null otherwise.</summary>
    internal static string? ConstantArgument(IList<Instruction> instructions, IList<Local> locals, int call, int argCount, int index)
    {
        if (index >= argCount) return null;
        // Values pushed after the wanted one.
        int above = argCount - 1 - index;
        for (int i = call - 1, steps = 0; i >= 0 && steps < MaxBackward; i--, steps++)
        {
            var ins = instructions[i];
            if (ins.OpCode.FlowControl is FlowControl.Branch or FlowControl.Cond_Branch or FlowControl.Return or FlowControl.Throw) return null;
            ins.CalculateStackUsage(out int pushes, out int pops);
            if (above < pushes)
                return ins.OpCode.Code == Code.Ldstr ? ins.Operand as string
                     : ins.IsLdloc() ? StoredConstant(instructions, locals, i, ins.GetLocal(locals)) : null;
            above += pops - pushes;
        }
        return null;
    }

    /// <summary>The ldstr stored to <paramref name="local"/> by the nearest stloc before <paramref name="at"/>.</summary>
    private static string? StoredConstant(IList<Instruction> instructions, IList<Local> locals, int at, Local? local)
    {
        if (local == null) return null;
        for (int i = at - 1, steps = 0; i > 0 && steps < MaxBackward; i--, steps++)
            if (instructions[i].IsStloc() && instructions[i].GetLocal(locals) == local)
                return instructions[i - 1].OpCode.Code == Code.Ldstr ? instructions[i - 1].Operand as string : null;
        return null;
    }

    /// <summary>A library name as the runtime matches it: file name without directory, extension or lib prefix, lowercase.</summary>
    public static string NormalizeLibrary(string name)
    {
        var file = name.Replace('\\', '/');
        file = file[(file.LastIndexOf('/') + 1)..].ToLowerInvariant();
        foreach (var ext in new[] { ".dll", ".so", ".dylib" })
            if (file.EndsWith(ext, StringComparison.Ordinal)) { file = file[..^ext.Length]; break; }
        int so = file.IndexOf(".so.", StringComparison.Ordinal);
        if (so > 0) file = file[..so];
        return file.StartsWith("lib", StringComparison.Ordinal) && file.Length > 3 ? file[3..] : file;
    }
}
