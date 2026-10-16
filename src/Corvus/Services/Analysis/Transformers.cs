using System.ComponentModel;
using System.Text.RegularExpressions;
using dnlib.DotNet;
using Corvus.Core;

namespace Corvus.Services.Analysis;

/// <summary>A .NET transformation tool named from what it leaves in the module.</summary>
public sealed record TransformerFinding(string Name,
    [property: Description("marker (its type or attribute), strong or likely (the shape of its runtime code).")] string Confidence,
    IReadOnlyList<string> Evidence);

/// <summary>
/// Names the transformation tool of a module from its marker types and attributes and the shapes of the runtime code
/// it adds. Reads metadata and IL only; no pass runs.
/// </summary>
public static partial class Transformers
{
    private const int MaxEvidence = 4;

    /// <summary>The tools found; none when the metadata is too damaged to read (dnlib reads it lazily and throws on bad rows).</summary>
    public static List<TransformerFinding> Identify(ModuleDef module)
    {
        try { return Read(module); }
        catch (Exception) { return []; }
    }

    private static List<TransformerFinding> Read(ModuleDef module)
    {
        var found = new List<TransformerFinding>();
        List<TypeDef> types;
        try { types = [.. module.GetTypes()]; }
        catch (Exception) { return found; }
        var attributes = new HashSet<string>(StringComparer.Ordinal);
        try
        {
            foreach (var ca in (module.Assembly?.CustomAttributes ?? []).Concat(module.CustomAttributes))
                if (ca.AttributeType?.FullName is { } n) attributes.Add(n);
        }
        catch (Exception) { }
        var typeNames = types.Select(t => t.FullName).ToHashSet(StringComparer.Ordinal);
        bool Named(string name) => typeNames.Contains(name) || attributes.Contains(name) || typeNames.Any(t => t.EndsWith("." + name, StringComparison.Ordinal) || t == name);
        var global = module.GlobalType;
        var globalMethods = global?.Methods.ToList() ?? [];
        var cctorCalls = Calls(global?.FindStaticConstructor());

        void Add(string name, string confidence, List<string> evidence)
        {
            if (evidence.Count > 0) found.Add(new TransformerFinding(name, confidence, [.. evidence.Take(MaxEvidence)]));
        }

        // ConfuserEx: its runtime is merged into <Module>, started from <Module>.cctor
        var confuser = new List<string>();
        if (Named("ConfusedByAttribute")) confuser.Add("ConfusedByAttribute");
        foreach (var m in globalMethods.Where(m => m.IsStatic && m.HasGenericParameters && m.MethodSig is { } sig && sig.Params.Count == 1
                                                   && sig.Params[0].ElementType is ElementType.U4 or ElementType.I4 && sig.RetType is GenericMVar))
            confuser.Add($"constants decoder <Module>::{Safe(m.Name)}<T>({m.MethodSig!.Params[0].TypeName}) returning T");
        var globalImports = globalMethods.Where(m => m.IsPinvokeImpl && m.ImplMap != null).Select(m => m.ImplMap!.Name.String).ToHashSet(StringComparer.Ordinal);
        if (globalImports.Contains("VirtualProtect") && cctorCalls.Count > 0) confuser.Add("anti-tamper: <Module> P/Invokes VirtualProtect and its .cctor calls into <Module>");
        if (globalMethods.Any(m => Calls(m).Any(c => c.Contains("AppDomain::add_AssemblyResolve", StringComparison.Ordinal) || c.Contains("AppDomain::add_ResourceResolve", StringComparison.Ordinal))
                               && Calls(m).Any(c => c.Contains("Assembly::Load(System.Byte[])", StringComparison.Ordinal))))
            confuser.Add("resource protection: a <Module> method loads an assembly from bytes on ResourceResolve / AssemblyResolve");
        Add("ConfuserEx", Named("ConfusedByAttribute") ? "marker" : confuser.Any(e => e.StartsWith("constants", StringComparison.Ordinal)) ? "strong" : "likely",
            confuser.Count >= 2 || Named("ConfusedByAttribute") || confuser.Any(e => e.StartsWith("constants", StringComparison.Ordinal)) ? confuser : []);

        // SmartAssembly: its runtime keeps its namespaces
        var smart = types.Where(t => t.Namespace.String.StartsWith("SmartAssembly.", StringComparison.Ordinal)).Select(t => t.FullName).Take(3).ToList();
        if (Named("SmartAssembly.Attributes.PoweredByAttribute")) smart.Insert(0, "SmartAssembly.Attributes.PoweredByAttribute");
        Add("SmartAssembly", "marker", smart.Select(s => s.StartsWith("SmartAssembly.Attributes", StringComparison.Ordinal) ? s : "runtime type " + s).ToList());

        // Dotfuscator: its attribute, PreEmptive's namespaces
        var dotfuscator = new List<string>();
        if (Named("DotfuscatorAttribute")) dotfuscator.Add("DotfuscatorAttribute");
        dotfuscator.AddRange(types.Where(t => t.Namespace.String.StartsWith("PreEmptive.", StringComparison.Ordinal)).Select(t => "runtime type " + t.FullName).Take(2));
        Add("Dotfuscator", "marker", dotfuscator);

        // Babel: its attributes; its renamed members use private-use characters
        var babel = new List<string>();
        foreach (var n in new[] { "BabelAttribute", "BabelObfuscatorAttribute" }) if (Named(n)) babel.Add(n);
        Add("Babel.NET", "marker", babel);

        // .NET Reactor: <PrivateImplementationDetails>{GUID} holders, NecroBit's empty bodies
        var reactor = types.Where(t => ReactorHolder().IsMatch(t.Name.String)).Select(t => $"type {Safe(t.Name)}").Take(2).ToList();
        int stubs = types.SelectMany(t => t.Methods).Count(m => m.RVA == 0 && !m.IsAbstract && !m.IsPinvokeImpl && !m.IsInternalCall && !m.IsRuntime && m.DeclaringType?.IsInterface != true);
        if (reactor.Count > 0 && stubs > 0) reactor.Add($"{stubs} method(s) without an IL body (NecroBit moves bodies to native code)");
        Add(".NET Reactor", stubs > 0 ? "strong" : "likely", reactor);

        // Eazfuscator.NET: a string decoder reading an embedded resource, in a type whose name is a single non-printing character
        var eaz = new List<string>();
        foreach (var t in types.Where(t => t.Name.String.Length is 1 or 2 && !t.Name.String.All(char.IsAsciiLetterOrDigit)))
            foreach (var m in t.Methods.Where(m => m.IsStatic && m.MethodSig is { } sig && sig.RetType.ElementType == ElementType.String && sig.Params.Count == 1
                                                   && sig.Params[0].ElementType == ElementType.I4))
                if (Calls(m).Any(c => c.Contains("GetManifestResourceStream", StringComparison.Ordinal)) || Calls(m).Any(c => c.Contains("BinaryReader", StringComparison.Ordinal)))
                    eaz.Add($"string decoder {Safe(t.Name)}::{Safe(m.Name)}(int) reading an embedded resource");
        if (Named("EazfuscatorNETAttribute") || attributes.Any(a => a.Contains("Eazfuscator", StringComparison.Ordinal))) eaz.Insert(0, "Eazfuscator attribute");
        Add("Eazfuscator.NET", eaz.Any(e => e.Contains("attribute", StringComparison.Ordinal)) ? "marker" : "likely", eaz);
        return found;
    }

    // <PrivateImplementationDetails>{0F3A6D2B-...}
    [GeneratedRegex(@"^<PrivateImplementationDetails>\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$")]
    private static partial Regex ReactorHolder();

    private static List<string> Calls(MethodDef? method)
    {
        if (method == null) return [];
        return [.. MetadataUtil.SafeInstructions(method).Where(i => i.OpCode.Code is dnlib.DotNet.Emit.Code.Call or dnlib.DotNet.Emit.Code.Callvirt or dnlib.DotNet.Emit.Code.Newobj)
            .Select(i => (i.Operand as IMethod)?.FullName).OfType<string>()];
    }

    /// <summary>A name with non-printing characters escaped, as transformed names often have them.</summary>
    private static string Safe(UTF8String name) =>
        string.Concat(name.String.Select(c => char.IsControl(c) || char.GetUnicodeCategory(c) is System.Globalization.UnicodeCategory.Format
            or System.Globalization.UnicodeCategory.PrivateUse or System.Globalization.UnicodeCategory.SpaceSeparator ? $"\\u{(int)c:x4}" : c.ToString()));
}
