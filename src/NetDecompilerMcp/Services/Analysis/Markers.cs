using dnlib.DotNet;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Services.Analysis;

/// <summary>Protector names matched by marker, heuristic findings, and the ratio of unreadable names (0..1).</summary>
public sealed record MarkerFacts(IReadOnlyList<string> Tools, IReadOnlyList<string> Indicators, double UnreadableNameRatio);

/// <summary>
/// Matches type names and assembly / module attribute names against the marker types of known protectors (the markers
/// de4dot uses), and reports SuppressIldasmAttribute. Heuristics: the share of type / method / field names that are
/// unreadable or one or two characters long (reported at 30% or more of at least 20 names), up to 3 static methods that
/// take one or two integers, return a string and are called from 10 or more methods, and methods without an IL body
/// that are not abstract, P/Invoke, internal-call, runtime or interface methods.
/// </summary>
public static class Markers
{
    /// <summary>Marker type full names (exact, or prefix when ending in '*'; contains when starting with '*').</summary>
    private static readonly (string Tool, string[] KnownMarkers)[] KnownMarkers =
    [
        ("Confuser / ConfuserEx", ["ConfusedByAttribute"]),
        ("Dotfuscator", ["DotfuscatorAttribute"]),
        ("SmartAssembly", ["SmartAssembly.Attributes.PoweredByAttribute*"]),
        ("Babel.NET", ["BabelAttribute", "BabelObfuscatorAttribute"]),
        ("Crypto Obfuscator", ["CryptoObfuscator.ProtectedWithCryptoObfuscatorAttribute"]),
        ("Agile.NET (CliSecure)", ["SecureTeam.Attributes.ObfuscatedByCliSecureAttribute*", "SecureTeam.Attributes.ObfuscatedByAgileDotNetAttribute*"]),
        ("Goliath.NET", ["*ObfuscatedByGoliath"]),
        ("Xenocode", ["Xenocode.Client.Attributes.AssemblyAttributes.ProcessedByXenocode", "Xenocode.User.Attributes.AssemblyAttributes.ProcessedByXenoCode"]),
        ("Spices.Net", ["NineRays.Obfuscator.Evaluation", "NineRays.Obfuscator.SoftwareWatermarkAttribute"]),
    ];

    private const double UnreadableThreshold = 0.3;
    private const int DecryptorMinCallers = 10;

    public static MarkerFacts Detect(ModuleScan scan)
    {
        var module = scan.Module;
        var tools = new List<string>();
        var indicators = new List<string>();

        var names = new HashSet<string>(StringComparer.Ordinal);
        List<TypeDef> types;
        try { types = module.GetTypes().ToList(); } catch (Exception) { types = []; }
        foreach (var t in types) names.Add(t.FullName);
        try
        {
            foreach (var ca in (module.Assembly?.CustomAttributes ?? []).Concat(module.CustomAttributes))
                if (ca.AttributeType?.FullName is { } n) names.Add(n);
        }
        catch (Exception) { /* unreadable attributes */ }

        foreach (var (tool, markers) in KnownMarkers)
            if (markers.Any(m => names.Any(n => Matches(n, m))))
                tools.Add(tool);
        if (names.Contains("System.Runtime.CompilerServices.SuppressIldasmAttribute"))
            indicators.Add("SuppressIldasmAttribute: asks ILDASM not to disassemble the assembly (common in protected code).");

        // unreadable or minimal identifiers
        int total = 0, unreadable = 0;
        foreach (var t in types)
        {
            foreach (var name in new[] { t.Name.String }.Concat(t.Methods.Where(m => !m.IsSpecialName && !m.IsRuntimeSpecialName).Select(m => m.Name.String))
                         .Concat(t.Fields.Where(f => !f.IsSpecialName).Select(f => f.Name.String)))
            {
                if (name.Length == 0 || name[0] == '<' || name.StartsWith("CS$", StringComparison.Ordinal)) continue; // compiler-generated
                total++;
                if (IsUnreadable(name)) unreadable++;
            }
        }
        double ratio = total == 0 ? 0 : Math.Round((double)unreadable / total, 3);
        if (total >= 20 && ratio >= UnreadableThreshold)
            indicators.Add($"{ratio:P0} of {total} type / method / field names are unreadable or one or two characters long (renamed).");

        // string decryptor: static, returns string, takes only integers, called from many methods
        var decryptors = scan.Calls
            .Where(c => c.Target is MethodDef { IsStatic: true, MethodSig: { } sig } md && md.Module == module // no signature: corrupt metadata
                        && sig.RetType?.ElementType == ElementType.String
                        && sig.Params.Count is 1 or 2
                        && sig.Params.All(p => p?.ElementType is ElementType.I4 or ElementType.U4 or ElementType.I8))
            .GroupBy(c => (MethodDef)c.Target)
            .Select(g => (Method: g.Key, Callers: g.Select(c => c.Caller).Distinct().Count()))
            .Where(x => x.Callers >= DecryptorMinCallers)
            .OrderByDescending(x => x.Callers).Take(3);
        foreach (var (method, callers) in decryptors)
            indicators.Add($"Possible string decryptor {Format.MemberLabel(method)}: an int -> string method called from {callers} methods.");

        // bodies that should be there
        int missing = types.SelectMany(t => t.Methods).Count(m => m.RVA == 0 && !m.IsAbstract && !m.IsPinvokeImpl && !m.IsInternalCall
                                                                  && !m.IsRuntime && m.DeclaringType?.IsInterface != true);
        if (missing > 0)
            indicators.Add($"{missing} method(s) have no IL body although they should (encrypted or stripped bodies, or a reference assembly).");

        return new MarkerFacts(tools, indicators, ratio);
    }

    private static bool Matches(string name, string marker) =>
        marker.StartsWith('*') ? name.Contains(marker[1..], StringComparison.Ordinal)
        : marker.EndsWith('*') ? name.StartsWith(marker[..^1], StringComparison.Ordinal)
        : name == marker;

    /// <summary>Not a plausible hand-written identifier: control / private-use / zero-width characters, or 1-2 characters.</summary>
    internal static bool IsUnreadable(string name)
    {
        var bare = name.Split('`')[0];
        if (bare.Length <= 2) return true;
        foreach (var c in bare)
        {
            if (char.IsControl(c) || char.IsWhiteSpace(c)) return true;
            var cat = char.GetUnicodeCategory(c);
            if (cat is System.Globalization.UnicodeCategory.PrivateUse or System.Globalization.UnicodeCategory.Format
                or System.Globalization.UnicodeCategory.OtherNotAssigned or System.Globalization.UnicodeCategory.Surrogate) return true;
        }
        return false;
    }
}

/// <summary>A way into the assembly's code: what kind of entry point, and the method or type.</summary>
public sealed record EntryPoint(string Kind, string Member);

/// <summary>
/// Entry points of an assembly: Main, the module initializer (&lt;Module&gt;'s static constructor, run when the assembly
/// is loaded), [ModuleInitializer] methods, native exports (metadata export info, and the PE export table up to 200
/// names), COM (un)registration functions, and types deriving from Installer, ServiceBase or AppDomainManager.
/// Corrupt metadata ends the metadata part early; what was found until then is returned.
/// </summary>
public static class EntryPoints
{
    private static readonly (string BaseType, string Kind)[] HostedBases =
    [
        ("System.Configuration.Install.Installer", "installer class (run by InstallUtil.exe)"),
        ("System.ServiceProcess.ServiceBase", "Windows service (OnStart runs when the service starts)"),
        ("System.AppDomainManager", "AppDomainManager (runs inside any host configured to use it)"),
    ];

    public static List<EntryPoint> Find(ModuleDef module, byte[]? image)
    {
        var list = new List<EntryPoint>();
        try
        {
            if (module.EntryPoint is { } main) list.Add(new EntryPoint("Main", Format.MemberLabel(main)));
            if (module.GlobalType?.FindStaticConstructor() is { } cctor)
                list.Add(new EntryPoint("module initializer (runs when the assembly is loaded)", Format.MemberLabel(cctor)));
            foreach (var type in module.GetTypes())
            {
                foreach (var m in type.Methods)
                {
                    if (m.CustomAttributes.IsDefined("System.Runtime.CompilerServices.ModuleInitializerAttribute"))
                        list.Add(new EntryPoint("[ModuleInitializer] method", Format.MemberLabel(m)));
                    if (m.ExportInfo is { } export)
                        list.Add(new EntryPoint($"native export '{export.Name ?? m.Name}'", Format.MemberLabel(m)));
                    if (m.CustomAttributes.IsDefined("System.Runtime.InteropServices.ComRegisterFunctionAttribute")
                        || m.CustomAttributes.IsDefined("System.Runtime.InteropServices.ComUnregisterFunctionAttribute"))
                        list.Add(new EntryPoint("COM (un)registration function (run by regasm.exe)", Format.MemberLabel(m)));
                }
                foreach (var (baseType, kind) in HostedBases)
                    if (DerivesFrom(type, baseType)) list.Add(new EntryPoint(kind, type.FullName));
            }
        }
        catch (Exception) { /* corrupt metadata: report what was found */ }

        // exports the metadata does not describe (mixed-mode or post-processed images)
        if (image != null && PeImage.TryParse(image) is { } pe)
            foreach (var name in pe.Exports(image, 200).Where(n => !list.Any(e => e.Kind.Contains($"'{n}'", StringComparison.Ordinal))))
                list.Add(new EntryPoint($"native export '{name}'", name));
        return list;
    }

    private static bool DerivesFrom(TypeDef type, string baseFullName)
    {
        var current = type.BaseType;
        for (int depth = 0; current != null && depth < 32; depth++)
        {
            if (current.FullName == baseFullName) return true;
            current = MetadataUtil.Try(() => current.ResolveTypeDef())?.BaseType;
        }
        return false;
    }
}
