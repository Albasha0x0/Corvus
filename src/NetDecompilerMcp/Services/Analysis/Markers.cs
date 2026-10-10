using dnlib.DotNet;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Services.Analysis;

/// <summary>Toolchains matched by marker, heuristic findings, and the unreadable-name ratio (0..1).</summary>
public sealed record MarkerFacts(IReadOnlyList<string> Tools, IReadOnlyList<string> Indicators, double UnreadableNameRatio);

/// <summary>
/// Detects toolchain marker types (as used by de4dot) and SuppressIldasmAttribute, plus heuristics: renamed
/// identifiers, int -> string decoder methods, and methods missing an IL body.
/// </summary>
public static class Markers
{
    /// <summary>Marker type full names: exact, prefix when ending in '*', substring when starting with '*'.</summary>
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
        ("Beebyte Obfuscator", ["Beebyte.Obfuscator.*"]),
    ];

    /// <summary>The toolchains whose marker types or attributes are among <paramref name="fullNames"/>.</summary>
    public static List<string> ToolsFromNames(IReadOnlyCollection<string> fullNames) =>
        [.. KnownMarkers.Where(k => k.KnownMarkers.Any(m => fullNames.Any(n => Matches(n, m)))).Select(k => k.Tool)];

    private const double UnreadableThreshold = 0.3;
    private const int DecoderMinCallers = 10;

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
        catch (Exception) { }

        tools.AddRange(ToolsFromNames(names));
        if (names.Contains("System.Runtime.CompilerServices.SuppressIldasmAttribute"))
            indicators.Add("SuppressIldasmAttribute: asks ILDASM not to disassemble the assembly (common in post-processed code).");

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

        // String decoder: static, int parameters only, returns string, called from many methods.
        var decoders = scan.Calls
            .Where(c => c.Target is MethodDef { IsStatic: true, MethodSig: { } sig } md && md.Module == module
                        && sig.RetType?.ElementType == ElementType.String
                        && sig.Params.Count is 1 or 2
                        && sig.Params.All(p => p?.ElementType is ElementType.I4 or ElementType.U4 or ElementType.I8))
            .GroupBy(c => (MethodDef)c.Target)
            .Select(g => (Method: g.Key, Callers: g.Select(c => c.Caller).Distinct().Count()))
            .Where(x => x.Callers >= DecoderMinCallers && LooksLikeDecoder(x.Method))
            .OrderByDescending(x => x.Callers).Take(3);
        foreach (var (method, callers) in decoders)
            indicators.Add($"Possible string decoder {Format.MemberLabel(method)}: an int -> string method called from {callers} methods.");

        // Concrete, non-native methods must have an IL body.
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

    /// <summary>
    /// True when the method uses XOR, indexes static array / string data, or calls a decoding API; formatting helpers do not.
    /// </summary>
    private static bool LooksLikeDecoder(MethodDef method)
    {
        var body = MetadataUtil.SafeInstructions(method);
        if (body.Count == 0) return true; // unreadable body: rely on the call-count heuristic
        bool staticData = false, element = false;
        foreach (var i in body)
        {
            switch (i.OpCode.Code)
            {
                case dnlib.DotNet.Emit.Code.Xor:
                    return true;
                case dnlib.DotNet.Emit.Code.Ldsfld or dnlib.DotNet.Emit.Code.Ldsflda:
                    if (i.Operand is IField f && (f.FieldSig?.Type is SZArraySig || f.FieldSig?.Type?.ElementType == ElementType.String || i.OpCode.Code == dnlib.DotNet.Emit.Code.Ldsflda))
                        staticData = true;
                    break;
                case dnlib.DotNet.Emit.Code.Call or dnlib.DotNet.Emit.Code.Callvirt:
                    var target = (i.Operand as IMethod)?.FullName ?? "";
                    if (target.Contains("Encoding::GetString", StringComparison.Ordinal) || target.Contains("Convert::FromBase64", StringComparison.Ordinal)
                        || target.Contains("System.String::Intern", StringComparison.Ordinal))
                        return true;
                    if (target.Contains("System.String::get_Chars", StringComparison.Ordinal)) element = true;
                    break;
                default:
                    if (i.OpCode.Code.ToString().StartsWith("Ldelem", StringComparison.Ordinal)) element = true;
                    break;
            }
        }
        return staticData && element;
    }

    /// <summary>Not a plausible hand-written identifier: 1-2 characters, or control / private-use / format characters.</summary>
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

/// <summary>An entry point kind and the method or type it refers to.</summary>
public sealed record EntryPoint(string Kind, string Member);

/// <summary>
/// Finds code that runs without an explicit call: Main, module initializers, native exports, COM registration
/// functions and hosted base types (Installer, ServiceBase, AppDomainManager). Returns partial results on corrupt metadata.
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
        catch (Exception) { }

        // PE exports not described by metadata (mixed-mode or post-processed images).
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
