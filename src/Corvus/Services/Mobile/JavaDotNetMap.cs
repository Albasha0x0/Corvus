using System.ComponentModel;
using System.Text;
using dnlib.DotNet;
using Corvus.Core;
using Corvus.Core.Mobile;
using Corvus.Services.Analysis;

namespace Corvus.Services.Mobile;

public sealed record JavaDotNetPair(
    [property: Description("Java side: a class descriptor Lpkg/C; or a method id Lpkg/C;->name(sig)ret.")] string Java,
    [property: Description(".NET side: Ns.Type or Ns.Type::Method(params), what decompile_member takes.")] string DotNet,
    [property: Description("The assembly: its workspace id when loaded, else its path inside the package.")] string Assembly,
    bool Loaded,
    [property: Description("register_attribute, component_name, crc64_package (the Java callable wrapper name computed from namespace and assembly), " +
                           "mono_android_package, override (a .NET override of a registered Java method); Unity C#: unity_call (Call / CallStatic / " +
                           "Get / Set by name), unity_new (AndroidJavaClass / AndroidJavaObject), unity_proxy (an AndroidJavaProxy of the interface), unity_jni (AndroidJNI).")] string Basis,
    [property: Description("Unity pairs: descriptor (a JNI signature), name_and_arity (the only Java method of that name and argument count), or name_match.")] string? Confidence = null);

public sealed record JavaDotNetResult(string Query, string Direction, IReadOnlyList<JavaDotNetPair> Items, IReadOnlyList<string> Notes);

/// <summary>
/// The Java / .NET binding of Xamarin and .NET for Android apps: Java callable wrappers (crc64 package names computed exactly as the
/// build does, or the Name of [Register] / [Activity] / [Service] / ... attributes) and bound Java types ([Register] with
/// DoNotGenerateAcw); methods through their own [Register] or the registered base method they override.
/// </summary>
public sealed class JavaDotNetMap(AssemblyWorkspace workspace, DexService? dex = null)
{
    private sealed record Source(ModuleDef Module, string Label, bool Loaded);

    private sealed class Index
    {
        public readonly Dictionary<string, (TypeDef Type, Source Source, string Basis)> ByJava = new(StringComparer.Ordinal);
        public readonly Dictionary<TypeDef, (string Java, string Basis)> ByType = [];
        public readonly Dictionary<string, TypeDef> ByName = new(StringComparer.Ordinal);
        public readonly Dictionary<TypeDef, Source> SourceOf = [];
        public readonly List<string> Notes = [];
        public readonly List<(UnityJavaCall Call, Source Source)> Unity = [];
        /// <summary>The package's DEX code, read when a method's base has no [Register] left.</summary>
        public Lazy<DexIndex?>? Dex;
    }

    private readonly object _lock = new();
    private (string Key, List<Source> Sources)? _packageCache;

    private static readonly string[] NameProviders =
    [
        "Android.App.ActivityAttribute", "Android.App.ApplicationAttribute", "Android.App.InstrumentationAttribute", "Android.App.ServiceAttribute",
        "Android.Content.BroadcastReceiverAttribute", "Android.Content.ContentProviderAttribute", "Android.Runtime.RegisterAttribute",
    ];

    /// <summary>Maps <paramref name="symbol"/> (a Java descriptor or id, or a .NET type or member) to the other side.</summary>
    public JavaDotNetResult Map(string symbol, string? path, CancellationToken ct)
    {
        symbol = symbol.Trim();
        var index = Build(path, ct);
        if (dex != null && path != null)
            index.Dex = new(() =>
            {
                try { return dex.Index(path, ct); }
                catch (ToolError ex) { index.Notes.Add($"The package's DEX code is not read ({ex.Message})."); return null; }
            });
        bool java = symbol.StartsWith('L') && (symbol.EndsWith(';') || symbol.Contains(";->", StringComparison.Ordinal)) || symbol.Contains('/', StringComparison.Ordinal)
                    || symbol.Contains("->", StringComparison.Ordinal);
        var sep = symbol.IndexOf("::", StringComparison.Ordinal);
        var typeName = (sep > 0 ? symbol[..sep] : symbol).Replace('+', '/');
        var type = java ? null : FindType(index, typeName);
        // The manifest's dotted Java name (com.example.app.MainActivity) when no .NET type has that name.
        if (type == null && sep < 0 && index.ByJava.ContainsKey(symbol.Replace('.', '/'))) java = true;
        var items = new List<JavaDotNetPair>();
        if (java)
        {
            var arrow = symbol.IndexOf("->", StringComparison.Ordinal);
            var cls = arrow > 0 ? symbol[..arrow] : symbol;
            var javaName = cls.StartsWith('L') && cls.EndsWith(';') ? cls[1..^1] : cls.Replace('.', '/');
            if (!index.ByJava.TryGetValue(javaName, out var hit) && UnityToDotNet(index, javaName, arrow > 0 ? symbol[(arrow + 2)..] : null) is { Count: > 0 } unity)
                return new JavaDotNetResult(symbol, "java_to_dotnet", unity, index.Notes);
            if (hit.Type == null)
                throw new ToolError(ErrorCode.NotFound, $"no .NET type is bound to {javaName} in {Describe(path)}.",
                    "load the app's assemblies (unpack_container) or pass path=the package; Java-only classes have no .NET side") { Details = new { index.Notes } };
            if (arrow < 0) items.Add(new($"L{javaName};", TypeLabel(hit.Type), hit.Source.Label, hit.Source.Loaded, hit.Basis));
            else
            {
                var member = symbol[(arrow + 2)..];
                foreach (var (m, java2, basis) in Methods(index, hit.Type))
                    if (java2 == member) items.Add(new($"L{javaName};->{member}", Format.MemberLabel(m), hit.Source.Label, hit.Source.Loaded, basis));
                if (items.Count == 0)
                    throw new ToolError(ErrorCode.NotFound, $"{TypeLabel(hit.Type)} (bound to {javaName}) has no method registered as {member}.",
                        $"map_java_dotnet with L{javaName}; and get_type_info on {TypeLabel(hit.Type)}");
            }
            return new JavaDotNetResult(symbol, "java_to_dotnet", items, index.Notes);
        }
        if (type == null) throw new ToolError(ErrorCode.NotFound, $"no type {typeName} among the assemblies of {Describe(path)}.");
        if (!index.ByType.TryGetValue(type, out var bound) && DotNetToUnity(index, type, sep > 0 ? symbol[(sep + 2)..] : null, path, ct) is { Count: > 0 } calls)
            return new JavaDotNetResult(symbol, "dotnet_to_java", calls, index.Notes);
        if (bound.Java == null)
            throw new ToolError(ErrorCode.NotFound, $"{TypeLabel(type)} is not a Java peer (no [Register] binding and no registered base type): it has no Java side.");
        var source = index.SourceOf[type];
        if (sep < 0) items.Add(new($"L{bound.Java};", TypeLabel(type), source.Label, source.Loaded, bound.Basis));
        else
        {
            var name = symbol[(sep + 2)..];
            var paren = name.IndexOf('(');
            var simple = paren >= 0 ? name[..paren] : name;
            foreach (var (m, javaMember, basis) in Methods(index, type))
                if (m.Name == simple && (paren < 0 || Format.MemberLabel(m).EndsWith(name, StringComparison.Ordinal)))
                    items.Add(new($"L{bound.Java};->{javaMember}", Format.MemberLabel(m), source.Label, source.Loaded, basis));
            if (items.Count == 0)
                throw new ToolError(ErrorCode.NotFound, $"{TypeLabel(type)}::{name} is not registered with Java and overrides no registered method.",
                    path == null ? "pass path=the package: release builds strip [Register] from Mono.Android, and the Java callable wrapper in the DEX names the overrides" : null);
        }
        return new JavaDotNetResult(symbol, "dotnet_to_java", items, index.Notes);
    }

    /// <summary>The .NET type behind each Java class name of a package's assemblies (for manifest components); empty without .NET code.</summary>
    public IReadOnlyDictionary<string, string> ComponentTypes(string path, CancellationToken ct)
    {
        Index index;
        try { index = Build(path, ct); }
        catch (ToolError) { return new Dictionary<string, string>(); }
        return index.ByJava.Where(p => p.Value.Basis != "register_attribute" || !IsBinding(p.Value.Type))
            .ToDictionary(p => p.Key.Replace('/', '.'), p => $"{TypeLabel(p.Value.Type)} ({p.Value.Source.Label}, {p.Value.Basis})", StringComparer.Ordinal);
    }

    private static TypeDef? FindType(Index index, string name) =>
        index.ByName.GetValueOrDefault(name)
        ?? index.ByName.Values.Where(t => t.Name == name || t.FullName.EndsWith("." + name, StringComparison.Ordinal)).Take(2).ToList() switch { [var one] => one, _ => null };

    private static string Describe(string? path) => path ?? "the loaded assemblies";

    private static string UnityBasis(string kind) => kind switch
    {
        "new" => "unity_new",
        "proxy" => "unity_proxy",
        "jni" => "unity_jni",
        _ => "unity_call",
    };

    /// <summary>Unity C# that reaches a Java class or member by name: the calling methods, and an AndroidJavaProxy's methods of that name.</summary>
    private static List<JavaDotNetPair> UnityToDotNet(Index index, string javaClass, string? member)
    {
        var pairs = new List<JavaDotNetPair>();
        string? name = member, signature = null;
        int? arity = null;
        if (member != null && member.IndexOf('(') is var paren and > 0 && member.IndexOf(')') is var close and > 0)
        {
            name = member[..paren];
            signature = member[paren..];
            arity = DexIndex.SplitParameters(member[(paren + 1)..close]).Count;
        }
        var java = member == null ? $"L{javaClass};" : $"L{javaClass};->{member}";
        foreach (var (call, source) in index.Unity)
        {
            if (call.Class != javaClass) continue;
            if (call.Kind == "proxy")
            {
                var proxy = call.Caller.DeclaringType;
                if (member == null) pairs.Add(new(java, TypeLabel(proxy), source.Label, source.Loaded, "unity_proxy", "name_match"));
                else
                    foreach (var m in proxy.Methods.Where(m => m.Name == name && (arity == null || m.MethodSig.Params.Count == arity)))
                        pairs.Add(new(java, Format.MemberLabel(m), source.Label, source.Loaded, "unity_proxy", arity != null ? "name_and_arity" : "name_match"));
                continue;
            }
            if (member == null ? call.Member != null : call.Member != name) continue;
            if (call.Signature != null && signature != null && call.Signature != signature) continue;
            if (call.Arity != null && arity != null && call.Arity != arity) continue;
            string confidence = call.Signature != null ? "descriptor" : call.Arity != null && arity != null ? "name_and_arity" : "name_match";
            var label = Format.MemberLabel(call.Caller);
            if (!pairs.Any(p => p.DotNet == label))
                pairs.Add(new(java, label, source.Label, source.Loaded, UnityBasis(call.Kind), confidence));
        }
        return pairs;
    }

    /// <summary>The Java classes and members a Unity C# type or method reaches, as exact DEX ids when the package's DEX code has them.</summary>
    private List<JavaDotNetPair> DotNetToUnity(Index index, TypeDef type, string? member, string? path, CancellationToken ct)
    {
        var simple = member?.Split('(')[0];
        var calls = index.Unity.Where(u => u.Call.Caller.DeclaringType == type && (simple == null || u.Call.Caller.Name == simple || u.Call.Kind == "proxy")).ToList();
        if (calls.Count == 0) return [];
        DexIndex? code = null;
        if (dex != null && path != null)
        {
            try { code = dex.Index(path, ct); }
            catch (ToolError ex) { index.Notes.Add($"The package's DEX code is not read ({ex.Message}); Java members are named, not resolved to exact ids."); }
        }
        var pairs = new List<JavaDotNetPair>();
        void Add(JavaDotNetPair pair) { if (!pairs.Any(p => p.Java == pair.Java && p.DotNet == pair.DotNet)) pairs.Add(pair); }
        foreach (var (call, source) in calls)
        {
            if (call.Class == null) continue;
            if (call.Kind == "proxy")
            {
                if (simple == null) Add(new($"L{call.Class};", TypeLabel(type), source.Label, source.Loaded, "unity_proxy", "name_match"));
                else
                    foreach (var m in type.Methods.Where(m => m.Name == simple))
                        foreach (var (id, confidence) in JavaMembers(code, call.Class, m.Name, m.MethodSig.Params.Count, null))
                            Add(new(id, Format.MemberLabel(m), source.Label, source.Loaded, "unity_proxy", confidence));
                continue;
            }
            var label = Format.MemberLabel(call.Caller);
            if (call.Member == null) Add(new($"L{call.Class};", label, source.Label, source.Loaded, UnityBasis(call.Kind), "name_match"));
            else
                foreach (var (id, confidence) in JavaMembers(code, call.Class, call.Member, call.Arity, call.Signature, call.Kind is "get" or "set" or "get_static" or "set_static"))
                    Add(new(id, label, source.Label, source.Loaded, UnityBasis(call.Kind), confidence));
        }
        return pairs;
    }

    /// <summary>The DEX methods (or fields) of a class or its nearest DEX superclass with that name and arity; the bare name without DEX code.</summary>
    private static List<(string Id, string Confidence)> JavaMembers(DexIndex? code, string cls, string name, int? arity, string? signature, bool field = false)
    {
        var bare = $"L{cls};->{name}{signature}";
        var found = new List<string>();
        for (var c = $"L{cls};"; code != null && c != null && code.Classes.TryGetValue(c, out var entry); c = entry.Class.SuperClass)
        {
            if (field) found.AddRange(code.FindFields($"{c}->{name}"));
            else
                found.AddRange(code.Methods.Values.Where(m => m.Ref.Class == c && m.Ref.Name == name
                    && (signature != null ? m.Ref.Proto.Descriptor == signature : arity == null || m.Ref.Proto.Parameters.Count == arity)).Select(m => m.Descriptor));
            if (found.Count > 0) break;
        }
        if (found.Count == 0) return [(bare, signature != null ? "descriptor" : "name_match")];
        string confidence = signature != null ? "descriptor" : found.Count == 1 && (arity != null || field) ? "name_and_arity" : "name_match";
        return [.. found.Select(f => (f, confidence))];
    }

    private static string TypeLabel(TypeDef t) => t.FullName.Replace('/', '+');

    /// <summary>Java methods of a .NET type: its own [Register] methods and overrides of registered base methods, as name(sig)ret.</summary>
    private static IEnumerable<(MethodDef Method, string Java, string Basis)> Methods(Index index, TypeDef type)
    {
        List<(string Java, string Connector)>? wrapper = null;
        foreach (var m in type.Methods)
        {
            if (Register(m) is { } own && own.Signature != null) { yield return (m, own.Name + own.Signature, "register_attribute"); continue; }
            if (!m.IsVirtual || m.IsNewSlot) continue;
            bool registered = false;
            for (var b = Base(index, type); b != null; b = Base(index, b))
            {
                var baseMethod = b.Methods.FirstOrDefault(x => x.Name == m.Name && x.IsVirtual && new SigComparer().Equals(x.MethodSig, m.MethodSig));
                if (baseMethod == null) continue;
                if (Register(baseMethod) is { Signature: not null } r) { yield return (m, r.Name + r.Signature, "override"); registered = true; break; }
                if (baseMethod.IsNewSlot) break;
                // An unregistered override in between (MauiAppCompatActivity.OnCreate): the registered slot is further down.
            }
            if (registered) continue;
            // Release builds strip [Register] from Mono.Android: the wrapper's registration names the overrides.
            wrapper ??= index.ByType.TryGetValue(type, out var bound) && index.Dex?.Value is { } code ? WrapperMethods(code, bound.Java) : [];
            foreach (var (java, connector) in wrapper)
                if (ConnectorNames(connector, m.Name) && DexIndex.SplitParameters(java[(java.IndexOf('(') + 1)..java.IndexOf(')')]).Count == m.MethodSig.Params.Count)
                    yield return (m, java, "override");
        }
    }

    /// <summary>
    /// The methods a Java callable wrapper registers in its static initializer, as name(sig)ret with the .NET connector
    /// ("n_onCreate:(Landroid/os/Bundle;)V:GetOnCreate_Landroid_os_Bundle_Handler" lines).
    /// </summary>
    private static List<(string Java, string Connector)> WrapperMethods(DexIndex code, string javaClass)
    {
        var result = new List<(string, string)>();
        if (!code.Methods.TryGetValue($"L{javaClass};-><clinit>()V", out var init) || init.Encoded.CodeOffset == 0
            || init.File.Code(init.Encoded.CodeOffset) is not { } body) return result;
        foreach (var i in Dalvik.Decode(body.Instructions))
        {
            if (i.Ref != DalvikRef.String) continue;
            foreach (var line in init.File.String(i.Index).Split('\n'))
                if (line.Split(':') is [var name, var signature, var connector, ..] && name.StartsWith("n_", StringComparison.Ordinal) && signature.StartsWith('('))
                    result.Add((name[2..] + signature, connector));
        }
        return result;
    }

    /// <summary>Whether a connector (GetOnCreate_Landroid_os_Bundle_Handler, GetOnPauseHandler) belongs to the .NET method <paramref name="name"/>.</summary>
    private static bool ConnectorNames(string connector, string name) =>
        connector.StartsWith("Get", StringComparison.Ordinal) && connector.EndsWith("Handler", StringComparison.Ordinal)
        && connector[3..^7] is var core && (core == name || core.StartsWith(name + "_", StringComparison.Ordinal));

    private static (string Name, string? Signature, bool DoNotGenerateAcw)? Register(IHasCustomAttribute member)
    {
        var a = member.CustomAttributes.FirstOrDefault(x => x.TypeFullName == "Android.Runtime.RegisterAttribute");
        if (a == null || a.ConstructorArguments.Count == 0 || a.ConstructorArguments[0].Value?.ToString() is not { Length: > 0 } name) return null;
        string? signature = a.ConstructorArguments.Count > 1 ? a.ConstructorArguments[1].Value?.ToString() : null;
        bool noAcw = a.NamedArguments.Any(n => n.Name == "DoNotGenerateAcw" && n.Argument.Value is true);
        return (name, signature, noAcw);
    }

    private static bool IsBinding(TypeDef t) => Register(t) is { DoNotGenerateAcw: true };

    private static TypeDef? Base(Index index, TypeDef t) =>
        t.BaseType is { } b ? b.ResolveTypeDef() ?? index.ByName.GetValueOrDefault(b.FullName) : null;

    private Index Build(string? path, CancellationToken ct)
    {
        var sources = new List<Source>();
        var loadedNames = new HashSet<string>(StringComparer.Ordinal);
        workspace.Read(() =>
        {
            foreach (var a in workspace.Assemblies)
            {
                sources.Add(new Source(a.Module, a.Id, true));
                loadedNames.Add(a.Module.Assembly?.Name ?? a.Module.Name);
            }
            return 0;
        });
        var notes = new List<string>();
        if (path != null)
        {
            var full = InputFiles.RequireRegularFile(path, "package");
            var info = new FileInfo(full);
            var key = $"{full}|{info.Length}|{info.LastWriteTimeUtc.Ticks}";
            List<Source> fromPackage;
            lock (_lock) fromPackage = _packageCache is { } c && c.Key == key ? c.Sources : [];
            if (fromPackage.Count == 0)
            {
                var (_, _, assemblies, _) = UnpackService.Managed(full, AnalysisLimits.Default, ct);
                var context = new ModuleContext();
                foreach (var a in assemblies)
                {
                    try { fromPackage.Add(new Source(ModuleDefMD.Load(a.Bytes, context), a.Path, false)); }
                    catch (Exception) { notes.Add($"{a.Path} is not readable .NET metadata."); } // dnlib throws several types on malformed images
                }
                if (fromPackage.Count == 0) throw new ToolError(ErrorCode.NotFound, $"{full} has no .NET assemblies: a Java-only package has no .NET side.");
                lock (_lock) _packageCache = (key, fromPackage);
            }
            // A loaded copy of an assembly wins: its id is what decompile_member takes.
            sources.AddRange(fromPackage.Where(s => !loadedNames.Contains(s.Module.Assembly?.Name ?? s.Module.Name)));
            return BuildIndex(sources, notes, ct);
        }
        if (sources.Count == 0) throw new ToolError(ErrorCode.NotLoaded, "no assemblies are loaded.", "pass path=the .apk, or load its assemblies with unpack_container");
        return BuildIndex(sources, notes, ct);
    }

    private static Index BuildIndex(List<Source> sources, List<string> notes, CancellationToken ct)
    {
        var index = new Index();
        index.Notes.AddRange(notes);
        foreach (var s in sources)
        {
            foreach (var t in s.Module.GetTypes())
            {
                index.ByName.TryAdd(t.FullName, t);
                index.SourceOf.TryAdd(t, s);
            }
            index.Unity.AddRange(UnityJavaCalls.Scan(s.Module, ct).Select(c => (c, s)));
        }
        var peer = new Dictionary<TypeDef, bool>();
        bool IsPeer(TypeDef t, int depth)
        {
            if (peer.TryGetValue(t, out var known)) return known;
            bool result = depth < 64 && (Register(t) != null || t.Interfaces.Any(i => i.Interface.FullName is "Android.Runtime.IJavaObject" or "Java.Interop.IJavaPeerable")
                                         || (Base(index, t) is { } b && IsPeer(b, depth + 1)));
            peer[t] = result;
            return result;
        }
        foreach (var (t, s) in index.SourceOf)
        {
            if (t.IsInterface && Register(t) == null) continue;
            if (!IsPeer(t, 0)) continue;
            var (java, basis) = JniName(t, s.Module);
            index.ByType[t] = (java, basis);
            index.ByJava.TryAdd(java, (t, s, basis));
        }
        return index;
    }

    /// <summary>The Java name the build gives a Java peer type (JavaNativeTypeManager.ToJniName).</summary>
    private static (string Java, string Basis) JniName(TypeDef type, ModuleDef module)
    {
        var parts = new List<string>();
        var outer = type;
        for (var t = type; t != null; t = t.DeclaringType)
        {
            outer = t;
            if (NameFromAttributes(t) is { } named)
            {
                parts.Reverse();
                var basis = t.CustomAttributes.Any(a => a.TypeFullName == "Android.Runtime.RegisterAttribute") ? "register_attribute" : "component_name";
                return (parts.Count == 0 ? named : named + "_" + string.Join("_", parts), basis);
            }
            parts.Add(t.Name.String.Replace('`', '_'));
        }
        parts.Reverse();
        var assembly = module.Assembly?.Name.String ?? module.Name.String;
        var ns = outer.Namespace.String;
        var package = assembly == "Mono.Android" ? ns.ToLowerInvariant() : "crc64" + Crc64(ns + ":" + assembly);
        var name = string.Join("_", parts);
        return (package.Length == 0 ? name : package.Replace('.', '/') + "/" + name, assembly == "Mono.Android" ? "mono_android_package" : "crc64_package");
    }

    private static string? NameFromAttributes(TypeDef t)
    {
        foreach (var a in t.CustomAttributes)
        {
            if (!NameProviders.Contains(a.TypeFullName)) continue;
            var name = a.NamedArguments.FirstOrDefault(n => n.Name == "Name")?.Argument.Value?.ToString()
                       ?? (a.ConstructorArguments.Count > 0 && a.ConstructorArguments[0].Type.FullName == "System.String" ? a.ConstructorArguments[0].Value?.ToString() : null);
            if (!string.IsNullOrEmpty(name)) return name.Replace('.', '/');
        }
        return null;
    }

    private static readonly ulong[] Table = BuildTable();

    private static ulong[] BuildTable()
    {
        const ulong Reflected = 0x95AC9329AC4BC9B5; // crc-64-jones (0xad93d23594c935a9) bit-reversed
        var table = new ulong[256];
        for (ulong i = 0; i < 256; i++)
        {
            ulong c = i;
            for (int k = 0; k < 8; k++) c = (c & 1) != 0 ? (c >> 1) ^ Reflected : c >> 1;
            table[i] = c;
        }
        return table;
    }

    /// <summary>Java.Interop's package hash: CRC-64-Jones from all ones, XORed with the length, bytes in little-endian hex.</summary>
    public static string Crc64(string value)
    {
        var data = Encoding.UTF8.GetBytes(value);
        ulong crc = ulong.MaxValue;
        foreach (var b in data) crc = Table[(crc ^ b) & 0xFF] ^ (crc >> 8);
        crc ^= (ulong)data.Length;
        return Convert.ToHexStringLower(BitConverter.GetBytes(crc));
    }
}
