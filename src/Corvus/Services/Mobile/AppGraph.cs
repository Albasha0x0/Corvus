using System.ComponentModel;
using System.Diagnostics;
using System.IO.Compression;
using System.Text;
using Corvus.Core;
using Corvus.Core.Hermes;
using Corvus.Core.Mobile;

namespace Corvus.Services.Mobile;

public sealed record AppLayer(
    [property: Description("dex, native, dotnet, il2cpp, js or web.")] string Layer,
    [property: Description("How many items the layer holds (classes, libraries, assemblies, methods, strings).")] int Items,
    string What);

public sealed record AppEdgeKind(
    [property: Description("jni (DEX native method to .so function), java_dotnet (Java callable wrapper or bound class to .NET type), unity_java " +
                           "(Unity C# to the Java class it names), il2cpp_native (C# method to its libil2cpp.so code), js_native_module (JS bundle to a " +
                           "React Native module class), cordova_plugin, capacitor_plugin (web code to plugin class).")] string Kind,
    int Edges,
    [property: Description("The items that could have an edge of this kind (native methods, Unity calls, modules ...).")] int Candidates,
    [property: Description("complete, partial (candidates without an edge; reason says which) or unknown (the layer was not read).")] string Coverage,
    [property: Description("How each edge is verified.")] string Basis,
    string? Reason);

public sealed record AppEdge(string Kind, string From, string To,
    [property: Description("The evidence: static_export, registered, register_attribute, crc64_package, unity_call, metadata_address, module_name ...")] string Basis);

public sealed record AppGraphFacts(IReadOnlyList<AppLayer> Layers, IReadOnlyList<AppEdgeKind> EdgeKinds, IReadOnlyList<AppEdge> Edges, int Offset, int Total,
    [property: Description("Seconds the graph took.")] double Seconds, IReadOnlyList<string> Notes);

/// <summary>
/// One graph of an Android package's code layers (DEX, native libraries, .NET, Il2Cpp, JS bundle) with the edges between
/// them, each verified the way its bridge binds at run time: JNI name mangling and RegisterNatives tables, [Register] and
/// crc64 wrapper names, Unity's Java calls by class name, Il2Cpp metadata addresses, React Native module names, Cordova and Capacitor plugin names. Composes
/// the bridge services; coverage per edge kind says what is joined and what is not.
/// </summary>
public sealed class AppGraph(DexService dex, JniBindings jni, JavaDotNetMap map, Il2CppRawLoader? il2cpp = null)
{
    public const int DefaultLimit = 100;
    private const string ReactModule = "Lcom/facebook/react/bridge/ReactContextBaseJavaModule;", BaseModule = "Lcom/facebook/react/bridge/BaseJavaModule;";

    public AppGraphFacts Build(string path, int offset, int limit, CancellationToken ct)
    {
        var watch = Stopwatch.StartNew();
        var full = InputFiles.RequireRegularFile(path, "package");
        var layers = new List<AppLayer>();
        var kinds = new List<AppEdgeKind>();
        var edges = new List<AppEdge>();
        var notes = new List<string>();
        List<string> entries;
        using (var package = AndroidPackage.Open(full)) entries = [.. package.Entries];

        DexIndex? index = null;
        try
        {
            index = dex.Index(full, ct);
            layers.Add(new("dex", index.Classes.Count, $"classes in {index.Files.Count} DEX file(s)"));
        }
        catch (ToolError e) { notes.Add($"DEX code not read: {e.Message}"); }
        var libraries = entries.Where(e => e.StartsWith("lib/", StringComparison.Ordinal) && e.EndsWith(".so", StringComparison.Ordinal)).ToList();
        if (libraries.Count > 0)
            layers.Add(new("native", libraries.Count, $"libraries for {string.Join(", ", libraries.Select(l => l.Split('/')[1]).Distinct().Order(StringComparer.Ordinal))}"));

        var wrappers = DotNet(full, index, layers, kinds, edges, notes, ct);
        if (index != null && libraries.Count > 0) Jni(full, wrappers, kinds, edges, notes, ct);
        Il2Cpp(full, entries, layers, kinds, edges, notes, ct);
        if (index != null) Js(full, index, layers, kinds, edges, notes, ct);
        if (index != null)
            using (var package = AndroidPackage.Open(full)) WebBridges.Add(package, entries, index, layers, kinds, edges, notes, ct);

        var ordered = edges.OrderBy(e => e.Kind, StringComparer.Ordinal).ThenBy(e => e.From, StringComparer.Ordinal).ThenBy(e => e.To, StringComparer.Ordinal).ToList();
        offset = Math.Max(0, offset);
        var page = ordered.Skip(offset).Take(Math.Clamp(limit, 1, 2000)).ToList();
        if (kinds.Count == 0) notes.Add("No bridge between layers was found: a single-layer app, or layers this view does not join (Flutter, Xamarin.iOS).");
        return new AppGraphFacts(layers, kinds, page, offset, ordered.Count, Math.Round(watch.Elapsed.TotalSeconds, 2), notes);
    }

    /// <param name="wrappers">Java callable wrapper classes of .NET types: the .NET runtime registers their native methods, not a library.</param>
    private void Jni(string full, HashSet<string> wrappers, List<AppEdgeKind> kinds, List<AppEdge> edges, List<string> notes, CancellationToken ct)
    {
        JniBindingList rows;
        // A table's class from the code that passes it: read in libraries up to 8 MB, so an engine library (libunity.so) does not cost seconds.
        try { rows = jni.Rows(full, null, null, null, 0, int.MaxValue, ct, readCodeUpTo: 8 << 20); }
        catch (ToolError e) { notes.Add($"JNI bindings not read: {e.Message}"); return; }
        int bound = 0, unresolved = 0, byRuntime = 0;
        foreach (var r in rows.Items)
        {
            if (r.Kind == "unresolved" && r.JavaMethod is { } id && wrappers.Contains(id[..Math.Max(0, id.IndexOf("->", StringComparison.Ordinal))])) { byRuntime++; continue; }
            if (r.Kind == "unresolved") { unresolved++; continue; }
            if (r.JavaMethod == null || r.JavaMethod.StartsWith("?->", StringComparison.Ordinal)) continue;
            bound++;
            edges.Add(new("jni", r.JavaMethod, $"{r.Library}!{r.Symbol ?? "(registered)"}@{r.Address}", r.Kind));
        }
        int natives = bound + unresolved;
        if (natives == 0 && rows.Libraries.Count == 0) return;
        int exportOnly = rows.Items.Count(r => r.Kind == "export_only");
        kinds.Add(new("jni", bound, natives, unresolved == 0 ? "complete" : "partial", "JNI name mangling of exports (short and overload forms) and RegisterNatives table entries",
            unresolved == 0 ? null : $"{unresolved} native method(s) have no Java_ export or RegisterNatives entry found (list_jni_bindings kind=unresolved)"));
        if (byRuntime > 0) notes.Add($"{byRuntime} native method(s) of Java callable wrappers are registered by the .NET runtime (their .NET side is in java_dotnet).");
        if (exportOnly > 0) notes.Add($"{exportOnly} Java_ export(s) name no native method of the DEX code (list_jni_bindings kind=export_only).");
        notes.AddRange(rows.Notes.Select(n => "JNI: " + n));
    }

    // Classes of the Android platform: bound by .NET for Android, defined by the device, never in the app's DEX code.
    private static readonly string[] Platform = ["Landroid/", "Ljava/", "Ljavax/", "Ldalvik/", "Lorg/w3c/", "Lorg/xml/", "Lorg/json/", "Lorg/apache/http/"];

    /// <summary>.NET for Android and Unity Mono edges; returns the Java callable wrapper classes.</summary>
    private HashSet<string> DotNet(string full, DexIndex? index, List<AppLayer> layers, List<AppEdgeKind> kinds, List<AppEdge> edges, List<string> notes, CancellationToken ct)
    {
        var wrappers = new HashSet<string>(StringComparer.Ordinal);
        JavaDotNetResult pairs;
        try { pairs = map.Map("*", full, ct); }
        catch (ToolError e) when (e.Code is ErrorCode.NotFound or ErrorCode.NotLoaded or ErrorCode.Unsupported) { return wrappers; } // no .NET code in the package
        var assemblies = pairs.Items.Select(p => p.Assembly).Distinct(StringComparer.Ordinal).Count();
        layers.Add(new("dotnet", assemblies, "assemblies with Java bridge pairs"));
        static string ClassOf(string java) => java.Contains("->", StringComparison.Ordinal) ? java[..java.IndexOf("->", StringComparison.Ordinal)] : java;
        bool InDex(string java) => index == null || index.Classes.ContainsKey(ClassOf(java));
        var bridge = pairs.Items.Where(p => !p.Basis.StartsWith("unity_", StringComparison.Ordinal)).ToList();
        if (bridge.Count > 0)
        {
            int missing = 0;
            foreach (var p in bridge)
            {
                bool app = InDex(p.Java), platform = !app && Platform.Any(prefix => p.Java.StartsWith(prefix, StringComparison.Ordinal));
                if (!app && !platform) { missing++; continue; }
                if (app) wrappers.Add(ClassOf(p.Java));
                edges.Add(new("java_dotnet", p.Java, $"{p.Assembly}!{p.DotNet}", platform ? p.Basis + ", platform class" : p.Basis));
            }
            kinds.Add(new("java_dotnet", bridge.Count - missing, bridge.Count, missing == 0 ? "complete" : "partial",
                "[Register] and component attribute names and crc64 wrapper names computed as the build does; the Java class defined by the DEX code or the platform",
                missing == 0 ? null : $"{missing} pair(s) name a Java class neither the DEX code nor the platform defines (a binding of a library the package does not carry)"));
        }
        var unity = pairs.Items.Where(p => p.Basis.StartsWith("unity_", StringComparison.Ordinal)).ToList();
        if (unity.Count > 0)
        {
            int resolved = 0;
            foreach (var p in unity)
            {
                bool there = InDex(p.Java);
                if (!there) continue;
                resolved++;
                edges.Add(new("unity_java", $"{p.Assembly}!{p.DotNet}", p.Java, $"{p.Basis} ({p.Confidence})"));
            }
            kinds.Add(new("unity_java", resolved, unity.Count, resolved == unity.Count ? "complete" : "partial",
                "AndroidJavaClass / AndroidJavaObject / AndroidJavaProxy / AndroidJNI names matched to classes the DEX code defines",
                resolved == unity.Count ? null : $"{unity.Count - resolved} call(s) name a Java class not in the DEX code (a framework class, or a name built at run time)"));
        }
        notes.AddRange(pairs.Notes.Select(n => ".NET: " + n));
        return wrappers;
    }

    private void Il2Cpp(string full, List<string> entries, List<AppLayer> layers, List<AppEdgeKind> kinds, List<AppEdge> edges, List<string> notes, CancellationToken ct)
    {
        if (!entries.Any(e => e.EndsWith("/global-metadata.dat", StringComparison.Ordinal))) return;
        Il2CppBuildModel? model = null;
        try
        {
            if (il2cpp != null && Il2CppPackages.Extract(full, null, ct: ct) is { } root && Il2CppBuildFiles.Find(root) is { Binary.Length: > 0 } files)
                model = il2cpp.Cached(files);
        }
        catch (ToolError e) { notes.Add($"Il2Cpp build not located: {e.Message}"); }
        if (model == null)
        {
            layers.Add(new("il2cpp", 0, "global-metadata.dat and libil2cpp.so, not read yet"));
            kinds.Add(new("il2cpp_native", 0, 0, "unknown", "Il2Cpp metadata method addresses",
                $"load_assembly path={full} reads the Il2Cpp metadata once (kept in the cache); this view then joins every C# method to its code"));
            return;
        }
        layers.Add(new("il2cpp", model.MethodDefinitions, $"C# methods (Unity {model.UnityVersion}, metadata v{model.MetadataVersion})"));
        foreach (var m in model.Methods)
            if (m.Address != 0) edges.Add(new("il2cpp_native", $"{m.Image}!{m.Name}", $"libil2cpp.so@0x{model.ImageBase + m.Address:X}", "metadata_address"));
        // Methods holds definitions with code and generic instances, each with the address the code registration gives.
        int joined = model.Methods.Count(m => m.Address != 0);
        kinds.Add(new("il2cpp_native", joined, model.Methods.Count, joined == model.Methods.Count ? "complete" : "partial", "Il2Cpp metadata method pointers (code registration)",
            joined == model.Methods.Count ? null : $"{model.Methods.Count - joined} method(s) have no address read"));
    }

    private static void Js(string full, DexIndex index, List<AppLayer> layers, List<AppEdgeKind> kinds, List<AppEdge> edges, List<string> notes, CancellationToken ct)
    {
        bool IsModule(DexClassEntry c)
        {
            var super = c.Class.SuperClass;
            for (int depth = 0; super != null && depth < 16; depth++)
            {
                if (super is ReactModule or BaseModule) return true;
                super = index.Classes.GetValueOrDefault(super)?.Class.SuperClass;
            }
            return false;
        }
        var modules = index.Classes.Values.Where(c => (c.Class.Access & 0x400) == 0 && IsModule(c)).ToList();
        HashSet<string>? strings = null;
        string? bundleName = null;
        try
        {
            using var zip = ZipFile.OpenRead(full);
            var entry = zip.GetEntry("assets/index.android.bundle") ?? HermesBundlesEntry(zip);
            if (entry != null && entry.Length <= 512L << 20)
            {
                bundleName = entry.FullName;
                using var s = entry.Open();
                var bytes = Blob.ReadBounded(s, 512L << 20) ?? [];
                if (HermesFile.Looks(bytes))
                {
                    var hbc = HermesFile.Read(bytes);
                    strings = new HashSet<string>(StringComparer.Ordinal);
                    for (int i = 0; i < hbc.StringCount; i++) if (hbc.String(i) is { } t) strings.Add(t);
                    layers.Add(new("js", hbc.StringCount, $"strings of the Hermes bytecode v{hbc.Version} bundle {entry.FullName}"));
                }
                else
                {
                    strings = Quoted(Encoding.UTF8.GetString(bytes));
                    layers.Add(new("js", strings.Count, $"quoted strings of the JS bundle {entry.FullName}"));
                }
            }
        }
        catch (Exception e) when (e is IOException or InvalidDataException) { notes.Add($"JS bundle not read: {e.Message}"); }
        if (modules.Count == 0) return;
        if (strings == null)
        {
            kinds.Add(new("js_native_module", 0, modules.Count, "unknown", "module names from getName() found as strings of the JS bundle",
                "the package has React Native modules but no JS bundle (assets/index.android.bundle) was found"));
            return;
        }
        index.EnsureCode(ct);
        var firstString = new Dictionary<int, string>();
        foreach (var r in index.Refs)
            if (r.Kind == DexRefKind.String) firstString.TryAdd(r.From, index.KeyText(r.Target));
        int joined = 0, named = 0;
        foreach (var m in modules)
        {
            var getName = $"{m.Class.Descriptor}->getName()Ljava/lang/String;";
            if (index.FindKey(getName) is not { } key || !firstString.TryGetValue(key, out var name)) continue;
            named++;
            if (!strings.Contains(name)) continue;
            joined++;
            edges.Add(new("js_native_module", $"{bundleName}:NativeModules.{name}", m.Class.Descriptor, "module_name"));
        }
        kinds.Add(new("js_native_module", joined, modules.Count, joined == modules.Count ? "complete" : "partial",
            "the name getName() returns (its string constant) found among the bundle's strings",
            joined == modules.Count ? null : string.Join("; ", new[]
            {
                modules.Count > named ? $"{modules.Count - named} module(s) return no constant name" : null,
                named > joined ? $"{named - joined} module name(s) not among the bundle's strings (modules the JS code does not use)" : null,
            }.OfType<string>())));
    }

    private static ZipArchiveEntry? HermesBundlesEntry(ZipArchive zip) =>
        zip.Entries.FirstOrDefault(e => e.FullName.StartsWith("assets/", StringComparison.Ordinal) && (e.FullName.EndsWith(".bundle", StringComparison.Ordinal) || e.FullName.EndsWith(".hbc", StringComparison.Ordinal)));

    /// <summary>The contents of the '...' and "..." literals of JS text (escapes left as written).</summary>
    private static HashSet<string> Quoted(string text)
    {
        var set = new HashSet<string>(StringComparer.Ordinal);
        for (int i = 0; i < text.Length; i++)
        {
            char q = text[i];
            if (q is not ('"' or '\'')) continue;
            int start = i + 1, j = start;
            while (j < text.Length && text[j] != q && text[j] != '\n') j += text[j] == '\\' ? 2 : 1;
            if (j < text.Length && text[j] == q && j - start is > 0 and < 128) set.Add(text[start..j]);
            i = j;
        }
        return set;
    }
}
