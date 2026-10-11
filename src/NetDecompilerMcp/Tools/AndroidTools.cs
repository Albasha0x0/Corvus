using System.ComponentModel;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Core.Mobile;
using NetDecompilerMcp.Services.Mobile;
using static NetDecompilerMcp.Tools.ToolSupport;

namespace NetDecompilerMcp.Tools;

[McpServerToolType]
public sealed class AndroidTools(AndroidPackageService packages, DexService dex, JavaDecompilerService java, JavaDotNetMap map, JniBindings jni, OutputPager pager)
{
    public const string PackageDescription = "An Android package: .apk, .aab (its base module), or a split set (.apks, .xapk, .apkm, read through its base APK).";
    public const string CodeDescription = "An Android package (.apk, .aab, .apks, .xapk, .apkm), a .dex file, or a jar / zip with classes*.dex.";

    [McpServerTool(Name = "get_android_manifest", Title = "Android manifest", UseStructuredContent = true)]
    [Description("AndroidManifest.xml of an Android package, decoded natively: package, versions and SDKs; permissions (-sdk-23, maxSdkVersion) " +
                 "and declared ones with protection levels; application flags (debuggable, allowBackup, cleartext traffic, network security config, " +
                 "extractNativeLibs); each component with explicit and effective exported state and why, permissions, intent filters, launcher, deep " +
                 "links, meta-data (and its .NET type in a .NET for Android app); queries, features, libraries; highlights. The XML: get_android_resource.")]
    public Task<AndroidManifestSummary> GetAndroidManifest(
        [Description(PackageDescription)] string path,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => packages.Manifest(path, cancellationToken), cancellationToken);

    [McpServerTool(Name = "list_android_resources", Title = "List Android resources", UseStructuredContent = true)]
    [Description("Compiled resources of an Android package (resources.arsc, or an app bundle's resources.pb): a row per resource and " +
                 "configuration with id, type, name, qualifiers (pt-rBR, night, xxhdpi, v31; '' is the default), value type and value (references " +
                 "by name; styles, arrays and plurals as name=value lists); types counts each type.")]
    public Task<AndroidResourceList> ListAndroidResources(
        [Description(PackageDescription)] string path,
        [Description("Only this type: string, layout, xml, drawable, color, ...")] string? type = null,
        [Description("Only names matching this (case-insensitive; * and ? wildcards).")] string? name = null,
        [Description("Only this configuration: qualifiers as in a directory name (values-pt-rBR: pt-rBR), or default.")] string? config = null,
        [Description("Rows to skip.")] int offset = 0,
        [Description("Most rows to return (default 500).")] int limit = 500,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => packages.Resources(path, type, name, config, offset, limit), cancellationToken);

    [McpServerTool(Name = "get_android_resource", Title = "Get Android resource")]
    [Description("One file of an Android package, or one resource: a path (res/xml/network_security_config.xml, res/layout/main.xml, assets/..., " +
                 "AndroidManifest.xml) is read with binary XML decoded and resource references named, text as text, other data as a hex preview; " +
                 "@type/name or 0x7f... gives the resource's value in every configuration, or its file. savePath writes the raw bytes.")]
    public Task<string> GetAndroidResource(
        [Description(PackageDescription)] string path,
        [Description("An entry path, @type/name (@xml/network_security_config, @string/app_name) or a resource id 0x7f...")] string name,
        [Description("Write the entry's bytes to this file.")] string? savePath = null,
        [Description("Replace savePath if it exists.")] bool overwrite = false,
        [Description(OffsetDescription)] int offset = 0,
        [Description(MaxCharsDescription)] int? maxChars = null,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => packages.Resource(path, name, savePath, overwrite, offset, maxChars), cancellationToken);

    [McpServerTool(Name = "list_dex_classes", Title = "List DEX classes", UseStructuredContent = true)]
    [Description("Classes defined in the DEX code of an Android package (every classes*.dex, inner and anonymous classes included): descriptor, " +
                 "Java name, DEX file, access, superclass, interfaces, method and field counts, source file. Read natively, no Java tools.")]
    public Task<DexClassList> ListDexClasses(
        [Description(CodeDescription)] string path,
        [Description("Only classes whose Java name or descriptor contains this (case-insensitive), or matches it with * and ? wildcards.")] string? query = null,
        [Description("Only this package and its subpackages, e.g. com.example.")] string? package = null,
        [Description("Classes to skip.")] int offset = 0,
        [Description("Most classes to return (default 500).")] int limit = 500,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => dex.ListClasses(path, query, package, offset, limit, cancellationToken), cancellationToken);

    [McpServerTool(Name = "get_dex_class", Title = "DEX class", UseStructuredContent = true)]
    [Description("One DEX class in full: access, superclass, interfaces, source file, generic signature, enclosing and inner classes, Kotlin @Metadata " +
                 "(kind and names), annotations; fields with type, access, static initial value and annotations; methods with their exact id " +
                 "(Lpkg/C;->name(params)ret, so overloads never collide), Java signature, access, code size, registers and parameter names.")]
    public Task<DexClassDetail> GetDexClass(
        [Description(CodeDescription)] string path,
        [Description("Class: Lpkg/Name;, pkg.Name, or pkg.Outer.Inner / pkg.Outer$Inner.")] string @class,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => dex.GetClass(path, @class, cancellationToken), cancellationToken);

    [McpServerTool(Name = "disassemble_dex", Title = "Disassemble DEX")]
    [Description("Smali of a method or a class of an Android package's DEX code in baksmali's layout (operands resolved, labels, .line, " +
                 "try / catch, payloads, annotations). A method is one exact id (Lpkg/C;->m(I)V) or one overload (pkg.C::m(int)). format=annotated " +
                 "adds code offsets and units.")]
    public Task<string> DisassembleDex(
        [Description(CodeDescription)] string path,
        [Description("A method (Lpkg/C;->name(params)ret, or pkg.C::name with optional (int, String)) or a class (pkg.C, Lpkg/C;).")] string symbol,
        [Description("Output layout (default smali).")] string? format = null,
        [Description(OffsetDescription)] int offset = 0,
        [Description(MaxCharsDescription)] int? maxChars = null,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => pager.Page(dex.Disassemble(path, symbol, (format ?? "smali").Trim().ToLowerInvariant() switch
        {
            "smali" or "" => false,
            "annotated" => true,
            var f => throw new ToolError(ErrorCode.InvalidArgument, $"unknown format '{f}'; use smali or annotated."),
        }, cancellationToken), offset, maxChars), cancellationToken);

    [McpServerTool(Name = "decompile_java", Title = "Decompile Java")]
    [Description("Java source of a class or one method (one exact overload) of an Android package through the JADX headless server " +
                 "(NDM_JAVA_DECOMPILER, java -jar, JDK 17+), one session per package kept loaded; a timeout keeps it. Where JADX fails, smali " +
                 "(smaliFallback). Without JADX: provider_unavailable; disassemble_dex gives smali.")]
    public async Task<string> DecompileJava(
        [Description(CodeDescription)] string path,
        [Description("A class (pkg.C, Lpkg/C;) or a method (Lpkg/C;->name(params)ret, or pkg.C::name with optional (int, String)).")] string symbol,
        [Description("Return smali when JADX fails on the code (default true).")] bool smaliFallback = true,
        [Description("jadx (the only engine).")] string? engine = null,
        [Description(OffsetDescription)] int offset = 0,
        [Description(MaxCharsDescription)] int? maxChars = null,
        CancellationToken cancellationToken = default)
    {
        if (engine is { Length: > 0 } e && !e.Trim().Equals("jadx", StringComparison.OrdinalIgnoreCase))
            throw new ToolError(ErrorCode.InvalidArgument, $"unknown engine '{e}'; use jadx.");
        var text = await Task.Run(() => java.Decompile(path, symbol, smaliFallback, cancellationToken), cancellationToken).ConfigureAwait(false);
        return pager.Page(text, offset, maxChars);
    }

    [McpServerTool(Name = "map_java_dotnet", Title = "Map Java and .NET", UseStructuredContent = true)]
    [Description("The other side of a Java / .NET bridge, ready for decompile_member or get_dex_class. Xamarin / .NET for Android: a Java class or " +
                 "method id gives the .NET type or method and back (wrapper names computed as the build does: crc64 of namespace and assembly, or the " +
                 "Name of [Register] / [Activity] / ...; methods by [Register] or the registered method they override). Unity Mono: the C# reaching a " +
                 "Java class or member through AndroidJavaClass / AndroidJavaObject, AndroidJavaProxy or AndroidJNI, and back, with a confidence. " +
                 "Reads the loaded assemblies, and the package's with path.")]
    public Task<JavaDotNetResult> MapJavaDotNet(
        [Description("A Java class (Lpkg/C; or pkg.C), Java method id (Lpkg/C;->onCreate(Landroid/os/Bundle;)V), or a .NET type or member.")] string symbol,
        [Description("The .apk / .aab whose assemblies to read (without loading them); optional when they are loaded.")] string? path = null,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => map.Map(symbol, path, cancellationToken), cancellationToken);

    [McpServerTool(Name = "list_jni_bindings", Title = "List JNI bindings", UseStructuredContent = true)]
    [Description("Java native methods of an Android package paired with their code in lib/<abi>/*.so: Java_ exports by JNI name mangling (overloads " +
                 "included) and RegisterNatives tables in the libraries' data, a table's class from its FindClass string or a unique name and signature; " +
                 "also unbound methods and stray Java_ exports.")]
    public Task<JniBindingList> ListJniBindings(
        [Description(PackageDescription)] string path,
        [Description("ABI to read (arm64-v8a, x86_64, ...) or all; default arm64-v8a, else the first.")] string? abi = null,
        [Description("Only rows naming this class (pkg.C or pkg/C).")] string? @class = null,
        [Description("Only this kind.")] string? kind = null,
        [Description("Rows to skip.")] int offset = 0,
        [Description("Most rows (default 200).")] int limit = JniBindings.DefaultLimit,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => jni.List(path, abi, @class, kind, offset, limit, cancellationToken), cancellationToken);

    [McpServerTool(Name = "search_dex", Title = "Search DEX code", UseStructuredContent = true)]
    [Description("Search the DEX code of an Android package. kind=string: string literals loaded by code, with the method and offset of each use; " +
                 "type: defined classes and type uses (new-instance, check-cast, const-class...); method / field: defined and referenced members with " +
                 "their use counts; const: numeric constants (42, 0x7f010000, 1.5); opcode: instructions by mnemonic (invoke-static, sget-object). " +
                 "query is a case-insensitive substring, or a pattern with * and ? wildcards.")]
    public Task<DexHitList> SearchDex(
        [Description(CodeDescription)] string path,
        [Description("string, type, method, field, const or opcode.")] string kind,
        [Description("Text to find (substring or wildcard pattern); for const a number.")] string query,
        [Description("Hits to skip.")] int offset = 0,
        [Description("Most hits to return (default 200).")] int limit = 200,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => dex.Search(path, kind, query, offset, limit, cancellationToken), cancellationToken);

    [McpServerTool(Name = "find_dex_references", Title = "Find DEX references", UseStructuredContent = true)]
    [Description("Cross-references in DEX code with the method and code offset of each instruction. direction=to: callers of a method, readers and " +
                 "writers of a field, uses of a class (type uses and accesses to its members) or of a string literal. direction=from: what a method " +
                 "(or every method of a class) calls, reads, writes and loads. Methods are matched by exact id, so one overload never stands for another.")]
    public Task<DexReferenceList> FindDexReferences(
        [Description(CodeDescription)] string path,
        [Description("A class, a method (Lpkg/C;->m(I)V, or pkg.C::m with optional parameters (int, String)), a field (Lpkg/C;->f:I or pkg.C::f), " +
                     "or a string in double quotes.")] string target,
        [Description("to (default: who refers to the target) or from (what the target refers to).")] string? direction = null,
        [Description("auto (default), class, method, field or string (target taken literally).")] string? kind = null,
        [Description("References to skip.")] int offset = 0,
        [Description("Most references to return (default 500).")] int limit = 500,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => dex.References(path, target, kind, direction, offset, limit, cancellationToken), cancellationToken);
}
