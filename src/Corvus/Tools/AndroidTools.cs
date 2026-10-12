using System.ComponentModel;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Core.Mobile;
using Corvus.Services.Mobile;
using static Corvus.Tools.ToolSupport;

namespace Corvus.Tools;

[McpServerToolType]
public sealed class AndroidTools(AndroidPackageService packages, DexService dex, JavaDecompilerService java, JavaDotNetMap map, JniBindings jni, OutputPager pager)
{
    public const string PackageDescription = "An .apk, .aab (base module) or split set (.apks, .xapk, .apkm).";
    public const string CodeDescription = "An Android package (.apk, .aab, .apks, .xapk, .apkm), a .dex, or a jar / zip with classes*.dex.";

    [McpServerTool(Name = "get_android_manifest", Title = "Android manifest", UseStructuredContent = true)]
    [Description("AndroidManifest.xml of an Android package, decoded: package, versions, SDKs; used and declared permissions; application " +
                 "flags (debuggable, allowBackup, cleartext traffic, network security config); each component with its effective exported state and " +
                 "why, permissions, intent filters, deep links, meta-data; queries, features, libraries; highlights. The raw XML: get_android_resource.")]
    public Task<AndroidManifestSummary> GetAndroidManifest(
        [Description(PackageDescription)] string path,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => packages.Manifest(path, cancellationToken), cancellationToken);

    [McpServerTool(Name = "list_android_resources", Title = "List Android resources", UseStructuredContent = true)]
    [Description("Compiled resources of an Android package (resources.arsc or a bundle's resources.pb): a row per resource and " +
                 "configuration with id, type, name, qualifiers ('' is the default), value type and value (references by name); types counts each type.")]
    public Task<AndroidResourceList> ListAndroidResources(
        [Description(PackageDescription)] string path,
        [Description("Only this type (string, layout, xml, ...).")] string? type = null,
        [Description("Only names matching this (* and ? wildcards).")] string? name = null,
        [Description("Only this configuration: qualifiers as in a directory name (pt-rBR), or default.")] string? config = null,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description("Most rows to return.")] int limit = 500,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => packages.Resources(path, type, name, config, offset, limit), cancellationToken);

    [McpServerTool(Name = "get_android_resource", Title = "Get Android resource")]
    [Description("One file or resource of an Android package: an entry path is read with binary XML decoded and references named, text as " +
                 "text, other data as a hex preview; @type/name or 0x7f... gives the resource's value in every configuration. savePath writes the raw bytes.")]
    public Task<string> GetAndroidResource(
        [Description(PackageDescription)] string path,
        [Description("An entry path (res/xml/x.xml, assets/...), @type/name or a resource id 0x7f...")] string name,
        [Description("Write the entry's bytes to this file.")] string? savePath = null,
        [Description("Replace savePath if it exists.")] bool overwrite = false,
        [Description(CharOffsetDescription)] int offset = 0,
        [Description(MaxTokensDescription)] int? maxTokens = null,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => packages.Resource(path, name, savePath, overwrite, offset, maxTokens), cancellationToken);

    [McpServerTool(Name = "list_dex_classes", Title = "List DEX classes", UseStructuredContent = true)]
    [Description("Classes defined in the DEX code of an Android package (every classes*.dex): descriptor, Java name, DEX file, access, " +
                 "superclass, interfaces, member counts, source file. No Java tools needed.")]
    public Task<DexClassList> ListDexClasses(
        [Description(CodeDescription)] string path,
        [Description("Only classes whose Java name or descriptor contains this, or matches it (* and ? wildcards).")] string? query = null,
        [Description("Only this package and its subpackages.")] string? package = null,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description("Most classes to return.")] int limit = 500,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => dex.ListClasses(path, query, package, offset, limit, cancellationToken), cancellationToken);

    [McpServerTool(Name = "get_dex_class", Title = "DEX class", UseStructuredContent = true)]
    [Description("One DEX class in full: superclass, interfaces, generic signature, enclosing and inner classes, Kotlin @Metadata, annotations; " +
                 "fields with type and static initial value; methods with their exact id (Lpkg/C;->name(params)ret, unique per overload), Java " +
                 "signature, code size, registers and parameter names.")]
    public Task<DexClassDetail> GetDexClass(
        [Description(CodeDescription)] string path,
        [Description("Class: Lpkg/Name;, pkg.Name, or pkg.Outer.Inner / pkg.Outer$Inner.")] string @class,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => dex.GetClass(path, @class, cancellationToken), cancellationToken);

    [McpServerTool(Name = "disassemble_dex", Title = "Disassemble DEX")]
    [Description("Smali of a method or class of an Android package's DEX code, in baksmali's layout. format=annotated adds code offsets and units.")]
    public Task<string> DisassembleDex(
        [Description(CodeDescription)] string path,
        [Description("A method (Lpkg/C;->name(params)ret, or pkg.C::name with optional (int, String)) or a class (pkg.C, Lpkg/C;).")] string symbol,
        [Description("Output layout (default smali).")] string? format = null,
        [Description(CharOffsetDescription)] int offset = 0,
        [Description(MaxTokensDescription)] int? maxTokens = null,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => pager.Page(dex.Disassemble(path, symbol, (format ?? "smali").Trim().ToLowerInvariant() switch
        {
            "smali" or "" => false,
            "annotated" => true,
            var f => throw new ToolError(ErrorCode.InvalidArgument, $"unknown format '{f}'; use smali or annotated."),
        }, cancellationToken), offset, maxTokens), cancellationToken);

    [McpServerTool(Name = "decompile_java", Title = "Decompile Java")]
    [Description("Java source of a class or one method of an Android package through JADX (CORVUS_JAVA_DECOMPILER, JDK 17+; one session per " +
                 "package kept loaded). Without JADX: provider_unavailable; disassemble_dex gives smali.")]
    public async Task<string> DecompileJava(
        [Description(CodeDescription)] string path,
        [Description("A class (pkg.C, Lpkg/C;) or a method (Lpkg/C;->name(params)ret, or pkg.C::name with optional (int, String)).")] string symbol,
        [Description("Return smali where JADX fails.")] bool smaliFallback = true,
        [Description("Decompiler.")] string? engine = null,
        [Description(CharOffsetDescription)] int offset = 0,
        [Description(MaxTokensDescription)] int? maxTokens = null,
        CancellationToken cancellationToken = default)
    {
        if (engine is { Length: > 0 } e && !e.Trim().Equals("jadx", StringComparison.OrdinalIgnoreCase))
            throw new ToolError(ErrorCode.InvalidArgument, $"unknown engine '{e}'; use jadx.");
        var text = await Task.Run(() => java.Decompile(path, symbol, smaliFallback, cancellationToken), cancellationToken).ConfigureAwait(false);
        return pager.Page(text, offset, maxTokens);
    }

    [McpServerTool(Name = "map_java_dotnet", Title = "Map Java and .NET", UseStructuredContent = true)]
    [Description("The other side of a Java / .NET bridge, ready for decompile_member or get_dex_class. .NET for Android (Xamarin / MAUI): a " +
                 "Java wrapper class or method gives its .NET type or method and back ([Register] names and crc64 wrapper names). Unity Mono: the C# " +
                 "reaching a Java class or member through AndroidJavaClass / AndroidJavaObject / AndroidJavaProxy / AndroidJNI, and back, with a " +
                 "confidence. Reads the loaded assemblies, and the package's with path.")]
    public Task<JavaDotNetResult> MapJavaDotNet(
        [Description("A Java class (Lpkg/C; or pkg.C), Java method id (Lpkg/C;->m(I)V), or a .NET type or member.")] string symbol,
        [Description("The .apk / .aab whose assemblies to read without loading; optional when they are loaded.")] string? path = null,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => map.Map(symbol, path, cancellationToken), cancellationToken);

    [McpServerTool(Name = "list_jni_bindings", Title = "List JNI bindings", UseStructuredContent = true)]
    [Description("Java native methods of an Android package paired with their code in lib/<abi>/*.so: Java_ exports by JNI name mangling " +
                 "and RegisterNatives tables in the libraries' data; also unbound methods and stray Java_ exports.")]
    public Task<JniBindingList> ListJniBindings(
        [Description(PackageDescription)] string path,
        [Description("ABI to read, or all; default arm64-v8a, else the first.")] string? abi = null,
        [Description("Only rows naming this class (pkg.C or pkg/C).")] string? @class = null,
        [Description("Only this kind.")] string? kind = null,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description("Most rows.")] int limit = JniBindings.DefaultLimit,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => jni.List(path, abi, @class, kind, offset, limit, cancellationToken), cancellationToken);

    [McpServerTool(Name = "search_dex", Title = "Search DEX code", UseStructuredContent = true)]
    [Description("Search the DEX code of an Android package. kind=string: string literals with the method and offset of each use; type: " +
                 "defined classes and type uses; method / field: defined and referenced members with use counts; const: numeric constants; opcode: " +
                 "instructions by mnemonic (invoke-static).")]
    public Task<DexHitList> SearchDex(
        [Description(CodeDescription)] string path,
        [Description("What to search.")] string kind,
        [Description("Case-insensitive substring or * / ? pattern; for const a number.")] string query,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description("Most hits to return.")] int limit = 200,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => dex.Search(path, kind, query, offset, limit, cancellationToken), cancellationToken);

    [McpServerTool(Name = "find_dex_references", Title = "Find DEX references", UseStructuredContent = true)]
    [Description("Cross-references in DEX code with the method and code offset of each instruction. direction=to: callers of a method, readers and " +
                 "writers of a field, uses of a class or a string literal. direction=from: what a method (or every method of a class) calls, reads, " +
                 "writes and loads. Methods match by exact id, never another overload.")]
    public Task<DexReferenceList> FindDexReferences(
        [Description(CodeDescription)] string path,
        [Description("A class, a method (Lpkg/C;->m(I)V, or pkg.C::m with optional parameters (int, String)), a field (Lpkg/C;->f:I or pkg.C::f), " +
                     "or a string in double quotes.")] string target,
        [Description("to (default: who refers to the target) or from (what it refers to).")] string? direction = null,
        [Description("How to read target (default auto; string: taken literally).")] string? kind = null,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description("Most references to return.")] int limit = 500,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => dex.References(path, target, kind, direction, offset, limit, cancellationToken), cancellationToken);
}
