using System.ComponentModel;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Core.Mobile;
using Corvus.Mcp;
using Corvus.Services.Mobile;
using static Corvus.Tools.ToolSupport;

namespace Corvus.Tools;

[McpServerToolType]
public sealed class AndroidTools(AndroidPackageService packages, DexService dex, JavaDecompilerService java, JavaDotNetMap map, JniBindings jni, OutputPager pager)
{
    public const string PackageDescription = "An .apk, .aab or split set (.apks, .xapk, .apkm).";
    /// <summary>get_android_resource's record beside its text page: the entry, and where its bytes went.</summary>
    public sealed record AndroidResourceFile(
        [property: Description("The package entry read; resources.arsc for a resource's values.")] string Entry,
        [property: Description("Where the bytes were written (outputPath).")] string? OutputPath,
        [property: Description("The entry's size in bytes.")] long? Bytes,
        [property: Description("SHA-256 of the bytes written.")] string? Sha256);

    public const string CodeDescription = "An .apk, .aab or split set (.apks, .xapk, .apkm), a .dex, or a jar with classes*.dex.";

    [McpServerTool(Name = "get_android_manifest", Title = "Android manifest", UseStructuredContent = true)]
    [Description("AndroidManifest.xml of an Android package, decoded: package, versions, SDKs; permissions; application flags (debuggable, " +
                 "allowBackup, cleartext traffic, network security config); each component's effective exported state and why, permissions, intent " +
                 "filters, deep links, meta-data; queries, features, libraries; highlights. Raw XML: get_android_resource.")]
    public Task<AndroidManifestSummary> GetAndroidManifest(
        [Description(PackageDescription)] string path,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => packages.Manifest(path, cancellationToken), cancellationToken);

    [McpServerTool(Name = "list_android_resources", Title = "List Android resources", UseStructuredContent = true, OutputSchemaType = typeof(AndroidResourceList))]
    [Description("Compiled resources of an Android package (resources.arsc or a bundle's resources.pb): a row per resource and " +
                 "configuration with id, type, name, qualifiers ('' is the default), value type and value (references by name); types counts each type.")]
    public Task<string> ListAndroidResources(
        [Description(PackageDescription)] string path,
        [Description("Only this type (string, layout, xml, ...).")] string? type = null,
        [Description("Only names matching this (* and ? wildcards).")] string? name = null,
        [Description("Only this configuration (pt-rBR, or default).")] string? config = null,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description("Most rows.")] int limit = 100,
        CancellationToken cancellationToken = default) => Task.Run(() =>
    {
        var r = packages.Resources(path, type, name, config, offset, ClampLimit(limit));
        return ToolOutput.List(r.Items, r.Offset, ClampLimit(limit), r.Total,
            x => $"{x.Id} @{x.Type}/{x.Name}{(x.Config.Length > 0 ? $" [{x.Config}]" : "")}  {x.ValueType}: {x.Value}{(x.ValueTruncated == true ? " ..." : "")}",
            rows => r with { Items = rows }, "resource", $"Types: {string.Join(", ", r.Types.Select(t => $"{t.Key} {t.Value}"))}\n");
    }, cancellationToken);

    [McpServerTool(Name = "get_android_resource", Title = "Get Android resource", UseStructuredContent = true, OutputSchemaType = typeof(AndroidResourceFile))]
    [Description("One file or resource of an Android package: an entry path is read with binary XML decoded and references named, text as " +
                 "text, other data as a hex preview; @type/name or 0x7f... gives the resource's value in every configuration. outputPath writes the raw bytes.")]
    public Task<string> GetAndroidResource(
        [Description(PackageDescription)] string path,
        [Description("An entry path (res/xml/x.xml, assets/...), @type/name or a resource id 0x7f...")] string name,
        [Description("Write the entry's bytes to this file.")] string? outputPath = null,
        [Description("Replace outputPath if it exists.")] bool overwrite = false,
        [Description(CharOffsetDescription)] int offset = 0,
        [Description(MaxTokensDescription)] int? maxTokens = null,
        CancellationToken cancellationToken = default) => Task.Run(() =>
    {
        var r = packages.Resource(path, name, outputPath, overwrite);
        var record = new AndroidResourceFile(r.Entry, r.OutputPath, r.Bytes, r.Sha256);
        return r.OutputPath != null ? ToolOutput.Report(r.Text, record) : ToolOutput.Text(pager, r.Text, offset, record, maxTokens);
    }, cancellationToken);

    [McpServerTool(Name = "list_dex_classes", Title = "List DEX classes", UseStructuredContent = true, OutputSchemaType = typeof(DexClassList))]
    [Description("Classes defined in the DEX code of an Android package (every classes*.dex): descriptor, DEX file, access, " +
                 "superclass, interfaces, member counts, source file; unfiltered, the packages with most classes. No Java tools needed.")]
    public Task<string> ListDexClasses(
        [Description(CodeDescription)] string path,
        [Description("Only classes whose name contains or matches (* ?) this.")] string? query = null,
        [Description("Only this package and its subpackages.")] string? package = null,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description("Most classes.")] int limit = 100,
        CancellationToken cancellationToken = default) => Task.Run(() =>
    {
        var r = dex.ListClasses(path, query, package, offset, ClampLimit(limit), cancellationToken);
        static string Row(DexClassRow c) => $"{c.Descriptor}  [{string.Join("; ", new[]
        {
            c.Access.Length > 0 ? c.Access : null,
            c.Super is { } s && s != "Ljava/lang/Object;" ? "extends " + s : null,
            c.Interfaces.Count > 0 ? "implements " + string.Join(", ", c.Interfaces) + (c.InterfacesTotal is { } t ? $" (+{t - c.Interfaces.Count})" : "") : null,
            c.Methods + c.Fields > 0 ? $"{c.Methods} methods, {c.Fields} fields" : null, c.DexFile, c.SourceFile,
        }.OfType<string>())}]";
        var header = string.Concat(r.Notes.Take(5).Select(n => $"Note: {n}\n"))
                     + (r.Packages is { Count: > 0 } p ? $"Packages with most classes: {string.Join(", ", p.Select(x => $"{x.Package} {x.Classes}"))}\n" : "");
        return ToolOutput.List(r.Items, r.Offset, ClampLimit(limit), r.Total, Row, rows => r with { Items = rows }, "class", header);
    }, cancellationToken);

    [McpServerTool(Name = "get_dex_class", Title = "DEX class", UseStructuredContent = true, OutputSchemaType = typeof(DexClassPage))]
    [Description("One DEX class: superclass, interfaces, generic signature, enclosing and inner classes, Kotlin @Metadata, annotations; then its " +
                 "members, paged: fields (type, static value) and methods (exact id Lpkg/C;->name(params)ret, Java signature, code size, registers, parameter names).")]
    public Task<string> GetDexClass(
        [Description(CodeDescription)] string path,
        [Description("Class: Lpkg/Name;, pkg.Name, or pkg.Outer.Inner / pkg.Outer$Inner.")] string @class,
        [Description("all (default), fields or methods.")] string? members = null,
        [Description("Only members whose name contains this.")] string? query = null,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description("Most members.")] int limit = 150,
        CancellationToken cancellationToken = default) => Task.Run(() =>
    {
        var (fields, methods) = (members ?? "all").Trim().ToLowerInvariant() switch
        {
            "all" or "" => (true, true),
            "fields" or "field" => (true, false),
            "methods" or "method" => (false, true),
            var m => throw new ToolError(ErrorCode.InvalidArgument, $"unknown members '{m}'; use all, fields or methods."),
        };
        var c = dex.GetClass(path, @class, cancellationToken);
        bool Wanted(string name) => query is not { Length: > 0 } q || name.Contains(q, StringComparison.OrdinalIgnoreCase);
        static IReadOnlyList<T>? Some<T>(IReadOnlyList<T> list) => list.Count > 0 ? list : null;
        var all = (fields ? c.Fields.Where(f => Wanted(f.Name)).Select(f => new DexMember("field", f.Id, f.Access, $"{DexFile.JavaName(f.Type)} {f.Name}", f.Value, null, null,
                       f.GenericSignature, Some(f.Annotations), null)) : [])
            .Concat(methods ? c.Methods.Where(m => Wanted(m.Name)).Select(m => new DexMember("method", m.Id, m.Access, m.Signature, null, m.CodeUnits, m.Registers,
                       m.GenericSignature, Some(m.Annotations), m.ParameterNames.Any(n => n != null) ? m.ParameterNames : null)) : []).ToList();
        var page = all.Skip(Math.Max(0, offset)).Take(ClampLimit(limit)).ToList();
        var record = new DexClassPage(c.Descriptor, c.JavaName, c.DexFile, c.Access, c.Super, c.Interfaces, c.SourceFile, c.GenericSignature, c.EnclosingClass,
            c.EnclosingMethod, c.InnerClasses, c.Kotlin, c.Annotations, c.Fields.Count, c.Methods.Count, page, Math.Max(0, offset), all.Count);
        var header = new System.Text.StringBuilder($"{c.Descriptor} ({c.DexFile}) {c.Access}");
        if (c.Super is { } s) header.Append($" extends {s}");
        if (c.Interfaces.Count > 0) header.Append($" implements {string.Join(", ", c.Interfaces)}");
        header.Append('\n');
        void Line(string label, string? value) { if (value is { Length: > 0 }) header.Append($"{label}: {value}\n"); }
        Line("source", c.SourceFile);
        Line("signature", c.GenericSignature);
        Line("enclosing class", c.EnclosingClass);
        Line("enclosing method", c.EnclosingMethod);
        Line("inner classes", string.Join(", ", c.InnerClasses));
        Line("Kotlin", c.Kotlin);
        foreach (var a in c.Annotations) header.Append(a).Append('\n');
        header.Append($"{c.Fields.Count} fields, {c.Methods.Count} methods\n");
        static string Row(DexMember m) => $"{m.Kind} {m.Id}  {m.Declaration}{(m.Value != null ? " = " + m.Value : "")}"
            + (m.CodeUnits is { } u ? $"  [{u} units, {m.Registers} registers{(m.ParameterNames != null ? "; params " + string.Join(", ", m.ParameterNames.Select(n => n ?? "?")) : "")}]" : "")
            + (m.GenericSignature != null ? $"  signature {m.GenericSignature}" : "") + (m.Annotations != null ? "  " + string.Join(" ", m.Annotations) : "");
        return ToolOutput.List(page, record.Offset, ClampLimit(limit), all.Count, Row, rows => record with { Items = rows }, "member", header.ToString());
    }, cancellationToken);

    [McpServerTool(Name = "disassemble_dex", Title = "Disassemble DEX", UseStructuredContent = true, OutputSchemaType = typeof(TextPageRecord))]
    [Description("Smali (baksmali layout) of a DEX method or class; a class starts with its method ids and sizes. format=annotated adds code offsets and units.")]
    public Task<string> DisassembleDex(
        [Description(CodeDescription)] string path,
        [Description("A method (Lpkg/C;->m(I)V, or pkg.C::m with optional (int, String)) or a class (pkg.C, Lpkg/C;).")] string symbol,
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

    [McpServerTool(Name = "decompile_java", Title = "Decompile Java", UseStructuredContent = true, OutputSchemaType = typeof(TextPageRecord))]
    [Description("Java source of a class or method of an Android package or a jar through JADX (CORVUS_JAVA_DECOMPILER, JDK 17+). A member, " +
                 "anonymous or lambda class comes from the code JADX writes it in. Without JADX: provider_unavailable; disassemble_dex gives smali.")]
    public async Task<string> DecompileJava(
        [Description("An .apk, .aab or split set, a .dex, or a jar (DEX or .class files).")] string path,
        [Description("A class (pkg.C, Lpkg/C;) or method (Lpkg/C;->m(I)V, or pkg.C::m with optional (int, String)).")] string symbol,
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

    [McpServerTool(Name = "map_java_dotnet", Title = "Map Java and .NET", UseStructuredContent = true, OutputSchemaType = typeof(JavaDotNetResult))]
    [Description("The other side of a Java / .NET bridge, for decompile_member or get_dex_class. .NET for Android (Xamarin / MAUI): a Java " +
                 "wrapper class or method to its .NET type or method and back ([Register] and crc64 names). Unity Mono: the C# " +
                 "reaching a Java class or member through AndroidJavaClass / AndroidJavaObject / AndroidJavaProxy / AndroidJNI, and back, with a " +
                 "confidence. A * / ? pattern lists the pairs it matches. Reads loaded assemblies, and the package's with path.")]
    public Task<string> MapJavaDotNet(
        [Description("A Java class (Lpkg/C; or pkg.C), Java method id (Lpkg/C;->m(I)V), a .NET type or member, or a pattern (crc64*).")] string symbol,
        [Description("The package whose assemblies to read; optional when they are loaded.")] string? path = null,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description("Most pairs.")] int limit = 100,
        CancellationToken cancellationToken = default) => Task.Run(() =>
    {
        var r = map.Map(symbol, path, cancellationToken);
        return ToolOutput.List(r.Items, offset, ClampLimit(limit),
            p => $"{p.Java}  <->  {p.DotNet}  [{p.Basis}{(p.Confidence != null ? ", " + p.Confidence : "")}; {p.Assembly}{(p.Loaded ? "" : ", not loaded")}]",
            rows => r with { Items = rows, Offset = Math.Max(0, offset) }, "pair",
            $"{r.Query} ({r.Direction.Replace('_', ' ')}){string.Concat(r.Notes.Take(5).Select(n => "\nNote: " + n))}\n");
    }, cancellationToken);

    [McpServerTool(Name = "list_jni_bindings", Title = "List JNI bindings", UseStructuredContent = true, OutputSchemaType = typeof(JniBindingList))]
    [Description("Java native methods of an Android package paired with their code in lib/<abi>/*.so: Java_ exports by JNI name mangling " +
                 "and RegisterNatives tables in the libraries' data; also unbound methods and stray Java_ exports.")]
    public Task<string> ListJniBindings(
        [Description(PackageDescription)] string path,
        [Description("ABI to read, or all; default arm64-v8a, else the first.")] string? abi = null,
        [Description("Only rows naming this class (pkg.C or pkg/C).")] string? @class = null,
        [Description("Only this kind.")] string? kind = null,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description("Most rows.")] int limit = JniBindings.DefaultLimit,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, progress => Task.Run(() =>
    {
        progress.Report(new ProgressNotificationValue { Progress = 0, Message = "reading the DEX code and native libraries" });
        var r = jni.List(path, abi, @class, kind, offset, ClampLimit(limit, 2_000), cancellationToken);
        static string Row(JniBinding b) => $"{b.Kind}  {b.JavaMethod ?? "(no native method)"}" + (b.Library != null ? $"  ->  {b.Library} {b.Symbol ?? ""}{(b.Address != null ? " @" + b.Address : "")}" : "")
                                          + (b.Confidence != null ? $"  [{b.Confidence}{(b.Table != null ? ", table " + b.Table : "")}]" : "");
        var header = string.Concat(r.Libraries.Select(l => $"{l.Library}: {l.JavaExports} Java_ exports, {l.RegisteredMethods} registered in {l.RegisterNativesTables} tables{(l.HasJniOnLoad ? ", JNI_OnLoad" : "")}\n"))
                     + string.Concat(r.Notes.Select(n => $"Note: {n}\n"));
        return ToolOutput.List(r.Items, r.Offset, ClampLimit(limit, 2_000), r.Total, Row, rows => r with { Items = rows }, "binding", header);
    }, cancellationToken));

    [McpServerTool(Name = "search_dex", Title = "Search DEX code", UseStructuredContent = true, OutputSchemaType = typeof(DexHitList))]
    [Description("Search DEX code. kind=string: literals with the method and offset of each use; type: defined classes and type uses; " +
                 "method / field: defined and referenced members with use counts; const: numeric constants; opcode: instructions by mnemonic.")]
    public Task<string> SearchDex(
        [Description(CodeDescription)] string path,
        [Description("What to search.")] string kind,
        [Description("Case-insensitive substring or * / ? pattern; for const a number.")] string query,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description("Most hits.")] int limit = 100,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, progress => Task.Run(() =>
    {
        progress.Report(new ProgressNotificationValue { Progress = 0, Message = "indexing the DEX code (once per package)" });
        var r = dex.Search(path, kind, query, offset, ClampLimit(limit), cancellationToken);
        static string Row(DexHit h) => $"{h.Kind} {h.Value}" + (h.Method != null ? $"  in {h.Method} @{h.Offset} {h.Opcode}" : "") + (h.Uses is { } u ? $"  ({u} uses)" : "");
        return ToolOutput.List(r.Items, r.Offset, ClampLimit(limit), r.Total, Row, rows => r with { Items = rows }, "hit", string.Concat(r.Notes.Select(n => $"Note: {n}\n")));
    }, cancellationToken));

    [McpServerTool(Name = "find_dex_references", Title = "Find DEX references", UseStructuredContent = true, OutputSchemaType = typeof(DexReferenceList))]
    [Description("Cross-references in DEX code, with the method and code offset of each instruction. direction=to: callers of a method, readers and " +
                 "writers of a field, uses of a class or string. direction=from: what a method (or each method of a class) calls, reads, writes and " +
                 "loads. Methods match by exact id.")]
    public Task<string> FindDexReferences(
        [Description(CodeDescription)] string path,
        [Description("A class, method (Lpkg/C;->m(I)V or pkg.C::m(int)), field (Lpkg/C;->f:I or pkg.C::f) or a \"quoted\" string.")] string target,
        [Description("to (default; who refers to target) or from.")] string? direction = null,
        [Description("How to read target (default auto; string: taken literally).")] string? kind = null,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description("Most references.")] int limit = 100,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, progress => Task.Run(() =>
    {
        progress.Report(new ProgressNotificationValue { Progress = 0, Message = "indexing the DEX code (once per package)" });
        var r = dex.References(path, target, kind, direction, offset, ClampLimit(limit), cancellationToken);
        static string Row(DexReference x) => $"{x.Method} @{x.Offset}  {x.Opcode} {x.Target}";
        var header = $"{(r.Direction == "from" ? "From" : "To")} {r.TargetKind} {r.Target}\n" + string.Concat(r.Notes.Select(n => $"Note: {n}\n"));
        return ToolOutput.List(r.Items, r.Offset, ClampLimit(limit), r.Total, Row, rows => r with { Items = rows }, "reference", header);
    }, cancellationToken));
}
