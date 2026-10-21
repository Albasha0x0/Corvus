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

    public const string CodeDescription = "An Android package, a .dex, or a jar with classes*.dex.";
    private const string MappingDescription = "R8/ProGuard mapping.txt: shows and accepts original names; kept per package.";

    [McpServerTool(Name = "get_android_manifest", Title = "Android manifest", UseStructuredContent = true, OutputSchemaType = typeof(AndroidManifestView))]
    [Description("AndroidManifest.xml decoded. view=summary: package, versions, SDKs, permissions, application flags, component counts, exported " +
                 "components and why, queries, features, libraries, highlights. components: each with intent filters, deep links, meta-data.")]
    public Task<string> GetAndroidManifest(
        [Description(PackageDescription)] string path,
        [Description("summary (default) or components.")] string? view = null,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description("Most components.")] int limit = 50,
        CancellationToken cancellationToken = default) => Task.Run(() =>
    {
        bool components = (view ?? "summary").Trim().ToLowerInvariant() switch
        {
            "summary" or "" => false,
            "components" => true,
            var v => throw new ToolError(ErrorCode.InvalidArgument, $"unknown view '{v}'; use summary or components."),
        };
        var m = packages.Manifest(path, cancellationToken);
        static string Meta(AndroidMetaData d) => $"{d.Name}={d.Value ?? d.Resource}";
        static string Filter(AndroidIntentFilter f) => string.Join(" ", f.Actions.Concat(f.Categories)
            .Concat(f.Data.Select(d => $"{d.Scheme}://{d.Host}{(d.Port != null ? ":" + d.Port : "")}{d.Path}{(d.MimeType != null ? " " + d.MimeType : "")}"))
            .Concat(f.AutoVerify ? ["autoVerify"] : []).Concat(f.Priority is { } p ? [$"priority {p}"] : []));
        static string Row(AndroidComponentRow c) => $"{c.Kind} {c.Name}  {(c.EffectiveExported ? "exported" : "not exported")} ({c.ExportedReason})"
            + string.Concat(new[]
            {
                c.Launcher == true ? "launcher" : null, c.Permission != null ? "permission " + c.Permission : null, c.Authorities != null ? "authorities " + c.Authorities : null,
                c.TargetActivity != null ? "target " + c.TargetActivity : null, c.DeepLinks != null ? "deep links " + string.Join(", ", c.DeepLinks) : null,
                c.IntentFilters != null ? "filters: " + string.Join(" | ", c.IntentFilters) : null,
                c.MetaData != null ? "meta-data " + string.Join(", ", c.MetaData) : null, c.DotNetType != null ? ".NET " + c.DotNetType : null,
            }.OfType<string>().Select(s => "; " + s));
        static IReadOnlyList<string>? Some(IEnumerable<string> list) => list.ToList() is { Count: > 0 } l ? l : null;
        static string Exported(AndroidComponent c) => $"{c.Kind} {c.Name}  ({c.ExportedReason}){(c.Permission != null ? "; permission " + c.Permission : "")}" +
            $"{(c.Launcher ? "; launcher" : "")}{(c.DeepLinks.Count > 0 ? "; deep links " + string.Join(", ", c.DeepLinks) : "")}";
        if (components)
        {
            var page = m.Components.Skip(Math.Max(0, offset)).Take(ClampLimit(limit)).Select(c => new AndroidComponentRow(c.Kind, c.Name, c.Exported, c.EffectiveExported,
                c.ExportedReason, c.Permission, c.Enabled, c.Process, c.TargetActivity, c.Authorities, c.ReadPermission, c.WritePermission, c.GrantUriPermissions,
                c.Launcher ? true : null, Some(c.DeepLinks), Some(c.IntentFilters.Select(Filter)), Some(c.MetaData.Select(Meta)), c.DotNetType)).ToList();
            var list = new AndroidManifestView(m.Package, m.VersionCode, m.VersionName, m.MinSdk, m.TargetSdk, m.MaxSdk, m.CompileSdk, m.Split, null, null, null, null,
                null, null, null, null, null, null, null, null, page, Math.Max(0, offset), m.Components.Count);
            return ToolOutput.List(page, Math.Max(0, offset), ClampLimit(limit), m.Components.Count, Row, rows => list with { Items = rows }, "component", $"{m.Package}\n");
        }
        var exported = m.Components.Where(c => c.EffectiveExported).ToList();
        var counts = m.Components.GroupBy(c => c.Kind).ToDictionary(g => g.Key, g => $"{g.Count()} ({g.Count(c => c.EffectiveExported)} exported)");
        var record = new AndroidManifestView(m.Package, m.VersionCode, m.VersionName, m.MinSdk, m.TargetSdk, m.MaxSdk, m.CompileSdk, m.Split, m.Application,
            [.. m.Permissions.Select(p => p.Name + (p.MaxSdkVersion is { } x ? $" (maxSdk {x})" : "") + (p.Sdk23Only ? " (sdk 23+)" : ""))],
            Some(m.DeclaredPermissions.Select(p => $"{p.Name} ({p.ProtectionLevel}{(p.Group != null ? ", group " + p.Group : "")})")), counts,
            [.. exported.Take(MaxExportedShown).Select(Exported)], exported.Count, Some(m.Queries.Packages.Concat(m.Queries.Intents).Concat(m.Queries.Providers)),
            m.Features, m.Libraries, Some(m.MetaData.Select(Meta)), m.Highlights, m.Issues, null, null, null);
        var sb = new System.Text.StringBuilder($"{m.Package} {m.VersionName} ({m.VersionCode}); SDK min {m.MinSdk}, target {m.TargetSdk}{(m.CompileSdk is { } cs ? $", compile {cs}" : "")}{(m.Split != null ? $"; split {m.Split}" : "")}\n");
        var a = m.Application;
        sb.Append($"application {a.Name}{(a.Label != null ? $" \"{a.Label}\"" : "")}: debuggable={a.Debuggable?.ToString() ?? "-"}, allowBackup={a.AllowBackup?.ToString() ?? "-"}, " +
                  $"usesCleartextTraffic={a.UsesCleartextTraffic?.ToString() ?? "-"}{(a.NetworkSecurityConfig != null ? ", networkSecurityConfig " + a.NetworkSecurityConfig : "")}\n");
        foreach (var h in m.Highlights) sb.Append("! ").Append(h).Append('\n');
        sb.Append($"permissions ({record.Permissions!.Count}): {string.Join(", ", record.Permissions)}\n");
        if (record.DeclaredPermissions != null) sb.Append($"declared: {string.Join(", ", record.DeclaredPermissions)}\n");
        sb.Append($"components: {string.Join(", ", counts.Select(c => $"{c.Key} {c.Value}"))}\n");
        sb.Append($"exported ({exported.Count}{(exported.Count > MaxExportedShown ? $", first {MaxExportedShown}; view=components lists all" : "")}):\n");
        foreach (var e in record.Exported!) sb.Append("  ").Append(e).Append('\n');
        if (m.Features.Count > 0) sb.Append($"features: {string.Join(", ", m.Features)}\n");
        if (m.Libraries.Count > 0) sb.Append($"libraries: {string.Join(", ", m.Libraries)}\n");
        if (m.Queries.Packages.Count + m.Queries.Intents.Count + m.Queries.Providers.Count > 0)
            sb.Append($"queries: {string.Join(", ", m.Queries.Packages.Concat(m.Queries.Intents).Concat(m.Queries.Providers))}\n");
        if (record.MetaData != null) sb.Append($"meta-data: {string.Join(", ", record.MetaData)}\n");
        foreach (var i in m.Issues) sb.Append("issue: ").Append(i).Append('\n');
        return ToolOutput.Report(sb.ToString(), record);
    }, cancellationToken);

    /// <summary>Exported components the summary names; view=components pages all.</summary>
    private const int MaxExportedShown = 30;

    /// <summary>A manifest component with its intent filters and meta-data as text.</summary>
    public sealed record AndroidComponentRow(string Kind, string Name,
        [property: Description("android:exported as written.")] bool? Exported, bool EffectiveExported, string ExportedReason, string? Permission, bool? Enabled,
        string? Process, string? TargetActivity, string? Authorities, string? ReadPermission, string? WritePermission, bool? GrantUriPermissions, bool? Launcher,
        IReadOnlyList<string>? DeepLinks,
        [property: Description("Each filter: actions, categories, data as scheme://host:port/path and MIME type.")] IReadOnlyList<string>? IntentFilters,
        [property: Description("name=value or resource.")] IReadOnlyList<string>? MetaData,
        [property: Description("The .NET type implementing it (Xamarin / MAUI).")] string? DotNetType);

    /// <summary>get_android_manifest: the summary (view=summary) or a page of components (view=components).</summary>
    public sealed record AndroidManifestView(string Package, string? VersionCode, string? VersionName, int? MinSdk, int? TargetSdk, int? MaxSdk, int? CompileSdk,
        [property: Description("Set on a split APK: its split name.")] string? Split,
        AndroidApplicationFlags? Application,
        [property: Description("Used permissions, with maxSdk and sdk-23-only marks.")] IReadOnlyList<string>? Permissions,
        [property: Description("Declared permissions with protection level and group.")] IReadOnlyList<string>? DeclaredPermissions,
        [property: Description("Components per kind, with how many are exported.")] IReadOnlyDictionary<string, string>? ComponentCounts,
        [property: Description("First 30 exported components: kind, name, why, permission, launcher, deep links.")] IReadOnlyList<string>? Exported,
        int? ExportedTotal, [property: Description("Packages, intents and providers it queries.")] IReadOnlyList<string>? Queries, IReadOnlyList<string>? Features,
        IReadOnlyList<string>? Libraries, [property: Description("Application meta-data, name=value.")] IReadOnlyList<string>? MetaData,
        [property: Description("debuggable, cleartext traffic, backups, unguarded exported components, deep links.")] IReadOnlyList<string>? Highlights,
        IReadOnlyList<string>? Issues,
        [property: Description("view=components: the page of components.")] IReadOnlyList<AndroidComponentRow>? Items, int? Offset, int? Total);

    [McpServerTool(Name = "list_android_resources", Title = "List Android resources", UseStructuredContent = true, OutputSchemaType = typeof(AndroidResourceList))]
    [Description("Compiled resources of an Android package (resources.arsc, or resources.pb in a bundle): a row per resource and configuration with " +
                 "id, type, name, qualifiers, value type and value (cut at 200 characters); counts per type.")]
    public Task<string> ListAndroidResources(
        [Description(PackageDescription)] string path,
        [Description("Only this type (string, layout, xml...).")] string? type = null,
        [Description("Only names matching this (* and ? wildcards).")] string? name = null,
        [Description("Only this configuration (pt-rBR, or default).")] string? config = null,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description("Most rows.")] int limit = 100,
        [Description(ToolSupport.MaxTokensDescription)] int? maxTokens = null,
        CancellationToken cancellationToken = default) => Task.Run(() =>
    {
        var r = packages.Resources(path, type, name, config, offset, ClampLimit(limit));
        return ToolOutput.List(r.Items, r.Offset, ClampLimit(limit), r.Total,
            x => $"{x.Id} @{x.Type}/{x.Name}{(x.Config.Length > 0 ? $" [{x.Config}]" : "")}  {x.ValueType}: {x.Value}{(x.ValueTruncated == true ? " ..." : "")}",
            rows => r with { Items = rows }, "resource", $"Types: {string.Join(", ", r.Types.Select(t => $"{t.Key} {t.Value}"))}\n");
    }, cancellationToken);

    [McpServerTool(Name = "get_android_resource", Title = "Get Android resource", UseStructuredContent = true, OutputSchemaType = typeof(AndroidResourceFile))]
    [Description("One entry or resource of an Android package: an entry path (binary XML decoded, references named; text; else a hex preview), " +
                 "or @type/name / 0x7f... for its value in every configuration.")]
    public Task<string> GetAndroidResource(
        [Description(PackageDescription)] string path,
        [Description("Entry path (res/xml/x.xml, assets/...), @type/name or resource id 0x7f...")] string name,
        [Description("Write the entry bytes to this file.")] string? outputPath = null,
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
    [Description("Classes defined in the DEX code of an Android package (every classes*.dex): descriptor, DEX file, access, superclass, interfaces, " +
                 "member counts, source file; unfiltered, the largest packages.")]
    public Task<string> ListDexClasses(
        [Description(CodeDescription)] string path,
        [Description("Only classes whose name contains or matches (* ?) this.")] string? query = null,
        [Description("Only this package and its subpackages.")] string? package = null,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description("Most classes.")] int limit = 100,
        [Description(ToolSupport.MaxTokensDescription)] int? maxTokens = null,
        [Description(MappingDescription)] string? mapping = null,
        CancellationToken cancellationToken = default) => Task.Run(() =>
    {
        var r = dex.ListClasses(path, query, package, offset, ClampLimit(limit), cancellationToken, mapping);
        static string Row(DexClassRow c) => $"{c.Descriptor}{(c.Original != null ? " = " + c.Original : "")}  [{string.Join("; ", new[]
        {
            c.Access.Length > 0 ? c.Access : null,
            c.Super is { } s && s != "Ljava/lang/Object;" ? "extends " + s : null,
            c.Interfaces.Count > 0 ? "implements " + string.Join(", ", c.Interfaces) + (c.InterfacesTotal is { } t ? $" (+{t - c.Interfaces.Count})" : "") : null,
            c.Methods + c.Fields > 0 ? $"{c.Methods} methods, {c.Fields} fields" : null, c.DexFile, c.SourceFile,
        }.OfType<string>())}]";
        var header = string.Concat(r.Notes.Take(5).Select(n => $"Note: {n}\n"))
                     + (r.Packages is { Count: > 0 } p ? $"Packages with most classes: {string.Join(", ", p)}\n" : "");
        return ToolOutput.List(r.Items, r.Offset, ClampLimit(limit), r.Total, Row, rows => r with { Items = rows }, "class", header);
    }, cancellationToken);

    [McpServerTool(Name = "get_dex_class", Title = "DEX class", UseStructuredContent = true, OutputSchemaType = typeof(DexClassPage))]
    [Description("One DEX class: superclass, interfaces, generic signature, enclosing and inner classes, Kotlin @Metadata, annotations; then its " +
                 "members, paged: fields (type, static value), methods (id, Java signature, code size, registers, parameters).")]
    public Task<string> GetDexClass(
        [Description(CodeDescription)] string path,
        [Description("Class: Lpkg/Name;, pkg.Name, or pkg.Outer.Inner / pkg.Outer$Inner.")] string @class,
        [Description("all (default), fields or methods.")] string? members = null,
        [Description("Only members whose name contains this.")] string? query = null,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description("Most members.")] int limit = 150,
        [Description(MappingDescription)] string? mapping = null,
        CancellationToken cancellationToken = default) => Task.Run(() =>
    {
        var (fields, methods) = (members ?? "all").Trim().ToLowerInvariant() switch
        {
            "all" or "" => (true, true),
            "fields" or "field" => (true, false),
            "methods" or "method" => (false, true),
            var m => throw new ToolError(ErrorCode.InvalidArgument, $"unknown members '{m}'; use all, fields or methods."),
        };
        var c = dex.GetClass(path, @class, cancellationToken, mapping);
        bool Wanted(string name) => query is not { Length: > 0 } q || name.Contains(q, StringComparison.OrdinalIgnoreCase);
        static IReadOnlyList<T>? Some<T>(IReadOnlyList<T> list) => list.Count > 0 ? list : null;
        var all = (fields ? c.Fields.Where(f => Wanted(f.Name)).Select(f => new DexMember("field", f.Id, f.Access, $"{DexFile.JavaName(f.Type)} {f.Name}", f.Value, null, null,
                       f.GenericSignature, Some(f.Annotations), null) { Original = f.Original }) : [])
            .Concat(methods ? c.Methods.Where(m => Wanted(m.Name)).Select(m => new DexMember("method", m.Id, m.Access, m.Signature, null, m.CodeUnits, m.Registers,
                       m.GenericSignature, Some(m.Annotations), m.ParameterNames.Any(n => n != null) ? m.ParameterNames : null) { Original = m.Original }) : []).ToList();
        var page = all.Skip(Math.Max(0, offset)).Take(ClampLimit(limit)).ToList();
        var record = new DexClassPage(c.Descriptor, c.JavaName, c.DexFile, c.Access, c.Super, c.Interfaces, c.SourceFile, c.GenericSignature, c.EnclosingClass,
            c.EnclosingMethod, c.InnerClasses, c.Kotlin, c.Annotations, c.Fields.Count, c.Methods.Count, page, Math.Max(0, offset), all.Count) { Original = c.Original };
        var header = new System.Text.StringBuilder(string.Concat(c.Notes.Select(n => $"Note: {n}\n")) + $"{c.Descriptor}{(c.Original != null ? " = " + c.Original : "")} ({c.DexFile}) {c.Access}");
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
        static string Row(DexMember m) => $"{m.Kind} {m.Id}  {m.Declaration}{(m.Value != null ? " = " + m.Value : "")}{(m.Original != null ? "  (original " + m.Original + ")" : "")}"
            + (m.CodeUnits is { } u ? $"  [{u} units, {m.Registers} registers{(m.ParameterNames != null ? "; params " + string.Join(", ", m.ParameterNames.Select(n => n ?? "?")) : "")}]" : "")
            + (m.GenericSignature != null ? $"  signature {m.GenericSignature}" : "") + (m.Annotations != null ? "  " + string.Join(" ", m.Annotations) : "");
        return ToolOutput.List(page, record.Offset, ClampLimit(limit), all.Count, Row, rows => record with { Items = rows }, "member", header.ToString());
    }, cancellationToken);

    [McpServerTool(Name = "disassemble_dex", Title = "Disassemble DEX", UseStructuredContent = true, OutputSchemaType = typeof(TextPageRecord))]
    [Description("Smali (baksmali layout) of a DEX method or class (a class lists its method ids and sizes first); format=annotated adds code offsets. " +
                 "A jar or .class: the javap -c -p listing.")]
    public Task<string> DisassembleDex(
        [Description("An Android package, .dex, jar or .class.")] string path,
        [Description("Method (Lpkg/C;->m(I)V, pkg.C::m, pkg.C::m(int)) or class (pkg.C, Lpkg/C;).")] string symbol,
        [Description("Output layout (default smali).")] string? format = null,
        [Description(CharOffsetDescription)] int offset = 0,
        [Description(MaxTokensDescription)] int? maxTokens = null,
        [Description(MappingDescription)] string? mapping = null,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => pager.Page(dex.Disassemble(path, symbol, (format ?? "smali").Trim().ToLowerInvariant() switch
        {
            "smali" or "" => false,
            "annotated" => true,
            var f => throw new ToolError(ErrorCode.InvalidArgument, $"unknown format '{f}'; use smali or annotated."),
        }, cancellationToken, mapping), offset, maxTokens), cancellationToken);

    [McpServerTool(Name = "decompile_java", Title = "Decompile Java", UseStructuredContent = true, OutputSchemaType = typeof(TextPageRecord))]
    [Description("Java source of a class or method of an Android package or jar via JADX (CORVUS_JAVA_DECOMPILER, JDK 17+), or of a jar or .class via " +
                 "Vineflower (engine=vineflower, CORVUS_JAVA_DECOMPILER2). Members, anonymous and lambda classes come from the code they are written " +
                 "in. Without them: disassemble_dex.")]
    public async Task<string> DecompileJava(
        [Description("An .apk, .aab or split set, a .dex, a jar or a .class.")] string path,
        [Description("Class (pkg.C, Lpkg/C;) or method (Lpkg/C;->m(I)V, pkg.C::m, pkg.C::m(int)).")] string symbol,
        [Description("Partial Java where JADX fails; default: smali there.")] bool javaOnly = false,
        [Description("jadx (default) or vineflower (class files only).")] string? engine = null,
        [Description(CharOffsetDescription)] int offset = 0,
        [Description(MaxTokensDescription)] int? maxTokens = null,
        [Description(MappingDescription)] string? mapping = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default)
    {
        var decompiler = (engine ?? "").Trim().ToLowerInvariant() switch
        {
            "" or JavaDecompilerService.Jadx => JavaDecompilerService.Jadx,
            JavaDecompilerService.Vineflower => JavaDecompilerService.Vineflower,
            var e => throw new ToolError(ErrorCode.InvalidArgument, $"unknown engine '{e}'; use jadx or vineflower."),
        };
        var text = await OrderedProgress.Run(context, progress =>
        {
            progress.Report(new ProgressNotificationValue { Progress = 0, Message = decompiler == JavaDecompilerService.Jadx
                ? "JADX: starting and loading the package (once per package)" : "Vineflower: decompiling the class" });
            return Task.Run(() => java.Decompile(path, symbol, !javaOnly, cancellationToken, mapping, decompiler), cancellationToken);
        }).ConfigureAwait(false);
        return pager.Page(text, offset, maxTokens);
    }

    [McpServerTool(Name = "map_java_dotnet", Title = "Map Java and .NET", UseStructuredContent = true, OutputSchemaType = typeof(JavaDotNetResult))]
    [Description("Pairs across a Java / .NET bridge. .NET for Android (Xamarin, MAUI): Java wrapper classes and methods to .NET types and methods and " +
                 "back ([Register], crc64 names). Unity Mono: C# reaching Java via AndroidJavaClass / Object / Proxy / AndroidJNI, and back, with a " +
                 "confidence. A * / ? pattern lists pairs.")]
    public Task<string> MapJavaDotNet(
        [Description("Java class (Lpkg/C;, pkg.C) or method (Lpkg/C;->m(I)V), .NET symbol, or pattern.")] string symbol,
        [Description("Package whose assemblies to read; optional when they are loaded.")] string? path = null,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description("Most pairs.")] int limit = 100,
        [Description(ToolSupport.MaxTokensDescription)] int? maxTokens = null,
        CancellationToken cancellationToken = default) => Task.Run(() =>
    {
        var r = map.Map(symbol, path, cancellationToken);
        return ToolOutput.List(r.Items, offset, ClampLimit(limit),
            p => $"{p.Java}  <->  {p.DotNet}  [{p.Basis}{(p.Confidence != null ? ", " + p.Confidence : "")}; {p.Assembly}{(p.Loaded ? "" : ", not loaded")}]",
            rows => r with { Items = rows, Offset = Math.Max(0, offset) }, "pair",
            $"{r.Query} ({r.Direction.Replace('_', ' ')}){string.Concat(r.Notes.Take(5).Select(n => "\nNote: " + n))}\n");
    }, cancellationToken);

    [McpServerTool(Name = "list_jni_bindings", Title = "List JNI bindings", UseStructuredContent = true, OutputSchemaType = typeof(JniBindingList))]
    [Description("Java native methods of an Android package paired with their code in lib/<abi>/*.so: Java_ exports by JNI name mangling and " +
                 "RegisterNatives tables; also unbound methods and stray Java_ exports.")]
    public Task<string> ListJniBindings(
        [Description(PackageDescription)] string path,
        [Description("ABI to read, or all; default arm64-v8a, else the first.")] string? abi = null,
        [Description("Only rows naming this class (pkg.C or pkg/C).")] string? @class = null,
        [Description("Only this kind.")] string? kind = null,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description("Most rows.")] int limit = JniBindings.DefaultLimit,
        [Description(ToolSupport.MaxTokensDescription)] int? maxTokens = null,
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
    [Description("Search DEX code. kind=string: literals with method and offset per use; type: defined classes and type uses; method / field: defined " +
                 "and referenced members with use counts; const: numeric constants; opcode: instructions by mnemonic.")]
    public Task<string> SearchDex(
        [Description(CodeDescription)] string path,
        [Description("What to search.")] string kind,
        [Description("Case-insensitive substring or * / ? pattern; for const a number.")] string query,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description("Most hits.")] int limit = 100,
        [Description(ToolSupport.MaxTokensDescription)] int? maxTokens = null,
        [Description(MappingDescription)] string? mapping = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, progress => Task.Run(() =>
    {
        progress.Report(new ProgressNotificationValue { Progress = 0, Message = "indexing the DEX code (once per package)" });
        var r = dex.Search(path, kind, query, offset, ClampLimit(limit), cancellationToken, mapping);
        static string Row(DexHit h) => $"{h.Kind} {h.Value}{(h.Original != null ? " = " + h.Original : "")}" + (h.Method != null ? $"  in {h.Method}{(h.InOriginal != null ? " (" + h.InOriginal + ")" : "")} @{h.Offset} {h.Opcode}" : "")
                                       + (h.Uses is { } u ? $"  ({u} uses)" : "");
        return ToolOutput.List(r.Items, r.Offset, ClampLimit(limit), r.Total, Row, rows => r with { Items = rows }, "hit", string.Concat(r.Notes.Select(n => $"Note: {n}\n")));
    }, cancellationToken));

    [McpServerTool(Name = "find_dex_references", Title = "Find DEX references", UseStructuredContent = true, OutputSchemaType = typeof(DexReferenceList))]
    [Description("Cross-references in DEX code, with method and code offset per instruction. direction=to: callers of a method, readers and writers " +
                 "of a field, uses of a class or string. from: what a method (or each method of a class) calls, reads, writes and loads. Methods " +
                 "match by exact id.")]
    public Task<string> FindDexReferences(
        [Description(CodeDescription)] string path,
        [Description("Class, method (Lpkg/C;->m(I)V, pkg.C::m(int)), field (Lpkg/C;->f:I, pkg.C::f), \"string\".")] string target,
        [Description("Default to: who refers to target.")] string? direction = null,
        [Description("How to read target (default auto; string: taken literally).")] string? kind = null,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description("Most references.")] int limit = 100,
        [Description(ToolSupport.MaxTokensDescription)] int? maxTokens = null,
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
