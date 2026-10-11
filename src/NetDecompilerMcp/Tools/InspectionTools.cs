using System.ComponentModel;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Services;
using NetDecompilerMcp.Services.Analysis;

namespace NetDecompilerMcp.Tools;

[McpServerToolType]
public sealed class InspectionTools(InspectionService inspection, AssemblyWorkspace? workspace = null, NativeCodeService? code = null)
{
    private const string AssemblyParam = "A loaded assembly (id, name, file name or path). Pass this or path.";
    private const string PathParam = "A .NET assembly file to analyze without loading it. Pass this or assembly.";

    [McpServerTool(Name = "summarize_file", Title = "Summarize file", UseStructuredContent = true)]
    [Description("Summary of a file or loaded assembly, without executing it: file hashes, type and entropy; per managed assembly its identity " +
                 "(name, version, MVID, framework, GUI/console/library, architecture, ReadyToRun, merged), signature (strong name, " +
                 "Authenticode signer, digest check, chain), toolchain markers, container wrapping (embedded assemblies, " +
                 "decoded content, high-entropy sections), features with ATT&CK techniques, extracted values, and " +
                 "entry points (Main, module initializer, native exports, installer / service / AppDomainManager / COM hooks). Containers " +
                 "(single-file bundles, packages, APKs, zips, Costura hosts) are opened: the app's own assembly in full, up to 7 more in brief " +
                 "(framework libraries last, translations skipped); an apphost launcher's .dll next to it is summarized as the app. For a NativeAOT " +
                 "executable, nativeAot gives the runtime version, module sections, recovery stages and counts of named methods, MethodTables and " +
                 "frozen strings. ELF / Mach-O: nativeImage gives format, slices, build id, libraries, platform, code signature, entitlements and FairPlay encryption. " +
                 "Android packages: android gives package, versions, SDKs, runtimes with evidence (dotnet-android, unity-il2cpp, unity-mono, flutter, " +
                 "react-native, kotlin / java), ABIs, DEX files, exported components and the APK signature verdict. A loaded native image adds triage" +
                 " (entry points, top functions with roles, top strings, import groups, roots).")]
    public async Task<InspectionService.FileSummary> SummarizeFile(
        [Description("Any file: assembly, single-file bundle, .nupkg, .apk, zip, native executable. Pass this or assembly.")] string? path = null,
        [Description(AssemblyParam)] string? assembly = null,
        CancellationToken cancellationToken = default)
    {
        var native = NativeNamed(assembly, path);
        if (native == null || code == null) return await Task.Run(() => inspection.Summarize(assembly, path, cancellationToken), cancellationToken);
        var index = await code.Index(native, null, cancellationToken);
        var summary = await Task.Run(() => inspection.Summarize(null, native.FilePath, cancellationToken), cancellationToken);
        return summary with { Triage = await Task.Run(() => NativeTriageBuilder.Build(index, cancellationToken), cancellationToken) };
    }

    /// <summary>The loaded native image an argument names (a managed assembly of that name wins), or null.</summary>
    private LoadedNative? NativeNamed(string? assembly, string? path)
    {
        if (workspace == null || (assembly == null) == (path == null)) return null;
        return workspace.Read(() =>
        {
            if (assembly != null)
            {
                if (workspace.FindNative(assembly) is not { } n) return null;
                try { workspace.Get(assembly); return null; }
                catch (ToolError) { return n; }
            }
            return File.Exists(path) ? workspace.FindNative(Path.GetFullPath(path!)) : null;
        });
    }

    [McpServerTool(Name = "survey_features", Title = "Survey features", UseStructuredContent = true)]
    [Description("Rule-based (capa-style) survey of the APIs an assembly calls, the native functions it imports (P/Invoke) and its string " +
                 "literals, in categories: network, execution, registry, persistence, collection (keylogging, screen, clipboard, browser " +
                 "credentials), anti-debug / anti-VM, defense evasion, reflective loading and run-time compilation, process injection, " +
                 "discovery, crypto. Each matched feature has its MITRE ATT&CK technique where the operation is the technique itself, and " +
                 "its evidence (pattern, count, up to 5 locations). Native images (a loaded one, or a PE / ELF / Mach-O path) get the same rules over " +
                 "static and late-bound (GetProcAddress) imports, call arguments (VirtualProtect with PAGE_EXECUTE_READWRITE, " +
                 "CREATE_SUSPENDED...), strings, sections (entropy, packer names, writable code) and RTTI class names, located by address and function.")]
    public Task<InspectionService.FeatureReport> SurveyFeatures(
        [Description(AssemblyParam + " A loaded native image works too.")] string? assembly = null,
        [Description("A .NET assembly or native PE / ELF / Mach-O file to analyze without loading it. Pass this or assembly.")] string? path = null,
        [Description("Only this category (network, execution, registry, persistence, collection, credential access, anti-analysis, defense evasion, " +
                     "privilege escalation, code loading, injection, discovery, crypto, impact...) or ATT&CK technique prefix (T1055).")] string? category = null,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => inspection.SurveyFeatures(assembly, path, category, cancellationToken), cancellationToken);

    [McpServerTool(Name = "extract_strings", Title = "Extract typed strings", UseStructuredContent = true)]
    [Description("Typed values from string literals, constants, resource text and base64 / hex / compressed text decoded from the " +
                 "assembly: URLs, domains, IPv4 / IPv6, email addresses, file paths, named pipes, registry keys, mutex names, user agents and " +
                 "crypto keys, each with its count, locations and the APIs it is passed to. XML namespace URLs, version numbers and file " +
                 "names that look like domains are excluded. Pass savePath to export JSON or CSV.")]
    public Task<InspectionService.ValueReport> ExtractStrings(
        [Description(AssemblyParam)] string? assembly = null,
        [Description(PathParam)] string? path = null,
        [Description("Only these types (comma-separated): url, domain, ipv4, ipv6, email, file_path, named_pipe, registry_key, mutex, user_agent, crypto_key.")] string? types = null,
        [Description("Write the values to this file.")] string? savePath = null,
        [Description("Export format: json (default) or csv; a .csv savePath implies csv.")] string? format = null,
        [Description("Replace savePath if it exists.")] bool overwrite = false,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => inspection.ExtractStrings(assembly, path,
            types?.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries), savePath, format, overwrite, cancellationToken), cancellationToken);

    [McpServerTool(Name = "extract_embedded", Title = "Extract embedded content", UseStructuredContent = true)]
    [Description("Embedded content of an assembly: embedded resources, .resources entries, static byte arrays (<PrivateImplementationDetails>) and " +
                 "string literals of 64+ characters, decoded through hex, base64, gzip / zlib / deflate and XOR (key recovered from a known PE / " +
                 "ZIP / gzip header; text XOR with xorText=true) until a known kind appears: PE images, archives, ELF / Mach-O, or text; plus " +
                 "high-entropy blobs (1 KB+, 7.5+ bits per byte). Each item shows its source and encoding chain. save=true writes them (defanged " +
                 "names) to a directory of their own; load=true also loads the .NET ones. Nothing is executed.")]
    public Task<InspectionService.EmbeddedReport> ExtractEmbedded(
        [Description(AssemblyParam)] string? assembly = null,
        [Description(PathParam)] string? path = null,
        [Description("Write the items to disk.")] bool save = false,
        [Description("Directory to write into (new, empty, or an earlier extraction of the same file). Default: under the temp directory.")] string? outputDirectory = null,
        [Description("Load the .NET assemblies found into the workspace (implies save).")] bool load = false,
        [Description("Also recover XOR keys of 1-16 bytes over unreadable resources and arrays, keeping a decode only if it is clearly natural " +
                     "text (UTF-8 or UTF-16) or structured configuration (JSON, XML, URL / key=value lines). Off by default: heuristic, slower.")] bool xorText = false,
        [Description("Also list (and save) images: png, jpeg, gif, ico. By default they are only counted in notes.")] bool includeMedia = false,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => inspection.ExtractEmbedded(assembly, path, save, outputDirectory, load, cancellationToken, xorText, includeMedia), cancellationToken);
}
