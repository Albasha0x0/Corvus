using System.ComponentModel;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Services.Analysis;

namespace NetDecompilerMcp.Tools;

[McpServerToolType]
public sealed class InspectionTools(InspectionService inspection)
{
    private const string AssemblyParam = "A loaded assembly (id, name, file name or path). Pass this or path.";
    private const string PathParam = "A .NET assembly file to analyze without loading it. Pass this or assembly.";

    [McpServerTool(Name = "summarize_file", Title = "Summarize file", ReadOnly = true, Idempotent = true, OpenWorld = false, UseStructuredContent = true)]
    [Description("Summary of a file or loaded assembly, without executing it: file hashes, type and entropy; per managed assembly its identity " +
                 "(name, version, MVID, target framework, GUI/console/library, architecture, ReadyToRun, merged), signature (strong name, " +
                 "Authenticode signer with a digest check and chain), toolchain markers and heuristics, container wrapping (embedded assemblies, " +
                 "decoded embedded content, high-entropy sections), features with ATT&CK techniques, a summary of extracted values, and " +
                 "entry points (Main, module initializer, native exports, installer / service / AppDomainManager / COM hooks). Containers " +
                 "(single-file bundles, packages, APKs, zips, Costura hosts) are opened: the app's own assembly in full, up to 7 more in brief " +
                 "(framework libraries last, translations skipped); an apphost launcher's .dll next to it is summarized as the app. highlights lists " +
                 "the notable findings.")]
    public Task<InspectionService.FileSummary> SummarizeFile(
        [Description("Any file: assembly, single-file bundle, .nupkg, .apk, zip, native executable. Pass this or assembly.")] string? path = null,
        [Description(AssemblyParam)] string? assembly = null,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => inspection.Summarize(assembly, path, cancellationToken), cancellationToken);

    [McpServerTool(Name = "survey_features", Title = "Survey features", ReadOnly = true, Idempotent = true, OpenWorld = false, UseStructuredContent = true)]
    [Description("Rule-based (capa-style) survey of the APIs an assembly calls, the native functions it imports (P/Invoke) and its string " +
                 "literals, in categories: network, execution, registry, persistence, collection (keylogging, screen, clipboard, browser " +
                 "credentials), anti-debug / anti-VM, defense evasion, reflective loading and run-time compilation, process injection, " +
                 "discovery, crypto. Each matched feature has its MITRE ATT&CK technique where the operation is the technique itself, and " +
                 "its evidence (pattern, count, up to 5 locations). Native images (a loaded one, or a native PE path) get the same rules over " +
                 "static and late-bound (GetProcAddress) imports, call arguments (VirtualProtect with PAGE_EXECUTE_READWRITE, CreateProcess " +
                 "with CREATE_SUSPENDED...), strings, sections (entropy, packer names, writable code) and RTTI class names, with addresses and functions as locations.")]
    public Task<InspectionService.FeatureReport> SurveyFeatures(
        [Description(AssemblyParam + " A loaded native image works too.")] string? assembly = null,
        [Description("A .NET assembly or native PE file to analyze without loading it. Pass this or assembly.")] string? path = null,
        [Description("Only this category (network, execution, registry, persistence, collection, credential access, anti-analysis, defense evasion, " +
                     "privilege escalation, code loading, injection, discovery, crypto, impact...) or ATT&CK technique prefix (T1055).")] string? category = null,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => inspection.SurveyFeatures(assembly, path, category, cancellationToken), cancellationToken);

    [McpServerTool(Name = "extract_strings", Title = "Extract typed strings", Idempotent = true, OpenWorld = false, UseStructuredContent = true)]
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

    [McpServerTool(Name = "extract_embedded", Title = "Extract embedded content", Idempotent = true, OpenWorld = false, UseStructuredContent = true)]
    [Description("Embedded content of an assembly: embedded resources, .resources entries, static byte arrays (<PrivateImplementationDetails>) and " +
                 "string literals of 64+ characters, decoded through hex, base64, gzip / zlib / deflate and XOR (key recovered from a known PE / " +
                 "ZIP / gzip header; repeating-key XOR over plain text with xorText=true) until a recognized kind appears: .NET / native PE images, archives, " +
                 "ELF / Mach-O binaries, or text; plus high-entropy blobs (1 KB+, 7.5+ bits per byte). Each item shows its source and encoding " +
                 "chain. save=true writes them (defanged names) to a directory of their own; load=true also loads the .NET ones into the " +
                 "workspace. Nothing is executed.")]
    public Task<InspectionService.EmbeddedReport> ExtractEmbedded(
        [Description(AssemblyParam)] string? assembly = null,
        [Description(PathParam)] string? path = null,
        [Description("Write the items to disk.")] bool save = false,
        [Description("Directory to write into (new, empty, or an earlier extraction of the same file). Default: under the temp directory.")] string? outputDirectory = null,
        [Description("Load the .NET assemblies found into the workspace (implies save).")] bool load = false,
        [Description("Also recover XOR keys of 1-16 bytes over text on resources and arrays that are not readable as they are (UTF-8 in any " +
                     "script, or UTF-16), keeping a decode only if it is clearly natural text (words of one script, spaces, likely letter pairs) " +
                     "or structured configuration (JSON, XML, URL / key=value lines). Off by default: heuristic, and slower on large data.")] bool xorText = false,
        [Description("Also list (and save) images: png, jpeg, gif, ico. By default they are only counted in notes.")] bool includeMedia = false,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => inspection.ExtractEmbedded(assembly, path, save, outputDirectory, load, cancellationToken, xorText, includeMedia), cancellationToken);
}
