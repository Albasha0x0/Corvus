using NetDecompilerMcp.Core;


namespace NetDecompilerMcp.Native.Pe;

public sealed partial class PeFile
{
    private interface IArea
    {
        IReadOnlyList<ParseIssue> Issues { get; }
    }

    /// <summary>
    /// A directory parsed on first use. The parser records problems in its log; an exception escaping it is a parser
    /// bug, recorded as an issue with the fallback value returned, so callers never see it.
    /// </summary>
    private sealed class Area<T>(string name, Func<IssueLog, T> parse, T fallback) : IArea
    {
        private readonly Lock gate = new();
        private bool done;
        private T value = default!;
        private IReadOnlyList<ParseIssue> issues = [];

        public T Value
        {
            get
            {
                lock (gate)
                {
                    if (!done) Run();
                    return value;
                }
            }
        }

        public IReadOnlyList<ParseIssue> Issues
        {
            get
            {
                lock (gate)
                {
                    if (!done) Run();
                    return issues;
                }
            }
        }

        private void Run()
        {
            var log = new IssueLog(name);
            try { value = parse(log); }
            catch (Exception ex)
            {
                value = fallback;
                log.Add($"internal error: {ex.GetType().Name}: {ex.Message}");
            }
            issues = log.ToList();
            done = true;
        }
    }

    private Area<ImportTable> imports = null!;
    private Area<ImportTable> delayImports = null!;
    private Area<IReadOnlyList<PeBoundImport>> boundImports = null!;
    private Area<ExportTable> exports = null!;
    private Area<RelocationTable> relocations = null!;
    private Area<TlsInfo> tls = null!;
    private Area<IReadOnlyList<RuntimeFunction>> runtimeFunctions = null!;
    private Area<DebugInfo> debug = null!;
    private Area<PeLoadConfig?> loadConfig = null!;
    private Area<ResourceTable> resources = null!;
    private Area<PeRichHeader?> rich = null!;
    private Area<PeChecksum> checksum = null!;
    private Area<PeOverlay?> overlay = null!;
    private Area<CertificateInfo> certificate = null!;

    private void InitAreas()
    {
        imports = new("imports", ParseImports, ImportTable.Empty);
        delayImports = new("delay imports", ParseDelayImports, ImportTable.Empty);
        boundImports = new("bound imports", ParseBoundImports, []);
        exports = new("exports", ParseExports, ExportTable.Empty);
        relocations = new("relocations", ParseRelocations, RelocationTable.Empty);
        tls = new("tls", ParseTls, TlsInfo.Empty);
        runtimeFunctions = new("exception directory", ParseRuntimeFunctions, []);
        debug = new("debug directory", ParseDebug, DebugInfo.Empty);
        loadConfig = new("load config", ParseLoadConfig, null);
        resources = new("resources", ParseResources, ResourceTable.Empty);
        rich = new("rich header", ParseRichHeader, null);
        checksum = new("checksum", _ => ComputeChecksum(), new PeChecksum(Optional.CheckSum, 0));
        overlay = new("overlay", _ => FindOverlay(), null);
        certificate = new("certificate", _ => Certificates.Read(data), new CertificateInfo(false, Problem: "not read"));
    }

    private IEnumerable<IArea> AllAreas() =>
        [imports, delayImports, boundImports, exports, relocations, tls, runtimeFunctions, debug, loadConfig, resources, rich, checksum, overlay];

    /// <summary>Regular imports followed by delay-load imports.</summary>
    public IReadOnlyList<NativeImport> Imports => allImports ??= [.. imports.Value.Functions, .. delayImports.Value.Functions];
    private IReadOnlyList<NativeImport>? allImports;
    public IReadOnlyList<PeImportModule> ImportModules => imports.Value.Modules;
    public IReadOnlyList<PeImportModule> DelayImportModules => delayImports.Value.Modules;
    public IReadOnlyList<PeBoundImport> BoundImports => boundImports.Value;

    /// <summary>One entry per exported name, plus one per nameless ordinal; ordered by ordinal.</summary>
    public IReadOnlyList<NativeExport> Exports => exports.Value.Entries;
    public PeExportDirectory? ExportDirectory => exports.Value.Directory;

    public IReadOnlyList<uint> RelocationRvas => relocations.Value.PointerRvas;
    /// <summary>Every base relocation entry except the ABSOLUTE padding, in table order.</summary>
    public IReadOnlyList<PeRelocation> BaseRelocations => relocations.Value.All;

    public IReadOnlyList<uint> TlsCallbackRvas => tls.Value.CallbackRvas;
    public PeTlsDirectory? TlsDirectory => tls.Value.Directory;

    public IReadOnlyList<RuntimeFunction> RuntimeFunctions => runtimeFunctions.Value;

    public IReadOnlyList<PeDebugEntry> DebugEntries => debug.Value.Entries;
    /// <summary>The first CodeView record (RSDS or NB10).</summary>
    public PeCodeView? CodeView => debug.Value.CodeView;
    /// <summary>Extended DLL characteristics from the EX_DLLCHARACTERISTICS debug entry, 0 when absent.</summary>
    public uint ExDllCharacteristics => debug.Value.ExDllCharacteristics;
    public IReadOnlyList<string> ExDllCharacteristicNames => PeNames.ExDllCharacteristics(ExDllCharacteristics);

    public PeLoadConfig? LoadConfig => loadConfig.Value;

    /// <summary>Every resource data entry of the resource tree, in tree order.</summary>
    public IReadOnlyList<PeResource> Resources => resources.Value.Entries;
    /// <summary>The first RT_VERSION resource, decoded.</summary>
    public PeVersionInfo? VersionInfo => resources.Value.Version;
    /// <summary>Text of the first RT_MANIFEST resource.</summary>
    public string? Manifest => resources.Value.Manifest;
    /// <summary>Every string of the RT_STRING tables.</summary>
    public IReadOnlyList<PeResourceString> ResourceStrings => resources.Value.Strings;

    public PeRichHeader? RichHeader => rich.Value;
    public PeChecksum Checksum => checksum.Value;
    /// <summary>Bytes after the last section's raw data, null when there are none.</summary>
    public PeOverlay? Overlay => overlay.Value;
}
