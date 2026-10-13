using System.ComponentModel;
using System.Text;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Native;
using Corvus.Native.Pdb;
using Corvus.Services;
using static Corvus.Tools.ToolSupport;

namespace Corvus.Tools;

/// <summary>Native debug symbols (PDB): locate, download on request, read, and name functions and data from them.</summary>
[McpServerToolType]
public sealed class PdbTools(AssemblyWorkspace workspace, PdbService pdbs)
{
    private const int MaxProbesShown = 25;

    private Task<LoadedNative> Native(string image, CancellationToken ct) => Task.Run(() =>
    {
        return Targets.Native(workspace, image);
    }, ct);

    /// <summary>One line on the image's PDB for get_pe_info, or null when the image names no PDB and none is loaded.</summary>
    public static string? Status(LoadedNative native)
    {
        if (PdbService.StateOf(native) is { } s)
            return $"PDB loaded: {s.Path} ({(s.Verified ? "GUID and age match" : "not verified")}{(s.Automatic ? ", found automatically" : "")}), " +
                   $"{Plural(s.Names.Count, "name")} (search_pdb_symbols)";
        if (native.Pe?.CodeView is not { Format: "RSDS" }) return null;
        if (PdbService.AutoSearchOf(native) is { } search)
            return $"PDB not found locally ({Plural(search.Probes.Count, "place")} searched); load_pdb with a path, or download=true";
        return "PDB not loaded (load_pdb)";
    }

    [McpServerTool(Name = "load_pdb", Title = "Load native debug symbols", UseStructuredContent = true, OutputSchemaType = typeof(PdbLoadOutcome))]
    [Description("Load the PDB of a native image: function and data names (publics, globals, procedures, thunks), checked against its GUID and " +
                 "age. Searched: path, the image's folder, its recorded path, _NT_SYMBOL_PATH, the debugger caches and C:\\symbols; download=true " +
                 "fetches it from a symbol server. Names show as source 'pdb' (user names win); missed functions become function starts. A matching " +
                 "local PDB is read automatically. Names are saved and reapplied when the file loads again; clear=true removes them.")]
    public Task<string> LoadPdb(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("PDB file, or a directory (or symbol store) to look in first.")] string? path = null,
        [Description("Download from a symbol server when no local PDB matches (network).")] bool download = false,
        [Description("Symbol server URL for download (default: _NT_SYMBOL_PATH servers, else https://msdl.microsoft.com/download/symbols).")] string? server = null,
        [Description("Use the PDB at path even when its GUID or age differs from the image (names may be wrong).")] bool allowMismatch = false,
        [Description("Download time limit in seconds.")] int timeoutSeconds = 120,
        [Description("Download size limit in MB.")] int maxMegabytes = 2048,
        [Description("Remove the PDB names and their saved copy instead (not read again this session).")] bool clear = false,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var native = await Native(image, cancellationToken);
        if (clear)
        {
            var (removed, deleted) = await Task.Run(() => workspace.Read(() => pdbs.Clear(native)), cancellationToken);
            var changes = new List<EditChange>();
            if (removed is { } count) changes.Add(new EditChange("names", native.Id, Plural(count, "PDB name"), null));
            if (deleted) changes.Add(new EditChange("saved_names", native.Id, "saved", null));
            return ToolOutput.With(
                removed is { } n ? $"{native.Id}: removed {Plural(n, "PDB name")}{(deleted ? " and the saved copy" : "")}."
                : deleted ? $"{native.Id}: deleted the saved PDB names." : $"{native.Id}: no PDB names were loaded.", new PdbLoadOutcome(changes.Count > 0, changes, null));
        }
        progress.Report(new ProgressNotificationValue { Progress = 0, Message = $"locating the PDB of {native.Id}" });
        var timeout = TimeSpan.FromSeconds(Math.Clamp(timeoutSeconds, 5, 3600));
        long maxBytes = Math.Clamp(maxMegabytes, 1, 16 * 1024) * (1L << 20);
        var r = await pdbs.Load(native, path, download, server, allowMismatch, timeout, maxBytes, cancellationToken);
        if (r.State is not { } s)
        {
            var why = native.Pe?.CodeView is { Format: "RSDS" } cv
                ? $"No PDB matching {native.Id} (GUID {cv.Guid:D}, age {cv.Age}, {cv.PdbPath}) was found."
                : $"{native.Id} has no PDB 7.0 CodeView record, so no PDB can be matched to it.";
            var sb = new StringBuilder(why);
            if (r.DownloadError != null) sb.Append(" Download: ").Append(r.DownloadError);
            sb.Append('\n').Append(Probes(r.Location.Probes));
            throw new ToolError(ErrorCode.NotFound, sb.ToString().TrimEnd(),
                download ? "pass the PDB's path, or another server" : "pass the PDB's path, or download=true to fetch it from a symbol server");
        }
        var p = s.Pdb;
        var text = new StringBuilder();
        text.AppendLine($"{native.Id}: {s.Path}");
        text.AppendLine($"  GUID {p.Guid:D}, age {p.DbiAge} (info stream age {p.InfoAge}): " +
                        (native.Pe?.CodeView is { Format: "RSDS" } c ? (p.Matches(c) ? "matches the image" : $"DOES NOT match the image (GUID {c.Guid:D}, age {c.Age}); used because allowMismatch=true") : "the image has no RSDS record to check against") +
                        (s.Downloaded ? "; downloaded" : ""));
        int procs = p.Symbols.Count(x => x.Kind is PdbSymbolKind.GlobalProc or PdbSymbolKind.LocalProc);
        int pubs = p.Symbols.Count(x => x.IsPublic);
        int data = p.Symbols.Count(x => x.Kind is PdbSymbolKind.GlobalData or PdbSymbolKind.LocalData);
        int unmapped = p.Symbols.Count(x => x.Rva == null);
        text.AppendLine($"  read in {s.Elapsed.TotalSeconds:0.0} s: {p.FileSize:N0} bytes, {Plural(p.Modules.Count, "module")}, {Plural(p.Symbols.Count, "symbol")} " +
                        $"({pubs} public, {procs} procedures, {data} data{(unmapped > 0 ? $", {unmapped} with no address in the image" : "")})" +
                        (p.HasOmap ? "; addresses mapped through OMAP" : ""));
        text.AppendLine($"  {Plural(s.Names.Count, "address")} named ({s.Names.Count(n => n.IsFunction)} functions); {r.NamesApplied} applied as 'pdb' names" +
                        (r.UserNamesKept > 0 ? $", {r.UserNamesKept} keep the user's name" : ""));
        text.AppendLine(r.SaveProblem == null ? "  saved with the image's annotations: reapplied automatically when this file is loaded again (clear=true removes them)"
            : $"  not saved for the next load: {r.SaveProblem}");
        if (r.NewFunctionStarts > 0)
            text.AppendLine($"  {Plural(r.NewFunctionStarts, "function")} named by the PDB were not found by discovery: " +
                            (r.Rebuilding ? "the code index is rebuilding in the background with them as function starts" : "they become function starts when the index is built"));
        if (p.Modules.Count == 0 && pubs > 0) text.AppendLine("  public symbols only (a stripped PDB): no procedure sizes or static functions");
        foreach (var t in p.Truncations) text.AppendLine($"  Limit: {t}");
        foreach (var i in p.Issues.Take(10)) text.AppendLine($"  Issue ({i.Area}): {i.Message}");
        if (p.Issues.Count > 10) text.AppendLine($"  ... {p.Issues.Count - 10} more issues");
        var applied = new List<EditChange> { new("names", native.Id, null, $"{r.NamesApplied} pdb names from {Path.GetFileName(s.Path)}") };
        if (r.NewFunctionStarts > 0) applied.Add(new EditChange("function_starts", native.Id, null, Plural(r.NewFunctionStarts, "function start")));
        var match = native.Pe?.CodeView is { Format: "RSDS" } rsds ? p.Matches(rsds) : (bool?)null;
        return ToolOutput.With(text.ToString(), new PdbLoadOutcome(true, applied, new PdbIdentity(s.Path, p.Guid.ToString("D"), (int)p.DbiAge, match, s.Downloaded)));
    });

    /// <summary>load_pdb's outcome (S4.2): what changed, and the PDB read.</summary>
    public sealed record PdbLoadOutcome(bool Applied, IReadOnlyList<EditChange> Changes, PdbIdentity? Pdb);

    public sealed record PdbIdentity(string Path, string Guid, int Age,
        [property: System.ComponentModel.Description("The image's GUID and age match; absent when it has no RSDS record.")] bool? Match, bool Downloaded);

    private static string Probes(IReadOnlyList<PdbProbe> probes)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"Searched ({probes.Count}):");
        foreach (var p in probes.Take(MaxProbesShown)) sb.AppendLine($"  {p.Location}: {p.Outcome}");
        if (probes.Count > MaxProbesShown) sb.AppendLine($"  ... {probes.Count - MaxProbesShown} more");
        return sb.ToString();
    }

    [McpServerTool(Name = "search_pdb_symbols", Title = "Search native debug symbols", UseStructuredContent = true, OutputSchemaType = typeof(PdbSymbolList))]
    [Description("Symbols of the PDB loaded for a native image (load_pdb, or found automatically): address, kind, size, name, the signature " +
                 "undecorated from the public name, and the object file.")]
    public Task<string> SearchPdbSymbols(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("Name or decorated name substring (case-insensitive); empty for all.")] string? query = null,
        [Description("Only this kind (default all).")] string? kind = null,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description("Max rows.")] int limit = 200,
        [Description(MaxTokensDescription)] int? maxTokens = null,
        CancellationToken cancellationToken = default) => Task.Run(async () =>
    {
        var native = await Native(image, cancellationToken);
        var s = PdbService.StateOf(native) ?? throw new ToolError(ErrorCode.NotLoaded, $"No PDB is loaded for {native.Id}.",
            "call load_pdb first (it searches locally; download=true fetches it)");
        Func<PdbSymbol, bool> kindFilter = (kind?.Trim().ToLowerInvariant()) switch
        {
            null or "" or "all" => _ => true,
            "function" or "functions" => x => x.IsFunction,
            "data" => x => !x.IsFunction,
            "public" or "publics" => x => x.IsPublic,
            _ => throw new ToolError(ErrorCode.InvalidArgument, $"Unknown kind '{kind}'.", "use function, data, public or all"),
        };
        var q = query?.Trim() ?? "";
        var matches = new List<PdbSymbol>();
        foreach (var x in s.Pdb.Symbols)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (kindFilter(x) && (q.Length == 0 || x.Name.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                                  (x.IsPublic && PdbNaming.Display(x.Name).Contains(q, StringComparison.OrdinalIgnoreCase))))
                matches.Add(x);
        }
        limit = Math.Clamp(limit, 1, 5_000);
        offset = Math.Max(0, offset);
        var page = matches.Skip(offset).Take(limit).Select(x =>
        {
            string at = x.Rva is { } rva ? NativeAddress.Va(native.Image, rva) : $"{x.Segment:X4}:{x.Offset:X8} (not in the image)";
            string name = x.IsPublic ? PdbNaming.Display(x.Name) : x.Name;
            string? sig = x.IsPublic && PdbNaming.Signature(x.Name) is { } full && full != name ? full : null;
            string? mod = x.Module >= 0 && x.Module < s.Pdb.Modules.Count ? Path.GetFileName(s.Pdb.Modules[x.Module].Name) : null;
            return new PdbSymbolEntry(at, KindName(x.Kind), x.Size > 0 ? (int)x.Size : null, name, sig, mod);
        }).ToList();
        return ToolOutput.List(page, offset, limit, matches.Count,
            e => $"{e.Address}  {e.Kind,-8}{(e.Size is { } n ? $" {n,6}" : "       ")}  {e.Name}{(e.Signature != null ? $"  [{e.Signature}]" : "")}{(e.Module != null ? $"  ({e.Module})" : "")}",
            rows => new PdbSymbolList(native.Id, rows, offset, matches.Count), "symbol", $"{native.Id} ({Path.GetFileName(s.Path)}): ");
    }, cancellationToken);

    public sealed record PdbSymbolEntry(string Address, string Kind, int? Size, string Name,
        [property: Description("Undecorated signature of a public symbol, when it says more than the name.")] string? Signature,
        [property: Description("The object file.")] string? Module);

    public sealed record PdbSymbolList(string Image, IReadOnlyList<PdbSymbolEntry> Items, int Offset, int Total);

    private static string KindName(PdbSymbolKind kind) => kind switch
    {
        PdbSymbolKind.GlobalProc => "function",
        PdbSymbolKind.LocalProc => "static",
        PdbSymbolKind.PublicFunction => "public",
        PdbSymbolKind.PublicData => "pubdata",
        PdbSymbolKind.Thunk => "thunk",
        PdbSymbolKind.GlobalData => "data",
        _ => "sdata",
    };
}
