using System.ComponentModel;
using System.Text;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Pdb;
using NetDecompilerMcp.Services;
using static NetDecompilerMcp.Tools.ToolSupport;

namespace NetDecompilerMcp.Tools;

/// <summary>Native debug symbols (PDB): locate, download on request, read, and name functions and data from them.</summary>
[McpServerToolType]
public sealed class PdbTools(AssemblyWorkspace workspace, PdbService pdbs, OutputPager pager)
{
    private const int MaxProbesShown = 25;

    private Task<LoadedNative> Native(string image, CancellationToken ct) => Task.Run(() =>
    {
        var id = workspace.Read(() => workspace.FindNative(image)?.Id);
        if (id == null && !string.IsNullOrWhiteSpace(image) && Path.IsPathFullyQualified(image.Trim()) && File.Exists(image.Trim()))
            id = workspace.LoadAny(image.Trim()).Native?.Id ?? throw new ToolError(ErrorCode.Unsupported, $"{image} is a .NET assembly, not a native image.",
                "use the .NET tools for it");
        return workspace.Read(() => workspace.GetNative(id ?? image));
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

    [McpServerTool(Name = "load_pdb", Title = "Load native debug symbols")]
    [Description("Load the PDB (MSF 7.0) of a native image: function and data names with addresses (publics, global and static data, procedures of every " +
                 "module, thunks), checked against the image's CodeView GUID and age. Searched: the path given (file or directory), the image's directory, " +
                 "the path recorded in the image, _NT_SYMBOL_PATH caches and directories, the Visual Studio / WinDbg / IDA caches and C:\\symbols. " +
                 "download=true (off by default) fetches it from a symbol server (server, else those in _NT_SYMBOL_PATH, else Microsoft's) into a per-user cache. " +
                 "Names show up as source 'pdb' in list_functions, disassemble and cross-references; user names (rename_native) are kept. Functions the PDB " +
                 "names that discovery missed become function starts (the index rebuilds in the background). A matching local PDB is also read " +
                 "automatically when the index is first built. The next decompile_native loads the PDB's types (structs, enums, prototypes) into " +
                 "the IDA database. The names of a load_pdb are saved with the image's annotations (PDB path, GUID and age, " +
                 "names, function starts) and reapplied automatically when the same file is loaded again, even when the PDB has moved; clear=true " +
                 "removes the PDB names and the saved copy.")]
    public Task<string> LoadPdb(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("PDB file, or a directory (or symbol store) to look in first.")] string? path = null,
        [Description("Download from a symbol server when no local PDB matches (network; off by default).")] bool download = false,
        [Description("Symbol server URL for download (default: _NT_SYMBOL_PATH servers, else https://msdl.microsoft.com/download/symbols).")] string? server = null,
        [Description("Use the PDB at path even when its GUID or age differs from the image (names may be wrong).")] bool force = false,
        [Description("Download time limit in seconds (default 120).")] int timeoutSeconds = 120,
        [Description("Download size limit in MB (default 2048).")] int maxMegabytes = 2048,
        [Description("Remove the image's PDB names and their saved copy instead of loading (a matching local PDB is not read again in this session).")] bool clear = false,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var native = await Native(image, cancellationToken);
        if (clear)
        {
            var (removed, deleted) = await Task.Run(() => workspace.Read(() => pdbs.Clear(native)), cancellationToken);
            return removed is { } n ? $"{native.Id}: removed {Plural(n, "PDB name")}{(deleted ? " and the saved copy" : "")}."
                : deleted ? $"{native.Id}: deleted the saved PDB names." : $"{native.Id}: no PDB names were loaded.";
        }
        progress.Report(new ProgressNotificationValue { Progress = 0, Message = $"locating the PDB of {native.Id}" });
        var timeout = TimeSpan.FromSeconds(Math.Clamp(timeoutSeconds, 5, 3600));
        long maxBytes = Math.Clamp(maxMegabytes, 1, 16 * 1024) * (1L << 20);
        var r = await pdbs.Load(native, path, download, server, force, timeout, maxBytes, cancellationToken);
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
                        (native.Pe?.CodeView is { Format: "RSDS" } c ? (p.Matches(c) ? "matches the image" : $"DOES NOT match the image (GUID {c.Guid:D}, age {c.Age}); used because force=true") : "the image has no RSDS record to check against") +
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
        return text.ToString();
    });

    private static string Probes(IReadOnlyList<PdbProbe> probes)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"Searched ({probes.Count}):");
        foreach (var p in probes.Take(MaxProbesShown)) sb.AppendLine($"  {p.Location}: {p.Outcome}");
        if (probes.Count > MaxProbesShown) sb.AppendLine($"  ... {probes.Count - MaxProbesShown} more");
        return sb.ToString();
    }

    [McpServerTool(Name = "search_pdb_symbols", Title = "Search native debug symbols")]
    [Description("Symbols of the PDB loaded for a native image (load_pdb, or found automatically): address, kind (function, data, public, thunk), size, " +
                 "name, the full signature undecorated from the public name, and the module (object file). query matches names case-insensitively; " +
                 "empty lists all.")]
    public Task<string> SearchPdbSymbols(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("Text the name (or decorated name) contains; empty for all.")] string? query = null,
        [Description("Only this kind: function, data, public, or all (default).")] string? kind = null,
        [Description("Index of the first row.")] int offset = 0,
        [Description("Max rows (default 200).")] int limit = 200,
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
        var page = matches.Skip(offset).Take(limit).ToList();
        var lines = page.Select(x =>
        {
            string at = x.Rva is { } rva ? NativeAddress.Va(native.Image, rva) : $"{x.Segment:X4}:{x.Offset:X8} (not in the image)";
            string name = x.IsPublic ? PdbNaming.Display(x.Name) : x.Name;
            string sig = x.IsPublic && PdbNaming.Signature(x.Name) is { } full && full != name ? $"  [{full}]" : "";
            string mod = x.Module >= 0 && x.Module < s.Pdb.Modules.Count ? $"  ({Path.GetFileName(s.Pdb.Modules[x.Module].Name)})" : "";
            string size = x.Size > 0 ? $" {x.Size,6}" : "       ";
            return $"  {at}  {KindName(x.Kind),-8}{size}  {name}{sig}{mod}";
        }).ToList();
        int fit = pager.FitRows(lines, 400);
        var sb = new StringBuilder();
        sb.AppendLine($"{native.Id} ({Path.GetFileName(s.Path)}): {Plural(matches.Count, "symbol")} (showing {(fit == 0 ? 0 : offset + 1)}-{offset + fit}):");
        foreach (var line in lines.Take(fit)) sb.AppendLine(line);
        if (fit < lines.Count) sb.AppendLine(OutputPager.CapNote(fit, lines.Count, offset + fit));
        else if (offset + page.Count < matches.Count) sb.AppendLine($"[More: call again with offset={offset + page.Count}]");
        return pager.Page(sb.ToString());
    }, cancellationToken);

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
