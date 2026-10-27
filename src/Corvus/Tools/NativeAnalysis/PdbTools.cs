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
            return s.Pdb.Format == DebugInfoFormat.Dwarf
                ? $"DWARF loaded: {s.Path} ({(s.Verified ? "build-id matches" : "not verified")}{(s.Automatic ? ", found automatically" : "")}), " +
                  $"{Plural(s.Names.Count, "name")} (search_pdb_symbols)"
                : $"PDB loaded: {s.Path} ({(s.Verified ? "GUID and age match" : "not verified")}{(s.Automatic ? ", found automatically" : "")}), " +
                  $"{Plural(s.Names.Count, "name")} (search_pdb_symbols)";
        if (native.Pe?.CodeView is not { Format: "RSDS" }) return null;
        if (PdbService.AutoSearchPending(native)) return "PDB search pending: local matches load on their own (load_pdb reads one now)";
        if (PdbService.AutoSearchOf(native) is { } search)
            return $"PDB not found locally ({Plural(search.Probes.Count, "place")} searched); load_pdb with a path, or download=true";
        return "PDB not loaded (load_pdb)";
    }

    [McpServerTool(Name = "load_pdb", Title = "Load native debug symbols", UseStructuredContent = true, OutputSchemaType = typeof(EditResult))]
    [Description("Load PDB (GUID and age checked) or DWARF debug symbols for a native image: names, types, source lines. Searches path, the " +
                 "image folder, symbol paths and CORVUS_DEBUG_DIRS; local matches load automatically.")]
    public Task<string> LoadPdb(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("PDB or debug file, dSYM, or a folder or symbol store to look in first.")] string? path = null,
        [Description("If nothing local matches: symbol server (PDB), debuginfod (ELF).")] bool download = false,
        [Description("Default: _NT_SYMBOL_PATH servers, else Microsoft (PDB); CORVUS_DEBUGINFOD_URLS (DWARF).")] string? server = null,
        [Description("Use the path file even if GUID/age or build-id differs.")] bool allowMismatch = false,
        [Description("Download time limit, seconds.")] int timeoutSeconds = 120,
        [Description("Download size limit in MB.")] int maxMegabytes = 2048,
        [Description("Remove the PDB names and saved copy instead.")] bool clear = false,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var native = await Native(image, cancellationToken);
        if (clear)
        {
            var (removed, deleted) = await Task.Run(() => workspace.Read(() => pdbs.Clear(native)), cancellationToken);
            var changes = new List<EditResult.Change>();
            if (removed is { } count) changes.Add(new("names", $"{native.Id}: {Plural(count, "PDB name")} removed"));
            if (deleted) changes.Add(new("saved_names", $"{native.Id}: saved copy deleted"));
            return ToolOutput.With(
                removed is { } n ? $"{native.Id}: removed {Plural(n, "PDB name")}{(deleted ? " and the saved copy" : "")}."
                : deleted ? $"{native.Id}: deleted the saved PDB names." : $"{native.Id}: no PDB names were loaded.", new EditResult(changes.Count > 0, false, changes, []));
        }
        progress.Report(new ProgressNotificationValue { Progress = 0, Message = $"locating the PDB of {native.Id}" });
        var timeout = TimeSpan.FromSeconds(Math.Clamp(timeoutSeconds, 5, 3600));
        long maxBytes = Math.Clamp(maxMegabytes, 1, 16 * 1024) * (1L << 20);
        var r = await pdbs.Load(native, path, download, server, allowMismatch, timeout, maxBytes, cancellationToken);
        bool dwarf = native.Image.Format is ImageFormat.Elf or ImageFormat.MachO;
        if (r.State == null && dwarf)
        {
            var sb = new StringBuilder($"No DWARF for {native.Id}{(native.Image.BuildId is { } id ? $" ({(native.Image.Format == ImageFormat.MachO ? "UUID" : "build-id")} {id})" : "")} was found.");
            if (r.DownloadError != null) sb.Append(" Download: ").Append(r.DownloadError);
            sb.Append('\n').Append(Probes(r.Location.Probes));
            throw new ToolError(ErrorCode.NotFound, sb.ToString().TrimEnd(),
                "pass the debug file, its folder or the dSYM bundle as path" + (native.Image.Format == ImageFormat.Elf && !download ? ", or download=true with a debuginfod server" : ""));
        }
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
        if (p.Format == DebugInfoFormat.Dwarf)
        {
            bool own = string.Equals(s.Path, native.FilePath, StringComparison.OrdinalIgnoreCase);
            text.AppendLine($"  DWARF {(own ? "in the image's own sections" : "in a separate debug file")}" +
                            (p.BuildId != null ? $", {(native.Image.Format == ImageFormat.MachO ? "UUID" : "build-id")} {p.BuildId}" : "") +
                            (s.Verified ? ": matches the image" : ": not verified against the image") + (s.Downloaded ? "; downloaded" : ""));
            int functions = p.Symbols.Count(x => x.IsFunction), variables = p.Symbols.Count - functions;
            text.AppendLine($"  read in {s.Elapsed.TotalSeconds:0.0} s: {p.FileSize:N0} bytes, {Plural(p.Modules.Count, "unit")}, {Plural(functions, "function")}, " +
                            $"{Plural(variables, "variable")}, {Plural(p.TypeRecords?.Offsets.Length ?? 0, "type record")}" +
                            (p.Source is { } src ? $"; {Plural(src.LineTables, "line table")}, {Plural(src.InlinedInstances, "inlined call")} (resolve_address shows them)" : ""));
        }
        else
        {
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
            if (p.Modules.Count == 0 && pubs > 0) text.AppendLine("  public symbols only (a stripped PDB): no procedure sizes or static functions");
        }
        text.AppendLine($"  {Plural(s.Names.Count, "address")} named ({s.Names.Count(n => n.IsFunction)} functions); {r.NamesApplied} applied as 'pdb' names" +
                        (r.UserNamesKept > 0 ? $", {r.UserNamesKept} keep the user's name" : ""));
        text.AppendLine(r.SaveProblem == null ? "  saved: reapplied when this file loads again (clear=true removes them)"
            : $"  not saved for the next load: {r.SaveProblem}");
        if (r.NewFunctionStarts > 0)
            text.AppendLine($"  {Plural(r.NewFunctionStarts, "function")} named by the {(p.Format == DebugInfoFormat.Dwarf ? "DWARF" : "PDB")} were not found by discovery: " +
                            (r.Rebuilding ? "the code index is rebuilding in the background with them as function starts" : "they become function starts when the index is built"));
        foreach (var t in p.Truncations) text.AppendLine($"  Limit: {t}");
        foreach (var i in p.Issues.Take(10)) text.AppendLine($"  Issue ({i.Area}): {i.Message}");
        if (p.Issues.Count > 10) text.AppendLine($"  ... {p.Issues.Count - 10} more issues");
        var applied = new List<EditResult.Change> { new("names", $"{native.Id}: {r.NamesApplied} pdb names from {Path.GetFileName(s.Path)}") };
        if (r.NewFunctionStarts > 0) applied.Add(new("function_starts", $"{native.Id}: {Plural(r.NewFunctionStarts, "function start")}"));
        return ToolOutput.With(text.ToString(), new EditResult(true, false, applied, []));
    });

    private static string Probes(IReadOnlyList<PdbProbe> probes)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"Searched ({probes.Count}):");
        foreach (var p in probes.Take(MaxProbesShown)) sb.AppendLine($"  {p.Location}: {p.Outcome}");
        if (probes.Count > MaxProbesShown) sb.AppendLine($"  ... {probes.Count - MaxProbesShown} more");
        return sb.ToString();
    }

    [McpServerTool(Name = "search_pdb_symbols", Title = "Search native debug symbols", UseStructuredContent = true, OutputSchemaType = typeof(PdbSymbolList))]
    [Description("Search the PDB or DWARF symbols loaded for a native image: address, kind, size, name, signature, object file.")]
    public Task<string> SearchPdbSymbols(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("Name or decorated name substring (case-insensitive); empty for all.")] string? query = null,
        [Description("Only this kind (default all).")] string? kind = null,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description(ToolSupport.LimitDescription)] int limit = 150,
        [Description(MaxTokensDescription)] int? maxTokens = null,
        CancellationToken cancellationToken = default) => Task.Run(async () =>
    {
        var native = await Native(image, cancellationToken);
        var s = PdbService.StateOf(native) ?? throw new ToolError(ErrorCode.NotLoaded, $"No debug symbols (PDB or DWARF) are loaded for {native.Id}.",
            "call load_pdb first (it searches locally; download=true fetches them)");
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
                                  (x.IsPublic && PdbNaming.Display(x.Name).Contains(q, StringComparison.OrdinalIgnoreCase)) ||
                                  x.LinkageName?.Contains(q, StringComparison.OrdinalIgnoreCase) == true))
                matches.Add(x);
        }
        limit = Math.Clamp(limit, 1, 5_000);
        offset = Math.Max(0, offset);
        var page = matches.Skip(offset).Take(limit).Select(x =>
        {
            string at = x.Rva is { } rva ? NativeAddress.Va(native.Image, rva) : $"{x.Segment:X4}:{x.Offset:X8} (not in the image)";
            string name = x.IsPublic ? PdbNaming.Display(x.Name) : x.Name;
            string? sig = x.IsPublic && PdbNaming.Signature(x.Name) is { } full && full != name ? full
                : x.LinkageName is { } linkage ? Corvus.Native.Itanium.ItaniumDemangler.Demangle(linkage) ?? linkage : null;
            string? mod = x.Module >= 0 && x.Module < s.Pdb.Modules.Count ? Corvus.Core.Format.ForeignFileName(s.Pdb.Modules[x.Module].Name) : null;
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
