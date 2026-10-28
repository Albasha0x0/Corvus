using System.Diagnostics;
using System.Runtime.CompilerServices;
using Microsoft.Extensions.Logging;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Code;
using Corvus.Native.Dwarf;
using Corvus.Native.Pdb;

namespace Corvus.Services;

/// <summary>A PDB loaded for a native image: where it came from, what it holds, and the names it contributes.</summary>
public sealed record PdbState(
    PdbFile Pdb,
    string Path,
    bool Verified,
    bool Downloaded,
    bool Automatic,
    IReadOnlyList<PdbName> Names,
    IReadOnlyList<PdbProbe> Probes,
    TimeSpan Elapsed)
{
    /// <summary>Function starts the PDB names (procedures, code publics, thunks).</summary>
    public IReadOnlyCollection<uint> FunctionStarts { get; } = Names.Where(n => n.IsFunction).Select(n => n.Rva).ToArray();
}

// The local file is read on the index build thread before discovery, so its functions become starts. PDB names rank
// above discovered names and below the user's. An explicit load is saved with the annotations and restored on reload.
/// <summary>Debug symbols (PDB, DWARF) for native images: a matching local file read automatically (no network) or one
/// loaded by load_pdb, applied as the "pdb" name layer. State is kept per loaded image and survives patching.</summary>
public sealed class PdbService
{
    /// <summary>Set to 0 to turn off reading local PDBs automatically.</summary>
    public const string AutoVariable = "CORVUS_AUTO_PDB";

    private static readonly ConditionalWeakTable<LoadedNative, Slot> States = new();
    private readonly NativeCodeService _code;
    private readonly ILogger<PdbService>? _logger;

    private sealed class Slot
    {
        public readonly object Gate = new();
        public PdbState? State;
        public PdbLocation? AutoSearch;
        public bool AutoTried;
        /// <summary>Completes when the automatic search (and read) finishes; null before it starts.</summary>
        public TaskCompletionSource? Auto;
    }

    public PdbService(NativeCodeService code, ILogger<PdbService>? logger = null)
    {
        _code = code;
        _logger = logger;
        if (Environment.GetEnvironmentVariable(AutoVariable) != "0") code.SymbolStarts = AutoLoad;
    }

    /// <summary>The PDB loaded for <paramref name="native"/>, or null.</summary>
    public static PdbState? StateOf(LoadedNative native) => States.TryGetValue(native, out var s) ? s.State : null;

    /// <summary>The result of the automatic local search, when it ran and found nothing.</summary>
    public static PdbLocation? AutoSearchOf(LoadedNative native) => States.TryGetValue(native, out var s) ? s.AutoSearch : null;

    /// <summary>Whether the automatic local search (and read) for <paramref name="native"/> has started and not finished.</summary>
    public static bool AutoSearchPending(LoadedNative native) => States.TryGetValue(native, out var s) && s.Auto is { Task.IsCompleted: false };

    /// <summary>Runs or joins the automatic local search for up to <paramref name="wait"/>; false when it is still running.</summary>
    public bool SettleAutoSearch(LoadedNative native, TimeSpan wait, CancellationToken ct)
    {
        if (Environment.GetEnvironmentVariable(AutoVariable) == "0") return true;
        // The search outlives a cancelled request: the index build joins it and takes its result.
        return Task.Run(() => AutoLoad(native, CancellationToken.None), CancellationToken.None).Wait(wait, ct);
    }

    // Engines work on a copy of the image, so they cannot find a PDB next to it themselves.
    /// <summary>The PDB an engine should use: the loaded one, else a matching local one (no network); null when none.</summary>
    public static string? PathForEngines(LoadedNative native)
    {
        if (StateOf(native) is { } s) return s.Path;
        if (native.Pe is not { CodeView.Format: "RSDS" } pe) return null;
        try { return PdbLocator.Locate(pe).Path; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ToolError) { return null; }
    }

    /// <summary>The PDB's function starts, reading the matching local PDB on the first call; concurrent calls share one read.</summary>
    private IReadOnlyCollection<uint>? AutoLoad(LoadedNative native, CancellationToken ct)
    {
        var slot = States.GetValue(native, _ => new Slot());
        var saved = NativeNameLayers.OfOrNull(native)?.Get(NativeNameSource.Pdb) is { Info: { Restored: true } info } ? info : null;
        bool dwarf = native.Image.Format is ImageFormat.Elf or ImageFormat.MachO;
        TaskCompletionSource? running, mine = null;
        lock (slot.Gate)
        {
            if (slot.State != null) return slot.State.FunctionStarts;
            running = slot.Auto;
            if (running == null)
            {
                if (slot.AutoTried || (saved == null && !dwarf && native.Pe?.CodeView is not { Format: "RSDS" })) return null;
                slot.AutoTried = true;
                slot.Auto = mine = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            }
        }
        if (running != null)
        {
            running.Task.Wait(ct);
            lock (slot.Gate) return slot.State?.FunctionStarts;
        }
        try { return AutoSearch(native, slot, saved, dwarf, ct); }
        finally { mine!.TrySetResult(); }
    }

    /// <summary>Called as the automatic search starts, on its thread (tests hold it there).</summary>
    internal static Action<LoadedNative>? AutoSearchStarting;

    private IReadOnlyCollection<uint>? AutoSearch(LoadedNative native, Slot slot, ImportInfo? saved, bool dwarf, CancellationToken ct)
    {
        AutoSearchStarting?.Invoke(native);
        if (saved != null) return Reopen(native, slot, saved, ct);
        PdbLocation location;
        if (dwarf) location = DwarfLocator.Locate(native.Image, native.FilePath);
        else if (native.Pe is { } pe) location = PdbLocator.Locate(pe);
        else return null;
        if (location.Path == null)
        {
            lock (slot.Gate) slot.AutoSearch = location;
            return null;
        }
        PdbState state;
        try { state = Read(native, location.Path, location.Probes, verified: true, downloaded: false, automatic: true, ct); }
        catch (Exception ex) when (ex is ToolError or IOException or UnauthorizedAccessException)
        {
            lock (slot.Gate) slot.AutoSearch = location with { Path = null, Probes = [.. location.Probes, new PdbProbe(location.Path, "unreadable: " + ex.Message)] };
            return null;
        }
        lock (slot.Gate)
        {
            // load_pdb won meanwhile.
            if (slot.State != null) return slot.State.FunctionStarts;
            slot.State = state;
        }
        // The index is not built yet: the layer is replayed onto it when it is.
        NativeNameLayers.Of(native).Set(Layer(state), null);
        _logger?.LogInformation("Read {Path} for {Id}: {Names} names in {Seconds:0.0} s", state.Path, native.Id, state.Names.Count, state.Elapsed.TotalSeconds);
        return state.FunctionStarts;
    }

    // No local search: the saved PDB was the user's choice.
    /// <summary>Reads a restored layer's PDB again when it is unchanged on disk; otherwise the saved names stand alone.</summary>
    private IReadOnlyCollection<uint>? Reopen(LoadedNative native, Slot slot, ImportInfo saved, CancellationToken ct)
    {
        if (saved.SourcePath is not { } path || !File.Exists(path)) return null;
        try
        {
            var state = Read(native, path, [new PdbProbe(path, "saved by an earlier load_pdb")], verified: false, downloaded: false, automatic: false, ct);
            if (Identity(state.Pdb) != saved.SourceIdentity) return null;
            state = state with
            {
                Verified = native.Pe?.CodeView is { Format: "RSDS" } cv ? state.Pdb.Matches(cv) : state.Pdb.BuildId != null && state.Pdb.BuildId == native.Image.BuildId,
            };
            lock (slot.Gate)
            {
                if (slot.State != null) return slot.State.FunctionStarts;
                slot.State = state;
            }
            return state.FunctionStarts;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ToolError)
        {
            _logger?.LogInformation("Saved PDB {Path} of {Id} not read again: {Message}", path, native.Id, ex.Message);
            return null;
        }
    }

    /// <summary>Debug information's identity as saved with its names: "GUID age" for a PDB, "dwarf build-id size" for DWARF.</summary>
    public static string Identity(PdbFile pdb) =>
        pdb.Format == DebugInfoFormat.Dwarf ? $"dwarf {pdb.BuildId ?? "-"} {pdb.FileSize}" : $"{pdb.Guid:D} {pdb.DbiAge}";

    private static PdbState Read(LoadedNative native, string path, IReadOnlyList<PdbProbe> probes, bool verified, bool downloaded, bool automatic, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        var pdb = native.Image.Format is ImageFormat.Elf or ImageFormat.MachO ? ReadDwarf(native, path, ct) : PdbFile.Open(path, native.Image.Sections, ct);
        var names = PdbNaming.Choose(pdb, native.Image.SizeOfImage, ct);
        return new PdbState(pdb, pdb.Path, verified, downloaded, automatic, names, probes, sw.Elapsed);
    }

    private static NativeNameLayers.Layer Layer(PdbState state) =>
        new(NativeNameSource.Pdb, state.Names.ToDictionary(n => n.Rva, n => n.Name), new Dictionary<uint, string>(), state.Path);

    /// <summary>What <see cref="Load"/> did.</summary>
    public sealed record LoadResult(PdbState? State, PdbLocation Location, string? DownloadError, int NamesApplied, int UserNamesKept, int NewFunctionStarts, bool Rebuilding,
        string? SaveProblem = null);

    /// <summary>Locates, optionally downloads, reads and applies the image's PDB; refuses a GUID or age mismatch unless <paramref name="force"/>.</summary>
    public async Task<LoadResult> Load(LoadedNative native, string? path, bool download, string? server, bool force, TimeSpan downloadTimeout,
        long maxDownloadBytes, CancellationToken ct)
    {
        bool dwarf = native.Image.Format is ImageFormat.Elf or ImageFormat.MachO;
        if (!string.IsNullOrWhiteSpace(server))
        {
            if (dwarf) PdbLocator.RequireConfigured(server, DwarfLocator.Servers(), DwarfLocator.ServersVariable);
            else PdbLocator.RequireConfigured(server, PdbLocator.ConfiguredServers(), "_NT_SYMBOL_PATH (srv*<cache>*<url>)");
        }
        if (dwarf)
            return await LoadDwarf(native, path, download, server, force, downloadTimeout, maxDownloadBytes, ct).ConfigureAwait(false);
        var pe = native.RequirePe("load_pdb");
        // A symbol server (srv*, URL) is not a local path.
        if (path != null && Targets.LooksLikePath(path) && !path.Contains('*') && !path.Contains("://", StringComparison.Ordinal)
            && !File.Exists(path) && !Directory.Exists(path))
            throw Targets.FileNotFound(path);
        var cv = pe.CodeView;
        var location = await Task.Run(() => PdbLocator.Locate(pe, path), ct);
        string? found = location.Path;
        bool verified = found != null && cv is { Format: "RSDS" };
        bool downloaded = false;
        string? downloadError = null;
        var probes = location.Probes.ToList();

        if (found == null && !string.IsNullOrWhiteSpace(path) && File.Exists(path) && force)
        {
            found = Path.GetFullPath(path);
            probes.Add(new PdbProbe(found, "used without a match (allowMismatch=true)"));
        }
        if (found == null && download)
        {
            if (cv is not { Format: "RSDS" })
                downloadError = "the image has no PDB 7.0 (RSDS) record to download by";
            else
            {
                var servers = !string.IsNullOrWhiteSpace(server) ? [server.Trim()] : location.Servers.Count > 0 ? location.Servers.ToList() : [PdbLocator.DefaultServer];
                foreach (var s in servers)
                {
                    try
                    {
                        found = await PdbLocator.DownloadAsync(cv, s, downloadTimeout, maxDownloadBytes, null, null, ct);
                        probes.Add(new PdbProbe(s, "downloaded to " + found));
                        verified = downloaded = true;
                        break;
                    }
                    catch (ToolError e)
                    {
                        probes.Add(new PdbProbe(s, "download failed: " + e.Message));
                        downloadError = e.Message;
                    }
                }
            }
        }
        if (found == null) return new LoadResult(null, location with { Probes = probes }, downloadError, 0, 0, 0, false);

        var state = await Task.Run(() => Read(native, found, probes, verified, downloaded, automatic: false, ct), ct);
        if (cv is { Format: "RSDS" } && !state.Pdb.Matches(cv) && !force)
            throw new ToolError(ErrorCode.Conflict,
                $"{found} does not belong to {native.Id}: PDB {state.Pdb.Guid:D} age {state.Pdb.DbiAge}, image {cv.Guid:D} age {cv.Age}.",
                "pass the PDB of this exact build, or allowMismatch=true to use it anyway (names may be wrong)");
        return Apply(native, state, location with { Probes = probes, Path = found }, downloadError);
    }

    /// <summary>load_pdb for ELF and Mach-O: local or debuginfod DWARF; refuses a build-id or UUID mismatch unless <paramref name="force"/>.</summary>
    private async Task<LoadResult> LoadDwarf(LoadedNative native, string? path, bool download, string? server, bool force, TimeSpan downloadTimeout,
        long maxDownloadBytes, CancellationToken ct)
    {
        if (path != null && !File.Exists(path) && !Directory.Exists(path)) throw Targets.FileNotFound(path);
        var location = await Task.Run(() => DwarfLocator.Locate(native.Image, native.FilePath, path), ct).ConfigureAwait(false);
        string? found = location.Path;
        bool verified = found != null, downloaded = false;
        string? downloadError = null;
        var probes = location.Probes.ToList();
        if (found == null && !string.IsNullOrWhiteSpace(path) && File.Exists(path) && force)
        {
            found = Path.GetFullPath(path);
            verified = false;
            probes.Add(new PdbProbe(found, "used without a match (allowMismatch=true)"));
        }
        if (found == null && download)
        {
            var servers = !string.IsNullOrWhiteSpace(server) ? [server.Trim()] : location.Servers.ToList();
            if (ReferencePacks.Offline) downloadError = "CORVUS_OFFLINE=1: nothing is downloaded";
            else if (servers.Count == 0) downloadError = $"no debuginfod server: pass server=<url> or set {DwarfLocator.ServersVariable}";
            foreach (var s in ReferencePacks.Offline ? [] : servers)
            {
                try
                {
                    found = await DwarfLocator.DownloadAsync(native.Image, s, downloadTimeout, maxDownloadBytes, null, null, ct).ConfigureAwait(false);
                    probes.Add(new PdbProbe(s, "downloaded to " + found));
                    downloaded = verified = true;
                    downloadError = null;
                    break;
                }
                catch (ToolError e)
                {
                    probes.Add(new PdbProbe(s, "download failed: " + e.Message));
                    downloadError = e.Message;
                }
            }
        }
        if (found == null) return new LoadResult(null, location with { Probes = probes }, downloadError, 0, 0, 0, false);
        var state = await Task.Run(() => Read(native, found, probes, verified, downloaded, automatic: false, ct), ct).ConfigureAwait(false);
        return Apply(native, state, location with { Probes = probes, Path = found }, downloadError);
    }

    /// <summary>Makes <paramref name="state"/> the image's debug information: the name layer (saved), and function starts the index lacks.</summary>
    private LoadResult Apply(LoadedNative native, PdbState state, PdbLocation location, string? downloadError)
    {
        var slot = States.GetValue(native, _ => new Slot());
        lock (slot.Gate) { slot.State = state; slot.AutoTried = true; slot.AutoSearch = null; }

        var index = _code.Ready(native);
        var info = new ImportInfo(state.Path, Identity(state.Pdb), DateTime.UtcNow, state.FunctionStarts.Order().ToArray());
        NativeNameLayers.Of(native).Set(Layer(state) with { Info = info }, index);
        var saveProblem = _code.SaveImported(native, NativeNameSource.Pdb);
        int userKept = 0, newStarts = 0;
        bool rebuilding = false;
        if (index != null)
        {
            foreach (var n in state.Names)
                if (index.Sourced.NameAt(n.Rva) is { Source: NativeNameSource.User }) userKept++;
            newStarts = state.FunctionStarts.Count(r => index.FunctionByStart(r) == null && native.Image.SectionAt(r) is { IsExecutable: true });
            if (newStarts > 0)
            {
                _ = _code.Rebuild(native);
                rebuilding = true;
            }
        }
        return new LoadResult(state, location, downloadError, state.Names.Count - userKept, userKept, newStarts, rebuilding, saveProblem);
    }

    /// <summary>The DWARF at <paramref name="path"/> (the image itself when it is the image's file) for the image.</summary>
    private static PdbFile ReadDwarf(LoadedNative native, string path, CancellationToken ct)
    {
        var image = native.Image;
        bool own = string.Equals(Path.GetFullPath(path), Path.GetFullPath(native.FilePath), StringComparison.OrdinalIgnoreCase);
        Func<DebugContainer> open = own ? () => DebugContainer.FromMemory(native.FilePath, DwarfLocator.FileBytes(image)) : () => DebugContainer.Open(path, image.BuildId);
        using var container = open();
        return DwarfDebugInfo.Read(container, image, open, ct);
    }

    // A matching local PDB is not read automatically again in this session.
    /// <summary>Removes the PDB names and saved copy; returns the name count (null when none) and whether a saved copy was deleted.</summary>
    public (int? Removed, bool SavedDeleted) Clear(LoadedNative native)
    {
        _code.RestoreImported(native);
        var slot = States.GetValue(native, _ => new Slot());
        lock (slot.Gate) { slot.State = null; slot.AutoTried = true; slot.AutoSearch = null; }
        var removed = NativeNameLayers.OfOrNull(native)?.Remove(NativeNameSource.Pdb, _code.Ready(native));
        return (removed?.Names.Count, _code.ForgetImported(native, NativeNameSource.Pdb));
    }
}
