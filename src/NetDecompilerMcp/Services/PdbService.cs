using System.Diagnostics;
using System.Runtime.CompilerServices;
using Microsoft.Extensions.Logging;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native.Code;
using NetDecompilerMcp.Native.Pdb;

namespace NetDecompilerMcp.Services;

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

/// <summary>
/// Debug symbols for native images. The matching local PDB (no network) is read on the code index build thread, before
/// discovery, so its functions become function starts and its names apply when the index is ready; load_pdb loads one
/// explicitly (a path, or a download when asked) and rebuilds the index in the background when it adds function starts.
/// PDB names form the "pdb" layer of <see cref="NativeNameLayers"/>: they rank above discovered and Il2Cpp names and
/// below the user's names, which they never replace. State is kept per loaded image (it survives patching; a reload
/// starts over).
/// </summary>
public sealed class PdbService
{
    /// <summary>Set to 0 to turn off reading local PDBs automatically.</summary>
    public const string AutoVariable = "NDM_AUTO_PDB";

    private static readonly ConditionalWeakTable<LoadedNative, Slot> States = new();
    private readonly NativeCodeService _code;
    private readonly ILogger<PdbService>? _logger;

    private sealed class Slot
    {
        public readonly object Gate = new();
        public PdbState? State;
        public PdbLocation? AutoSearch;
        public bool AutoTried;
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

    /// <summary>
    /// The PDB an engine (IDA) should use for <paramref name="native"/>: the loaded one, else a matching local one (no
    /// network); null when none. Engines work on a copy of the image, so they cannot find a PDB next to it themselves.
    /// </summary>
    public static string? PathForEngines(LoadedNative native)
    {
        if (StateOf(native) is { } s) return s.Path;
        if (native.Image.CodeView is not { Format: "RSDS" }) return null;
        try { return PdbLocator.Locate(native.Image).Path; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ToolError) { return null; }
    }

    /// <summary>On the index build thread: the PDB's function starts, reading the matching local PDB on the first build.</summary>
    private IReadOnlyCollection<uint>? AutoLoad(LoadedNative native, CancellationToken ct)
    {
        var slot = States.GetValue(native, _ => new Slot());
        lock (slot.Gate)
        {
            if (slot.State != null) return slot.State.FunctionStarts;
            if (slot.AutoTried || native.Image.CodeView is not { Format: "RSDS" }) return null;
            slot.AutoTried = true;
        }
        var location = PdbLocator.Locate(native.Image);
        if (location.Path == null)
        {
            lock (slot.Gate) slot.AutoSearch = location;
            return null;
        }
        var state = Read(native, location.Path, location.Probes, verified: true, downloaded: false, automatic: true, ct);
        lock (slot.Gate)
        {
            if (slot.State != null) return slot.State.FunctionStarts; // load_pdb won meanwhile
            slot.State = state;
        }
        // the index is not built yet: the layer is replayed onto it when it is
        NativeNameLayers.Of(native).Set(Layer(state), null);
        _logger?.LogInformation("Read {Path} for {Id}: {Names} names in {Seconds:0.0} s", state.Path, native.Id, state.Names.Count, state.Elapsed.TotalSeconds);
        return state.FunctionStarts;
    }

    private static PdbState Read(LoadedNative native, string path, IReadOnlyList<PdbProbe> probes, bool verified, bool downloaded, bool automatic, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        var pdb = PdbFile.Open(path, native.Image.Sections, ct);
        var names = PdbNaming.Choose(pdb, native.Image.SizeOfImage, ct);
        return new PdbState(pdb, pdb.Path, verified, downloaded, automatic, names, probes, sw.Elapsed);
    }

    private static NativeNameLayers.Layer Layer(PdbState state) =>
        new(NativeNameSource.Pdb, state.Names.ToDictionary(n => n.Rva, n => n.Name), new Dictionary<uint, string>(), state.Path);

    /// <summary>What <see cref="Load"/> did.</summary>
    public sealed record LoadResult(PdbState? State, PdbLocation Location, string? DownloadError, int NamesApplied, int UserNamesKept, int NewFunctionStarts, bool Rebuilding);

    /// <summary>
    /// Locates (or takes <paramref name="path"/>), optionally downloads, reads and applies the image's PDB. A PDB whose
    /// GUID or age does not match is refused unless <paramref name="force"/>.
    /// </summary>
    public async Task<LoadResult> Load(LoadedNative native, string? path, bool download, string? server, bool force, TimeSpan downloadTimeout,
        long maxDownloadBytes, CancellationToken ct)
    {
        var cv = native.Image.CodeView;
        var location = await Task.Run(() => PdbLocator.Locate(native.Image, path), ct);
        string? found = location.Path;
        bool verified = found != null && cv is { Format: "RSDS" };
        bool downloaded = false;
        string? downloadError = null;
        var probes = location.Probes.ToList();

        if (found == null && !string.IsNullOrWhiteSpace(path) && File.Exists(path) && force)
        {
            found = Path.GetFullPath(path);
            probes.Add(new PdbProbe(found, "used without a match (force=true)"));
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
                "pass the PDB of this exact build, or force=true to use it anyway (names may be wrong)");

        var slot = States.GetValue(native, _ => new Slot());
        lock (slot.Gate) { slot.State = state; slot.AutoTried = true; slot.AutoSearch = null; }

        var index = _code.Ready(native);
        NativeNameLayers.Of(native).Set(Layer(state), index);
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
        return new LoadResult(state, location with { Probes = probes, Path = found }, downloadError, state.Names.Count - userKept, userKept, newStarts, rebuilding);
    }
}
