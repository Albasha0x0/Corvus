using System.Runtime.CompilerServices;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native.Pdb;
using NetDecompilerMcp.Native.Providers;

namespace NetDecompilerMcp.Services;

/// <summary>
/// Brings an image's PDB types (structs, classes, unions, enums, typedefs, function prototypes) into its engine
/// database: through the engine's own PDB loader (IDA's pdb plugin), else, when that loader is not available or does
/// not take the file, as C declarations written from the PDB's type stream (<see cref="PdbTypes"/>). The PDB's
/// identity (GUID, age, file size) and the route are recorded as a stamp in the database and saved with it, so a
/// database that already has this PDB's types is not loaded again (in this or a later session); a different PDB for
/// the same image (load_pdb) loads again. A PDB IDA loaded itself during the auto-analysis of a new database is
/// recognized and not loaded twice. Loading replaces the names pushed into the database, so they are pushed again.
/// </summary>
public sealed class NativePdbTypes
{
    public const string StampKey = "pdb";
    public const string RouteIda = "ida_pdb_loader", RouteOwn = "own_tpi_reader";

    /// <summary>Use the own declarations even when the engine's loader is available (tests).</summary>
    internal bool PreferOwnReader { get; set; }

    private static readonly ConditionalWeakTable<INativeDecompilerSession, State> States = new();

    private sealed class State
    {
        public readonly SemaphoreSlim Gate = new(1, 1);
        public string? Identity;
        public PdbTypeSource? Result;
        public int Failures;
    }

    /// <summary>
    /// The PDB types in a session's database. <see cref="Route"/>: ida_pdb_loader or own_tpi_reader, null when they
    /// could not be applied (<see cref="Error"/>); <see cref="AlreadyInDatabase"/>: recorded earlier;
    /// <see cref="FromAnalysis"/>: IDA loaded the PDB itself during auto-analysis; <see cref="FallbackReason"/>: why the
    /// engine's loader was not used.
    /// </summary>
    public sealed record PdbTypeSource(string PdbPath, string Identity, string? Route, bool AlreadyInDatabase, bool FromAnalysis, int TypesAdded,
        PdbTypeDeclarations? Own, TypeBatchResult? OwnApplied, string? FallbackReason, string? Error, TimeSpan Elapsed);

    private sealed class SourceCache
    {
        public PdbState? Key;
        public (string Path, string Identity, bool Matches, PdbFile? Read)? Value;
        public bool Set;
    }

    private static readonly ConditionalWeakTable<LoadedNative, SourceCache> Sources = new();

    /// <summary>
    /// The PDB the engine should have and its identity, or null when the image has none; looked up again when a PDB
    /// is loaded for the image (load_pdb), not on every call.
    /// </summary>
    internal static (string Path, string Identity, bool Matches, PdbFile? Read)? Source(LoadedNative native)
    {
        var cache = Sources.GetValue(native, _ => new SourceCache());
        var key = PdbService.StateOf(native);
        lock (cache)
            if (cache.Set && ReferenceEquals(cache.Key, key)) return cache.Value;
        var value = Locate(native);
        lock (cache) (cache.Key, cache.Value, cache.Set) = (key, value, true);
        return value;
    }

    private static (string Path, string Identity, bool Matches, PdbFile? Read)? Locate(LoadedNative native)
    {
        var path = PdbService.PathForEngines(native);
        if (path == null) return null;
        try
        {
            var state = PdbService.StateOf(native);
            Guid guid;
            uint age;
            PdbFile? read = null;
            if (state != null && string.Equals(state.Path, path, StringComparison.OrdinalIgnoreCase))
                (guid, age, read) = (state.Pdb.Guid, state.Pdb.DbiAge != 0 ? state.Pdb.DbiAge : state.Pdb.InfoAge, state.Pdb);
            else
            {
                var id = PdbFile.ReadIdentity(path);
                (guid, age) = (id.Guid, id.DbiAge != 0 ? id.DbiAge : id.InfoAge);
            }
            bool matches = native.Image.CodeView is { Format: "RSDS" } cv && cv.Guid == guid && cv.Age == age;
            return (path, $"{guid:N}-{age}-{new FileInfo(path).Length}", matches, read);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ToolError or InvalidDataException) { return null; }
    }

    /// <summary>
    /// Makes the session's database have the image's PDB types; null when the image has no PDB. Engine failures are
    /// reported in the result (and tried again on the next call), cancellation propagates.
    /// </summary>
    /// <param name="openedWith">The PDB path the session was opened with (IDA searched there first during analysis).</param>
    public async Task<PdbTypeSource?> EnsureAsync(LoadedNative native, INativeDecompilerSession session, string? openedWith, CancellationToken ct)
    {
        var source = await Task.Run(() => Source(native), ct).ConfigureAwait(false);
        if (source is not { } s) return null;
        var state = States.GetValue(session, _ => new State());
        await state.Gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            // applied, or failed twice for this PDB (a PDB that times out is not loaded on every call)
            if (state.Identity == s.Identity && (state.Result is { Route: not null } || state.Failures >= 2)) return state.Result;
            if (state.Identity != s.Identity) state.Failures = 0;
            var clock = System.Diagnostics.Stopwatch.StartNew();
            PdbTypeSource result;
            try
            {
                result = await ApplyAsync(native, session, s.Path, s.Identity, s.Matches, s.Read, openedWith, clock, ct).ConfigureAwait(false);
            }
            catch (Exception e) when (e is ToolError or IOException or UnauthorizedAccessException or InvalidDataException)
            {
                result = new PdbTypeSource(s.Path, s.Identity, null, false, false, 0, null, null, null,
                    e is ToolError t ? $"{t.Code}: {t.Message}" : e.Message, clock.Elapsed);
                state.Failures++;
            }
            lock (state) (state.Identity, state.Result) = (s.Identity, result);
            return result;
        }
        finally { state.Gate.Release(); }
    }

    private async Task<PdbTypeSource> ApplyAsync(LoadedNative native, INativeDecompilerSession session, string path, string identity, bool matches, PdbFile? read,
        string? openedWith, System.Diagnostics.Stopwatch clock, CancellationToken ct)
    {
        var stamp = await session.GetStampAsync(StampKey, ct).ConfigureAwait(false);
        if (stamp != null && stamp.StartsWith(identity + "|", StringComparison.Ordinal))
            return new PdbTypeSource(path, identity, stamp[(identity.Length + 1)..], true, false, 0, null, null, null, null, clock.Elapsed);

        string? fallback = null;
        if (!PreferOwnReader)
        {
            // IDA searched the PDB's directory first when it analyzed a new database: a PDB it loaded then (it loads only matching ones) is this one
            bool trust = !session.ReusedDatabase && matches && string.Equals(openedWith, path, StringComparison.OrdinalIgnoreCase);
            var loaded = await session.LoadPdbAsync(path, StampKey, identity + "|" + RouteIda, trust, ct).ConfigureAwait(false);
            if (loaded.Loaded)
            {
                NativeNamePush.Forget(session);
                NativeUserTypePush.Forget(session);
                return new PdbTypeSource(path, identity, RouteIda, false, loaded.FromAnalysis, Math.Max(0, loaded.TypesAfter - loaded.TypesBefore), null, null, null, null,
                    clock.Elapsed);
            }
            fallback = loaded.LoaderAvailable ? "the engine's PDB loader did not take the file" : $"the {session.ProviderId} engine's PDB loader is not available";
        }
        else fallback = "own reader requested";

        // the declarations from the PDB's type stream
        var pdb = read ?? await Task.Run(() => PdbFile.Open(path, native.Image.Sections, ct), ct).ConfigureAwait(false);
        var own = await Task.Run(() => PdbTypes.Build(pdb, native.Image.Is64Bit ? 8 : 4, ct), ct).ConfigureAwait(false);
        var batch = new NativeTypeBatch(own.Declarations, own.Prototypes.Select(p => new NativePrototype(p.Rva, p.Declaration)).ToList(), [], [],
            native.Image.Is64Bit ? 8 : 4);
        var applied = await session.ApplyTypesAsync(batch, StampKey, identity + "|" + RouteOwn, save: true, ct).ConfigureAwait(false);
        return new PdbTypeSource(path, identity, RouteOwn, false, false, own.Structs + own.Unions + own.Enums + own.Typedefs, own, applied, fallback, null, clock.Elapsed);
    }

    /// <summary>The PDB types last brought into <paramref name="session"/>, or null.</summary>
    public static PdbTypeSource? Current(INativeDecompilerSession session) =>
        States.TryGetValue(session, out var s) ? s.Result : null;

    /// <summary>
    /// <see cref="Current"/> for tool output: a load is reported once, later calls see the types as already in the database.
    /// </summary>
    public static PdbTypeSource? Report(INativeDecompilerSession session)
    {
        if (!States.TryGetValue(session, out var s)) return null;
        lock (s)
        {
            var r = s.Result;
            if (r is { Route: not null, AlreadyInDatabase: false }) s.Result = r with { AlreadyInDatabase = true };
            return r;
        }
    }

    /// <summary>Whether the session's database has PDB types (other type sources leave the PDB's classes alone).</summary>
    public static bool Applied(INativeDecompilerSession session) => Current(session) is { Route: not null };

    /// <summary>A key for output caches: changes when other PDB types are applied.</summary>
    public static string CurrentStamp(INativeDecompilerSession session) => Current(session) is { Route: { } r } c ? $"{c.Identity}|{r}" : "";

    /// <summary>One line for tool output.</summary>
    public static string? Describe(PdbTypeSource? r)
    {
        if (r == null) return null;
        var file = Path.GetFileName(r.PdbPath);
        if (r.Route == null) return $"types: the PDB {file} could not be applied ({r.Error}); pseudocode uses the engine's own types";
        var how = r.Route == RouteIda ? "IDA's PDB loader" : "the server's PDB type reader";
        if (r.AlreadyInDatabase) return $"types: PDB {file} via {how} (already in the database)";
        if (r.FromAnalysis) return $"types: PDB {file} via {how} (loaded during auto-analysis)";
        if (r.Own is { } own)
        {
            var t = r.OwnApplied!;
            return $"types: PDB {file} via {how} ({r.FallbackReason}): {own.Structs} structs, {own.Unions} unions, {own.Enums} enums, {own.Typedefs} typedefs" +
                   (t.DeclarationErrors > 0 ? $" ({t.DeclarationErrors} declaration errors)" : "") +
                   $", {t.Typed} of {own.Prototypes.Count} prototypes applied in {r.Elapsed.TotalSeconds:0.0} s";
        }
        return $"types: PDB {file} via {how}: loaded in {r.Elapsed.TotalSeconds:0.0} s ({r.TypesAdded} types added)";
    }
}
