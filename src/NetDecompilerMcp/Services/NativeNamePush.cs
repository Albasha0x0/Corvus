using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Annotations;
using NetDecompilerMcp.Native.Code;
using NetDecompilerMcp.Native.Providers;

namespace NetDecompilerMcp.Services;

/// <summary>
/// Pushes the names and comments in effect for an image (user annotations over the il2cpp layer; PDB names are the engine's own) into its
/// engine session before engine output is shown, so decompile_native uses the same names as the built-in tools.
/// Batched (<see cref="BatchSize"/> per request); the last batch records a stamp (SHA-256 of the pushed set) in the
/// database and saves it, so a later session on the same database skips the push when nothing changed. Within a
/// session only the differences since the last push are sent, including removals.
/// </summary>
public sealed class NativeNamePush(NativeCodeService code)
{
    public const string StampKey = "names";
    public const int BatchSize = 20_000;

    private static readonly ConditionalWeakTable<INativeDecompilerSession, State> States = new();

    /// <summary>A name and comment in effect at an address; <see cref="Function"/>: an imported name in code (a function start).</summary>
    public readonly record struct Entry(string? Name, string? Comment, bool Function);

    /// <summary>What a push did: entries sent, of them removals, the engine's counts, or that the database already had this set.</summary>
    public sealed record PushResult(int Sent, int Removed, NameBatchResult? Totals, bool AlreadyInDatabase, string Stamp, TimeSpan Elapsed);

    private sealed class State
    {
        public readonly SemaphoreSlim Gate = new(1, 1);
        public Dictionary<uint, Entry>? Pushed;
        public string Stamp = "";
        public object[]? Inputs;
    }

    /// <summary>
    /// The names and comments in effect from every source above discovered names, by RVA. PDB names are left out
    /// (unless <paramref name="withPdb"/>: the engine's PDB loader was not used): the engine loads the same PDB itself
    /// and keeps its decorated, typed names, which lower layers do not override; so are the engine's own library names
    /// (the ida layer).
    /// </summary>
    public static Dictionary<uint, Entry> Effective(NativeAnnotations? user, IReadOnlyList<NativeNameLayers.Layer> layers, INativeImage image, bool withPdb = false)
    {
        var result = new Dictionary<uint, Entry>();
        var pdb = withPdb ? null : layers.FirstOrDefault(l => l.Source == NativeNameSource.Pdb)?.Names;
        foreach (var layer in layers.Where(l => l.Source != NativeNameSource.Ida && (withPdb || l.Source != NativeNameSource.Pdb)).OrderBy(l => l.Source.Rank()))
        {
            foreach (var (rva, name) in layer.Names)
                if (pdb == null || !pdb.ContainsKey(rva))
                    result[rva] = result.GetValueOrDefault(rva) with { Name = name, Function = image.SectionAt(rva) is { IsExecutable: true } };
            foreach (var (rva, comment) in layer.Comments)
                result[rva] = result.GetValueOrDefault(rva) with { Comment = comment };
        }
        if (user != null)
        {
            foreach (var (rva, name) in user.Names()) result[rva] = result.GetValueOrDefault(rva) with { Name = name, Function = false };
            foreach (var (rva, comment) in user.Comments()) result[rva] = result.GetValueOrDefault(rva) with { Comment = comment };
        }
        return result;
    }

    /// <summary>SHA-256 of a set of entries in RVA order.</summary>
    public static string StampOf(Dictionary<uint, Entry> entries)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Span<byte> rva = stackalloc byte[5];
        foreach (var (key, e) in entries.OrderBy(kv => kv.Key))
        {
            BitConverter.TryWriteBytes(rva, key);
            rva[4] = e.Function ? (byte)1 : (byte)0;
            hash.AppendData(rva);
            hash.AppendData(Encoding.UTF8.GetBytes((e.Name ?? "") + "\0" + (e.Comment ?? "") + "\0"));
        }
        return Convert.ToHexString(hash.GetHashAndReset());
    }

    /// <summary>
    /// Brings the session's names up to date; null when nothing had changed since the last call. Engine failures
    /// during the push propagate (the session restarts on the next request).
    /// </summary>
    public async Task<PushResult?> EnsureAsync(LoadedNative native, INativeDecompilerSession session, CancellationToken ct)
    {
        var state = States.GetValue(session, _ => new State());
        await state.Gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var user = code.Annotations(native);
            var layers = NativeNameLayers.OfOrNull(native)?.Layers ?? [];
            // PDB names go in when the engine did not load the PDB with its own loader
            bool withPdb = NativePdbTypes.Current(session) is { Route: NativePdbTypes.RouteOwn };
            // Layers are immutable and replaced as a whole, so they compare by reference; user annotations by content.
            object[] inputs = [withPdb, .. layers, .. user.Names().Select(n => (object)n), "|", .. user.Comments().Select(c => (object)c)];
            if (state.Inputs != null && inputs.SequenceEqual(state.Inputs)) return null;

            var clock = System.Diagnostics.Stopwatch.StartNew();
            var effective = Effective(user, layers, native.Image, withPdb);
            var stamp = StampOf(effective);
            var items = new List<NativeNameItem>();
            int removed = 0;
            if (state.Pushed == null)
            {
                if (effective.Count == 0 || await session.GetStampAsync(StampKey, ct).ConfigureAwait(false) == stamp)
                {
                    Record(state, effective, stamp, inputs);
                    return effective.Count == 0 ? null : new PushResult(0, 0, null, true, stamp, clock.Elapsed);
                }
                items.AddRange(effective.OrderBy(kv => kv.Key).Select(kv => new NativeNameItem(kv.Key, kv.Value.Name, kv.Value.Comment, kv.Value.Function)));
            }
            else
            {
                foreach (var (rva, e) in effective.OrderBy(kv => kv.Key))
                {
                    var before = state.Pushed.GetValueOrDefault(rva);
                    if (before != e)
                        items.Add(new NativeNameItem(rva, e.Name != before.Name ? e.Name ?? "" : null, e.Comment != before.Comment ? e.Comment ?? "" : null,
                            e.Function && !before.Function));
                }
                foreach (var (rva, before) in state.Pushed)
                    if (!effective.ContainsKey(rva))
                    {
                        items.Add(new NativeNameItem(rva, before.Name != null ? "" : null, before.Comment != null ? "" : null));
                        removed++;
                    }
            }
            if (items.Count == 0)
            {
                Record(state, effective, stamp, inputs);
                return null;
            }

            int named = 0, failed = 0, commented = 0, created = 0;
            var failures = new List<string>();
            for (int i = 0; i < items.Count; i += BatchSize)
            {
                bool last = i + BatchSize >= items.Count;
                var batch = items.GetRange(i, Math.Min(BatchSize, items.Count - i));
                var r = await session.ApplyNamesAsync(batch, last ? StampKey : null, last ? stamp : null, save: last, ct).ConfigureAwait(false);
                named += r.Named;
                failed += r.NameFailures;
                commented += r.Commented;
                created += r.FunctionsCreated;
                failures.AddRange(r.Failures.Take(20 - failures.Count));
            }
            Record(state, effective, stamp, inputs);
            return new PushResult(items.Count, removed, new NameBatchResult(named, failed, commented, created, clock.Elapsed, failures), false, stamp, clock.Elapsed);
        }
        finally { state.Gate.Release(); }
    }

    /// <summary>Drops what is known of the session's names (its database's names were replaced): the next push sends the whole set.</summary>
    public static void Forget(INativeDecompilerSession session) => States.Remove(session);

    /// <summary>The stamp of the set last pushed to <paramref name="session"/>, or "" before any push.</summary>
    public static string CurrentStamp(INativeDecompilerSession session) => States.TryGetValue(session, out var s) ? s.Stamp : "";

    private static void Record(State state, Dictionary<uint, Entry> effective, string stamp, object[] inputs)
    {
        state.Pushed = effective;
        state.Stamp = stamp;
        state.Inputs = inputs;
    }

    /// <summary>One line describing a push for tool output, or null when nothing was pushed.</summary>
    public static string? Describe(PushResult? r) => r switch
    {
        null => null,
        { AlreadyInDatabase: true } => "names: the database already has the current names and comments",
        { Totals: { } t } => $"names: pushed {r.Sent} name/comment change(s) to the database in {r.Elapsed.TotalSeconds:0.0} s ({t.Named} named, {t.Commented} commented" +
                             (t.FunctionsCreated > 0 ? $", {t.FunctionsCreated} functions created" : "") + (r.Removed > 0 ? $", {r.Removed} removed" : "") +
                             (t.NameFailures > 0 ? $"; {t.NameFailures} rejected, e.g. {string.Join(", ", t.Failures.Take(3))}" : "") + ")",
        _ => null,
    };
}
