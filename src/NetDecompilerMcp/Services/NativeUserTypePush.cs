using System.Runtime.CompilerServices;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native.Annotations;
using NetDecompilerMcp.Native.Providers;

namespace NetDecompilerMcp.Services;

/// <summary>
/// Keeps an engine session's database in step with the image's user types (<see cref="UserTypeLayer"/>, kept in the
/// annotation sidecar). A whole layer is pushed when the database's stamp differs (a new database, a new IDA build, edits
/// lost with an unsaved database) and saved; single edits go through <see cref="ApplyAsync"/>, journaled by the session
/// and recorded in the layer only when the engine took them. Runs after the name and type pushes so user types win.
/// </summary>
public sealed class NativeUserTypePush(NativeCodeService code)
{
    public const string StampKey = "user_types";

    private static readonly ConditionalWeakTable<INativeDecompilerSession, State> States = new();

    public sealed record PushResult(int Items, UserTypeResult? Totals, bool AlreadyInDatabase);

    private sealed class State
    {
        public readonly SemaphoreSlim Gate = new(1, 1);
        /// <summary>Stamp of the layer the database holds; null: not known yet.</summary>
        public string? Stamp;
        /// <summary>Engine scripts run on the session: their changes are not tracked, only counted (see <see cref="Touch"/>).</summary>
        public int Scripts;
    }

    /// <summary>Brings the session's user types up to date; null when nothing changed.</summary>
    public async Task<PushResult?> EnsureAsync(LoadedNative native, INativeDecompilerSession session, CancellationToken ct)
    {
        var state = States.GetValue(session, _ => new State());
        await state.Gate.WaitAsync(ct).ConfigureAwait(false);
        try { return await EnsureCoreAsync(native, session, state, ct).ConfigureAwait(false); }
        finally { state.Gate.Release(); }
    }

    private async Task<PushResult?> EnsureCoreAsync(LoadedNative native, INativeDecompilerSession session, State state, CancellationToken ct)
    {
        var layer = code.Annotations(native).UserTypes;
        if (state.Stamp == layer.Stamp) return null;
        if (state.Stamp == null && (layer.IsEmpty || await session.GetStampAsync(StampKey, ct).ConfigureAwait(false) == layer.Stamp))
        {
            state.Stamp = layer.Stamp;
            return layer.IsEmpty ? null : new PushResult(layer.Count, null, true);
        }
        var totals = await session.ApplyUserTypesAsync(layer.ToBatch(), StampKey, layer.Stamp, save: true, ct).ConfigureAwait(false);
        state.Stamp = layer.Stamp;
        return new PushResult(layer.Count, totals, false);
    }

    /// <summary>
    /// Applies <paramref name="edit"/> (the layer is brought up to date first), then records it with <paramref name="record"/>,
    /// which returns the new layer or null to record nothing (the engine did not take it).
    /// </summary>
    public async Task<UserTypeResult> ApplyAsync(LoadedNative native, INativeDecompilerSession session, NativeUserTypeBatch edit,
        Func<UserTypeResult, UserTypeLayer, UserTypeLayer?> record, CancellationToken ct)
    {
        var state = States.GetValue(session, _ => new State());
        await state.Gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await EnsureCoreAsync(native, session, state, ct).ConfigureAwait(false);
            var result = await session.ApplyUserTypesAsync(edit, cancellationToken: ct).ConfigureAwait(false);
            var before = code.Annotations(native).UserTypes;
            var after = code.Annotations(native).ChangeUserTypes(layer => record(result, layer) ?? layer);
            if (!ReferenceEquals(before, after) && after.Stamp != state.Stamp)
            {
                await session.ApplyUserTypesAsync(NativeUserTypeBatch.Empty, StampKey, after.Stamp, cancellationToken: ct).ConfigureAwait(false);
                state.Stamp = after.Stamp;
            }
            return result;
        }
        finally { state.Gate.Release(); }
    }

    /// <summary>Drops what is known of the session's user types (the database's types were replaced): the next call pushes the layer.</summary>
    public static void Forget(INativeDecompilerSession session) => States.Remove(session);

    /// <summary>Marks the session's database as changed by an engine script, so cached engine output is made again.</summary>
    public static void Touch(INativeDecompilerSession session) => Interlocked.Increment(ref States.GetValue(session, _ => new State()).Scripts);

    /// <summary>Identity of the session's user types for output caches, or "" before any push.</summary>
    public static string CurrentStamp(INativeDecompilerSession session) =>
        States.TryGetValue(session, out var s) ? $"{s.Stamp}+{Volatile.Read(ref s.Scripts)}" : "";

    /// <summary>One line describing a push for tool output, or null when nothing was pushed.</summary>
    public static string? Describe(PushResult? r) => r switch
    {
        null => null,
        { AlreadyInDatabase: true } => "user types: the database already has them",
        { Totals: { } t } => $"user types: pushed {r.Items} item(s) in {t.Elapsed.TotalSeconds:0.0} s" +
                             (t.Items.Count(i => !i.Applied) is > 0 and var failed ? $"; {failed} not applied, e.g. {string.Join("; ", t.Items.Where(i => !i.Applied).Take(3).Select(i => $"{i.Kind} {i.Target}: {i.Error}"))}" : "") +
                             (t.DeclarationErrors > 0 ? $"; {t.DeclarationErrors} declaration error(s)" : ""),
        _ => null,
    };
}
