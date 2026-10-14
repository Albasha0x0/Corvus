using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Text.Json.Nodes;
using Corvus.Core;
using Corvus.Native.Annotations;
using Corvus.Native.Patching;

namespace Corvus.Services;

/// <summary>
/// Crash safety for unsaved work: after every change, each assembly's edits are written as an edit script (the
/// export_edits format, which apply_edits reads) and each native image's patches as a json patch set (which
/// migrate_native_patches reads) to &lt;annotations&gt;/journal/&lt;sha256&gt;.&lt;session&gt;.&lt;id&gt;.{edits,patches}.json.
/// One file per server process and target, so processes never contend. A journal is removed when its work is saved,
/// reverted, unloaded or replayed; loading a file with a journal left by a process that is gone offers the replay.
/// </summary>
public sealed class EditJournal
{
    public const string EditsSuffix = ".edits.json", PatchesSuffix = ".patches.json";
    public static readonly TimeSpan MaxAge = TimeSpan.FromDays(30);

    private readonly AssemblyWorkspace _workspace;
    private readonly EditHistoryService _history;
    private readonly object _gate = new();
    // Per target: the version last journaled (-1: none written) and the version last saved.
    private readonly ConditionalWeakTable<object, State> _states = new();
    private readonly Dictionary<string, object> _files = new(StringComparer.OrdinalIgnoreCase);
    private string? _lastProblem;

    private sealed class State
    {
        public int Journaled = -1;
        public int Saved = -1;
        public string? File;
    }

    public EditJournal(AssemblyWorkspace workspace, AnnotationStore store, EditHistoryService history)
    {
        _workspace = workspace;
        _history = history;
        Root = Path.Combine(store.Root, "journal");
        Prune();
        workspace.AssembliesLoaded += loaded => { foreach (var a in loaded) Offer(a.Id, a.OriginalSha256); };
        workspace.NativeLoaded += native => Offer(native.Id, native.OriginalSha256);
    }

    public string Root { get; }

    /// <summary>This process's journal name part.</summary>
    public string Session { get; } = Guid.NewGuid().ToString("N")[..12];

    private static readonly long StartTicks = Process.GetCurrentProcess().StartTime.ToUniversalTime().Ticks;

    private void Prune()
    {
        try
        {
            if (!Directory.Exists(Root)) return;
            foreach (var file in Directory.EnumerateFiles(Root, "*.json"))
                if (DateTime.UtcNow - File.GetLastWriteTimeUtc(file) > MaxAge) File.Delete(file);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }

    private static string Safe(string id) => string.Concat(id.Select(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '-' ? c : '_'));

    private string FileFor(string sha256, string id, string suffix) => Path.Combine(Root, $"{sha256.ToLowerInvariant()}.{Session}.{Safe(id)}{suffix}");

    /// <summary>Writes or removes the journal of every loaded target whose edits changed since the last call; never throws.</summary>
    /// <remarks>
    /// The shared lock is taken before the gate, as by <see cref="Saved"/>, which runs under it: the other order deadlocked
    /// with a save waiting for the gate while a queued writer kept the gate holder out of the shared lock.
    /// </remarks>
    public void Sync()
    {
        try
        {
            _workspace.Read(() =>
            {
                using (AssemblyWorkspace.Lock(_gate)) SyncLocked();
                return 0;
            });
        }
        catch (OperationCanceledException) { } // the call was cancelled while waiting: the next change journals it
    }

    private void SyncLocked()
    {
        List<(object Target, int Version, string File, byte[]? Content)> pending = [];
        HashSet<object> live = [];
        foreach (var asm in _workspace.Assemblies)
        {
            live.Add(asm);
            var state = _states.GetValue(asm, _ => new State());
            int version = asm.IsDirty && asm.Version != state.Saved ? asm.Version : -1;
            if (version == state.Journaled) continue;
            var file = state.File ??= FileFor(asm.OriginalSha256, asm.Id, EditsSuffix);
            byte[]? content = version < 0 ? null : Envelope(JsonNode.Parse(EditHistoryService.Serialize(_history.BuildScript(asm)))!);
            pending.Add((asm, version, file, content));
        }
        foreach (var native in _workspace.Natives)
        {
            live.Add(native);
            var state = _states.GetValue(native, _ => new State());
            int version = native.HasPatches && native.Patches.Version != state.Saved ? native.Patches.Version : -1;
            if (version == state.Journaled) continue;
            var file = state.File ??= FileFor(native.OriginalSha256, native.Id, PatchesSuffix);
            byte[]? content;
            // a patch set that cannot be rendered is not journaled; the tool call that made it must not fail for that
            try { content = version < 0 ? null : Envelope(JsonNode.Parse(NativeEditService.RenderPatches(native, PatchExport.Format.Json).Content)!); }
            catch (ToolError ex)
            {
                if (_lastProblem != ex.Message) _workspace.Notify($"The edit journal could not be written ({ex.Message}); unsaved edits are not crash-safe until it can.");
                _lastProblem = ex.Message;
                continue;
            }
            pending.Add((native, version, file, content));
        }
        // Targets unloaded or reloaded since: their edits were discarded deliberately.
        foreach (var (file, target) in _files.ToList())
            if (!live.Contains(target))
            {
                Delete(file);
                _files.Remove(file);
            }
        foreach (var (target, version, file, content) in pending)
        {
            try
            {
                if (content is { } bytes)
                {
                    Directory.CreateDirectory(Root);
                    SafeFile.WriteAllBytes(file, bytes, overwrite: true);
                    _files[file] = target;
                }
                else
                {
                    Delete(file);
                    _files.Remove(file);
                }
                _states.GetValue(target, _ => new State()).Journaled = version;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ToolError)
            {
                if (_lastProblem != ex.Message) _workspace.Notify($"The edit journal could not be written ({ex.Message}); unsaved edits are not crash-safe until it can.");
                _lastProblem = ex.Message;
            }
        }
    }

    /// <summary>The work of <paramref name="target"/> (an assembly or native image) was saved: its journal goes until it changes again.</summary>
    public void Saved(object target)
    {
        lock (_gate)
        {
            var state = _states.GetValue(target, _ => new State());
            state.Saved = target switch
            {
                LoadedAssembly asm => asm.Version,
                LoadedNative native => native.Patches.Version,
                _ => -1,
            };
        }
        Sync();
    }

    /// <summary>A journal replayed with apply_edits or migrate_native_patches is not offered again.</summary>
    public void Replayed(string path)
    {
        try
        {
            var full = Path.GetFullPath(path.Trim());
            if (Path.GetDirectoryName(full) is { } dir && string.Equals(dir.TrimEnd(Path.DirectorySeparatorChar), Root.TrimEnd(Path.DirectorySeparatorChar),
                    OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal)
                && !Path.GetFileName(full).Contains($".{Session}.", StringComparison.Ordinal))
                Delete(full);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException) { }
    }

    private static void Delete(string file)
    {
        try { File.Delete(file); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }

    private static readonly JsonSerializerOptions Indented = new() { WriteIndented = true };

    /// <summary>Who wrote a journal, so a live process's journal is not offered as lost work.</summary>
    private byte[] Envelope(JsonNode document)
    {
        document["journal"] = new JsonObject
        {
            ["session"] = Session,
            ["pid"] = Environment.ProcessId,
            ["processStart"] = StartTicks,
            ["written"] = DateTime.UtcNow,
        };
        return JsonSerializer.SerializeToUtf8Bytes(document, Indented);
    }

    /// <summary>A journal left by another server process, with what it holds.</summary>
    public sealed record Entry(string Path, string Kind, int Count, DateTime Written, bool Live);

    /// <summary>The journals of <paramref name="sha256"/> that other server processes wrote.</summary>
    public IReadOnlyList<Entry> Others(string sha256)
    {
        var result = new List<Entry>();
        try
        {
            if (!Directory.Exists(Root)) return result;
            foreach (var file in Directory.EnumerateFiles(Root, sha256.ToLowerInvariant() + ".*.json"))
            {
                if (Path.GetFileName(file).Contains($".{Session}.", StringComparison.Ordinal)) continue;
                try
                {
                    using var doc = JsonDocument.Parse(File.ReadAllBytes(file));
                    var root = doc.RootElement;
                    bool edits = file.EndsWith(EditsSuffix, StringComparison.OrdinalIgnoreCase);
                    int count = root.TryGetProperty(edits ? "edits" : "patches", out var list) && list.ValueKind == JsonValueKind.Array ? list.GetArrayLength() : 0;
                    bool live = false;
                    var written = File.GetLastWriteTimeUtc(file);
                    if (root.TryGetProperty("journal", out var j))
                    {
                        if (j.TryGetProperty("written", out var w) && w.TryGetDateTime(out var at)) written = at;
                        live = j.TryGetProperty("pid", out var pid) && j.TryGetProperty("processStart", out var start) && Alive(pid.GetInt32(), start.GetInt64());
                    }
                    if (count > 0) result.Add(new Entry(file, edits ? "edits" : "patches", count, written, live));
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or InvalidOperationException or FormatException) { }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        return result;
    }

    private static bool Alive(int pid, long startTicks)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            return p.StartTime.ToUniversalTime().Ticks == startTicks;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception or NotSupportedException) { return false; }
    }

    private void Offer(string id, string sha256)
    {
        // The newest abandoned session per kind is offered in full; older ones only counted, so the notice stays one line each.
        foreach (var kind in Others(sha256).Where(e => !e.Live).GroupBy(e => e.Kind))
        {
            var all = kind.OrderByDescending(e => e.Written).ToList();
            var e = all[0];
            string older = all.Count > 1 ? $" {all.Count - 1} older unsaved session(s) are kept in {Root}." : "";
            _workspace.Notify(e.Kind == "edits"
                ? $"{id}: {e.Count} unsaved edit(s) from a session that ended at {e.Written:yyyy-MM-dd HH:mm} UTC without saving; replay with apply_edits path=\"{e.Path}\" assembly={id} (dryRun=true first).{older}"
                : $"{id}: {e.Count} unsaved patch(es) from a session that ended at {e.Written:yyyy-MM-dd HH:mm} UTC without saving; replay with migrate_native_patches " +
                  $"oldImage={id} newImage={id} patchSet=\"{e.Path}\" (dryRun=true first).{older}");
        }
    }
}
