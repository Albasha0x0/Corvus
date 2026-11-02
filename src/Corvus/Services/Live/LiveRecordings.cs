using System.Text;
using System.Text.Json;

namespace Corvus.Services;

/// <summary>
/// The header of a kept session: what a restart needs to name it and to
/// start another on the same target. <c>Unkept</c> counts events past the
/// per-session cap, <c>Ended</c> is the end reason (null while open) and
/// <c>Start</c> is the call that starts a new session on the same target.
/// </summary>
public sealed record LiveSavedHeader(string Id, string Backend, string Program, bool Spawned, int ProcessId, DateTime Opened, DateTime Saved,
    string State, string? Ended, string Start, long Unkept);

/// <summary>
/// A session of an earlier server as it was kept: its header and its events,
/// read-only.
/// </summary>
public sealed class LiveSavedSession(LiveSavedHeader header, IReadOnlyList<LiveRingEvent> events)
{
    /// <summary>The kept header.</summary>
    public LiveSavedHeader Header { get; } = header;
    /// <summary>The session id.</summary>
    public string Id => Header.Id;
    /// <summary>The kept events in sequence order; empty when none were kept.</summary>
    public IReadOnlyList<LiveRingEvent> Events { get; } = events;

    /// <summary>Whether a watch or script of this id recorded an event.</summary>
    public bool Issued(string id) => Events.Any(e => string.Equals(e.Source, id, StringComparison.Ordinal));

    /// <summary>
    /// Filtered events from sequence <paramref name="from"/> on, as
    /// <c>LiveSession.Page</c> returns them.
    /// </summary>
    internal (IReadOnlyList<LiveRingEvent> Events, LiveRingGaps Gaps, long Last, bool More) Page(long from, string? kind, long? thread, int limit, string? source = null)
    {
        var rows = Events.Where(e => e.Sequence >= from && (kind == null || e.Kind == kind) && (thread == null || e.Thread == thread)
                                     && (source == null || e.Source == source)).Take(limit + 1).ToList();
        var more = rows.Count > limit;
        if (more) rows.RemoveAt(limit);
        return (rows, new LiveRingGaps([], []), Events.Count > 0 ? Events[^1].Sequence : 0, more);
    }
}

/// <summary>
/// Keeps what a server's sessions and runs record under one folder per
/// server start, and reads the folders of earlier starts back. A write that
/// fails loses that record only; a read of a damaged file finds nothing.
/// </summary>
internal sealed class LiveRecordings(Func<string> folder) : IDisposable
{
    /// <summary>Server folders kept; older ones are removed at the first write.</summary>
    public const int KeptServers = 20;
    /// <summary>
    /// Bytes of events one session keeps; later events are counted in the
    /// header.
    /// </summary>
    public const long MaxEventBytes = 64L << 20;
    private static readonly TimeSpan SaveEvery = TimeSpan.FromSeconds(15);
    private static int _starts;
    private readonly string _stamp = $"{DateTime.UtcNow:yyyyMMddHHmmssfff}-{Environment.ProcessId}-{Interlocked.Increment(ref _starts):D4}";
    private readonly object _gate = new();
    private readonly List<KeptRun> _tracked = [];
    private string? _own;
    private Timer? _timer;
    private bool _disposed;

    private string Own()
    {
        lock (_gate)
        {
            if (_own != null) return _own;
            var root = folder();
            Directory.CreateDirectory(root);
            var old = Directory.EnumerateDirectories(root).Select(Path.GetFileName).Order(StringComparer.Ordinal).ToList();
            // Leave room for the folder created below, so the count stays at the cap.
            foreach (var gone in old.Take(Math.Max(0, old.Count - (KeptServers - 1))))
                try { Directory.Delete(Path.Combine(root, gone!), recursive: true); }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
            _own = Path.Combine(root, _stamp);
            Directory.CreateDirectory(_own);
            _timer = new Timer(_ => SaveAll(), null, SaveEvery, SaveEvery);
            return _own;
        }
    }

    /// <summary>
    /// Keeps <paramref name="snapshot"/> as <c>folder/name.json</c>, written now
    /// and again until sealed; the periodic write is skipped while
    /// <paramref name="version"/> is unchanged.
    /// </summary>
    internal KeptRun Keep(string subfolder, string name, Func<object> snapshot, Func<long>? version = null)
    {
        var run = new KeptRun(this, subfolder, name, snapshot, version);
        lock (_gate)
            if (!_disposed) _tracked.Add(run);
        run.Save();
        return run;
    }

    /// <summary>Opens the event file of a session and keeps its header.</summary>
    internal LiveEventLog OpenEvents(string session, Func<long, object> header) => new(this, session, header);

    internal string PathOf(string subfolder, string file)
    {
        var dir = Path.Combine(Own(), subfolder);
        Directory.CreateDirectory(dir);
        return Path.Combine(dir, file);
    }

    internal void Untrack(KeptRun run)
    {
        lock (_gate) _tracked.Remove(run);
    }

    private void SaveAll()
    {
        KeptRun[] runs;
        lock (_gate) runs = [.. _tracked];
        foreach (var run in runs) run.Save(onlyIfChanged: true);
    }

    /// <summary>Writes every tracked record again and stops saving.</summary>
    public void Dispose()
    {
        KeptRun[] runs;
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            runs = [.. _tracked];
            _tracked.Clear();
            _timer?.Dispose();
        }
        foreach (var run in runs) run.Save();
    }

    /// <summary>The folders of earlier server starts, newest first.</summary>
    private IEnumerable<string> Earlier()
    {
        string root;
        try { root = folder(); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { yield break; }
        if (!Directory.Exists(root)) yield break;
        foreach (var dir in Directory.EnumerateDirectories(root).OrderByDescending(d => Path.GetFileName(d), StringComparer.Ordinal))
            if (!string.Equals(Path.GetFileName(dir), _stamp, StringComparison.Ordinal)) yield return dir;
    }

    /// <summary>
    /// The session of an earlier start with this id, newest first; null when
    /// none was kept or the file is damaged.
    /// </summary>
    internal LiveSavedSession? ReadSession(string id)
    {
        foreach (var dir in Earlier())
        {
            var header = Path.Combine(dir, id, "session.json");
            if (!File.Exists(header)) continue;
            try
            {
                var head = JsonSerializer.Deserialize<LiveSavedHeader>(File.ReadAllText(header, Encoding.UTF8));
                if (head?.Id == null) continue;
                var events = new List<LiveRingEvent>();
                var file = Path.Combine(dir, id, "events.jsonl");
                if (File.Exists(file))
                {
                    // The server that wrote the file may still hold it open.
                    using var reader = new StreamReader(new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite), Encoding.UTF8);
                    while (reader.ReadLine() is { } line)
                        // A line cut by a kill is the last; the events before it stand.
                        try { events.Add(JsonSerializer.Deserialize<LiveRingEvent>(line) ?? throw new JsonException()); }
                        catch (JsonException) { break; }
                }
                return new LiveSavedSession(head, events);
            }
            catch (Exception e) when (e is IOException or JsonException or UnauthorizedAccessException) { }
        }
        return null;
    }

    /// <summary>
    /// The run of an earlier start with this id, newest first; null when none
    /// was kept or the file is damaged.
    /// </summary>
    internal T? ReadRun<T>(string id) where T : class
    {
        foreach (var file in RunFiles(id)) if (Read<T>(file) is { } run) return run;
        return null;
    }

    /// <summary>
    /// The runs whose ids start with <paramref name="prefix"/>, newest start
    /// first; an id kept more than once appears once.
    /// </summary>
    internal IReadOnlyList<T> ReadRuns<T>(string prefix, Func<T, string> id) where T : class
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var runs = new List<T>();
        foreach (var file in RunFiles(prefix + "*"))
            if (Read<T>(file) is { } run && id(run) is { } key && seen.Add(key)) runs.Add(run);
        return runs;
    }

    private IEnumerable<string> RunFiles(string pattern)
    {
        foreach (var dir in Earlier())
            foreach (var sub in Directory.EnumerateDirectories(dir))
                foreach (var file in Directory.EnumerateFiles(sub, pattern + ".json").Order(StringComparer.Ordinal))
                    yield return file;
    }

    private static T? Read<T>(string file) where T : class
    {
        try { return JsonSerializer.Deserialize<T>(File.ReadAllText(file, Encoding.UTF8)); }
        catch (Exception e) when (e is IOException or JsonException or UnauthorizedAccessException) { return null; }
    }

    /// <summary>
    /// The highest N among the ids <c>prefix-N</c> that earlier starts kept,
    /// as a session folder or a run file; 0 when none.
    /// </summary>
    internal int HighestId(string prefix)
    {
        var highest = 0;
        void Note(string name)
        {
            if (name.StartsWith(prefix + "-", StringComparison.OrdinalIgnoreCase)
                && int.TryParse(name[(prefix.Length + 1)..], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var n))
                highest = Math.Max(highest, n);
        }
        try
        {
            foreach (var dir in Earlier())
                foreach (var sub in Directory.EnumerateDirectories(dir))
                {
                    Note(Path.GetFileName(sub));
                    foreach (var file in Directory.EnumerateFiles(sub, prefix + "-*.json")) Note(Path.GetFileNameWithoutExtension(file));
                }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
        return highest;
    }

    /// <summary>One record kept as a JSON file, replaced whole on each save.</summary>
    internal sealed class KeptRun(LiveRecordings owner, string subfolder, string name, Func<object> snapshot, Func<long>? version)
    {
        private readonly object _write = new();
        private long _saved = -1;

        /// <summary>Writes the record now, or only when its version moved.</summary>
        public void Save(bool onlyIfChanged = false)
        {
            lock (_write)
                try
                {
                    var now = version?.Invoke() ?? -1;
                    if (onlyIfChanged && version != null && now == _saved) return;
                    _saved = now;
                    var path = owner.PathOf(subfolder, name + ".json");
                    File.WriteAllText(path + ".tmp", JsonSerializer.Serialize(snapshot()), Encoding.UTF8);
                    File.Move(path + ".tmp", path, overwrite: true);
                }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
        }

        /// <summary>Writes the record a last time and stops saving it.</summary>
        public void Seal()
        {
            owner.Untrack(this);
            Save();
        }
    }
}

/// <summary>
/// The events of one session appended to a file as they occur, and the
/// session's header beside it.
/// </summary>
internal sealed class LiveEventLog : IDisposable
{
    private readonly object _gate = new();
    private readonly LiveRecordings.KeptRun _header;
    private StreamWriter? _writer;
    private long _bytes;
    private long _unkept;
    private bool _failed;

    internal LiveEventLog(LiveRecordings owner, string session, Func<long, object> header)
    {
        try { _writer = new StreamWriter(new FileStream(owner.PathOf(session, "events.jsonl"), FileMode.Create, FileAccess.Write, FileShare.Read), new UTF8Encoding(false)); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { _failed = true; }
        // Build the header outside the gate: it takes the session's lock,
        // which is held while Append takes this gate.
        _header = owner.Keep(session, "session", () =>
        {
            long unkept;
            lock (_gate) { Flush(); unkept = _unkept; }
            return header(unkept);
        });
    }

    /// <summary>
    /// Appends one event; past <see cref="LiveRecordings.MaxEventBytes"/> it
    /// is counted, not kept.
    /// </summary>
    public void Append(LiveRingEvent e)
    {
        lock (_gate)
        {
            if (_writer == null || _failed) return;
            if (_bytes >= LiveRecordings.MaxEventBytes) { _unkept++; return; }
            var line = JsonSerializer.Serialize(e);
            try { _writer.WriteLine(line); }
            catch (IOException) { _failed = true; return; }
            _bytes += Encoding.UTF8.GetByteCount(line) + 1;
        }
    }

    private void Flush()
    {
        try { _writer?.Flush(); }
        catch (IOException) { _failed = true; }
    }

    /// <summary>Writes the events and the header now.</summary>
    public void Save() => _header.Save();

    /// <summary>
    /// Writes the events and the header a last time and closes the file.
    /// </summary>
    public void Dispose()
    {
        _header.Seal();
        lock (_gate)
        {
            _writer?.Dispose();
            _writer = null;
        }
    }
}
