using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Corvus.Core;
using Corvus.Native.Providers.Live.Inspector;
using Corvus.Services.Web;

namespace Corvus.Services;

/// <summary>
/// A script a V8 inspector reported: id, url, the local file a file: url names, and its source map once read (null with
/// <see cref="MapNote"/> saying why when the script names one that could not be read).
/// </summary>
public sealed class LiveScriptState(string id, string url, string? mapUrl)
{
    public string Id { get; } = id;
    public string Url { get; } = url;
    public string? MapUrl { get; } = mapUrl;
    public string? File { get; } = Uri.TryCreate(url, UriKind.Absolute, out var u) && u.IsFile ? u.LocalPath : null;
    public SourceMap? Map { get; internal set; }
    public string? MapNote { get; internal set; }
    internal bool MapRead { get; set; }
    /// <summary>The url's last segment, or the url when it has none.</summary>
    public string Name => Url.TrimEnd('/') is var t && t.LastIndexOfAny(['/', '\\']) is var i and >= 0 ? t[(i + 1)..] : Url;
}

/// <summary>
/// The script side of a session on a managed runtime's debugger (a V8 inspector or a JVM's JDWP agent): the target, the
/// runtime it reports, the scripts or classes by id and, for a JVM, its threads as last read.
/// </summary>
public sealed class LiveScriptRuntime(string kind)
{
    /// <summary>"V8 inspector" or "JVM".</summary>
    public string Kind { get; } = kind;
    public bool Jvm => Kind == "JVM";
    public string Target { get; internal set; } = "";
    public string? Runtime { get; internal set; }
    public Dictionary<string, LiveScriptState> Scripts { get; } = new(StringComparer.Ordinal);
    public IReadOnlyList<LiveJvmThread> Threads { get; internal set; } = [];
    // The app's static IPC rows, read once per app path.
    internal (string? App, IReadOnlyList<Analysis.ElectronRow> Rows)? IpcCode { get; set; }
}

/// <summary>A JVM thread: id, name, state, whether a stop point holds it, its stack depth and its first frames.</summary>
public sealed record LiveJvmThread(long Id, string Name, string Status, bool Held, int Depth, IReadOnlyList<LiveScriptFrame> Frames);

/// <summary>
/// A paused script or JVM frame: function, script id and name, generated position (1-based line and column; 0 when
/// unknown or, for a JVM, not reported) and the original position its map gives, if any.
/// </summary>
public sealed record LiveScriptFrame(string Function, string ScriptId, string Script, int Line, int Column, string? Original)
{
    /// <summary>SCRIPT:LINE:COLUMN, leaving out the parts that are 0.</summary>
    public string Position => $"{Script}{(Line > 0 ? $":{Line}" : "")}{(Column > 0 ? $":{Column}" : "")}";
    public string Display => $"{(Function.Length > 0 ? Function : "(anonymous)")} {Position}{(Original != null ? $" = {Original}" : "")}";
}

public sealed partial class LiveSessionService
{
    /// <summary>Refuses <paramref name="what"/> on a script session, which has no native code to resolve; returns otherwise.</summary>
    internal static void NativeOnly(LiveSession session, string what)
    {
        if (session.ScriptRuntime is { } runtime)
            throw new ToolError(ErrorCode.Unsupported, $"{what} works on native code; {session.Id} is a {runtime.Kind} session with {(runtime.Jvm ? "classes" : "scripts")} only.",
                runtime.Jvm ? "live_break at=File.java:LINE stops in a class; live_session action=status lists threads and stacks"
                    : "live_break at=FILE:LINE stops in a script; live_events kind=output shows console output");
    }

    // Scripts the runtime itself loads (node:internal/..., extensions) are never a program's own.
    private static bool OwnScript(LiveScriptState s) => s.Url.Length > 0 && !s.Url.StartsWith("node:", StringComparison.Ordinal) && !s.Url.StartsWith("chrome-extension:", StringComparison.Ordinal);

    // A V8 inspector or a JVM's JDWP agent, each served by its own worker over the same protocol.
    private async Task<LiveSession> OpenScriptRuntimeAsync(string program, CancellationToken ct)
    {
        var jvm = Native.Providers.Live.Jdwp.JdwpWorker.Is(program);
        Native.Providers.Live.ILiveBackend backend = jvm ? new Native.Providers.Live.Jdwp.JdwpBackend() : new InspectorBackend();
        var worker = backend.Start();
        var session = new LiveSession("live-" + Interlocked.Increment(ref _next), backend.Name, program.Trim(), false, worker) { ScriptRuntime = new(jvm ? "JVM" : "V8 inspector") };
        worker.EventReceived += e => OnEvent(session, e);
        try
        {
            await worker.WaitReadyAsync(StartTimeout, ct).ConfigureAwait(false);
            await worker.RequestAsync("hello", null, StartTimeout, ct).ConfigureAwait(false);
            var info = await worker.RequestAsync("open", new JsonObject { [jvm ? "jdwp" : "inspector"] = program.Trim() }, RequestTimeout, ct).ConfigureAwait(false);
            session.ProcessId = info.GetProperty("pid").GetInt32();
            session.Arch = info.GetProperty("arch").GetString() ?? "";
            session.Platform = info.GetProperty("platform").GetString() ?? "";
            session.Suspended = info.GetProperty("suspended").GetBoolean();
            var target = info.GetProperty("target");
            session.ScriptRuntime!.Target = jvm ? target.GetProperty("id").GetString() ?? ""
                : $"{target.GetProperty("type").GetString()} \"{target.GetProperty("title").GetString()}\" {target.GetProperty("url").GetString()}".Trim();
            session.ScriptRuntime.Runtime = info.GetProperty("runtime").GetString();
            await RefreshScriptsAsync(session, ct).ConfigureAwait(false);
        }
        catch
        {
            worker.Kill("open failed");
            worker.Dispose();
            throw;
        }
        Track(session);
        return session;
    }

    // Maps read by one status: a program's own scripts rarely name more.
    private const int MapsPerRefresh = 200;

    /// <summary>Reads the script list again; scripts already known keep their maps. <paramref name="readMaps"/>: also read the maps the program's own scripts name.</summary>
    internal async Task RefreshScriptsAsync(LiveSession session, CancellationToken ct, bool readMaps = false)
    {
        var list = await session.Worker.RequestAsync("scripts", null, RequestTimeout, ct).ConfigureAwait(false);
        var js = session.ScriptRuntime!;
        lock (js.Scripts)
            foreach (var s in list.EnumerateArray())
            {
                var id = s.GetProperty("id").GetString()!;
                if (!js.Scripts.ContainsKey(id))
                    js.Scripts[id] = new LiveScriptState(id, s.GetProperty("url").GetString() ?? "", s.TryGetProperty("map", out var m) ? m.GetString() : null);
            }
        if (js.Jvm && readMaps) await ReadThreadsAsync(session, ct).ConfigureAwait(false);
        if (!readMaps || js.Jvm) return;
        List<LiveScriptState> unread;
        lock (js.Scripts) unread = [.. js.Scripts.Values.Where(s => OwnScript(s) && s.MapUrl != null && !s.MapRead).Take(MapsPerRefresh)];
        foreach (var script in unread) await MapOfAsync(session, script, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// The map a script names, read once from the source the runtime holds (inline data: URLs, or a path relative to its
    /// file); null when it names none, or with <see cref="LiveScriptState.MapNote"/> when the map could not be read.
    /// </summary>
    private async Task<SourceMap?> MapOfAsync(LiveSession session, LiveScriptState script, CancellationToken ct)
    {
        if (script.MapRead || script.MapUrl == null) return script.Map;
        script.MapRead = true;
        if (!script.MapUrl.StartsWith("data:", StringComparison.Ordinal) && script.File == null)
        {
            script.MapNote = $"map {script.MapUrl} is relative to {script.Url}, which is not a file: not read";
            return null;
        }
        if (script.MapUrl.Contains("://", StringComparison.Ordinal))
        {
            script.MapNote = $"map {script.MapUrl} is remote: not fetched";
            return null;
        }
        try
        {
            var source = await session.Worker.RequestAsync("source", new JsonObject { ["script"] = script.Id }, RequestTimeout, ct).ConfigureAwait(false);
            var text = Encoding.UTF8.GetBytes(source.GetProperty("text").GetString() ?? "");
            script.Map = SourceMap.Locate(script.File ?? "", text)?.Map;
            if (script.Map == null) script.MapNote = $"map {script.MapUrl} not found";
        }
        catch (Exception e) when (e is ToolError or IOException or UnauthorizedAccessException or FormatException) { script.MapNote = $"map {script.MapUrl}: {e.Message}"; }
        return script.Map;
    }

    private static readonly Regex ScriptFileLine = new(@"^(?<file>.+?):(?<line>\d+)(?::(?<column>\d+))?$", RegexOptions.CultureInvariant);

    /// <summary>
    /// A stop point at FILE:LINE[:COLUMN] (1-based): an original source a loaded script's map names, mapped to its first
    /// generated position on that line or the next mapped one; else a loaded script whose url ends with FILE; else any
    /// script whose url ends with FILE once it is parsed (generated lines, as no map is known yet).
    /// </summary>
    private async Task<LiveStopPointState> SetScriptAsync(LiveSession session, string where, CancellationToken ct, string? id)
    {
        Live(session);
        var m = ScriptFileLine.Match(where.Trim());
        if (!m.Success || !int.TryParse(m.Groups["line"].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var line) || line < 1)
            throw new ToolError(ErrorCode.InvalidArgument, $"'{where}': a script session sets stop points at FILE:LINE.", "at=src/app.ts:12 (an original source) or at=app.js:40:7");
        int? column = m.Groups["column"].Success ? int.Parse(m.Groups["column"].Value, CultureInfo.InvariantCulture) - 1 : null;
        var file = m.Groups["file"].Value.Replace('\\', '/');
        await RefreshScriptsAsync(session, ct).ConfigureAwait(false);
        List<LiveScriptState> scripts;
        lock (session.ScriptRuntime!.Scripts) scripts = [.. session.ScriptRuntime.Scripts.Values.Where(OwnScript)];
        id ??= session.NextPointId();
        JsonObject args;
        string described;
        // Said when the worker resolves no location now.
        string? noCode = null;
        var mapped = await MappedAsync(session, scripts, file, line - 1, ct).ConfigureAwait(false);
        if (mapped is var (script, seg, original))
        {
            args = new JsonObject { ["url"] = script.Url, ["line"] = seg.Line, ["column"] = seg.Column };
            noCode = "; no code at that position yet";
            described = $"{script.Name}:{seg.Line + 1}:{seg.Column + 1} from {original}" + (seg.OriginalLine + 1 != line ? $" (line {line} has no code; the next line with code)" : "");
        }
        else
        {
            // One point covers every script whose url ends in FILE, loaded now or parsed later.
            var plain = scripts.Where(s => Ends(s.Url, file)).ToList();
            args = new JsonObject { ["urlRegex"] = "(^|[/\\\\])" + Regex.Escape(file.TrimStart('.', '/')) + "$", ["line"] = line - 1 };
            if (column is { } c) args["column"] = c;
            var jvm = session.ScriptRuntime!.Jvm;
            described = plain.Count == 0
                ? jvm ? $"any class from {file}, line {line}, once loaded" : $"any script ending in {file}, line {line}, once parsed (generated lines: no loaded script maps {file})"
                : jvm ? $"{file}:{line} in {plain.Count} loaded class(es) from {file}"
                : $"{file}:{line} in {plain.Count} loaded script(s) ending in {file} (generated line{(plain.Any(p => p.MapUrl != null) ? "; no map names such a source" : "")})";
            if (jvm && plain.Count > 0) noCode = $"; no code at line {line} in them";
        }
        args["id"] = id;
        var r = await session.Worker.RequestAsync("set", args, RequestTimeout, ct).ConfigureAwait(false);
        var locations = r.GetProperty("locations").GetArrayLength();
        var point = new LiveStopPointState(id, where.Trim(), 0, new LiveFrameName(0, null, null, 0, null, 0, null, null))
        {
            Script = described + (locations == 0 ? noCode : null),
        };
        lock (session.StopPoints) session.StopPoints[id] = point;
        return point;
    }

    // The first loaded script whose map names a source ending in file, with the generated segment for line (0-based).
    private async Task<(LiveScriptState Script, MapSegment Segment, string Original)?> MappedAsync(LiveSession session, List<LiveScriptState> scripts, string file, int line, CancellationToken ct)
    {
        foreach (var script in scripts.Where(s => s.MapUrl != null))
        {
            if (await MapOfAsync(session, script, ct).ConfigureAwait(false) is not { } map) continue;
            for (int i = 0; i < map.Sources.Count; i++)
                if (Ends(map.Sources[i], file) && map.Generated(i, line) is var (at, segments))
                {
                    var first = segments.OrderBy(s => s.Line).ThenBy(s => s.Column).First();
                    return (script, first, $"{map.Sources[i]}:{at + 1}");
                }
        }
        return null;
    }

    // A source or url ends with the path segments of file (either as given or file ends with it, for an absolute path).
    private static bool Ends(string path, string file)
    {
        var p = path.Replace('\\', '/');
        var f = file.TrimStart('.', '/');
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        return p.Equals(f, comparison) || p.EndsWith("/" + f, comparison) || (p.Length > 0 && f.EndsWith("/" + p.TrimStart('/'), comparison));
    }

    /// <summary>The held stop's frames, each script's map read first so every mapped frame names its original position.</summary>
    public async Task<IReadOnlyList<LiveScriptFrame>> ScriptFramesAsync(LiveSession session, LiveHeldStop held, CancellationToken ct)
    {
        var frames = held.ScriptFrames ?? [];
        var named = new List<LiveScriptFrame>(frames.Count);
        foreach (var f in frames)
        {
            LiveScriptState? script;
            lock (session.ScriptRuntime!.Scripts) session.ScriptRuntime.Scripts.TryGetValue(f.ScriptId, out script);
            var map = f.Original == null && script != null && session.Ended == null ? await MapOfAsync(session, script, ct).ConfigureAwait(false) : null;
            named.Add(map != null ? f with { Original = Original(map, f.Line - 1, f.Column - 1) } : f);
        }
        return named;
    }

    private static string? Original(SourceMap map, int line, int column) =>
        map.Find(line, column) is { Source: >= 0 } seg && seg.Source < map.Sources.Count
            ? $"{map.Sources[seg.Source]}:{seg.OriginalLine + 1}:{seg.OriginalColumn + 1}" + (seg.Name >= 0 && seg.Name < map.Names.Count ? $" ({map.Names[seg.Name]})" : "")
            : null;

    // A worker's frames (0-based positions; a JVM frame names its source file and has no column) by script and original position.
    private static List<LiveScriptFrame> Frames(LiveScriptRuntime js, JsonElement list)
    {
        var frames = new List<LiveScriptFrame>();
        foreach (var f in list.EnumerateArray())
        {
            var scriptId = f.GetProperty("script").GetString() ?? "";
            int line = f.GetProperty("line").GetInt32(), column = f.TryGetProperty("column", out var c) ? c.GetInt32() : -1;
            LiveScriptState? script;
            lock (js.Scripts) js.Scripts.TryGetValue(scriptId, out script);
            var url = f.GetProperty("url").GetString() ?? "";
            var name = f.TryGetProperty("name", out var n) ? n.GetString() : null;
            // Maps already read name the frame here; ScriptFramesAsync reads the others, off the event thread.
            frames.Add(new LiveScriptFrame(f.GetProperty("function").GetString() ?? "", scriptId, name ?? script?.Name ?? (url.Length > 0 ? url : "script " + scriptId), line + 1, column + 1,
                script?.Map is { } map ? Original(map, line, column) : null));
        }
        return frames;
    }

    // A JVM's threads with their stacks, read with the JVM suspended for the read only.
    private async Task ReadThreadsAsync(LiveSession session, CancellationToken ct)
    {
        if (session.Closed || session.Ended != null) return;
        var list = await session.Worker.RequestAsync("threads", null, RequestTimeout, ct).ConfigureAwait(false);
        var js = session.ScriptRuntime!;
        js.Threads = [.. list.EnumerateArray().Select(t => new LiveJvmThread(t.GetProperty("tid").GetInt64(), t.GetProperty("name").GetString() ?? "", t.GetProperty("status").GetString() ?? "",
            t.GetProperty("held").GetBoolean(), t.GetProperty("depth").GetInt32(), Frames(js, t.GetProperty("frames"))))];
    }

    // A pause: frames named by script and original position, held until a resume.
    private void ScriptStop(LiveSession session, JsonElement body)
    {
        var point = body.GetProperty("point").GetString() ?? "pause";
        var frames = Frames(session.ScriptRuntime!, body.GetProperty("frames"));
        long thread = body.TryGetProperty("tid", out var t) ? t.GetInt64() : 1;
        int hits = body.TryGetProperty("hits", out var h) ? h.GetInt32() : 0;
        lock (session.StopPoints)
            if (session.StopPoints.TryGetValue(point, out var sp)) sp.Hits = hits;
        var reason = body.GetProperty("reason").GetString();
        session.Add("stop", thread, null, (session.StopPoints.ContainsKey(point) ? $"stop point {point} hit {hits}" : $"paused ({reason})") + (frames.Count > 0 ? " at " + frames[0].Display : ""),
            seq => new LiveHeldStop(seq, thread, point, new Dictionary<string, string>(), []) { ScriptFrames = frames });
    }
}
