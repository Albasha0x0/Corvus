using System.Collections.Concurrent;
using System.Text.RegularExpressions;
using Corvus.Core;
using Corvus.Services.Mobile;

namespace Corvus.Services;

/// <summary>A Java frame as ART prints it: the method (class and name) and its source (File.java:12, Native method).</summary>
public sealed record LiveJavaFrame(string Method, string? Source);

/// <summary>A thread's Java stack from ART's dump: its name, its state (Native, Runnable, Sleeping) and its frames, innermost first.</summary>
public sealed record ArtThreadStack(string Name, string State, IReadOnlyList<LiveJavaFrame> Frames);

/// <summary>Reads the thread dump ART writes on SIGQUIT (to /data/anr, or to debuggerd -j).</summary>
public static partial class ArtStacks
{
    // "main" prio=5 tid=1 Native
    [GeneratedRegex(@"^""(?<name>.*)"" (?:daemon )?prio=\d+ tid=\d+ (?<state>\S+)")]
    private static partial Regex Header();

    [GeneratedRegex(@"\bsysTid=(?<tid>\d+)\b")]
    private static partial Regex SysTid();

    // at android.os.MessageQueue.next(MessageQueue.java:335)
    [GeneratedRegex(@"^\s+at (?<method>[^(]+)\((?<source>[^)]*)\)\s*$")]
    private static partial Regex Frame();

    /// <summary>The stack of the thread whose Linux thread id is <paramref name="tid"/>; null when the dump has no such thread.</summary>
    public static ArtThreadStack? Of(string dump, long tid)
    {
        string? name = null, state = null;
        bool match = false;
        var frames = new List<LiveJavaFrame>();
        foreach (var raw in dump.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            if (Header().Match(line) is { Success: true } h)
            {
                if (match) break;
                (name, state) = (h.Groups["name"].Value, h.Groups["state"].Value);
                frames.Clear();
                continue;
            }
            if (name == null) continue;
            if (SysTid().Match(line) is { Success: true } t) match = t.Groups["tid"].Value == tid.ToString(System.Globalization.CultureInfo.InvariantCulture);
            else if (Frame().Match(line) is { Success: true } f)
                frames.Add(new(f.Groups["method"].Value, f.Groups["source"].Value is { Length: > 0 } src ? src : null));
        }
        return match ? new ArtThreadStack(name!, state!, frames) : null;
    }
}

public sealed partial class LiveSessionService
{
    private const string AnrDirectory = "/data/anr";
    private static readonly TimeSpan JavaStackWait = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan DeviceReadyWait = TimeSpan.FromSeconds(15);
    private readonly ConcurrentDictionary<(string Serial, string Path), string?> _deviceFiles = new();
    private readonly Lazy<string> _deviceRoot = new(() => Path.Combine(Path.GetTempPath(), "corvus-device-" + Guid.NewGuid().ToString("N")[..8]));
    private DeviceService? _adb;

    private DeviceService Adb => _adb ??= new DeviceService(options ?? new ServerOptions());

    /// <summary>
    /// The file of a device module, pulled from the device once per server and path; the module's own path when the pull
    /// fails (the file is then unknown here, and the frame keeps its module and offset).
    /// </summary>
    private string DeviceFile(LiveSession session, LiveModuleState m)
    {
        if (m.Copy != null || session.Device is not { } serial) return m.LocalPath;
        var copy = _deviceFiles.GetOrAdd((serial, m.Path), key =>
        {
            var local = Path.Combine(_deviceRoot.Value, Sanitized(key.Serial), Path.Combine(key.Path.Split('/', StringSplitOptions.RemoveEmptyEntries).Select(Sanitized).ToArray()));
            try { return Adb.PullFile(key.Path, local, overwrite: true, key.Serial, CancellationToken.None).Local; }
            catch (ToolError) { return null; }
        });
        if (copy != null) m.Copy = copy;
        return m.LocalPath;

        static string Sanitized(string part) => string.Concat(part.Select(c => Path.GetInvalidFileNameChars().Contains(c) ? '_' : c));
    }

    /// <summary>The loaded image built from the same sources as a pulled device module: equal GNU build ids; null when either has none.</summary>
    private LoadedNative? SameBuild(LiveModuleState m)
    {
        if (m.Copy == null) return null;
        string? id;
        try { id = Native.NativeImageLoader.Open(m.Copy).BuildId; }
        catch (Exception e) when (e is ToolError or IOException or UnauthorizedAccessException or InvalidDataException) { return null; }
        return id == null ? null : workspace.Natives.FirstOrDefault(n => n.SliceName == null && n.Image.BuildId == id);
    }

    /// <summary>
    /// The Java stack of a held thread in a device session, from the thread dump ART writes to /data/anr (read as root);
    /// null with the reason when it is unknown: a thread outside ART, or no dump in time (ART suspends every thread for
    /// it, and cannot suspend one held while it runs managed code).
    /// </summary>
    public async Task<(ArtThreadStack? Stack, string? Unknown)> JavaStackAsync(LiveSession session, long thread, CancellationToken ct)
    {
        if (session.Device is not { } serial) return (null, "not a device session");
        try
        {
            // ART reuses its trace_NN slots: an entry is new when its ls -l line (size, time) is.
            var before = (await Task.Run(() => Adb.Listing(serial, AnrDirectory, ct), ct).ConfigureAwait(false)).ToHashSet(StringComparer.Ordinal);
            var r = await session.Worker.RequestAsync("art_dump", null, RequestTimeout, ct).ConfigureAwait(false);
            if (r.GetProperty("catcher").ValueKind == System.Text.Json.JsonValueKind.Null)
                return (null, "the program has no Signal Catcher thread (no ART, or ART has not started it yet)");
            string head = $"----- pid {session.ProcessId} at ", tail = $"----- end {session.ProcessId} -----";
            var until = DateTime.UtcNow + JavaStackWait;
            while (DateTime.UtcNow < until)
            {
                await Task.Delay(200, ct).ConfigureAwait(false);
                foreach (var line in Adb.Listing(serial, AnrDirectory, ct).Where(l => !before.Contains(l)))
                {
                    var path = AnrDirectory + "/" + line[(line.LastIndexOf(' ') + 1)..];
                    // ART writes the file as it walks the threads: its end line completes it.
                    var text = Adb.Text(serial, path, ct);
                    if (!text.Contains(head, StringComparison.Ordinal) || !text.Contains(tail, StringComparison.Ordinal)) continue;
                    Adb.Remove(serial, path, ct);
                    return ArtStacks.Of(text, thread) is { } stack ? (stack, null) : (null, $"thread {thread} is not an ART thread");
                }
            }
            return (null, $"ART wrote no thread dump in {JavaStackWait.TotalSeconds:0} s");
        }
        catch (ToolError e) { return (null, $"the thread dump could not be read ({e.Message})"); }
    }

    /// <summary>Removes the device files this server pulled.</summary>
    private void DeleteDeviceFiles()
    {
        if (!_deviceRoot.IsValueCreated) return;
        try { Directory.Delete(_deviceRoot.Value, recursive: true); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
    }
}
