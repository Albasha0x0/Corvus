using System.Collections.Concurrent;
using System.Text.RegularExpressions;
using Corvus.Core;
using Corvus.Services.Mobile;

namespace Corvus.Services;

/// <summary>A Java frame as ART prints it: the method (class and name) and its source (File.java:12, Native method).</summary>
public sealed record LiveJavaFrame(string Method, string? Source);

/// <summary>A thread's Java stack from ART's dump: name, state, frames innermost first, and the class loaders' files (empty when none listed).</summary>
public sealed record ArtThreadStack(string Name, string State, IReadOnlyList<LiveJavaFrame> Frames)
{
    public IReadOnlyList<string> ClassPath { get; init; } = [];
}

/// <summary>A Java frame joined to its DEX method: the exact descriptor, the dex pc of the frame's line (null when unknown) and the DEX file.</summary>
public sealed record DexFrameMatch(string Descriptor, int? DexPc, string DexFile);

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

    // #2 dalvik.system.PathClassLoader: [/data/app/x/base.apk:/data/app/x/base.apk!classes2.dex], parent #1
    [GeneratedRegex(@"^#\d+ [^:]+: \[(?<path>[^\]]*)\]")]
    private static partial Regex ClassLoader();

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
        return match ? new ArtThreadStack(name!, state!, frames) { ClassPath = ClassPath(dump) } : null;
    }

    /// <summary>The package, jar and DEX files of the dump's class loaders in loader order, each once; a multidex entry (x.apk!classes2.dex) names its package.</summary>
    public static IReadOnlyList<string> ClassPath(string dump)
    {
        var files = new List<string>();
        foreach (var raw in dump.Split('\n'))
            if (ClassLoader().Match(raw.TrimEnd('\r')) is { Success: true } m)
                foreach (var entry in m.Groups["path"].Value.Split(':', StringSplitOptions.RemoveEmptyEntries))
                {
                    var file = entry.Split('!')[0];
                    if (file.EndsWith(".apk", StringComparison.Ordinal) || file.EndsWith(".jar", StringComparison.Ordinal) || file.EndsWith(".dex", StringComparison.Ordinal))
                        if (!files.Contains(file)) files.Add(file);
                }
        return files;
    }

    /// <summary>The DEX method of <paramref name="frame"/>, overloads told apart by the frame's line; null when not found or still ambiguous.</summary>
    public static DexFrameMatch? Match(DexIndex index, LiveJavaFrame frame)
    {
        int dot = frame.Method.LastIndexOf('.');
        if (dot <= 0 || index.FindClass(frame.Method[..dot]) is not { } entry) return null;
        var name = frame.Method[(dot + 1)..];
        int? line = frame.Source is { } src && src.LastIndexOf(':') is var colon and >= 0
            && int.TryParse(src.AsSpan(colon + 1), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var n) ? n : null;
        var named = new List<(string Descriptor, int? Pc)>();
        foreach (var m in entry.File.ClassData(entry.Class).Methods)
        {
            var r = entry.File.Method(m.MethodIndex);
            if (r.Name != name) continue;
            var lines = line != null && m.CodeOffset != 0 && entry.File.Code(m.CodeOffset) is { } code ? entry.File.Debug(code.DebugInfoOffset).Lines : [];
            named.Add((r.Descriptor, lines.FirstOrDefault(l => l.Line == line) is { Line: > 0 } at ? at.Offset : null));
        }
        // One method by that name needs no line; overloads keep those whose line table holds the frame's line.
        var found = named.Count == 1 ? named : [.. named.Where(m => m.Pc != null)];
        return found.Count == 1 ? new DexFrameMatch(found[0].Descriptor, found[0].Pc, entry.File.Name) : null;
    }
}

public sealed partial class LiveSessionService
{
    private const string AnrDirectory = "/data/anr";
    private static readonly TimeSpan JavaStackWait = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan DeviceReadyWait = TimeSpan.FromSeconds(15);
    private readonly ConcurrentDictionary<(string Serial, string Path), string?> _deviceFiles = new();
    private readonly Lazy<string> _deviceRoot = new(() => Native.Providers.PrivateFolder.Temp("device-" + Guid.NewGuid().ToString("N")[..8]));
    private DeviceService? _adb;

    private DeviceService Adb => _adb ??= new DeviceService(options ?? new ServerOptions());

    /// <summary>The local file of a device module, pulled once per server and path; the module's own path when the pull fails.</summary>
    private string DeviceFile(LiveSession session, LiveModuleState m)
    {
        if (m.Copy != null || session.Device is not { } serial) return m.LocalPath;
        if (DeviceCopy(serial, m.Path) is { } copy) m.Copy = copy;
        return m.LocalPath;
    }

    /// <summary>A local copy of a device file, pulled once per server and path; null when the pull fails.</summary>
    public string? DeviceCopy(string serial, string path)
    {
        return _deviceFiles.GetOrAdd((serial, path), key =>
        {
            var local = Path.Combine(_deviceRoot.Value, Sanitized(key.Serial), Path.Combine(key.Path.Split('/', StringSplitOptions.RemoveEmptyEntries).Select(Sanitized).ToArray()));
            try { return Adb.PullFile(key.Path, local, overwrite: true, key.Serial, CancellationToken.None).Local; }
            catch (ToolError) { return null; }
        });

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

    /// <summary>The Java stack of a held thread from ART's /data/anr dump, read as root; null with the reason when unknown
    /// (not an ART thread, or no dump in time: ART cannot suspend a thread held while it runs managed code).</summary>
    public async Task<(ArtThreadStack? Stack, string? Unknown)> JavaStackAsync(LiveSession session, long thread, CancellationToken ct)
    {
        if (session.Device is not { } serial) return (null, "not a device session");
        try
        {
            // ART reuses its trace_NN slots: an entry is new when its ls -l line (size, time) is.
            var before = (await Task.Run(() => Adb.Listing(serial, AnrDirectory, ct), ct).ConfigureAwait(false)).ToHashSet(StringComparer.Ordinal);
            var r = await session.Worker.RequestAsync("art_dump", null, RequestTimeout, ct).ConfigureAwait(false);
            if (r.GetProperty("catcher").ValueKind == System.Text.Json.JsonValueKind.Null)
                return (null, "no Signal Catcher thread (no ART, or ART has not started it)");
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
