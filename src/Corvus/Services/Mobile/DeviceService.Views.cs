using System.Buffers.Binary;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using Corvus.Core;
using Corvus.Native.Providers;

namespace Corvus.Services.Mobile;

// get_android_device_info's screen, window, display and bugreport views: read-only, nothing on the device changes.
public sealed partial class DeviceService
{
    /// <summary>Most screenshot bytes read (a 4K PNG is well under it).</summary>
    public const long MaxScreenBytes = 64L << 20;

    /// <summary>Most bugreport bytes written; past it the partial file is removed and the call fails.</summary>
    internal long MaxBugreportBytes { get; init; } = 1L << 30;

    private static string Stamp() => DateTime.UtcNow.ToString("yyyyMMdd-HHmmss-fff", CultureInfo.InvariantCulture);

    private static string SafeSerial(string serial) => Blob.SafeRelativePath(serial.Replace(':', '_'), "device");

    /// <summary>Streams one adb call's stdout into a new file next to <paramref name="final"/>, moved into place on success.</summary>
    private (ExternalTools.RunResult Run, long Size, string Sha256) Stream(IEnumerable<string> args, string final, long budget, string what, CancellationToken ct,
        bool check = true)
    {
        var partial = final + ".partial-" + Guid.NewGuid().ToString("N")[..8];
        try
        {
            ExternalTools.RunResult r;
            using (var file = SafeFile.CreateNew(partial))
                r = ExternalTools.Run(AdbPath(), [.. args], Long, budget, ct, Environment, sink: file);
            if (r.Truncated)
                throw new ToolError(ErrorCode.LimitExceeded, $"{what} is over {budget >> 20} MB; nothing was kept.");
            if (check || r.StartError != null || r.TimedOut) Check(r, what);
            SafeFile.MoveToOutput(partial, final, overwrite: false);
            using var read = File.OpenRead(final);
            return (r, read.Length, Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(read)));
        }
        finally { TryDelete(partial); }
    }

    /// <summary>The file to write: <paramref name="outputPath"/> (never replaced) or a new file in the temporary folder.</summary>
    private static string NewFile(string? outputPath, string name)
    {
        var full = outputPath is { Length: > 0 } p ? SafeFile.Output(p) : Native.Providers.PrivateFolder.Temp("device", name);
        if (Directory.Exists(full)) full = Path.Combine(full, name);
        if (File.Exists(full)) throw new ToolError(ErrorCode.Conflict, $"{full} exists.", "pass another outputPath");
        Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        return full;
    }

    /// <summary>screencap -p through exec-out (binary-safe), checked as a PNG and measured from its IHDR.</summary>
    private List<AndroidProperty> Screen(string serial, string? outputPath, CancellationToken ct)
    {
        var path = NewFile(outputPath, $"{SafeSerial(serial)}-screen-{Stamp()}.png");
        var watch = System.Diagnostics.Stopwatch.StartNew();
        var (_, size, sha) = Stream(ExternalTools.Arguments(Adb, "screencap", ("serial", serial)), path, MaxScreenBytes, "capturing the screen", ct);
        var head = new byte[24];
        using (var f = File.OpenRead(path)) _ = f.ReadAtLeast(head, head.Length, throwOnEndOfStream: false);
        if (!head.AsSpan().StartsWith((ReadOnlySpan<byte>)[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]))
        {
            var text = Encoding.UTF8.GetString(File.ReadAllBytes(path)).Trim();
            TryDelete(path);
            throw new ToolError(ErrorCode.Failed, $"screencap did not return a PNG: {Tail(text)}", "a locked or secure (FLAG_SECURE) screen can refuse capture");
        }
        return
        [
            new("file", path),
            new("size", $"{BinaryPrimitives.ReadUInt32BigEndian(head.AsSpan(16))}x{BinaryPrimitives.ReadUInt32BigEndian(head.AsSpan(20))}"),
            new("bytes", size.ToString(CultureInfo.InvariantCulture)),
            new("sha256", sha),
            new("elapsed", $"{watch.ElapsedMilliseconds} ms"),
        ];
    }

    // Matches "com.example.app/com.example.app.Main" or "com.example.app/.Main" in a window or activity record.
    [GeneratedRegex(@"\b([A-Za-z][\w]*(?:\.[\w]+)+)/(\.?[\w.$]+)")]
    private static partial Regex Component();

    /// <summary>The focused window and app, the activity as a class name, and that class in a DEX index when one defines it.</summary>
    private List<AndroidProperty> Window(string serial, string? package, CancellationToken ct)
    {
        var rows = new List<AndroidProperty>();
        (string Package, string Class)? activity = null;
        void Take(string line, string name)
        {
            var value = line[(line.IndexOf('=') is var eq and >= 0 ? eq + 1 : line.IndexOf(':') + 1)..].Trim();
            rows.Add(new(name, value));
            if (activity == null && Component().Match(value) is { Success: true } m)
                activity = (m.Groups[1].Value, m.Groups[2].Value.StartsWith('.') ? m.Groups[1].Value + m.Groups[2].Value : m.Groups[2].Value);
        }
        var lines = Lines(serial, "window", "reading the window state").Select(l => l.Trim()).ToList();
        // The app first: a dialog or the IME can hold window focus while the activity stays focused.
        foreach (var (key, name) in new[] { ("mFocusedApp=", "focused app"), ("mCurrentFocus=", "focused window") })
            if (lines.FirstOrDefault(l => l.StartsWith(key, StringComparison.Ordinal)) is { } line) Take(line, name);
        if (activity == null)
            foreach (var key in new[] { "topResumedActivity=", "mResumedActivity:", "ResumedActivity:" })
                if (Lines(serial, "activities", "reading the activity stack").Select(l => l.Trim()).FirstOrDefault(l => l.StartsWith(key, StringComparison.Ordinal)) is { } line)
                {
                    Take(line, "resumed activity");
                    break;
                }
        if (activity is not { } a)
        {
            rows.Add(new("activity", "none focused (screen off or locked, or the launcher)"));
            return rows;
        }
        rows.Add(new("package", a.Package));
        rows.Add(new("activity", a.Class));
        var indexes = new List<DexIndex>();
        if (package is { Length: > 0 } local && dex != null) indexes.Add(dex.Index(local, ct));
        else if (dex != null) indexes.AddRange(dex.Cached());
        foreach (var index in indexes)
            if (index.FindClass(a.Class) is { } entry)
            {
                rows.Add(new("dex class", $"{entry.Class.Descriptor} in {index.Path} ({entry.File.Name})"));
                var chain = new List<string>();
                for (var super = entry.Class.SuperClass; super != null && chain.Count < 12; super = index.Classes.GetValueOrDefault(super)?.Class.SuperClass)
                    chain.Add(super);
                if (chain.Count > 0) rows.Add(new("extends", string.Join(" < ", chain)));
                return rows;
            }
        rows.Add(new("dex class", indexes.Count == 0
            ? "no package read: pass query=<local APK of the app>, or read it first with a DEX tool"
            : $"not defined in {string.Join(", ", indexes.Select(i => Path.GetFileName(i.Path)))}"));
        return rows;
    }

    // Matches DisplayDeviceInfo{"Built-in Screen": uniqueId=..., 1080 x 2400, modeId 1, ...}.
    [GeneratedRegex(@"DisplayDeviceInfo\{""([^""]*)"":?\s*(.*)\}\s*$")]
    private static partial Regex DisplayDevice();

    /// <summary>wm size and density, the screen state, and each display device dumpsys display lists.</summary>
    private List<AndroidProperty> Display(string serial, CancellationToken ct)
    {
        var rows = new List<AndroidProperty>();
        foreach (var what in new[] { "size", "density" })
            foreach (var line in Lines(serial, "wm", $"reading the display {what}", ("what", what)))
                if (line.Split(':', 2) is [var name, var value]) rows.Add(new(name.Trim().ToLowerInvariant(), value.Trim()));
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var raw in Lines(serial, "display", "reading the displays"))
        {
            ct.ThrowIfCancellationRequested();
            var line = raw.Trim();
            if (DisplayDevice().Match(line) is { Success: true } m && seen.Add(m.Groups[1].Value + m.Groups[2].Value))
                rows.Add(new($"display \"{m.Groups[1].Value}\"", m.Groups[2].Value.Length > 600 ? m.Groups[2].Value[..600] + "..." : m.Groups[2].Value));
            else if (line.StartsWith("mScreenState=", StringComparison.Ordinal) && seen.Add(line)) rows.Add(new("screen state", line[13..]));
        }
        return rows;
    }

    /// <summary>Writes a bugreport to a new or empty directory: streamed zip (Android 9+), pulled zip, or text (before Android 7), each bounded by <see cref="MaxBugreportBytes"/>.</summary>
    private List<AndroidProperty> Bugreport(string serial, string? outputPath, CancellationToken ct)
    {
        var dir = EmptyDirectory(outputPath is { Length: > 0 } p ? p : Native.Providers.PrivateFolder.Temp("device", $"{SafeSerial(serial)}-bugreport-{Stamp()}"));
        var watch = System.Diagnostics.Stopwatch.StartNew();
        var name = $"bugreport-{SafeSerial(serial)}-{Stamp()}";
        var zip = Path.Combine(dir, name + ".zip");
        // A device without bugreportz -s answers with usage text or an error, which is not a failure yet.
        var (_, size, sha) = Stream(ExternalTools.Arguments(Adb, "bugreport-stream", ("serial", serial)), zip, MaxBugreportBytes, "collecting the bugreport", ct, check: false);
        var method = "bugreportz -s (streamed)";
        if (!IsZip(zip))
        {
            var answer = File.ReadAllText(zip).Trim();
            TryDelete(zip);
            var made = Run(ExternalTools.Arguments(Adb, "bugreport-zip", ("serial", serial)), Long, MaxTextBytes, ct);
            var text = (made.Text + made.Stderr).Trim();
            if (made.ExitCode == 127 || text.Contains("bugreportz: not found", StringComparison.Ordinal) || text.Contains("bugreportz: inaccessible", StringComparison.Ordinal))
            {
                var txt = Path.Combine(dir, name + ".txt");
                (_, size, sha) = Stream(ExternalTools.Arguments(Adb, "bugreport-text", ("serial", serial)), txt, MaxBugreportBytes, "collecting the bugreport", ct);
                return Report(txt, "bugreport (text, before Android 7)");
            }
            var ok = text.Split('\n').Select(l => l.Trim()).FirstOrDefault(l => l.StartsWith("OK:", StringComparison.Ordinal));
            if (ok == null)
            {
                Check(made, "collecting the bugreport");
                throw new ToolError(ErrorCode.Failed, $"bugreportz failed: {Tail(text.Length > 0 ? text : answer)}");
            }
            var remote = ok[3..].Trim();
            var bytes = Check(Run(ExternalTools.Arguments(Adb, "size", ("serial", serial), ("remote", remote)), Short, 4096, ct), $"checking {remote}").Trim();
            if (long.TryParse(bytes, NumberStyles.Integer, CultureInfo.InvariantCulture, out var remoteSize) && remoteSize > MaxBugreportBytes)
                throw new ToolError(ErrorCode.LimitExceeded, $"the bugreport ({remoteSize >> 20} MB) is over {MaxBugreportBytes >> 20} MB; it stays on the device at {remote}.",
                    $"pull_android_file remotePath={remote}");
            Check(Run(ExternalTools.Arguments(Adb, "pull", ("serial", serial), ("remote", remote), ("local", zip)), Long, 1 << 20, ct), $"pulling {remote}");
            if (!File.Exists(zip)) throw new ToolError(ErrorCode.IoError, $"adb reported success but wrote nothing for {remote}.");
            using (var f = File.OpenRead(zip)) (size, sha) = (f.Length, Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(f)));
            method = $"bugreportz, pulled from {remote}";
        }
        return Report(zip, method);

        List<AndroidProperty> Report(string file, string how) =>
        [
            new("file", file),
            new("bytes", size.ToString(CultureInfo.InvariantCulture)),
            new("sha256", sha),
            new("method", how),
            new("elapsed", $"{watch.Elapsed.TotalSeconds:0.0} s"),
        ];
    }

    private static bool IsZip(string path)
    {
        var head = new byte[4];
        using var f = File.OpenRead(path);
        return f.ReadAtLeast(head, 4, throwOnEndOfStream: false) == 4 && Blob.StartsWith(head, "PK\x03\x04"u8);
    }
}
