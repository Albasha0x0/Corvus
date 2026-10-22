using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace Corvus.Native.Providers.Ghidra;

/// <summary>
/// What a Java worker that missed its time was doing: a thread dump and heap summary from the JDK's jcmd, or from jhsdb
/// when jcmd cannot attach (a JVM that does not reach a safepoint does not answer jcmd).
/// </summary>
internal static partial class JavaThreadDump
{
    private static readonly TimeSpan Limit = TimeSpan.FromSeconds(20);
    private static readonly TimeSpan DebuggerLimit = TimeSpan.FromSeconds(120);

    /// <summary>Folder for the dumps in place of the provider's own (a test run keeps it past its temporary caches).</summary>
    public const string FolderVariable = "CORVUS_STALL_DIR";

    /// <summary>
    /// Saves the thread dump and heap summary of process <paramref name="pid"/> under <see cref="FolderVariable"/>, else
    /// <paramref name="folder"/>, and returns the heap line, the busiest Ghidra threads, why jcmd failed when it did, and
    /// the file; null when the JDK has neither jcmd nor jhsdb.
    /// </summary>
    public static string? Report(string java, int pid, string folder)
    {
        var bin = Path.GetDirectoryName(java) ?? "";
        var jcmd = Path.Combine(bin, OperatingSystem.IsWindows() ? "jcmd.exe" : "jcmd");
        var jhsdb = Path.Combine(bin, OperatingSystem.IsWindows() ? "jhsdb.exe" : "jhsdb");
        if (!File.Exists(jcmd) && !File.Exists(jhsdb)) return null;
        var notes = new List<string>();
        var threads = File.Exists(jcmd) ? Run(jcmd, [pid.ToString(CultureInfo.InvariantCulture), "Thread.print"], Limit, "jcmd Thread.print", notes) : null;
        var heap = threads != null ? Run(jcmd, [pid.ToString(CultureInfo.InvariantCulture), "GC.heap_info"], Limit, "jcmd GC.heap_info", notes) ?? "" : "";
        // The serviceability agent reads the stopped process, so it needs no answer from the JVM.
        if (threads == null && File.Exists(jhsdb))
            threads = Run(jhsdb, ["jstack", "--pid", pid.ToString(CultureInfo.InvariantCulture)], DebuggerLimit, "jhsdb jstack", notes);
        var note = string.Join('\n', notes);
        string? file = null;
        if (Environment.GetEnvironmentVariable(FolderVariable) is { Length: > 0 } chosen) folder = chosen;
        try
        {
            Directory.CreateDirectory(folder);
            file = Path.Combine(folder, $"worker-{pid}-{DateTime.UtcNow:yyyyMMddTHHmmss}.txt");
            File.WriteAllText(file, string.Join('\n', new[] { note, heap, threads ?? "" }.Where(t => t.Length > 0)));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { file = null; }
        var summary = threads != null ? Summary(threads, heap) : "";
        return string.Join('\n', new[] { summary, note, file != null ? $"full dump: {file}" : "" }.Where(t => t.Length > 0));
    }

    /// <summary>The heap line and up to three running or blocked threads with a Ghidra frame, eight frames each.</summary>
    internal static string Summary(string threads, string heap)
    {
        var text = new StringBuilder();
        if (heap.Split('\n').Select(l => l.Trim()).FirstOrDefault(l => l.Contains("total", StringComparison.Ordinal) && l.Contains("used", StringComparison.Ordinal)) is { } h)
            text.Append("heap: ").Append(h).Append('\n');
        // jcmd separates threads with a blank line; each starts with its quoted name.
        var busy = threads.Replace("\r\n", "\n").Split("\n\n")
            .Where(t => t.StartsWith('"') && StateLine().IsMatch(t) && t.Contains("ghidra.", StringComparison.Ordinal))
            .Take(3);
        foreach (var t in busy)
        {
            var lines = t.Split('\n');
            text.Append(lines[0].Trim()).Append('\n');
            // jcmd writes "at frame", jhsdb "- frame".
            foreach (var frame in lines.Skip(1).Where(l => l.TrimStart().StartsWith("at ", StringComparison.Ordinal) || l.TrimStart().StartsWith("- ", StringComparison.Ordinal)).Take(8))
                text.Append("  ").Append(frame.Trim()).Append('\n');
        }
        return text.ToString().TrimEnd();
    }

    [GeneratedRegex(@"java\.lang\.Thread\.State: (RUNNABLE|BLOCKED)")]
    private static partial Regex StateLine();

    /// <summary>The tool's output, or null with the reason added to <paramref name="notes"/>.</summary>
    private static string? Run(string tool, IReadOnlyList<string> args, TimeSpan limit, string name, List<string> notes)
    {
        var r = ExternalTools.Run(tool, args, limit, 16 << 20, default);
        if (r.ExitCode == 0 && !r.TimedOut && r.StartError == null) return r.Text;
        var why = r.StartError ?? (r.TimedOut ? $"no answer within {limit.TotalSeconds:0} s" : $"exit code {r.ExitCode}");
        var detail = (r.Stderr.Trim().Length > 0 ? r.Stderr : r.Text).Trim();
        notes.Add($"{name} failed: {why}" + (detail.Length > 0 ? ": " + detail[..Math.Min(detail.Length, 300)] : ""));
        return null;
    }
}
