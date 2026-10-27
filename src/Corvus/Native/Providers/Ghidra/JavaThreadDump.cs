using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace Corvus.Native.Providers.Ghidra;

/// <summary>Thread dump and heap summary of a stalled Java worker, from jcmd, else jhsdb (a JVM off a safepoint ignores jcmd).</summary>
internal static partial class JavaThreadDump
{
    private static readonly TimeSpan Limit = TimeSpan.FromSeconds(20);
    private static readonly TimeSpan DebuggerLimit = TimeSpan.FromSeconds(120);

    /// <summary>Folder for the dumps in place of the provider's own (a test run keeps it past its temporary caches).</summary>
    public const string FolderVariable = "CORVUS_STALL_DIR";

    /// <summary>Saves the dump of the first JVM among <paramref name="pids"/> under <see cref="FolderVariable"/>, else <paramref name="folder"/>; returns its summary and file, or <see cref="WorkerConnection.StateUnknown"/> with the reason.</summary>
    public static string Report(string java, IReadOnlyList<int> pids, string folder)
    {
        var bin = Path.GetDirectoryName(java) ?? "";
        var jcmd = Path.Combine(bin, OperatingSystem.IsWindows() ? "jcmd.exe" : "jcmd");
        var jhsdb = Path.Combine(bin, OperatingSystem.IsWindows() ? "jhsdb.exe" : "jhsdb");
        // Read before the dump tools add their own CPU time; the native decompiler shows here, not in a thread dump.
        var processes = Processes(pids);
        if (!File.Exists(jcmd) && !File.Exists(jhsdb)) return WorkerConnection.StateUnknown + $"the JDK in {bin} has neither jcmd nor jhsdb\n{processes}";
        var notes = new List<string>();
        string? threads = null, heap = "";
        int pid = pids.Count > 0 ? pids[0] : 0;
        foreach (var p in File.Exists(jcmd) ? pids : [])
        {
            var id = p.ToString(CultureInfo.InvariantCulture);
            if ((threads = Run(jcmd, [id, "Thread.print"], Limit, $"jcmd Thread.print of {id}", notes)) == null) continue;
            pid = p;
            heap = Run(jcmd, [id, "GC.heap_info"], Limit, $"jcmd GC.heap_info of {id}", notes) ?? "";
            break;
        }
        // The serviceability agent reads the stopped process, so it needs no answer from the JVM.
        foreach (var p in threads == null && File.Exists(jhsdb) ? pids : [])
        {
            var id = p.ToString(CultureInfo.InvariantCulture);
            if ((threads = Run(jhsdb, ["jstack", "--pid", id], DebuggerLimit, $"jhsdb jstack of {id}", notes)) == null) continue;
            pid = p;
            break;
        }
        // Once a process answered, failures on the others (which host no JVM) say nothing.
        var answered = $" of {pid.ToString(CultureInfo.InvariantCulture)} ";
        var note = string.Join('\n', threads == null ? notes : notes.Where(n => n.Contains(answered, StringComparison.Ordinal)));
        string? file = null;
        if (Environment.GetEnvironmentVariable(FolderVariable) is { Length: > 0 } chosen) folder = chosen;
        try
        {
            Directory.CreateDirectory(folder);
            file = Path.Combine(folder, $"worker-{pid}-{DateTime.UtcNow:yyyyMMddTHHmmss}.txt");
            File.WriteAllText(file, string.Join('\n', new[] { processes, string.Join('\n', notes), heap, threads ?? "" }.Where(t => t.Length > 0)));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { file = null; }
        var summary = threads != null ? Summary(threads, heap) : "";
        var text = string.Join('\n', new[] { summary, processes, note, file != null ? $"full dump: {file}" : "" }.Where(t => t.Length > 0));
        return threads == null ? WorkerConnection.StateUnknown + text : text;
    }

    /// <summary>"processes: name pid, X s CPU in Y s; ..." for <paramref name="pids"/>; an unreadable process is "not read".</summary>
    internal static string Processes(IReadOnlyList<int> pids)
    {
        var rows = new List<string>();
        foreach (var id in pids)
        {
            try
            {
                using var p = System.Diagnostics.Process.GetProcessById(id);
                var age = DateTime.Now - p.StartTime;
                rows.Add(string.Create(CultureInfo.InvariantCulture, $"{p.ProcessName} {id}, {p.TotalProcessorTime.TotalSeconds:0.0} s CPU in {age.TotalSeconds:0} s"));
            }
            catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception or NotSupportedException)
            {
                rows.Add(string.Create(CultureInfo.InvariantCulture, $"{id} not read"));
            }
        }
        return rows.Count == 0 ? "" : "processes: " + string.Join("; ", rows);
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
