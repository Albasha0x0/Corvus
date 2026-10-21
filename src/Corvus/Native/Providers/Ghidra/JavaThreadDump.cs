using System.Text;
using System.Text.RegularExpressions;

namespace Corvus.Native.Providers.Ghidra;

/// <summary>What a Java worker that missed its time was doing: a thread dump and heap summary from the JDK's jcmd.</summary>
internal static partial class JavaThreadDump
{
    private static readonly TimeSpan Limit = TimeSpan.FromSeconds(20);

    /// <summary>
    /// Saves jcmd's thread dump and heap summary of process <paramref name="pid"/> under <paramref name="folder"/> and
    /// returns the heap line, the busiest Ghidra threads and the file; null when the JDK has no jcmd or it cannot attach.
    /// </summary>
    public static string? Report(string java, int pid, string folder)
    {
        var jcmd = Path.Combine(Path.GetDirectoryName(java) ?? "", OperatingSystem.IsWindows() ? "jcmd.exe" : "jcmd");
        if (!File.Exists(jcmd)) return null;
        var threads = Run(jcmd, pid, "Thread.print");
        if (threads == null) return null;
        var heap = Run(jcmd, pid, "GC.heap_info") ?? "";
        string? file = null;
        try
        {
            Directory.CreateDirectory(folder);
            file = Path.Combine(folder, $"worker-{pid}-{DateTime.UtcNow:yyyyMMddTHHmmss}.txt");
            File.WriteAllText(file, heap + "\n" + threads);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { file = null; }
        return Summary(threads, heap) + (file != null ? $"\nfull dump: {file}" : "");
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
            foreach (var frame in lines.Skip(1).Where(l => l.TrimStart().StartsWith("at ", StringComparison.Ordinal)).Take(8))
                text.Append("  ").Append(frame.Trim()).Append('\n');
        }
        return text.ToString().TrimEnd();
    }

    [GeneratedRegex(@"java\.lang\.Thread\.State: (RUNNABLE|BLOCKED)")]
    private static partial Regex StateLine();

    private static string? Run(string jcmd, int pid, string command)
    {
        var r = ExternalTools.Run(jcmd, [pid.ToString(System.Globalization.CultureInfo.InvariantCulture), command], Limit, 4 << 20, default);
        return r.ExitCode == 0 && !r.TimedOut ? r.Text : null;
    }
}
