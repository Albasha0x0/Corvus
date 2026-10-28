using System.Diagnostics;
using System.Globalization;
using System.Text;
using Corvus.Native.Dump;
using Corvus.Native.Live;
using Corvus.Native.Pe;

namespace Corvus.Tests;

/// <summary>What a live test's target was doing when the test failed: CPU time, threads and the worker's last line.</summary>
internal static class LiveTargetDiagnostics
{
    /// <summary>One line for the process (CPU time, thread count, the worker's quiet time), then one per thread: state, wait reason,
    /// suspend count and the top <paramref name="frames"/> frames as module+offset (Windows); a reason in place of what could not be read.</summary>
    public static string Describe(int pid, TimeSpan? sinceWorkerLine, int frames = 4, int maxThreads = 64)
    {
        var text = new StringBuilder();
        var worker = sinceWorkerLine is { } quiet ? $"; worker's last line {quiet.TotalSeconds.ToString("0.0", CultureInfo.InvariantCulture)} s ago" : "";
        Process process;
        try { process = Process.GetProcessById(pid); }
        catch (ArgumentException) { return $"process {pid}: ended{worker}"; }
        using (process)
        {
            List<ProcessThread> threads;
            try
            {
                text.Append(CultureInfo.InvariantCulture, $"process {pid}: cpu {process.TotalProcessorTime}");
                threads = [.. process.Threads.Cast<ProcessThread>()];
            }
            catch (Exception e) when (e is InvalidOperationException or System.ComponentModel.Win32Exception)
            {
                return $"process {pid}: not read ({e.Message}){worker}";
            }
            text.Append(CultureInfo.InvariantCulture, $", {threads.Count} threads{worker}");
            using var live = OperatingSystem.IsWindows() ? TryAttach(pid) : null;
            var images = new Dictionary<ulong, PeFile?>();
            foreach (var t in threads.Take(maxThreads))
            {
                text.Append(CultureInfo.InvariantCulture, $"\n  thread {t.Id} {State(t)}");
                if (live == null) continue;
                var read = live.ReadThread((uint)t.Id, context: true);
                if (read.SuspendCount is { } suspend) text.Append(CultureInfo.InvariantCulture, $", suspend {suspend}");
                if (read.Context is { } ctx && read.StackHigh is { } high)
                    text.Append(": ").Append(Frames(live, images, ctx, high, frames));
                else if (read.Error != null) text.Append(": ").Append(read.Error);
            }
            if (threads.Count > maxThreads) text.Append(CultureInfo.InvariantCulture, $"\n  {threads.Count - maxThreads} more threads");
        }
        return text.ToString();
    }

    private static LiveProcess? TryAttach(int pid)
    {
        try { return LiveProcess.Attach(pid); }
        catch (Exception e) when (e is Corvus.Core.ToolError or System.ComponentModel.Win32Exception or InvalidOperationException) { return null; }
    }

    private static string State(ProcessThread t)
    {
        try { return t.ThreadState == System.Diagnostics.ThreadState.Wait ? $"Wait/{t.WaitReason}" : t.ThreadState.ToString(); }
        catch (InvalidOperationException) { return "exited"; }
    }

    private static string Frames(LiveProcess live, Dictionary<ulong, PeFile?> images, DumpContext ctx, ulong stackHigh, int frames)
    {
        try
        {
            var walk = new StackWalker(live, m => Image(images, m)).Walk(ctx, ctx.Sp, stackHigh, frames);
            return string.Join(" <- ", walk.Frames.Select(f => Where(live, f.Ip)));
        }
        catch (Exception e) when (e is IOException or InvalidOperationException or ArgumentException) { return $"{Where(live, ctx.Ip)} (walk: {e.Message})"; }
    }

    private static PeFile? Image(Dictionary<ulong, PeFile?> images, DumpModule module)
    {
        if (images.TryGetValue(module.Base, out var cached)) return cached;
        PeFile? image = null;
        try { image = File.Exists(module.Path) ? PeFile.Open(module.Path) : null; }
        catch (Exception e) when (e is Corvus.Core.ToolError or IOException or UnauthorizedAccessException) { }
        return images[module.Base] = image;
    }

    private static string Where(LiveProcess live, ulong ip) =>
        live.ModuleAt(ip) is { } m ? $"{Path.GetFileName(m.Path)}+0x{ip - m.Base:x}" : $"0x{ip:x}";
}
