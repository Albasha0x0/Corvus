using NetDecompilerMcp.Native.Code;
using NetDecompilerMcp.Services;

namespace NetDecompilerMcp.Tests;

/// <summary>A caller waiting for a code index keeps hearing its phase while the build reports nothing new.</summary>
public sealed class IndexProgressTests
{
    private sealed class Collector : IProgress<CodeIndexProgress>
    {
        private readonly List<CodeIndexProgress> _seen = [];
        private (Func<CodeIndexProgress, bool> Match, TaskCompletionSource Seen)? _waiter;

        public IReadOnlyList<CodeIndexProgress> Seen { get { lock (_seen) return _seen.ToList(); } }

        public void Report(CodeIndexProgress value)
        {
            lock (_seen)
            {
                _seen.Add(value);
                if (_waiter is { } w && w.Match(value)) w.Seen.TrySetResult();
            }
        }

        /// <summary>Completes when a report matching <paramref name="match"/> arrives from now on.</summary>
        public Task Next(Func<CodeIndexProgress, bool> match)
        {
            var seen = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            lock (_seen) _waiter = (match, seen);
            return seen.Task.WaitAsync(TimeSpan.FromMinutes(1));
        }
    }

    [Fact]
    public async Task Heartbeat_repeats_the_latest_phase_until_disposed()
    {
        var progress = new Collector();
        CodeIndexProgress? latest = null;
        var started = progress.Next(p => p.Phase == "starting");
        var beat = NativeCodeService.Heartbeat(() => latest, progress, TimeSpan.FromMilliseconds(20));
        await started;
        latest = new CodeIndexProgress("resolving virtual calls", 0, 0);
        var phase = progress.Next(p => p.Phase == "resolving virtual calls");
        await phase;
        var again = progress.Next(p => p.Phase == "resolving virtual calls");
        await again;

        beat.Dispose();
        int count = progress.Seen.Count;
        await Task.Delay(100);
        Assert.Equal(count, progress.Seen.Count);
    }
}
