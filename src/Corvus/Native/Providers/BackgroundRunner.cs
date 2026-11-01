using Corvus.Core;

namespace Corvus.Native.Providers;

/// <summary>A session that holds at most one background job.</summary>
public interface IBackgroundJobs
{
    /// <summary>The session's job runner.</summary>
    BackgroundRunner Jobs { get; }
}

/// <summary>A job with no caller (reanalyze_native): image, start, budget.</summary>
public sealed record BackgroundJob(string What, string Image, DateTime Started, TimeSpan? Budget, Task Task, CancellationTokenSource Cancel)
{
    /// <summary>Elapsed budget share, 0 to 99 while running; null without one.</summary>
    // A zero budget counts as one second; 100 is left for an ended job.
    public int? Percent(DateTime now) =>
        Budget is { } budget ? (int)Math.Clamp((now - Started).TotalSeconds / Math.Max(1, budget.TotalSeconds) * 100, 0, 99) : null;

    /// <summary>Budget left; zero once passed; null without a budget.</summary>
    public TimeSpan? Remaining(DateTime now) =>
        Budget is { } budget ? budget > now - Started ? budget - (now - Started) : TimeSpan.Zero : null;
}

/// <summary>The outcome of a background job: image, kind, text, next call.</summary>
public sealed record BackgroundEnd(string File, string Image, string Kind, string Text, string? Remediation);

/// <summary>Runs one job per session; other calls get conflict meanwhile.</summary>
public sealed class BackgroundRunner(Func<string> file)
{
    /// <summary>When to ask again: a quarter of the estimate left, between 30 s and 5 min.</summary>
    public static TimeSpan RetryFor(double remainingSeconds) => TimeSpan.FromSeconds(Math.Clamp(remainingSeconds / 4, 30, 300));

    private readonly object _lock = new();

    // The job's own requests pass.
    private static readonly AsyncLocal<bool> InJobFlow = new();

    /// <summary>True on the flow of a running job, whose own requests pass.</summary>
    public static bool InJob => InJobFlow.Value;

    /// <summary>The running or last job.</summary>
    public BackgroundJob? Job { get; private set; }

    public string? Result { get; private set; }

    /// <summary>Complete, partial, failed or cancelled; null while running.</summary>
    public string? Kind { get; private set; }

    public bool Running => Job is { Task.IsCompleted: false };

    /// <summary>
    /// Starts a job for an image; conflict when one is running.
    /// <paramref name="run"/> gets the cancel token, returns kind and text.
    /// <paramref name="ended"/> gets the outcome once the job ended.
    /// </summary>
    public BackgroundJob Start(string what, string image, TimeSpan? budget, Func<CancellationToken, Task<(string Kind, string Text)>> run, Action<BackgroundEnd>? ended = null)
    {
        lock (_lock)
        {
            if (Running) throw Busy();
            Result = null;
            Kind = null;
            string? remediation = null;
            var started = DateTime.UtcNow;
            var cancel = new CancellationTokenSource();
            var task = Task.Run(async () =>
            {
                InJobFlow.Value = true;
                try
                {
                    var (kind, text) = await run(cancel.Token).ConfigureAwait(false);
                    Result = $"{what} ended in {(DateTime.UtcNow - started).TotalSeconds:0} s: {text}";
                    Kind = kind;
                }
                catch (OperationCanceledException) when (cancel.IsCancellationRequested)
                {
                    Result = $"{what} cancelled after {(DateTime.UtcNow - started).TotalSeconds:0} s";
                    Kind = "cancelled";
                }
                catch (Exception e)
                {
                    Result = $"{what} failed after {(DateTime.UtcNow - started).TotalSeconds:0} s: {e.Message}";
                    Kind = "failed";
                    remediation = (e as ToolError)?.Remediation;
                }
                finally { cancel.Dispose(); }
            });
            // Raise the end only once the task is complete, so a told client sees the engine free.
            _ = task.ContinueWith(_ =>
            {
                if (ended == null) return;
                // A failing subscriber must not fault the job.
                try { ended(new BackgroundEnd(file(), image, Kind!, Result!, remediation)); }
                catch (Exception e) { Console.Error.WriteLine($"The end notice of the background {what} failed: {e.Message}"); }
            }, TaskScheduler.Default);
            return Job = new BackgroundJob(what, image, started, budget, task, cancel);
        }
    }

    /// <summary>Signals the running job to cancel without waiting; for a closing session.</summary>
    public void Stop()
    {
        try { if (Running) Job!.Cancel.Cancel(); }
        catch (ObjectDisposedException) { }
    }

    /// <summary>Cancels the running job and waits for it to end; false when none runs.</summary>
    public async Task<bool> CancelAsync(CancellationToken cancellationToken)
    {
        BackgroundJob? job;
        lock (_lock) job = Running ? Job : null;
        if (job == null) return false;
        try { job.Cancel.Cancel(); }
        catch (ObjectDisposedException) { }
        await job.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
        return true;
    }

    /// <summary>The conflict for a call made while the job holds the engine.</summary>
    public ToolError Busy()
    {
        var job = Job!;
        var elapsed = DateTime.UtcNow - job.Started;
        var of = job.Budget is { } budget ? $" of {budget.TotalSeconds:0} s" : "";
        return new ToolError(ErrorCode.Conflict, $"A {job.What} of {job.Image} is running in the background ({elapsed.TotalSeconds:0}{of}).",
            $"get_engine_status image={job.Image} waitSeconds=60 waits for it to end; cancel=true stops it")
        { RetryAfter = RetryFor(job.Remaining(DateTime.UtcNow)?.TotalSeconds ?? 0), Retryable = true };
    }
}
