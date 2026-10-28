using System.Diagnostics;

/// <summary>
/// Loaded into a server process through DOTNET_STARTUP_HOOKS: holds the process to
/// <see cref="Environment.ProcessorCount"/> processors and blocks every thread-pool thread once a tools/call request
/// starts, as work that keeps the pool busy does.
/// </summary>
internal static class StartupHook
{
    private static readonly ManualResetEventSlim Never = new();
    private static ActivityListener? _listener;
    private static int _blocked;

    public static void Initialize()
    {
        // Workers the server starts run without the hook.
        Environment.SetEnvironmentVariable("DOTNET_STARTUP_HOOKS", null);
        if (OperatingSystem.IsWindows() || OperatingSystem.IsLinux())
            Process.GetCurrentProcess().ProcessorAffinity = (nint)((1L << Environment.ProcessorCount) - 1);
        _listener = new ActivityListener
        {
            ShouldListenTo = source => source.Name.Contains("ModelContextProtocol", StringComparison.Ordinal),
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.PropagationData,
            ActivityStarted = activity =>
            {
                if (!activity.OperationName.StartsWith("tools/call", StringComparison.Ordinal) || Interlocked.Exchange(ref _blocked, 1) != 0) return;
                for (int i = 0; i < ThreadPool.ThreadCount + 1000; i++) ThreadPool.UnsafeQueueUserWorkItem(_ => Never.Wait(), null);
            },
        };
        ActivitySource.AddActivityListener(_listener);
    }
}
