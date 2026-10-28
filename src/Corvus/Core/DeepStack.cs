using System.Runtime.ExceptionServices;

namespace Corvus.Core;

/// <summary>
/// Runs recursive work (parsers, decompilers, printers) on a thread with a
/// 256 MiB stack, so deep input ends at a reader's own limit or its
/// <see cref="System.Runtime.CompilerServices.RuntimeHelpers.EnsureSufficientExecutionStack"/>
/// check, not in a stack overflow. Returns the work's result and rethrows
/// its exception with the original stack trace.
/// </summary>
public static class DeepStack
{
    /// <summary>The stack reserved for each run, in bytes.</summary>
    public const int StackBytes = 256 << 20;

    /// <summary>The result of <paramref name="work"/>, run on a thread of its own; the calling thread waits.</summary>
    public static T Run<T>(Func<T> work, string name = "deep stack")
    {
        T result = default!;
        ExceptionDispatchInfo? error = null;
        // Thread.Start flows the execution context, so the call's async locals
        // hold on the new thread.
        var thread = new Thread(() =>
        {
            try { result = work(); }
            catch (Exception ex) { error = ExceptionDispatchInfo.Capture(ex); }
        }, StackBytes) { IsBackground = true, Name = name };
        thread.Start();
        thread.Join();
        error?.Throw();
        return result;
    }
}
