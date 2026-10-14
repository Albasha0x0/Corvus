using System.Runtime.CompilerServices;

namespace Corvus.Tests;

internal static class ThreadPoolSetup
{
    /// <summary>
    /// Every server a test starts holds pool threads for good: on Windows, ReadAsync on a child's redirected output (the
    /// SDK's stdio client, BeginErrorReadLine) blocks a pool thread in a synchronous read. With a few dozen servers up, a
    /// pool at its default minimum has no thread left, and on a busy machine it adds none (it does not grow while the CPU
    /// is saturated), so every test in the process stalls for seconds.
    /// </summary>
    [ModuleInitializer]
    internal static void ReserveThreads()
    {
        ThreadPool.GetMinThreads(out var workers, out var io);
        ThreadPool.SetMinThreads(Math.Max(workers, Environment.ProcessorCount * 2 + 32), io);
    }
}
