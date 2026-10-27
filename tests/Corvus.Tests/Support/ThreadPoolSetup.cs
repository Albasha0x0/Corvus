using System.Runtime.CompilerServices;

namespace Corvus.Tests;

internal static class ThreadPoolSetup
{
    /// <summary>Raises the pool minimum: each started server blocks pool threads on redirected output, and a saturated machine adds none.</summary>
    [ModuleInitializer]
    internal static void ReserveThreads()
    {
        ThreadPool.GetMinThreads(out var workers, out var io);
        ThreadPool.SetMinThreads(Math.Max(workers, Environment.ProcessorCount * 2 + 32), io);
    }
}
