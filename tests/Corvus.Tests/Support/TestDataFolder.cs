using System.Runtime.CompilerServices;
using Corvus.Native.Providers;

namespace Corvus.Tests;

internal static class TestDataFolder
{
    /// <summary>Tests and their servers keep data in their own folder, never the user's, so caches persist and legacy migration never runs.</summary>
    [ModuleInitializer]
    internal static void Isolate()
    {
        if (Environment.GetEnvironmentVariable(DataFolder.RootVariable) is not { Length: > 0 })
            Environment.SetEnvironmentVariable(DataFolder.RootVariable, Path.Combine(Path.GetTempPath(), "corvus-test-data"));
        // Stall dumps outlive the per-test caches they would otherwise go into.
        if (Environment.GetEnvironmentVariable(Native.Providers.Ghidra.JavaThreadDump.FolderVariable) is not { Length: > 0 })
            Environment.SetEnvironmentVariable(Native.Providers.Ghidra.JavaThreadDump.FolderVariable,
                Path.Combine(Environment.GetEnvironmentVariable(DataFolder.RootVariable)!, "stalls"));
        // Sidecars and journals belong to the run: one a killed server left was offered to later runs.
        if (Environment.GetEnvironmentVariable(Native.Annotations.AnnotationStore.RootVariable) is not { Length: > 0 })
            Environment.SetEnvironmentVariable(Native.Annotations.AnnotationStore.RootVariable, LeakGuard.DeleteAtEnd(LeakGuard.RunAnnotations));
        // Ghidra's answers stay fixed within a test; CompletionPassTests turns the pass on
        Environment.SetEnvironmentVariable("CORVUS_GHIDRA_COMPLETION", "off");
    }
}
