using System.Runtime.CompilerServices;
using Corvus.Native.Providers;

namespace Corvus.Tests;

internal static class TestDataFolder
{
    /// <summary>
    /// Tests and every server they start (children inherit the variable) keep their data in a folder of their own, never
    /// the user's: caches persist between runs there, and the legacy-folder migration, which skips a chosen folder, never runs.
    /// </summary>
    [ModuleInitializer]
    internal static void Isolate()
    {
        if (Environment.GetEnvironmentVariable(DataFolder.RootVariable) is not { Length: > 0 })
            Environment.SetEnvironmentVariable(DataFolder.RootVariable, Path.Combine(Path.GetTempPath(), "corvus-test-data"));
        // Stall dumps outlive the per-test caches they would otherwise go into.
        if (Environment.GetEnvironmentVariable(Native.Providers.Ghidra.JavaThreadDump.FolderVariable) is not { Length: > 0 })
            Environment.SetEnvironmentVariable(Native.Providers.Ghidra.JavaThreadDump.FolderVariable,
                Path.Combine(Environment.GetEnvironmentVariable(DataFolder.RootVariable)!, "stalls"));
        // Sidecars and edit journals belong to the run: one a killed server left in a shared folder was offered to every
        // later run's servers. Children inherit the folder; McpProtocolTests gives each of its servers one of its own.
        if (Environment.GetEnvironmentVariable(Native.Annotations.AnnotationStore.RootVariable) is not { Length: > 0 })
            Environment.SetEnvironmentVariable(Native.Annotations.AnnotationStore.RootVariable, LeakGuard.DeleteAtEnd(LeakGuard.RunAnnotations));
        // Ghidra's answers stay fixed within a test; CompletionPassTests turns the pass on
        Environment.SetEnvironmentVariable("CORVUS_GHIDRA_COMPLETION", "off");
    }
}
