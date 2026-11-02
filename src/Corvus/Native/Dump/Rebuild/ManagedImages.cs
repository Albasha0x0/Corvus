namespace Corvus.Native.Dump.Rebuild;

/// <summary>Assemblies the .NET runtime loaded from memory rather than from a mapped file.</summary>
public static class ManagedImages
{
    /// <summary>The in-memory assemblies the runtime lists; empty without a readable runtime.</summary>
    public static IReadOnlyList<RebuildTarget> InMemoryAssemblies(IProcessMemory memory, CancellationToken ct) => [];
}
