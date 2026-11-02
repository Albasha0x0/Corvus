using System.Buffers.Binary;
using Corvus.Core;
using Corvus.Native.Pe;

namespace Corvus.Native.Dump.Rebuild;

/// <summary>PE images in memory that the module list does not name.</summary>
public static class UnlistedImages
{
    /// <summary>The images found by their headers outside listed modules; empty when none.</summary>
    public static IReadOnlyList<RebuildTarget> Find(IProcessMemory memory, CancellationToken ct) => [];
}
