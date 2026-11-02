using System.Buffers.Binary;
using Corvus.Core;
using Corvus.Native.Pe;

namespace Corvus.Native.Dump.Rebuild;

/// <summary>Undoes or keeps the loader's relocations in a mapped image.</summary>
public static class PeRelocations
{
    /// <summary>Applies <paramref name="mode"/> to <paramref name="image"/> in place and adds one check.</summary>
    public static void Apply(byte[] image, CapturedImage captured, BaseMode mode, List<RebuildCheck> checks) =>
        checks.Add(RebuildCheck.Skipped("relocations", "kept as loaded"));
}
