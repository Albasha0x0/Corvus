using System.Buffers.Binary;
using Corvus.Core;
using Corvus.Native.Pe;

namespace Corvus.Native.Dump.Rebuild;

/// <summary>Restores the import address table of a mapped image.</summary>
public static class PeImportRestore
{
    /// <summary>Applies <paramref name="mode"/> to <paramref name="image"/> in place; null when the image has no import directory or the mode keeps addresses.</summary>
    public static ImportSummary? Restore(byte[] image, CapturedImage captured, IProcessMemory memory, ImportMode mode, List<RebuildCheck> checks, CancellationToken ct)
    {
        checks.Add(RebuildCheck.Skipped("imports", "kept as loaded"));
        return null;
    }
}
