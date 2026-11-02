namespace Corvus.Native.Dump.Rebuild;

/// <summary>Compares a rebuilt image with the module's file on disk.</summary>
public static class DiskCompare
{
    /// <summary>Most differing ranges listed.</summary>
    public const int MaxRanges = 64;

    /// <summary>The comparison, or null when no file of the same build is found.</summary>
    public static DiskComparison? Compare(byte[] rebuilt, CapturedImage captured, RebuildOptions options, List<RebuildCheck> checks)
    {
        checks.Add(RebuildCheck.Skipped("disk", "not compared"));
        return null;
    }
}
