namespace Corvus.Native.Dump.Rebuild;

/// <summary>Compares a rebuilt image with the module's file on disk.</summary>
public static class DiskCompare
{
    /// <summary>Most differing ranges listed.</summary>
    public const int MaxRanges = 64;

    /// <summary>The comparison, or null when no file of the same build is found.</summary>
    public static DiskComparison? Compare(byte[] rebuilt, CapturedImage captured, RebuildOptions options, List<RebuildCheck> checks)
    {
        if (!options.CompareWithDisk)
        {
            checks.Add(RebuildCheck.Skipped("disk", "comparison with the file on disk is off"));
            return null;
        }
        var candidates = Candidates(captured.Target, options);
        if (!DumpImages.TryHeader(captured.Image, out uint stamp, out uint size, out _))
        {
            checks.Add(RebuildCheck.Unknown("disk", "the captured headers do not give a build"));
            return null;
        }
        foreach (var path in candidates)
        {
            if (!SameBuild(path, stamp, size)) continue;
            checks.Add(RebuildCheck.Ok("disk", $"file of the same build found: {path}"));
            return new DiskComparison(path, true, 0, 0, []);
        }
        string searched = candidates.Count == 0 ? "no path recorded and no image directories" : string.Join("; ", candidates);
        checks.Add(RebuildCheck.Skipped("disk", $"no file of the same build found; searched {searched}"));
        return null;
    }

    /// <summary>The recorded path, then the module's file name in each image directory, without repeats.</summary>
    private static List<string> Candidates(RebuildTarget target, RebuildOptions options)
    {
        var list = new List<string>();
        if (!string.IsNullOrWhiteSpace(target.Path)) list.Add(target.Path);
        string name = Path.GetFileName(target.Path ?? target.Name);
        if (name.Length == 0) name = target.Name;
        foreach (var dir in (options.ImageDirectories ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            try { list.Add(Path.Combine(dir, name)); }
            catch (ArgumentException) { }
        }
        return [.. list.Distinct(StringComparer.OrdinalIgnoreCase)];
    }

    /// <summary>True when the file's time stamp and image size equal the captured headers; unreadable files are not the same build.</summary>
    private static bool SameBuild(string path, uint stamp, uint size)
    {
        try
        {
            if (!File.Exists(path)) return false;
            var head = new byte[0x1000];
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            int got = stream.Read(head, 0, head.Length);
            return DumpImages.TryHeader(head.AsSpan(0, got), out uint fileStamp, out uint fileSize, out _) && fileStamp == stamp && fileSize == size;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return false;
        }
    }
}
