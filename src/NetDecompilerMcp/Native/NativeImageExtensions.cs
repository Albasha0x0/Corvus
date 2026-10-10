namespace NetDecompilerMcp.Native;

public static class NativeImageExtensions
{
    /// <summary>
    /// Length of the prefix of [rva, rva + length) whose bytes come from the file; the rest of a section is zero fill.
    /// Binary search over <see cref="INativeImage.TryRvaToFileOffset"/> (the file-backed part of a section is a prefix).
    /// </summary>
    public static long FileBackedLength(this INativeImage image, uint rva, long length)
    {
        length = Math.Min(length, (long)uint.MaxValue + 1 - rva);
        if (length <= 0 || !image.TryRvaToFileOffset(rva, out _)) return 0;
        if (image.TryRvaToFileOffset((uint)(rva + length - 1), out _)) return length;
        long lo = 1, hi = length - 1; // lo bytes are backed, hi + 1 are not
        while (lo < hi)
        {
            long mid = lo + (hi - lo + 1) / 2;
            if (image.TryRvaToFileOffset((uint)(rva + mid - 1), out _)) lo = mid;
            else hi = mid - 1;
        }
        return lo;
    }
}
