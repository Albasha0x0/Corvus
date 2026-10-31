using System.Buffers.Binary;
using System.Text;

namespace Corvus.Services.Analysis;

/// <summary>
/// Finds equal 8-byte and 16-byte blocks at aligned offsets, within one buffer
/// or shared by two. Unaligned repeats and a trailing partial block are not
/// seen, and only the first 4 MiB of a buffer is scanned (the note says so).
/// Repetition is a structural signal only; it does not identify a transform.
/// </summary>
internal static class BlockRepeats
{
    internal const int MaxScanBytes = 4 * 1024 * 1024;
    private const int MaxGroups = 3, MaxOffsets = 4;
    private const int MaxHeaderShown = 8;
    // Shorter prefixes occur by chance (1 in 256 for one byte) in unrelated data.
    private const int MinHeaderBytes = 4;

    /// <summary>Notes on aligned blocks that occur more than once; null when none repeat or under 8 bytes.</summary>
    internal static string? Within(byte[] data)
    {
        int length = Math.Min(data.Length, MaxScanBytes);
        var notes = new List<string>();
        var covered = new HashSet<int>();
        foreach (int size in new[] { 16, 8 })
        {
            var seen = new Dictionary<UInt128, List<int>>();
            for (int at = 0; at + size <= length; at += size)
            {
                // A half of a repeated 16-byte block is already reported.
                if (size == 8 && covered.Contains(at & ~15)) continue;
                var block = data.AsSpan(at, size);
                if (IsUniform(block)) continue;
                var key = Key(block);
                if (!seen.TryGetValue(key, out var list)) seen[key] = list = [];
                list.Add(at);
            }
            var groups = seen.Values.Where(v => v.Count > 1).OrderBy(v => v[0]).ToList();
            if (size == 16) foreach (var g in groups) foreach (int o in g) covered.Add(o);
            foreach (var offsets in groups.Take(MaxGroups))
                notes.Add($"{size}-byte block {Convert.ToHexString(data.AsSpan(offsets[0], size))} repeats at {Offsets(offsets)}");
            if (groups.Count > MaxGroups) notes.Add($"and {groups.Count - MaxGroups} more {size}-byte groups");
        }
        return notes.Count == 0 ? null : Close(notes, data.Length > length);
    }

    /// <summary>Notes on equal blocks at the same aligned offset in both buffers; null when none match.</summary>
    internal static string? Shared(byte[] a, byte[] b) => Siblings(a, b, header: false);

    /// <summary>
    /// Notes on equal aligned blocks and the shared header of two buffers;
    /// null when neither is found.
    /// </summary>
    internal static string? Siblings(byte[] a, byte[] b) => Siblings(a, b, header: true);

    private static string? Siblings(byte[] a, byte[] b, bool header)
    {
        int common = Math.Min(a.Length, b.Length);
        int length = Math.Min(common, MaxScanBytes);
        var notes = new List<string>();
        var covered = new HashSet<int>();
        foreach (int size in new[] { 16, 8 })
        {
            var offsets = new List<int>();
            for (int at = 0; at + size <= length; at += size)
            {
                if (size == 8 && covered.Contains(at & ~15)) continue;
                var block = a.AsSpan(at, size);
                if (IsUniform(block) || !block.SequenceEqual(b.AsSpan(at, size))) continue;
                offsets.Add(at);
                if (size == 16) covered.Add(at);
            }
            if (offsets.Count > 0) notes.Add($"{size}-byte block shared at {Offsets(offsets)}");
        }
        if (header && Header(a, b) is { } text) notes.Add(text);
        return notes.Count == 0 ? null : Close(notes, common > length);
    }

    /// <summary>
    /// Reports the leading bytes two buffers share, the first offset where they
    /// differ and where a shorter buffer ends. Null under 4 shared bytes.
    /// </summary>
    internal static string? Header(byte[] a, byte[] b)
    {
        int common = Math.Min(a.Length, b.Length);
        int prefix = a.AsSpan(0, common).CommonPrefixLength(b.AsSpan(0, common));
        if (prefix < MinHeaderBytes) return null;
        string shown = Convert.ToHexString(a.AsSpan(0, Math.Min(prefix, MaxHeaderShown)));
        string more = prefix > MaxHeaderShown ? "..." : "";
        string end = prefix < common ? $"; differs at 0x{prefix:X}"
            : a.Length != b.Length ? $"; shorter buffer ends at 0x{common:X}" : "";
        return $"{prefix}-byte header shared ({shown}{more}){end}";
    }

    private static string Close(List<string> notes, bool truncated) =>
        string.Join("; ", notes) + (truncated ? $" (first {MaxScanBytes >> 20} MiB scanned; " : " (") + "structural signal only)";

    private static UInt128 Key(ReadOnlySpan<byte> block) =>
        block.Length == 16 ? BinaryPrimitives.ReadUInt128LittleEndian(block) : BinaryPrimitives.ReadUInt64LittleEndian(block);

    private static bool IsUniform(ReadOnlySpan<byte> block) => block.IndexOfAnyExcept(block[0]) < 0;

    private static string Offsets(List<int> offsets)
    {
        var text = new StringBuilder(string.Join(", ", offsets.Take(MaxOffsets).Select(o => $"0x{o:X}")));
        if (offsets.Count > MaxOffsets) text.Append($" and {offsets.Count - MaxOffsets} more");
        return text.ToString();
    }
}
