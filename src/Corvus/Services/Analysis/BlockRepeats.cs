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
    internal static string? Shared(byte[] a, byte[] b)
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
        return notes.Count == 0 ? null : Close(notes, common > length);
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
