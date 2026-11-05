using System.Buffers.Binary;
using System.IO.Hashing;

namespace Corvus.Core;

/// <summary>One packed Zstandard entry with its declared size and the two index checksums, used to validate a dictionary.</summary>
public readonly record struct ZstdSample(byte[] Packed, uint Original, uint IndexCrcA, uint IndexCrcB);

/// <summary>A dictionary carved from an executable: its bytes, the file and the offset it was read at.</summary>
public sealed record FoundZstdDictionary(uint Id, byte[] Bytes, string File, long Offset);

/// <summary>Finds a Zstandard dictionary by id in the executables next to an archive.</summary>
public static class ZstdDictionaryLocator
{
    /// <summary>Executables scanned per folder.</summary>
    public const int MaxFiles = 64;
    /// <summary>Largest executable scanned, in bytes.</summary>
    public const long MaxFileBytes = 1L << 30;
    /// <summary>Largest dictionary accepted, in bytes.</summary>
    public const int MaxDictionaryBytes = 1 << 20;
    private const int MinDictionaryBytes = 256, MaxMagics = 8192, Chunk = 1 << 20;
    private static readonly byte[] Magic = [0x37, 0xA4, 0x30, 0xEC];

    /// <summary>
    /// Returns the dictionary with <paramref name="id"/> found in an executable of <paramref name="folder"/>, or null.
    /// A candidate length is accepted only when every sample decodes to its declared size and passes its checksum.
    /// Limits reached and unreadable files are added to <paramref name="notes"/>.
    /// </summary>
    public static FoundZstdDictionary? Find(string folder, uint id, IReadOnlyList<ZstdSample> samples, List<string> notes, CancellationToken ct)
    {
        if (samples.Count == 0 || !Directory.Exists(folder)) return null;
        List<string> files;
        try { files = Directory.EnumerateFiles(folder).OrderBy(f => f, StringComparer.OrdinalIgnoreCase).ToList(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { notes.Add($"Folder not listed ({ex.Message}); dictionary search unknown."); return null; }
        int scanned = 0, over = 0;
        foreach (var file in files)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var s = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                if (!IsExecutable(s)) continue;
                if (s.Length > MaxFileBytes) { over++; continue; }
                if (scanned >= MaxFiles) { notes.Add($"Dictionary search stopped after {MaxFiles} executables; the rest are unknown."); break; }
                scanned++;
                if (Scan(s, file, id, samples, ct) is { } found) return found;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { notes.Add($"{Path.GetFileName(file)} not read for a dictionary ({ex.Message})."); }
        }
        if (over > 0) notes.Add($"{over:N0} executable(s) over {MaxFileBytes >> 20:N0} MiB not searched for a dictionary.");
        return null;
    }

    private static bool IsExecutable(Stream s)
    {
        Span<byte> h = stackalloc byte[64];
        s.Position = 0;
        int n = s.ReadAtLeast(h, h.Length, throwOnEndOfStream: false);
        return Native.NativeImageLoader.Detect(h[..n]) is not (Native.NativeFileKind.Unknown or Native.NativeFileKind.Wasm);
    }

    private static FoundZstdDictionary? Scan(FileStream s, string file, uint id, IReadOnlyList<ZstdSample> samples, CancellationToken ct)
    {
        var starts = new List<long>();
        var buf = new byte[Chunk + 7];
        long pos = 0;
        int keep = 0;
        s.Position = 0;
        while (starts.Count < MaxMagics)
        {
            ct.ThrowIfCancellationRequested();
            int n = s.Read(buf, keep, Chunk);
            if (n <= 0) break;
            int total = keep + n;
            int from = 0;
            while (from < total)
            {
                int at = buf.AsSpan(from, total - from).IndexOf(Magic);
                if (at < 0) break;
                starts.Add(pos + from + at);
                from += at + 1;
            }
            // Carry the last 3 bytes so a magic split across chunks is seen once.
            keep = Math.Min(3, total);
            Array.Copy(buf, total - keep, buf, 0, keep);
            pos += total - keep;
        }
        var head = new byte[8];
        for (int i = 0; i < starts.Count; i++)
        {
            if (starts[i] + 8 > s.Length) continue;
            s.Position = starts[i];
            s.ReadExactly(head);
            if (BinaryPrimitives.ReadUInt32LittleEndian(head.AsSpan(4)) != id) continue;
            long limit = i + 1 < starts.Count ? starts[i + 1] : s.Length;
            int room = (int)Math.Min(limit - starts[i], MaxDictionaryBytes);
            var window = new byte[room];
            s.Position = starts[i];
            s.ReadExactly(window);
            if (Accept(window, samples, ct) is { } bytes) return new FoundZstdDictionary(id, bytes, file, starts[i]);
        }
        return null;
    }

    // The length is not stored: try the span to the next magic or the end of the file, then round lengths downward.
    private static byte[]? Accept(byte[] window, IReadOnlyList<ZstdSample> samples, CancellationToken ct)
    {
        var seen = new HashSet<int>();
        foreach (int length in Lengths(window.Length))
        {
            ct.ThrowIfCancellationRequested();
            if (length < MinDictionaryBytes || !seen.Add(length)) continue;
            var candidate = window.AsSpan(0, length).ToArray();
            if (Validates(candidate, samples)) return candidate;
        }
        return null;
    }

    private static IEnumerable<int> Lengths(int max)
    {
        yield return max;
        for (int n = max & ~15; n > max - 16 * 64 && n > 0; n -= 16) yield return n;
        for (int n = max & ~1023; n > 0; n -= 1024) yield return n;
        for (int n = max - 1; n > max - 16; n--) yield return n;
    }

    private static bool Validates(byte[] dictionary, IReadOnlyList<ZstdSample> samples)
    {
        try
        {
            using var zstd = new ZstdSharp.Decompressor();
            zstd.LoadDictionary(dictionary);
            foreach (var sample in samples)
            {
                var output = new byte[sample.Original];
                if (zstd.Unwrap(sample.Packed, output) != sample.Original || !Checks(sample, output)) return false;
            }
            return true;
        }
        catch (Exception ex) when (ex is ZstdSharp.ZstdException or ArgumentException or InvalidDataException) { return false; }
    }

    // The frame's content checksum when it has one, else the index checksums; no checksum to compare fails.
    private static bool Checks(ZstdSample sample, byte[] output)
    {
        var frame = sample.Packed;
        if (frame.Length > 8 && (frame[4] & 0x04) != 0)
            return BinaryPrimitives.ReadUInt32LittleEndian(frame.AsSpan(frame.Length - 4)) == (uint)XxHash64.HashToUInt64(output);
        uint crc = Crc32.HashToUInt32(output);
        return crc != 0 && (crc == sample.IndexCrcA || crc == sample.IndexCrcB);
    }

    /// <summary>Decodes <paramref name="packed"/> with <paramref name="dictionary"/> into <paramref name="original"/> bytes; throws InvalidDataException on a mismatch.</summary>
    public static byte[] Decode(byte[] dictionary, ReadOnlySpan<byte> packed, uint original)
    {
        try
        {
            using var zstd = new ZstdSharp.Decompressor();
            zstd.LoadDictionary(dictionary);
            var output = new byte[original];
            int written = zstd.Unwrap(packed, output);
            return written == original ? output : throw new InvalidDataException($"{written:N0} of {original:N0} bytes decoded");
        }
        catch (ZstdSharp.ZstdException ex) { throw new InvalidDataException("corrupt Zstandard block: " + ex.Message); }
    }
}
