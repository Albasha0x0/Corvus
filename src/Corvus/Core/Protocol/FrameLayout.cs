namespace Corvus.Core;

/// <summary>One recorded Send or OnReceive call: its direction and the bytes it moved.</summary>
public sealed record RecordedChunk(bool Received, byte[] Data);

/// <summary>
/// The length-prefix framing of one direction of a recording. The byte order
/// is meaningful only for prefixes wider than one byte.
/// </summary>
/// <param name="Received">True for OnReceive chunks, false for Send chunks.</param>
/// <param name="PrefixBytes">Width of the length prefix: 1, 2, 4 or 8.</param>
/// <param name="BigEndian">Byte order of the prefix; true for a 1-byte prefix.</param>
/// <param name="LengthIncludesPrefix">True when the length counts the prefix itself.</param>
/// <param name="Frames">Complete frames parsed, empty frames included.</param>
/// <param name="EmptyFrames">Complete frames whose payload is empty.</param>
/// <param name="ParsedBytes">Bytes covered by the complete frames.</param>
/// <param name="SplitReads">Reads that end inside a frame.</param>
/// <param name="Buffered">Bytes after the last complete frame.</param>
/// <param name="Missing">
/// Bytes the open frame still needs, or null when its length is unknown
/// because the stream ends inside the prefix or at an invalid length.
/// </param>
/// <param name="Stopped">True when parsing stopped at an invalid length at ParsedBytes.</param>
/// <param name="Transform">The payload header shared by every frame, or null.</param>
public sealed record FrameLayout(
    bool Received, int PrefixBytes, bool BigEndian, bool LengthIncludesPrefix,
    int Frames, int EmptyFrames, int ParsedBytes, int SplitReads,
    int Buffered, int? Missing, bool Stopped, string? Transform)
{
    /// <summary>The layout as a line, such as "[u32 big-endian payload length][payload]".</summary>
    public string Describe() =>
        $"[u{PrefixBytes * 8} " +
        (PrefixBytes == 1 ? "" : BigEndian ? "big-endian " : "little-endian ") +
        (LengthIncludesPrefix ? "frame" : "payload") + " length][payload]" +
        (Transform == null ? "" : $" payload: {Transform}");
}

/// <summary>Infers length-prefix framing from recorded chunks.</summary>
public static class FrameInference
{
    // Bounds a declared payload so a random prefix is rejected early.
    private const int MaxFrame = 16 << 20;
    private static readonly int[] Widths = [8, 4, 2, 1];

    /// <summary>
    /// Returns the layout of one direction that explains the most bytes, or
    /// null when no prefix yields two frames. Parsing stops at the first
    /// invalid length and keeps the frames before it. Empty frames explain
    /// only their prefix. Ties prefer fewer empty frames, then the wider
    /// prefix, then a payload length over a frame length.
    /// </summary>
    public static FrameLayout? Infer(IReadOnlyList<RecordedChunk> chunks, bool received)
    {
        var reads = chunks.Where(c => c.Received == received && c.Data is { Length: > 0 })
            .Select(c => c.Data).ToList();
        var stream = new byte[reads.Sum(r => r.Length)];
        var pos = 0;
        foreach (var read in reads)
        {
            read.CopyTo(stream, pos);
            pos += read.Length;
        }
        FrameLayout? best = null;
        foreach (var width in Widths)
        foreach (var big in width == 1 ? new[] { true } : [true, false])
        foreach (var includes in new[] { false, true })
        {
            var layout = Parse(stream, reads, received, width, big, includes);
            if (layout != null && (best == null || Better(layout, best))) best = layout;
        }
        return best;
    }

    private static bool Better(FrameLayout a, FrameLayout b)
    {
        var (ea, eb) = (Explained(a), Explained(b));
        if (ea != eb) return ea > eb;
        if (a.EmptyFrames != b.EmptyFrames) return a.EmptyFrames < b.EmptyFrames;
        return a.PrefixBytes > b.PrefixBytes;
    }

    // Empty frames explain only their prefix, so a narrow prefix over zero bytes earns nothing.
    private static int Explained(FrameLayout l) => l.ParsedBytes - l.EmptyFrames * l.PrefixBytes;

    private static FrameLayout? Parse(
        byte[] stream, List<byte[]> reads, bool received, int width, bool big, bool includes)
    {
        var bounds = new List<int>();
        var transforms = new HashSet<string?>();
        var at = 0;
        var empty = 0;
        int? missing = null;
        var stopped = false;
        var open = false;
        while (at + width <= stream.Length)
        {
            ulong length = 0;
            for (var i = 0; i < width; i++)
                length = (length << 8) | stream[big ? at + i : at + width - 1 - i];
            var payload = includes ? (long)length - width : (long)length;
            if (payload < 0 || payload > MaxFrame)
            {
                stopped = true;
                break;
            }
            var end = (long)at + width + payload;
            if (end > stream.Length)
            {
                missing = (int)(end - stream.Length);
                open = true;
                break;
            }
            if (payload == 0) empty++;
            else transforms.Add(TransformOf(stream.AsSpan(at + width, (int)Math.Min(payload, 2))));
            at = (int)end;
            bounds.Add(at);
        }
        // One complete frame plus an open frame is the minimum evidence.
        if (bounds.Count - empty + (open ? 1 : 0) < 2) return null;
        var buffered = stream.Length - at;
        if (buffered == 0) missing = 0;
        var edges = bounds.ToHashSet();
        var split = 0;
        var offset = 0;
        foreach (var read in reads)
        {
            offset += read.Length;
            if (offset < stream.Length && !edges.Contains(offset)) split++;
        }
        var transform = transforms.Count == 1 ? transforms.First() : null;
        return new FrameLayout(received, width, big, includes, bounds.Count, empty, at, split,
            buffered, missing, stopped, transform);
    }

    private static string? TransformOf(ReadOnlySpan<byte> head) => head switch
    {
        [0x1F, 0x8B] => "gzip",
        [0x78, 0x01 or 0x5E or 0x9C or 0xDA] => "zlib",
        _ => null,
    };
}
