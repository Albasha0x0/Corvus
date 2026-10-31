using Corvus.Core;
using Corvus.Core.AutoIt;

namespace Corvus.Services.Analysis;

/// <summary>Script containers and compression streams found inside a native image, named for the overview.</summary>
internal static class NativeEmbeddedContent
{
    private const int MaxCandidates = 4096, MaxStreamBytes = 4 << 20, MaxExpandedBytes = 64 << 20;
    private const int MaxListed = 3;
    private const long MaxTriedBytes = 128L << 20;
    private static readonly byte[] GzipMagic = [0x1F, 0x8B, 0x08];

    /// <summary>One line per script container and a line for verified gzip streams; empty when none is found.</summary>
    public static List<string> Highlights(byte[] image, CancellationToken ct)
    {
        var lines = new List<string>();
        if (AutoItScript.Find(image) is >= 0 and var script)
            lines.Add($"Script container: {AutoItScript.Kind} at 0x{script:X}; unpack_container reads the script and its files.");
        var streams = new List<(int Offset, int Expanded)>();
        var hits = Blob.FindAll(image, GzipMagic, MaxCandidates);
        int unread = 0;
        long tried = 0;
        foreach (int at in hits)
        {
            ct.ThrowIfCancellationRequested();
            // Flags with reserved bits set and unknown OS bytes are not gzip headers.
            if (at + 10 > image.Length || (image[at + 3] & 0xE0) != 0 || image[at + 9] > 13) continue;
            int length = Math.Min(image.Length - at, MaxStreamBytes);
            if (tried + length > MaxTriedBytes) { unread++; continue; }
            tried += length;
            if (Blob.TryDecompress(image.AsSpan(at, length), "gzip", MaxExpandedBytes) is { Length: > 0 } expanded) streams.Add((at, expanded.Length));
            else if (image.Length - at > MaxStreamBytes) unread++;
        }
        bool capped = hits.Count >= MaxCandidates;
        if (streams.Count > 0 || unread > 0 || capped)
        {
            var text = streams.Count > 0
                ? $"{(unread > 0 || capped ? "at least " : "")}{streams.Count} gzip stream(s) at {string.Join(", ", streams.Take(MaxListed).Select(s => $"0x{s.Offset:X} ({s.Expanded:N0} bytes expanded)"))}{(streams.Count > MaxListed ? ", ..." : "")}"
                : "no gzip stream verified";
            var limit = unread > 0 || capped
                ? $"; some candidates not read (limits: {MaxStreamBytes >> 20} MiB read and {MaxExpandedBytes >> 20} MiB expanded per stream, {MaxTriedBytes >> 20} MiB read in total, {MaxCandidates} magic hits)"
                : "";
            if (streams.Count > 0 || limit.Length > 0) lines.Add($"Compression stream: {text}{limit}.");
        }
        return lines;
    }
}
