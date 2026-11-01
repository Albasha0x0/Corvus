using Corvus.Core;
using Corvus.Core.AutoIt;

namespace Corvus.Services.Analysis;

/// <summary>Script containers, Nim runtime names and compressed streams in a native image.</summary>
internal static class NativeEmbeddedContent
{
    private const int MaxCandidates = 4096, MaxStreamBytes = 4 << 20, MaxExpandedBytes = 64 << 20;
    private const int MaxListed = 3;
    private const long MaxTriedBytes = 128L << 20;
    private static readonly byte[] GzipMagic = [0x1F, 0x8B, 0x08];

    private static readonly (string Name, byte[] Bytes)[] NimMarkers =
        new[] { "NimMainInner", "NimMainModule", "nimGC_setStackBottom", "stdlib_system.nim.c" }
            .Select(m => (m, System.Text.Encoding.ASCII.GetBytes(m))).ToArray();

    // Two distinct names are required: one can appear in any file that mentions it.
    private static string[] NimNames(byte[] image) =>
        NimMarkers.Where(m => image.AsSpan().IndexOf(m.Bytes) >= 0).Select(m => m.Name).ToArray();

    /// <summary>One line per script container, Nim runtime name and verified gzip stream, the last naming its unpack_container call.</summary>
    public static List<string> Highlights(string path, byte[] image, CancellationToken ct)
    {
        var lines = new List<string>();
        if (AutoItScript.Find(image) is >= 0 and var script)
            lines.Add($"Script container: {AutoItScript.Kind} at 0x{script:X}; unpack_container reads the script and its files.");
        if (AutoHotkeyScript.Find(image) is { } ahk)
            lines.Add($"Script container: {AutoHotkeyScript.Kind}, resource {ahk.Resource.Name}; unpack_container reads the script.");
        if (NimNames(image) is { Length: >= 2 } nim) lines.Add($"Nim runtime names found: {string.Join(", ", nim)}.");
        var streams = new List<(int Offset, int Expanded)>();
        var hits = Blob.FindAll(image, GzipMagic, MaxCandidates);
        int unread = 0;
        long tried = 0;
        foreach (int at in hits)
        {
            ct.ThrowIfCancellationRequested();
            // A failed header check or an OS byte no writer uses is not a gzip header.
            // RFC 1952 lists 0-13 and 255 (unknown, Go's default); zlib 1.2.12
            // and later write 19 on macOS.
            if (Containers.GzipHeaderEnd(image, at) < 0 || image[at + 9] is > 13 and not (19 or 255)) continue;
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
            if (streams.Count > 0 || limit.Length > 0) lines.Add($"Compression stream: {text}{limit}.{(streams.Count > 0 ? $" unpack_container path={(path.Any(char.IsWhiteSpace) ? $"\"{path}\"" : path)} extracts them." : "")}");
        }
        return lines;
    }
}
