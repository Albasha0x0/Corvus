using System.Text.RegularExpressions;
using Corvus.Core;
using Corvus.Core.Archives;
using Corvus.Services.Analysis;
using Corvus.Services.Web.Scripts;

namespace Corvus.Services.Web;

/// <summary>A file a page's script builds in a Blob and saves, carved from its base64 literal.</summary>
public sealed record BlobPayload(string Name, string Kind, long Size, string Sha256, byte[] Bytes);

/// <summary>Carves the archive, program or document a standalone HTML or SVG page builds in a Blob; nothing runs.</summary>
internal static class BlobPayloads
{
    /// <summary>A payload at or under this many decoded bytes is not carved.</summary>
    public const int MinBytes = 4096;

    private const int MaxPayloads = 8;

    // 5,462 base64 characters decode to more than MinBytes.
    private static readonly Regex Literal = new(@"[A-Za-z0-9+/]{5462,}={0,2}", RegexOptions.NonBacktracking);

    // NonBacktracking matches a whole page in linear time, so no match timeout.
    private static readonly Regex Join = new(@"[""']\s*\+\s*[""']", RegexOptions.NonBacktracking);

    private static readonly Regex Build = new(@"\bnew\s+Blob\s*\(|\bBlob\s*\(", RegexOptions.NonBacktracking);
    private static readonly Regex Decode = new(@"\batob\s*\(|\bUint8Array\b|\bfromCharCode\b|\bcharCodeAt\b", RegexOptions.NonBacktracking);
    private static readonly Regex Save = new(
        @"\bmsSaveBlob\b|\bmsSaveOrOpenBlob\b|\.download\s*=|setAttribute\s*\(\s*[""']download[""']|\bcreateObjectURL\b|\bsaveAs\s*\(", RegexOptions.NonBacktracking);

    private static readonly HashSet<string> Kinds =
        ["zip", "7z", "rar", "cab", "gzip", "pdf", "lnk shortcut", "ole (msi/doc/xls)", "native PE", ".NET assembly", "NativeAOT executable", "elf", "mach-o"];

    /// <summary>Whether <paramref name="path"/> names an HTML or SVG page.</summary>
    public static bool IsPage(string path) => Path.GetExtension(path).ToLowerInvariant() is ".html" or ".htm" or ".xhtml" or ".svg";

    /// <summary>
    /// The payloads of a page whose own scripts build a Blob from decoded
    /// bytes and save it; empty for a page that loads script files, builds no
    /// Blob or holds no literal over <see cref="MinBytes"/> of a known type.
    /// </summary>
    public static List<BlobPayload> Find(string text, CancellationToken ct)
    {
        var found = new List<BlobPayload>();
        if (ScriptFileView.Blocks(text, out bool external) is not { Count: > 0 } blocks || external) return found;
        var code = string.Join("\n", blocks.Where(b => b.Language == "javascript").Select(b => b.Text));
        if (!Build.IsMatch(code) || !Decode.IsMatch(code) || !Save.IsMatch(code)) return found;
        var plain = ScriptReader.Read(code, "javascript", ct, milliseconds: ScriptBudget.BlockMilliseconds).Plain;
        // A literal split across concatenated strings reads as one run once the joins are dropped.
        var joined = Join.Replace(code, "");
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var source in new[] { joined, plain })
            foreach (Match m in Literal.Matches(source))
            {
                ct.ThrowIfCancellationRequested();
                if (found.Count >= MaxPayloads) return found;
                var value = m.Value.TrimEnd('=');
                byte[] bytes;
                try { bytes = Convert.FromBase64String(value.PadRight((value.Length + 3) / 4 * 4, '=')); }
                catch (FormatException) { continue; }
                if (bytes.Length <= MinBytes) continue;
                var kind = Blob.Identify(bytes);
                if (!Kinds.Contains(kind)) continue;
                var sha = Blob.Sha256(bytes);
                if (!seen.Add(sha)) continue;
                found.Add(new BlobPayload($"payload_{found.Count + 1}{Core.Documents.OneNoteReader.Extension(bytes)}", kind, bytes.Length, sha, bytes));
            }
        return found;
    }
}

/// <summary>The payloads a standalone HTML or SVG page builds in a Blob, as members.</summary>
internal sealed class BlobPayloadReader : IContainerReader
{
    private const long MaxPage = 16L << 20;

    public string Kind => "page";

    public bool Accepts(ReadOnlySpan<byte> data, string name) =>
        data.Length <= MaxPage && BlobPayloads.IsPage(name) && BlobPayloads.Find(ScriptText.Decode(data.ToArray(), out _), default).Count > 0;

    public ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        var items = new List<ExtractedItem>();
        var entries = new List<ContainerEntry>();
        var notes = new List<string>();
        long total = 0;
        foreach (var p in BlobPayloads.Find(ScriptText.Decode(data, out _), ct))
        {
            ArchiveItems.Take(items, entries, "payload built in a Blob", p.Name, p.Bytes, true, limits, ref total);
            notes.Add($"{p.Name}: {p.Kind}, {p.Size:N0} bytes, SHA-256 {p.Sha256}");
        }
        return new ContainerContents(Path.GetExtension(name).Equals(".svg", StringComparison.OrdinalIgnoreCase) ? "SVG page" : "HTML page", items, notes) { Entries = entries };
    }
}
