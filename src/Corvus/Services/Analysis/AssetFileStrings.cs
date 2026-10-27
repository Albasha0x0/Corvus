using System.Globalization;
using System.Text.RegularExpressions;
using Corvus.Core.Assets;

namespace Corvus.Services.Analysis;

/// <summary>String fields of serialized asset files and bundles for extract_strings; bounded, and each limit reached is named.</summary>
internal static partial class AssetFileStrings
{
    public const int MaxFiles = 2_000, MaxTexts = 500_000;
    public const long MaxBytes = 4L << 30, MaxFileBytes = 1L << 30;
    // Enumeration is bounded too: a build folder can hold far more files than assets.
    private const int MaxListed = 50_000;

    // Folders that hold code, native libraries or runtimes, not serialized assets.
    private static readonly HashSet<string> SkippedFolders = new(StringComparer.OrdinalIgnoreCase) { "Managed", "il2cpp_data", "Plugins", "MonoBleedingEdge", "bin" };
    private static readonly HashSet<string> SkippedExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".resS", ".resource", ".dll", ".so", ".dylib", ".exe", ".pdb", ".json", ".xml", ".txt", ".png", ".jpg", ".ogg", ".mp4", ".wav", ".bank", ".config", ".info",
    };

    /// <summary>An asset file to read: its label (path under its root, a split file by its joined name) and its pieces in order.</summary>
    public sealed record AssetFile(string Label, IReadOnlyList<string> Pieces);

    /// <summary>What the files gave: one part per serialized file (its label and values), notes, the gaps (null when none) and the MonoBehaviour assets not read whole.</summary>
    public sealed record Result(List<(string File, IReadOnlyList<ExtractedValue> Values)> Parts, List<string> Notes, string? Partial, int Unread);

    /// <summary>True for a path that can hold a serialized file or bundle: not a folder, code or runtime folder, or code or media file.</summary>
    public static bool IsAssetPath(string relative)
    {
        if (relative.Length == 0 || relative.EndsWith('/')) return false;
        var first = relative.IndexOf('/') is var slash and > 0 ? relative[..slash] : null;
        if (first != null && SkippedFolders.Contains(first)) return false;
        return !SkippedExtensions.Contains(Path.GetExtension(SplitBase(relative) ?? relative));
    }

    /// <summary>The read order of a path under the data folder: globalgamemanagers, levels, shared assets, resources, then the rest.</summary>
    public static int Rank(string relative)
    {
        var name = Path.GetFileName(SplitBase(relative) ?? relative);
        if (name.StartsWith("globalgamemanagers", StringComparison.OrdinalIgnoreCase) || name is "mainData" or "data.unity3d") return 0;
        if (name.StartsWith("level", StringComparison.OrdinalIgnoreCase)) return 1;
        if (name.StartsWith("sharedassets", StringComparison.OrdinalIgnoreCase)) return 2;
        if (name.StartsWith("resources", StringComparison.OrdinalIgnoreCase)) return 3;
        return relative.Contains('/') ? 5 : 4;
    }

    /// <summary>Asset files under the data and streaming roots, split pieces joined, data folder first, then by <see cref="Rank"/> and path; other heads are left out.</summary>
    public static List<AssetFile> Files(string data, IEnumerable<string> streaming, List<string> notes)
    {
        var found = new List<(AssetFile File, int Root)>();
        int listed = 0;
        foreach (var (root, index) in new[] { data }.Concat(streaming).Where(Directory.Exists).Distinct(StringComparer.OrdinalIgnoreCase).Select((r, i) => (r, i)))
        {
            if (listed > MaxListed) break;
            var prefix = index == 0 ? "" : Path.GetFileName(root) + "/";
            var splits = new Dictionary<string, SortedList<int, string>>(StringComparer.OrdinalIgnoreCase);
            IEnumerable<string> all;
            try { all = Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories); }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { continue; }
            foreach (var file in all)
            {
                if (++listed > MaxListed)
                {
                    notes.Add($"the first {MaxListed:N0} files under the data and streaming folders are checked");
                    break;
                }
                var relative = Path.GetRelativePath(root, file).Replace('\\', '/');
                // The Android streaming root is assets/, which holds the data folder under bin/; IsAssetPath skips it.
                if (!IsAssetPath(relative)) continue;
                relative = prefix + relative;
                if (SplitBase(relative) is { } joined)
                {
                    var list = splits.TryGetValue(joined, out var l) ? l : splits[joined] = new SortedList<int, string>();
                    list[SplitIndex(relative)] = file;
                    continue;
                }
                if (SerializedFile.IsAssetFile(file)) found.Add((new AssetFile(relative, [file]), index));
            }
            foreach (var (joined, pieces) in splits)
            {
                // A split file is whole only when its pieces run from 0 without a gap.
                if (pieces.Keys[0] != 0 || pieces.Keys[^1] != pieces.Count - 1)
                {
                    notes.Add($"{joined}: split pieces {string.Join(", ", pieces.Keys)} are not a full run from 0, so it is not read");
                    continue;
                }
                long whole;
                try { whole = pieces.Values.Sum(p => new FileInfo(p).Length); }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException) { continue; }
                if (SerializedFile.IsAssetFile(pieces.Values[0], whole)) found.Add((new AssetFile(joined, [.. pieces.Values]), index));
            }
        }
        return [.. found.OrderBy(f => f.Root).ThenBy(f => Rank(f.File.Label)).ThenBy(f => f.File.Label, StringComparer.Ordinal).Select(f => f.File)];
    }

    /// <summary>Reads the files in order until a limit, one part per serialized file; <paramref name="stop"/> keeps what was read and names the gap; null <paramref name="aotCache"/> uses the default.</summary>
    public static Result Read(IReadOnlyList<AssetFile> files, long maxBytes, CancellationToken stop, CancellationToken ct, string? aotCache = null)
    {
        maxBytes = Math.Clamp(maxBytes, 1, MaxBytes);
        var parts = new List<(string, IReadOnlyList<ExtractedValue>)>();
        var notes = new List<string>();
        var gaps = new List<string>();
        var reasons = new Dictionary<string, int>(StringComparer.Ordinal);
        var textAssets = new Dictionary<string, int>(StringComparer.Ordinal);
        long bytesRead = 0;
        int texts = 0, assets = 0, read = 0, partial = 0, unknown = 0, dropped = 0, encodedDropped = 0, filesRead = 0;
        foreach (var (file, index) in files.Take(MaxFiles).Select((f, i) => (f, i)))
        {
            ct.ThrowIfCancellationRequested();
            if (stop.IsCancellationRequested)
            {
                gaps.Add($"the time limit ended the read after {filesRead:N0} of {Math.Min(files.Count, MaxFiles):N0} asset files; {file.Label} and later files are not read");
                break;
            }
            long size;
            try { size = file.Pieces.Sum(p => new FileInfo(p).Length); }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                gaps.Add($"{file.Label} does not read ({e.Message})");
                continue;
            }
            if (size > MaxFileBytes)
            {
                gaps.Add($"{file.Label} is {size:N0} bytes, over the {MaxFileBytes:N0} byte limit per file");
                continue;
            }
            if (bytesRead + size > maxBytes)
            {
                gaps.Add($"the first {maxBytes:N0} bytes of asset files are read; {file.Label} and {Math.Min(files.Count, MaxFiles) - index - 1:N0} later files are not");
                break;
            }
            byte[] bytes;
            try { bytes = file.Pieces.Count == 1 ? File.ReadAllBytes(file.Pieces[0]) : [.. file.Pieces.SelectMany(p => File.ReadAllBytes(p))]; }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                gaps.Add($"{file.Label} does not read ({e.Message})");
                continue;
            }
            bytesRead += size;
            filesRead++;
            var s = AssetFileView.Strings(file.Pieces[0], bytes, file.Label, MaxTexts - texts, stop, ct, aotCache);
            (assets, read, partial, unknown, dropped) = (assets + s.Assets, read + s.Read, partial + s.Partial, unknown + s.Unknown, dropped + s.Dropped);
            foreach (var (reason, n) in s.Reasons) reasons[reason] = reasons.GetValueOrDefault(reason) + n;
            foreach (var (kind, n) in s.TextAssets) textAssets[kind] = textAssets.GetValueOrDefault(kind) + n;
            notes.AddRange(s.Notes.Select(n => $"{file.Label}: {n}"));
            texts += s.Texts.Count;
            foreach (var g in s.Texts.GroupBy(t => t.File))
            {
                parts.Add((g.Key, Values.FromFields(g.Select(t => (t.Text, t.Location)), out int over, ct)));
                if (over > 0) notes.Add($"{g.Key}: {over:N0} encoded values past the first {Values.MaxEncoded} are not listed");
                encodedDropped += over;
            }
            if (s.Stopped)
            {
                gaps.Add($"the time limit ended the read inside {file.Label}, after {filesRead:N0} asset files");
                break;
            }
        }
        if (files.Count > MaxFiles) gaps.Add($"the first {MaxFiles:N0} of {files.Count:N0} asset files are read");
        if (dropped > 0) gaps.Add($"{dropped:N0} field strings past the {MaxTexts:N0} kept are not read");
        if (textAssets.GetValueOrDefault("large") is > 0 and var large) gaps.Add($"{large:N0} TextAssets over {ConfigText.MaxBytes >> 20} MiB are not read");
        if (textAssets.GetValueOrDefault("unreadable") is > 0 and var bad) gaps.Add($"{bad:N0} TextAssets do not read");
        if (encodedDropped > 0) gaps.Add($"{encodedDropped:N0} encoded values past {Values.MaxEncoded} per file are not listed");
        notes.Insert(0, $"{filesRead:N0} of {files.Count:N0} asset files read ({bytesRead:N0} bytes): {assets:N0} MonoBehaviour assets, {read:N0} read, {partial:N0} partial, {unknown:N0} unknown." +
            (textAssets.Count > 0 ? $" TextAssets: {TextAssetCounts(textAssets)}." : ""));
        // Unknown is not absent: assets whose layout did not read are counted with their reasons.
        if (unknown + partial > 0)
            gaps.Add($"{unknown + partial:N0} of {assets:N0} MonoBehaviour assets are partial or unknown: " +
                     string.Join("; ", reasons.OrderByDescending(r => r.Value).ThenBy(r => r.Key, StringComparer.Ordinal).Take(3).Select(r => $"{r.Value} x {r.Key}")));
        return new Result(parts, notes, gaps.Count > 0 ? string.Join("; ", gaps) : null, unknown + partial);
    }

    /// <summary>TextAsset counts as "2 json, 1 ini read as config; 3 other text or binary, 1 over 4 MiB, 1 unreadable not read".</summary>
    private static string TextAssetCounts(Dictionary<string, int> kinds)
    {
        string Join(IEnumerable<(string Kind, string Label)> labels) =>
            string.Join(", ", labels.Select(l => kinds.TryGetValue(l.Kind, out int n) ? $"{n:N0} {l.Label}" : null).OfType<string>());
        var config = Join([("json", "json"), ("xml", "xml"), ("ini", "ini")]);
        var other = Join([("other", "other text or binary"), ("large", $"over {ConfigText.MaxBytes >> 20} MiB"), ("unreadable", "unreadable")]);
        return string.Join("; ", new[] { config.Length > 0 ? config + " read as config" : "", other.Length > 0 ? other + " not read" : "" }.Where(p => p.Length > 0));
    }

    /// <summary>The joined path of a split piece ("level0" for "level0.split3"), or null for any other path.</summary>
    private static string? SplitBase(string path) => Split().Match(path) is { Success: true } m ? m.Groups[1].Value : null;

    private static int SplitIndex(string path) => int.Parse(Split().Match(path).Groups[2].Value, CultureInfo.InvariantCulture);

    [GeneratedRegex(@"^(.+)\.split(\d{1,4})$", RegexOptions.CultureInvariant)]
    private static partial Regex Split();
}
