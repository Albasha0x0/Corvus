using System.Text;

namespace Corvus.Core;

/// <summary>Member and attachment names that disguise what a file is: bidirectional controls, a runnable double extension, long padding.</summary>
public static class MemberNames
{
    /// <summary>Whitespace runs at least this long push the real extension out of view.</summary>
    private const int PaddingRun = 20;

    private static readonly HashSet<string> DocumentExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf", ".txt", ".csv", ".jpg", ".jpeg", ".png", ".gif", ".zip", ".mp3", ".mp4",
    };

    /// <summary>Why <paramref name="name"/> disguises its type, or null when it does not; only the last path segment counts for extensions.</summary>
    public static string? Concern(string name)
    {
        foreach (var c in name)
            if (c is >= '\u202A' and <= '\u202E' or >= '\u2066' and <= '\u2069')
                return $"bidirectional control U+{(int)c:X4}";
        var file = name[(name.LastIndexOfAny(['/', '\\']) + 1)..];
        int run = 0;
        foreach (var c in file)
        {
            run = char.IsWhiteSpace(c) ? run + 1 : 0;
            if (run >= PaddingRun) return $"padded with {PaddingRun} or more whitespace characters";
        }
        var last = Path.GetExtension(file);
        if (last.Length > 0 && Blob.IsRunnableExtension(last) && DocumentExtensions.Contains(Path.GetExtension(file[..^last.Length])))
            return "a runnable extension after a document extension";
        return null;
    }

    /// <summary>One line naming the first names among <paramref name="names"/> that disguise their type, or null when none do.</summary>
    public static string? Check(IEnumerable<string> names)
    {
        var found = names.Select(n => (Name: n, Why: Concern(n))).Where(x => x.Why != null).Take(4).ToList();
        if (found.Count == 0) return null;
        return string.Join("; ", found.Take(3).Select(x => $"'{Show(x.Name)}' ({x.Why})")) + (found.Count > 3 ? "; ..." : "");
    }

    /// <summary>Why the path <paramref name="name"/> escapes or hides its place in an extraction folder, or null when it does not; a drive or stream part is ignored when <paramref name="streams"/> is false.</summary>
    public static string? PathConcern(string name, bool streams = true)
    {
        var path = name.Replace('\\', '/');
        if (path.StartsWith('/')) return "a rooted path";
        if (path.Length >= 2 && path[1] == ':' && char.IsAsciiLetter(path[0])) return "a drive letter";
        foreach (var part in path.Split('/'))
        {
            if (part == "..") return "a '..' part";
            if (part is "" or ".") continue;
            if (streams && part.Contains(':')) return "a ':' part naming a stream";
            if (part[^1] is ' ' or '.') return "a part ending in a blank or a dot";
        }
        return null;
    }

    /// <summary>The names in <paramref name="names"/> that are both a file and a folder, as the file's name.</summary>
    public static IEnumerable<string> Collisions(IEnumerable<string> names)
    {
        var files = new List<string>();
        var folders = new HashSet<string>(StringComparer.Ordinal);
        foreach (var raw in names)
        {
            var path = raw.Replace('\\', '/').Trim('/');
            if (path.Length == 0) continue;
            if (raw.EndsWith('/') || raw.EndsWith('\\')) folders.Add(path); else files.Add(path);
            for (int i = path.IndexOf('/'); i >= 0; i = path.IndexOf('/', i + 1)) folders.Add(path[..i]);
        }
        return files.Where(folders.Contains).Distinct();
    }

    /// <summary>One note per name that disguises its type, escapes its folder or is both a file and a folder; capped at <paramref name="max"/> with a count of the rest.</summary>
    public static List<string> Notes(IEnumerable<string> names, bool streams = true, int max = 20)
    {
        var list = names as IList<string> ?? [.. names];
        var found = new List<string>();
        foreach (var n in list)
        {
            if (Concern(n) is { } disguise) found.Add($"Member name that disguises its type: '{Show(n)}' ({disguise}).");
            if (PathConcern(n, streams) is { } path) found.Add($"Member name with an unsafe path: '{Show(n)}' ({path}).");
        }
        foreach (var n in Collisions(list)) found.Add($"Member name used for a file and a folder: '{Show(n)}'.");
        if (found.Count > max) { var rest = found.Count - max; found = [.. found.Take(max)]; found.Add($"{rest} more member names reported."); }
        return found;
    }

    /// <summary>The name with control and format characters as U+XXXX, clipped to 80 characters.</summary>
    internal static string Show(string name)
    {
        var sb = new StringBuilder();
        foreach (var c in name)
        {
            if (sb.Length >= 80) { sb.Append("..."); break; }
            if (char.IsControl(c) || char.GetUnicodeCategory(c) == System.Globalization.UnicodeCategory.Format) sb.Append($"<U+{(int)c:X4}>");
            else sb.Append(c);
        }
        return sb.ToString();
    }
}
