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

    /// <summary>The name with control and format characters as U+XXXX, clipped to 80 characters.</summary>
    private static string Show(string name)
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
