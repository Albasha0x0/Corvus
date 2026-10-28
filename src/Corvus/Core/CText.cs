using System.Text;

namespace Corvus.Core;

/// <summary>Escapes text read from an input file for generated C and C++ source.</summary>
public static class CText
{
    /// <summary>Text safe in a <c>//</c> comment: line breaks and control characters become escapes, a final line splice is broken.</summary>
    public static string Line(string? text)
    {
        var s = Visible(text ?? "");
        // A final backslash or "??/" (trigraph) would join the next line to the comment.
        if (s.EndsWith('\\')) return s[..^1] + @"\x5C";
        if (s.EndsWith("??/", StringComparison.Ordinal)) return s[..^1] + @"\x2F";
        return s;
    }

    /// <summary>Text safe in a <c>/* */</c> comment: as <see cref="Line"/>, and "*/" becomes "*\/".</summary>
    public static string Block(string? text) => Line(text).Replace("*/", @"*\/", StringComparison.Ordinal);

    /// <summary>A quoted C string literal of <paramref name="text"/>; control characters become octal escapes.</summary>
    public static string Quote(string? text)
    {
        var sb = new StringBuilder("\"");
        var s = text ?? "";
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            if (c is '"' or '\\') sb.Append('\\').Append(c);
            // "??" followed by another character can form a trigraph.
            else if (c == '?' && i > 0 && s[i - 1] == '?') sb.Append(@"\?");
            // Octal, not \x: a hex escape takes every hex digit that follows.
            else if (c < 0x20 || c == 0x7F) sb.Append('\\').Append(Convert.ToString(c, 8).PadLeft(3, '0'));
            else sb.Append(c);
        }
        return sb.Append('"').ToString();
    }

    private const char LineSeparator = (char)0x2028, ParagraphSeparator = (char)0x2029;

    private static string Visible(string s)
    {
        if (!s.Any(c => char.IsControl(c) || c is LineSeparator or ParagraphSeparator)) return s;
        var sb = new StringBuilder(s.Length + 8);
        foreach (var c in s)
            sb.Append(c switch
            {
                '\n' => @"\n",
                '\r' => @"\r",
                '\t' => @"\t",
                _ when char.IsControl(c) || c is LineSeparator or ParagraphSeparator => c < 0x100 ? $"\\x{(int)c:X2}" : $"\\u{(int)c:X4}",
                _ => c.ToString(),
            });
        return sb.ToString();
    }
}
