using System.Text;

namespace NetDecompilerMcp.Native.Code;

/// <summary>Recognizes NUL-terminated ASCII and UTF-16LE strings at referenced addresses.</summary>
internal static class StringDetector
{
    public const int MinLength = 4;

    /// <summary>A string of at least <see cref="MinLength"/> printable characters ending in NUL at <paramref name="rva"/>.</summary>
    public static StringLiteral? Detect(INativeImage image, uint rva, int maxLength, byte[] buffer)
    {
        int want = Math.Min(buffer.Length, (maxLength + 1) * 2);
        int n = image.Read(rva, buffer.AsSpan(0, want));
        if (n < MinLength + 1) return null;
        var span = buffer.AsSpan(0, n);

        // UTF-16LE: printable character, then a zero high byte for ASCII-range text
        if (n >= (MinLength + 1) * 2 && span[1] == 0 && IsPrintable(span[0]))
        {
            int chars = 0;
            for (int i = 0; i + 1 < n && chars <= maxLength; i += 2)
            {
                char c = (char)(span[i] | span[i + 1] << 8);
                if (c == 0)
                    return chars >= MinLength ? new StringLiteral(rva, chars, StringEncoding.Utf16) : null;
                if (!IsPrintableWide(c)) break;
                chars++;
            }
        }
        int len = 0;
        for (; len < n && len <= maxLength; len++)
        {
            byte b = span[len];
            if (b == 0) return len >= MinLength ? new StringLiteral(rva, len, StringEncoding.Ascii) : null;
            if (!IsPrintable(b)) return null;
        }
        return null;
    }

    private static bool IsPrintable(byte b) => b is >= 0x20 and < 0x7F or (byte)'\t' or (byte)'\r' or (byte)'\n';

    private static bool IsPrintableWide(char c) =>
        c < 0x80 ? IsPrintable((byte)c) : !char.IsControl(c) && !char.IsSurrogate(c) && c != '￿' && c != '￾' && char.GetUnicodeCategory(c) != System.Globalization.UnicodeCategory.OtherNotAssigned;

    public static string Read(INativeImage image, StringLiteral s, int maxChars)
    {
        int chars = Math.Min(s.Length, maxChars);
        var bytes = new byte[s.Encoding == StringEncoding.Utf16 ? chars * 2 : chars];
        int n = image.Read(s.Rva, bytes);
        return s.Encoding == StringEncoding.Utf16 ? Encoding.Unicode.GetString(bytes, 0, n & ~1) : Encoding.ASCII.GetString(bytes, 0, n);
    }

    /// <summary>Text quoted as a C string literal (escapes for quotes, backslashes and control characters).</summary>
    public static string Quote(string text, bool truncated)
    {
        var sb = new StringBuilder(text.Length + 2).Append('"');
        foreach (char c in text)
        {
            switch (c)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                default: sb.Append(c); break;
            }
        }
        sb.Append('"');
        if (truncated) sb.Append("...");
        return sb.ToString();
    }
}
