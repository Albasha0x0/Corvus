using System.Text;

namespace Corvus.Core.Documents;

/// <summary>Byte-to-text decoding for parts whose charset is not declared.</summary>
internal static class TextDecoding
{
    /// <summary>Bytes as text: UTF-16LE when every other byte is zero (an encoded command), else UTF-8 without a BOM.</summary>
    public static string Decode(byte[] bytes, out string encoding)
    {
        if (bytes.Length >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE) { encoding = "utf-16le"; return Encoding.Unicode.GetString(bytes, 2, bytes.Length - 2); }
        if (bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF) { encoding = "utf-8"; return Encoding.UTF8.GetString(bytes, 3, bytes.Length - 3); }
        int zeros = 0, n = Math.Min(bytes.Length, 4096) & ~1;
        for (int i = 1; i < n; i += 2) if (bytes[i] == 0) zeros++;
        if (n >= 4 && zeros * 2 >= n * 9 / 10) { encoding = "utf-16le"; return Encoding.Unicode.GetString(bytes); }
        encoding = "utf-8";
        return Encoding.UTF8.GetString(bytes);
    }
}
