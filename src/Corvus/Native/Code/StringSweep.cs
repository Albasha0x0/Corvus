namespace Corvus.Native.Code;

/// <summary>Lists printable ASCII and UTF-16LE runs in the file-backed data sections of an image, referenced or not.</summary>
public static class StringSweep
{
    /// <summary>Shortest run kept, in characters.</summary>
    public const int MinChars = 6;

    /// <summary>Longest run kept whole, in characters; a longer one continues as the next run.</summary>
    public const int MaxChars = 4096;

    private const int Chunk = 1 << 22;

    /// <summary>Runs by address; executable sections and sections without file bytes are skipped; empty for none.</summary>
    public static List<StringLiteral> Scan(INativeImage image, CancellationToken ct)
    {
        var found = new List<StringLiteral>();
        var buffer = new byte[Chunk + 2 * MaxChars + 2];
        foreach (var section in image.Sections.Where(s => !s.IsExecutable && s.RawSize > 0).OrderBy(s => s.Rva))
        {
            long size = Math.Min(section.MappedSize, section.RawSize);
            long pos = 0;
            while (pos < size)
            {
                ct.ThrowIfCancellationRequested();
                int want = (int)Math.Min(buffer.Length, size - pos);
                int n = image.Read(section.Rva + (uint)pos, buffer.AsSpan(0, want));
                if (n <= 0) break;
                bool last = pos + n >= size;
                // A run that reaches the window's end is read again from its start in the next window.
                int limit = last ? n : Math.Min(n, Chunk + MaxChars);
                int next = limit;
                for (int i = 0; i < limit;)
                {
                    var (chars, bytes, wide) = RunAt(buffer.AsSpan(0, n), i);
                    if (bytes == 0) { i++; continue; }
                    if (i + bytes >= n && !last) { next = i; break; }
                    if (chars >= MinChars)
                        found.Add(new StringLiteral(section.Rva + (uint)(pos + i), chars, wide ? StringEncoding.Utf16 : StringEncoding.Ascii));
                    i += bytes;
                }
                pos += Math.Max(next, 1);
            }
        }
        return found;
    }

    private static (int Chars, int Bytes, bool Wide) RunAt(ReadOnlySpan<byte> s, int i)
    {
        if (i + 1 < s.Length && Printable(s[i]) && s[i + 1] == 0)
        {
            int chars = 0, j = i;
            while (j + 1 < s.Length && chars < MaxChars && Printable(s[j]) && s[j + 1] == 0) { chars++; j += 2; }
            if (chars >= MinChars) return (chars, j - i, true);
        }
        if (!Printable(s[i])) return (0, 0, false);
        int len = 0;
        while (i + len < s.Length && len < MaxChars && Printable(s[i + len])) len++;
        return (len, len, false);
    }

    private static bool Printable(byte b) => b is >= 0x20 and < 0x7F or (byte)'\t';
}
