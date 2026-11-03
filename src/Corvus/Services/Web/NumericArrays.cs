namespace Corvus.Services.Web;

/// <summary>Reads byte arrays written as numeric literals in script text; nothing runs.</summary>
internal static class NumericArrays
{
    /// <summary>A list at or under this many values is not read.</summary>
    public const int MinValues = 4097;

    private const int MaxArrays = 8;
    private const int MaxTotalBytes = 16 * 1024 * 1024;
    private const string Call = "fromCharCode";

    /// <summary>
    /// The bracketed lists and <c>fromCharCode</c> argument lists of integers
    /// 0-255 over <see cref="MinValues"/> values; empty when none, a list with
    /// any other element is skipped, and at most 8 arrays or 16 MiB return.
    /// </summary>
    public static IReadOnlyList<byte[]> Find(string code, CancellationToken ct)
    {
        var found = new List<byte[]>();
        long total = 0;
        int i = 0;
        while (i < code.Length && found.Count < MaxArrays)
        {
            ct.ThrowIfCancellationRequested();
            int start;
            char close;
            if (code[i] == '[') { start = i + 1; close = ']'; }
            else if (code[i] == 'f' && string.CompareOrdinal(code, i, Call, 0, Call.Length) == 0)
            {
                int p = SkipSpace(code, i + Call.Length);
                if (p >= code.Length || code[p] != '(') { i++; continue; }
                start = p + 1;
                close = ')';
            }
            else { i++; continue; }

            var bytes = new List<byte>();
            int end = Parse(code, start, close, bytes, MaxTotalBytes - total, ct);
            if (end > 0 && bytes.Count >= MinValues)
            {
                found.Add(bytes.ToArray());
                total += bytes.Count;
            }
            i = Math.Max(i + 1, Math.Abs(end));
        }
        return found;
    }

    // Returns the index after the closing character when the list is valid,
    // else the negated index where reading stopped.
    private static int Parse(string s, int p, char close, List<byte> values, long room, CancellationToken ct)
    {
        while (true)
        {
            p = SkipSpace(s, p);
            if (p >= s.Length) return -p;
            if (s[p] == close) return values.Count > 0 ? p + 1 : -p;
            if (!Number(s, ref p, out int value)) return -p;
            if (value > 255 || values.Count >= room) return -p;
            values.Add((byte)value);
            if ((values.Count & 0xFFF) == 0) ct.ThrowIfCancellationRequested();
            p = SkipSpace(s, p);
            if (p >= s.Length) return -p;
            if (s[p] == ',') { p++; continue; }
            return s[p] == close ? p + 1 : -p;
        }
    }

    // A decimal without a leading zero, or 0x followed by hex digits.
    private static bool Number(string s, ref int p, out int value)
    {
        value = 0;
        int q = p;
        if (s[q] == '0' && q + 1 < s.Length && (s[q + 1] is 'x' or 'X'))
        {
            q += 2;
            int digits = q;
            while (q < s.Length && Uri.IsHexDigit(s[q]))
            {
                value = value * 16 + Convert.ToInt32(s[q].ToString(), 16);
                if (value > 255) return false;
                q++;
            }
            if (q == digits) return false;
        }
        else
        {
            int digits = q;
            while (q < s.Length && s[q] is >= '0' and <= '9')
            {
                value = value * 10 + (s[q] - '0');
                if (value > 255) return false;
                q++;
            }
            if (q == digits || (s[digits] == '0' && q - digits > 1)) return false;
        }
        if (q < s.Length && (char.IsLetterOrDigit(s[q]) || s[q] is '.' or '_')) return false;
        p = q;
        return true;
    }

    private static int SkipSpace(string s, int p)
    {
        while (p < s.Length && char.IsWhiteSpace(s[p])) p++;
        return p;
    }
}
