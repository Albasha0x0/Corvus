namespace Corvus.Core;

/// <summary>
/// Estimated model tokens of a text (STANDARDS S1.2): one pass over character classes, no allocation. Calibrated on
/// tests/Corvus.Tests/TokenCorpus to stay above the recorded counts (TokenEstimateCalibrationTests).
/// </summary>
public static class TokenEstimate
{
    // Characters per token as a fraction (num/den) for each class.
    private const int LowerNum = 1, LowerDen = 8;     // a lowercase run, with the capital that starts it
    private const int UpperNum = 1, UpperDen = 2;     // a run of capitals not followed by lowercase
    private const int DigitNum = 1, DigitDen = 2;
    private const int HexNum = 2, HexDen = 3;         // a hex word of 2+ characters with a digit (bytes, tokens)
    private const int AddressNum = 4, AddressDen = 5; // 0x…: addresses mix digits and letters, which split
    private const int PunctNum = 1, PunctDen = 2;     // a run of ASCII symbols
    private const int SpaceNum = 1, SpaceDen = 8;     // a run of spaces and tabs

    public static int Of(string? text) => text == null ? 0 : Of(text.AsSpan());

    public static int Of(ReadOnlySpan<char> text)
    {
        long tokens = 0;
        int n = text.Length, i = 0;
        while (i < n)
        {
            char ch = text[i];
            if (ch == '\n')
            {
                tokens++;
                i++;
            }
            else if (ch == '\r')
            {
                tokens++;
                i += i + 1 < n && text[i + 1] == '\n' ? 2 : 1;
            }
            else if (ch is ' ' or '\t')
            {
                int j = i;
                while (j < n && text[j] is ' ' or '\t') j++;
                // One space before a word is part of that word's token.
                int run = j < n && IsWord(text[j]) ? j - i - 1 : j - i;
                tokens += Ceil(run, SpaceNum, SpaceDen);
                i = j;
            }
            else if (IsWord(ch))
            {
                int j = i;
                while (j < n && IsWord(text[j])) j++;
                tokens += Word(text[i..j]);
                i = j;
            }
            else if (ch < 128)
            {
                int j = i;
                while (j < n && text[j] < 128 && !IsWord(text[j]) && text[j] is not (' ' or '\t' or '\r' or '\n')) j++;
                int run = j - i;
                // Quotes around an identifier count with it: "name" is a word.
                if (ch == '"' && i > 0 && IsWord(text[i - 1])) run--;
                if (run > 0 && text[j - 1] == '"' && j < n && IsLetter(text[j])) run--;
                tokens += Ceil(run, PunctNum, PunctDen);
                i = j;
            }
            else
            {
                // Each non-ASCII scalar (a surrogate pair is one); from U+0800 (three UTF-8 bytes) two, as rare CJK and the
                // text of misread UTF-16 data split into byte tokens.
                tokens += ch < 'ࠀ' ? 1 : 2;
                i += char.IsHighSurrogate(ch) && i + 1 < n && char.IsLowSurrogate(text[i + 1]) ? 2 : 1;
            }
        }
        return (int)Math.Min(tokens, int.MaxValue);
    }

    /// <summary>A run of ASCII letters and digits.</summary>
    private static long Word(ReadOnlySpan<char> w)
    {
        if (IsHexWord(w)) return w.Length > 2 && w[1] is 'x' or 'X' ? Ceil(w.Length, AddressNum, AddressDen) : Ceil(w.Length, HexNum, HexDen);
        long tokens = 0;
        int n = w.Length, k = 0;
        while (k < n)
        {
            int m = k;
            if (char.IsAsciiDigit(w[k]))
            {
                while (m < n && char.IsAsciiDigit(w[m])) m++;
                tokens += Ceil(m - k, DigitNum, DigitDen);
            }
            else if (char.IsAsciiLetterUpper(w[k]))
            {
                while (m < n && char.IsAsciiLetterUpper(w[m])) m++;
                if (m < n && char.IsAsciiLetterLower(w[m]))
                {
                    // The last capital starts the lowercase piece after it (camel case: Get|Type|Info, XML|Reader).
                    tokens += Ceil(m - k - 1, UpperNum, UpperDen);
                    k = m - 1;
                    while (m < n && char.IsAsciiLetterLower(w[m])) m++;
                    tokens += Letters(w[k..m]);
                }
                else tokens += Ceil(m - k, UpperNum, UpperDen);
            }
            else
            {
                while (m < n && char.IsAsciiLetterLower(w[m])) m++;
                tokens += Letters(w[k..m]);
            }
            k = m;
        }
        return tokens;
    }

    /// <summary>
    /// A lowercase piece (with the capital that starts it): a word costs one token per 8 letters up to 8, then one per 3 (a
    /// longer run is several words: Go's packed string tables); a piece that does not read as a word one per 2.
    /// </summary>
    private static long Letters(ReadOnlySpan<char> p)
    {
        if (Unpronounceable(p)) return Ceil(p.Length, 1, 2);
        return p.Length <= LongRun ? Ceil(p.Length, LowerNum, LowerDen) : 1 + Ceil(p.Length - LongRun, 1, 3);
    }

    private const int LongRun = 8;

    /// <summary>No vowel, four consonants in a row, or three at the start that start no English word: tokenizers split it.</summary>
    private static bool Unpronounceable(ReadOnlySpan<char> p)
    {
        if (p.Length < 3) return false;
        int run = 0;
        bool start = true;
        for (int i = 0; i <= p.Length; i++)
        {
            if (i < p.Length && char.ToLowerInvariant(p[i]) is not ('a' or 'e' or 'i' or 'o' or 'u' or 'y'))
            {
                run++;
                continue;
            }
            if (i == p.Length && start) return true;
            var cluster = p.Slice(i - run, run);
            if (run >= 4 && !Cluster(cluster) || start && run >= 3 && !Cluster(cluster)) return true;
            run = 0;
            start = false;
        }
        return false;
    }

    /// <summary>Consonant runs English words have: an onset (str, thr), or length, constructor, angstrom.</summary>
    private static bool Cluster(ReadOnlySpan<char> s)
    {
        if (s.Length > 5) return false;
        Span<char> lower = stackalloc char[5];
        s.ToLowerInvariant(lower);
        return lower[..s.Length] is "str" or "spr" or "scr" or "spl" or "thr" or "chr" or "sch" or "shr" or "phr" or "sph"
            or "ngth" or "ngths" or "nstr" or "rstr" or "ngst" or "mpts" or "ntts" or "rths";
    }

    private static bool IsHexWord(ReadOnlySpan<char> w)
    {
        if (w.Length > 2 && w[0] == '0' && w[1] is 'x' or 'X') return true;
        if (w.Length < 2) return false;
        bool digit = false;
        foreach (char c in w)
        {
            if (!char.IsAsciiHexDigit(c)) return false;
            digit |= char.IsAsciiDigit(c);
        }
        return digit;
    }

    private static bool IsLetter(char c) => char.IsAsciiLetter(c);

    private static bool IsWord(char c) => char.IsAsciiLetterOrDigit(c);

    private static long Ceil(int count, int num, int den) => count <= 0 ? 0 : ((long)count * num + den - 1) / den;
}
