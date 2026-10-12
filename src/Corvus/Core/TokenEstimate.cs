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
    private const int HexNum = 2, HexDen = 3;         // 0x… or a hex word of 2+ characters with a digit
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
                // Each non-ASCII scalar (a surrogate pair is one).
                tokens++;
                i += char.IsHighSurrogate(ch) && i + 1 < n && char.IsLowSurrogate(text[i + 1]) ? 2 : 1;
            }
        }
        return (int)Math.Min(tokens, int.MaxValue);
    }

    /// <summary>A run of ASCII letters and digits.</summary>
    private static long Word(ReadOnlySpan<char> w)
    {
        if (IsHexWord(w)) return Ceil(w.Length, HexNum, HexDen);
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
                    tokens += Ceil(m - k, LowerNum, LowerDen);
                }
                else tokens += Ceil(m - k, UpperNum, UpperDen);
            }
            else
            {
                while (m < n && char.IsAsciiLetterLower(w[m])) m++;
                tokens += Ceil(m - k, LowerNum, LowerDen);
            }
            k = m;
        }
        return tokens;
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
