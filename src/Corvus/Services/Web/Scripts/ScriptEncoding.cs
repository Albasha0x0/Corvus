using System.Text;
using System.Text.RegularExpressions;

namespace Corvus.Services.Web.Scripts;

/// <summary>Decodes Windows Script Encoder text (#@~^ ... ^#~@) back to the script it encodes.</summary>
public static class ScriptEncoding
{
    // Script Encoder substitution values, keyed by encoded character; checked against the
    // worked example of the published decoder manual.
    internal static readonly Dictionary<int, string> Table = new()
    {
        [9] = "Wn{",
        [32] = ".-2",
        [33] = "Gu0",
        [34] = "zR!",
        [35] = "V`)",
        [36] = "Bq[",
        [37] = "j^8",
        [38] = "/I3",
        [39] = "&\\=",
        [40] = "IbX",
        [41] = "A}:",
        [42] = "4)5",
        [43] = "26e",
        [44] = "[ 9",
        [45] = "v|\\",
        [46] = "rzV",
        [47] = "C\u007Fs",
        [48] = "8kf",
        [49] = "9cN",
        [50] = "p3E",
        [51] = "E+k",
        [52] = "hhb",
        [53] = "qQY",
        [54] = "Ofx",
        [55] = "\u0009v^",
        [56] = "b1}",
        [57] = "DdJ",
        [58] = "#Tm",
        [59] = "uCq",
        [60] = "JLA",
        [61] = "~:`",
        [62] = "JLA",
        [63] = "^~S",
        [64] = "@L@",
        [65] = "wEB",
        [66] = "J,'",
        [67] = "a*H",
        [68] = "]tr",
        [69] = "\"'u",
        [70] = "K71",
        [71] = "oD7",
        [72] = "NyM",
        [73] = ";YR",
        [74] = "L/\"",
        [75] = "PoT",
        [76] = "g&j",
        [77] = "*rG",
        [78] = "}jd",
        [79] = "t9-",
        [80] = "T{ ",
        [81] = "+?\u007F",
        [82] = "-8.",
        [83] = ",wL",
        [84] = "0g]",
        [85] = "nS~",
        [86] = "kGl",
        [87] = "f4o",
        [88] = "5xy",
        [89] = "%]t",
        [90] = "!0C",
        [91] = "d#&",
        [92] = "MZv",
        [93] = "R[%",
        [94] = "cl$",
        [95] = "?H+",
        [96] = "{U(",
        [97] = "xp#",
        [98] = ")iA",
        [99] = "(.4",
        [100] = "sL\u0009",
        [101] = "Y!*",
        [102] = "3$D",
        [103] = "\u007FN?",
        [104] = "mPw",
        [105] = "U\u0009;",
        [106] = "SVU",
        [107] = "|si",
        [108] = ":5a",
        [109] = "_ac",
        [110] = "eKP",
        [111] = "FXg",
        [112] = "X;Q",
        [113] = "1WI",
        [114] = "i\"O",
        [115] = "lmF",
        [116] = "ZMh",
        [117] = "H%|",
        [118] = "'(6",
        [119] = "\\Fp",
        [120] = "=Jn",
        [121] = "$2z",
        [122] = "yA/",
        [123] = "7=_",
        [124] = "`_K",
        [125] = "QOZ",
        [126] = " B,",
        [127] = "6eW",
    };

    internal static readonly byte[] Pick = [0, 1, 2, 0, 1, 2, 1, 2, 2, 1, 2, 1, 0, 2, 1, 2, 0, 2, 1, 2, 0, 0, 1, 2, 2, 1, 0, 2, 1, 2, 2, 1, 0, 0, 2, 1, 2, 1, 2, 0, 2, 0, 0, 1, 2, 0, 2, 1, 0, 2, 1, 2, 0, 0, 1, 2, 2, 0, 0, 1, 2, 0, 2, 1];

    // The header and trailer values are a length and a checksum; decoding needs neither.
    private static readonly Regex Encoded = new(@"#@~\^[A-Za-z0-9+/]{6}==(.*?)[A-Za-z0-9+/]{6}==\^#~@", RegexOptions.Singleline | RegexOptions.NonBacktracking);

    /// <summary>The text with each encoded block replaced by its script; <paramref name="blocks"/> counts them. Text without a block is returned unchanged.</summary>
    public static string Decode(string text, out int blocks)
    {
        int n = 0;
        if (!text.Contains("#@~^", StringComparison.Ordinal)) { blocks = 0; return text; }
        var result = Encoded.Replace(text, m => { n++; return DecodeBody(m.Groups[1].Value); });
        blocks = n;
        return result;
    }

    private static string DecodeBody(string body)
    {
        var sb = new StringBuilder(body.Length);
        int index = -1;
        for (int i = 0; i < body.Length; i++)
        {
            char c = body[i];
            if (c == '@' && i + 1 < body.Length && "&#*!$".Contains(body[i + 1]))
            {
                index++;
                sb.Append(body[++i] switch { '&' => '\n', '#' => '\r', '*' => '>', '!' => '<', _ => '@' });
                continue;
            }
            if (c < 128) index++;
            bool mapped = c is not ('<' or '>' or '@') && Table.ContainsKey(c);
            sb.Append(mapped ? Table[c][Pick[index % 64]] : c);
        }
        return sb.ToString();
    }
}
