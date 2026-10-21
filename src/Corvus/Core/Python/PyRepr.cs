using System.Globalization;
using System.Numerics;
using System.Text;

namespace Corvus.Core.Python;

/// <summary>Python's repr() of marshalled constants, as Python 2 or 3 prints them; a code object's address is left out.</summary>
internal static partial class PyRepr
{
    public static string Of(object? o, (int Major, int Minor) version)
    {
        var sb = new StringBuilder();
        Append(sb, o, version);
        return sb.ToString();
    }

    private static void Append(StringBuilder sb, object? o, (int Major, int Minor) v)
    {
        bool py2 = v.Major == 2;
        switch (o)
        {
            case null: sb.Append("<NULL>"); break;
            case PySingleton s when s == PySingleton.StopIteration: sb.Append(py2 ? "<type 'exceptions.StopIteration'>" : "<class 'StopIteration'>"); break;
            case PySingleton s: sb.Append(s.Name); break;
            case bool b: sb.Append(b ? "True" : "False"); break;
            case long l: sb.Append(l.ToString(CultureInfo.InvariantCulture)); break;
            case BigInteger big: sb.Append(big.ToString(CultureInfo.InvariantCulture)).Append(py2 ? "L" : ""); break;
            case double d: sb.Append(Float(d, dot0: true)); break;
            case PyComplex c: Complex(sb, c); break;
            case string s: Text(sb, s, v); break;
            case PyBytes b: Bytes(sb, b.Value, prefix: !py2); break;
            case PySequence { Kind: '(' } t:
                sb.Append('(');
                Items(sb, t.Items, v);
                sb.Append(t.Items.Length == 1 ? ",)" : ")");
                break;
            case PySequence { Kind: '[' } l:
                sb.Append('[');
                Items(sb, l.Items, v);
                sb.Append(']');
                break;
            case PySequence set:
                var kind = set.Kind == '>' ? "frozenset" : "set";
                if (py2) { sb.Append(kind).Append("(["); Items(sb, set.Items, v); sb.Append("])"); }
                else if (set.Items.Length == 0) sb.Append(kind).Append("()");
                else if (set.Kind == '>') { sb.Append("frozenset({"); Items(sb, set.Items, v); sb.Append("})"); }
                else { sb.Append('{'); Items(sb, set.Items, v); sb.Append('}'); }
                break;
            case PyDict dict:
                sb.Append('{');
                for (int i = 0; i < dict.Items.Count; i++)
                {
                    if (i > 0) sb.Append(", ");
                    Append(sb, dict.Items[i].Key, v);
                    sb.Append(": ");
                    Append(sb, dict.Items[i].Value, v);
                }
                sb.Append('}');
                break;
            case PySlice slice:
                sb.Append("slice(");
                Items(sb, [slice.Start, slice.Stop, slice.Step], v);
                sb.Append(')');
                break;
            case PyCode code:
                sb.Append("<code object ").Append(code.Name).Append(", file \"").Append(code.Filename).Append("\", line ")
                    .Append(code.FirstLineNo.ToString(CultureInfo.InvariantCulture)).Append('>');
                break;
            default: sb.Append(o); break;
        }
    }

    private static void Items(StringBuilder sb, object[] items, (int Major, int Minor) v)
    {
        for (int i = 0; i < items.Length; i++)
        {
            if (i > 0) sb.Append(", ");
            Append(sb, items[i], v);
        }
    }

    /// <summary>A str (a unicode in Python 2): the quote it does not contain, escapes for what is not printable.</summary>
    private static void Text(StringBuilder sb, string s, (int Major, int Minor) v)
    {
        bool py2 = v.Major == 2;
        char quote = s.Contains('\'') && !s.Contains('"') ? '"' : '\'';
        if (py2) sb.Append('u');
        sb.Append(quote);
        for (int k = 0; k < s.Length; k++)
        {
            // a lone surrogate (marshal's surrogatepass) is no rune: it prints escaped
            int c = char.IsSurrogatePair(s, k) ? char.ConvertToUtf32(s[k], s[++k]) : s[k];
            if (c == quote || c == '\\') sb.Append('\\').Append((char)c);
            else if (c == '\t') sb.Append("\\t");
            else if (c == '\n') sb.Append("\\n");
            else if (c == '\r') sb.Append("\\r");
            else if (c < ' ' || c == 0x7F || py2 && c > 0x7F || !py2 && c > 0x7F && !Printable(c, v))
                sb.Append(c <= 0xFF ? $"\\x{c:x2}" : c <= 0xFFFF ? $"\\u{c:x4}" : $"\\U{c:x8}");
            else sb.Append(char.ConvertFromUtf32(c));
        }
        sb.Append(quote);
    }

    /// <summary>Python's str.isprintable() for one character: every category but separators (except the space), controls, formats, surrogates, private use and unassigned.</summary>
    private static bool Printable(int c, (int Major, int Minor) v) => c == ' ' || Rune.IsValid(c) && Rune.GetUnicodeCategory(new Rune(c)) is not (UnicodeCategory.Control
        or UnicodeCategory.Format or UnicodeCategory.Surrogate or UnicodeCategory.PrivateUse or UnicodeCategory.OtherNotAssigned or UnicodeCategory.LineSeparator
        or UnicodeCategory.ParagraphSeparator or UnicodeCategory.SpaceSeparator) && Age(c) <= UnicodeOf(v);

    /// <summary>The Unicode version of each Python's character database (major * 10 + minor); 3.7 and before share 12.1's cut.</summary>
    private static int UnicodeOf((int Major, int Minor) v) => v.Minor switch { >= 13 => 151, 12 => 150, 11 => 140, 9 or 10 => 130, _ => 121 };

    private static readonly Lazy<(int First, int Last, int Age)[]> Recent = new(() => [.. RecentCharacters.Split(' ').Select(t =>
    {
        var (range, age) = (t[..t.IndexOf(':')], int.Parse(t[(t.IndexOf(':') + 1)..], CultureInfo.InvariantCulture));
        var ends = range.Split('-');
        return (int.Parse(ends[0], NumberStyles.HexNumber, CultureInfo.InvariantCulture), int.Parse(ends[^1], NumberStyles.HexNumber, CultureInfo.InvariantCulture), age);
    })]);

    /// <summary>The Unicode version that assigned <paramref name="c"/>, for characters from 13.0 on; 0 for older ones.</summary>
    private static int Age(int c)
    {
        var ranges = Recent.Value;
        int lo = 0, hi = ranges.Length - 1;
        while (lo <= hi)
        {
            int mid = (lo + hi) / 2;
            if (c < ranges[mid].First) hi = mid - 1;
            else if (c > ranges[mid].Last) lo = mid + 1;
            else return ranges[mid].Age;
        }
        return 0;
    }

    private static void Bytes(StringBuilder sb, byte[] b, bool prefix)
    {
        bool single = b.Contains((byte)'\''), dbl = b.Contains((byte)'"');
        char quote = single && !dbl ? '"' : '\'';
        if (prefix) sb.Append('b');
        sb.Append(quote);
        foreach (var c in b)
        {
            if (c == quote || c == '\\') sb.Append('\\').Append((char)c);
            else if (c == '\t') sb.Append("\\t");
            else if (c == '\n') sb.Append("\\n");
            else if (c == '\r') sb.Append("\\r");
            else if (c < ' ' || c >= 0x7F) sb.Append($"\\x{c:x2}");
            else sb.Append((char)c);
        }
        sb.Append(quote);
    }

    private static void Complex(StringBuilder sb, PyComplex c)
    {
        // a +0.0 real part prints the imaginary part alone, without parentheses
        if (c.Real == 0 && !double.IsNegative(c.Real))
        {
            sb.Append(Float(c.Imaginary, dot0: false)).Append('j');
            return;
        }
        var im = Float(c.Imaginary, dot0: false);
        sb.Append('(').Append(Float(c.Real, dot0: false)).Append(im[0] == '-' ? "" : "+").Append(im).Append("j)");
    }

    /// <summary>repr() of a float: the shortest digits that read back, in exponent form below 1e-4 and from 1e16; <paramref name="dot0"/> adds ".0" to whole numbers.</summary>
    internal static string Float(double d, bool dot0)
    {
        if (double.IsNaN(d)) return "nan";
        if (double.IsInfinity(d)) return d > 0 ? "inf" : "-inf";
        var sign = double.IsNegative(d) ? "-" : "";
        if (d == 0) return sign + (dot0 ? "0.0" : "0");
        var r = Math.Abs(d).ToString("R", CultureInfo.InvariantCulture);
        int exp = 0;
        if (r.IndexOf('E') is var e and >= 0)
        {
            exp = int.Parse(r[(e + 1)..], NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture);
            r = r[..e];
        }
        int dot = r.IndexOf('.');
        var digits = dot >= 0 ? r.Remove(dot, 1) : r;
        int point = (dot >= 0 ? dot : r.Length) + exp; // digits are 0.d1d2... times 10^point
        int lead = 0;
        while (lead < digits.Length - 1 && digits[lead] == '0') lead++;
        digits = digits[lead..].TrimEnd('0');
        point -= lead;
        if (digits.Length == 0) digits = "0";
        if (point <= -4 || point > 16)
        {
            int x = point - 1;
            return sign + digits[0] + (digits.Length > 1 ? "." + digits[1..] : "") + "e" + (x < 0 ? "-" : "+") + Math.Abs(x).ToString("00", CultureInfo.InvariantCulture);
        }
        if (point <= 0) return sign + "0." + new string('0', -point) + digits;
        if (point >= digits.Length) return sign + digits + new string('0', point - digits.Length) + (dot0 ? ".0" : "");
        return sign + digits[..point] + "." + digits[point..];
    }
}
