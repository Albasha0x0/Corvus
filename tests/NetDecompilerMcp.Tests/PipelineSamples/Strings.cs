// A .NET Framework program for the pipeline round trip (PipelineRoundTripTests): string and formatting work -
// StringBuilder, composite and interpolated formatting, numeric format specifiers, padding,
// split/join/replace/search, char handling, ordinal vs invariant comparison, UTF-8/UTF-16/Base64 round trips,
// non-ASCII literals and a small tokenizer/evaluator; its output depends only on its code.
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace Strings
{
    enum TokenKind { Number, Ident, Op, LParen, RParen }

    struct Token
    {
        public TokenKind Kind;
        public string Text;
        public Token(TokenKind kind, string text) { Kind = kind; Text = text; }
        public override string ToString()
        {
            switch (Kind)
            {
                case TokenKind.Number: return "N:" + Text;
                case TokenKind.Ident: return "I:" + Text;
                case TokenKind.Op: return "O:" + Text;
                default: return "P:" + Text;
            }
        }
    }

    sealed class Evaluator
    {
        readonly List<Token> tokens;
        readonly Dictionary<string, long> vars;
        int pos;

        public Evaluator(List<Token> tokens, Dictionary<string, long> vars) { this.tokens = tokens; this.vars = vars; }

        public static List<Token> Tokenize(string s)
        {
            var list = new List<Token>();
            int i = 0;
            while (i < s.Length)
            {
                char c = s[i];
                if (char.IsWhiteSpace(c)) { i++; continue; }
                int start = i;
                if (char.IsDigit(c))
                {
                    while (i < s.Length && char.IsDigit(s[i])) i++;
                    list.Add(new Token(TokenKind.Number, s.Substring(start, i - start)));
                }
                else if (char.IsLetter(c) || c == '_')
                {
                    while (i < s.Length && (char.IsLetterOrDigit(s[i]) || s[i] == '_')) i++;
                    list.Add(new Token(TokenKind.Ident, s.Substring(start, i - start)));
                }
                else if (c == '(') { list.Add(new Token(TokenKind.LParen, "(")); i++; }
                else if (c == ')') { list.Add(new Token(TokenKind.RParen, ")")); i++; }
                else if ("+-*/%^".IndexOf(c) >= 0) { list.Add(new Token(TokenKind.Op, c.ToString())); i++; }
                else throw new FormatException("unexpected char at " + i);
            }
            return list;
        }

        public long Parse() { pos = 0; long v = Sum(); if (pos != tokens.Count) throw new FormatException("trailing"); return v; }

        long Sum()
        {
            long v = Product();
            while (pos < tokens.Count && tokens[pos].Kind == TokenKind.Op && (tokens[pos].Text == "+" || tokens[pos].Text == "-"))
            {
                string op = tokens[pos++].Text;
                long r = Product();
                v = op == "+" ? v + r : v - r;
            }
            return v;
        }

        long Product()
        {
            long v = Power();
            while (pos < tokens.Count && tokens[pos].Kind == TokenKind.Op && "*/%".Contains(tokens[pos].Text))
            {
                char op = tokens[pos++].Text[0];
                long r = Power();
                switch (op)
                {
                    case '*': v *= r; break;
                    case '/': v /= r; break;
                    default: v %= r; break;
                }
            }
            return v;
        }

        long Power()
        {
            long b = Atom();
            if (pos < tokens.Count && tokens[pos].Text == "^")
            {
                pos++;
                long e = Power();
                long r = 1;
                for (long k = 0; k < e; k++) r *= b;
                return r;
            }
            return b;
        }

        long Atom()
        {
            Token t = tokens[pos++];
            switch (t.Kind)
            {
                case TokenKind.Number: return long.Parse(t.Text, CultureInfo.InvariantCulture);
                case TokenKind.Ident: return vars[t.Text];
                case TokenKind.LParen: { long v = Sum(); pos++; return v; }
                case TokenKind.Op: if (t.Text == "-") return -Atom(); break;
            }
            throw new FormatException("bad token " + t);
        }
    }

    static class Program
    {
        static readonly CultureInfo Inv = CultureInfo.InvariantCulture;

        static string Hex(byte[] bytes)
        {
            var sb = new StringBuilder(bytes.Length * 2);
            foreach (byte b in bytes) sb.Append(b.ToString("x2", Inv));
            return sb.ToString();
        }

        static string CodePoints(string s)
        {
            var sb = new StringBuilder();
            for (int i = 0; i < s.Length; i++)
            {
                int cp = char.ConvertToUtf32(s, i);
                if (char.IsHighSurrogate(s[i])) i++;
                if (sb.Length > 0) sb.Append(' ');
                sb.Append("U+").Append(cp.ToString("X4", Inv));
            }
            return sb.ToString();
        }

        static uint Fnv(string s)
        {
            uint h = 2166136261;
            foreach (char c in s) { h ^= c; h = unchecked(h * 16777619); }
            return h;
        }

        static int Main()
        {
            // StringBuilder manipulation
            var sb = new StringBuilder("hello");
            sb.Append(' ').Append("world").Insert(0, ">> ").Replace('o', '0').Remove(3, 1).AppendFormat(Inv, " [{0:D3}]", 7);
            sb[0] = '#';
            Console.WriteLine("sb: " + sb + " len=" + sb.Length);

            // Composite formatting with alignment
            string[] names = { "alpha", "beta", "gamma", "delta" };
            double[] amounts = { 1234.5, -0.125, 98765.4321, 0 };
            for (int i = 0; i < names.Length; i++)
                Console.WriteLine(string.Format(Inv, "|{0,-6}|{1,12:N2}|{2,8:F1}|{3,-5:X}|", names[i], amounts[i], amounts[i] / 3, (i + 1) * 4099));

            int n = 255; long big = 9876543210L; double d = 0.0123456; decimal m = 1234567.891m;
            Console.WriteLine(string.Format(Inv, "fmt: {0:X} {0:x4} {0:D8} {1:N0} {1:E3} {2:P2} {2:F5} {3:C2}", n, big, d, m).Replace("\u00A4", "$"));
            Console.WriteLine(string.Format(Inv, "custom: {0:#,##0.00;(#,##0.00);zero} {1:#,##0.00;(#,##0.00);zero} {2:#,##0.00;(#,##0.00);zero} {3:000.##} {4:0.0e+00}", 4321.567, -98.1, 0.0, 3.14159, 123456.0));
            FormattableString fs = $"interp: {n,5}|{d:F3}|{big:N0}|{names[1].ToUpperInvariant()}|{(n > 100 ? "big" : "small")}";
            Console.WriteLine(fs.ToString(Inv));
            Console.WriteLine("pad: [" + "7".PadLeft(4, '0') + "][" + "ab".PadRight(5, '.') + "][" + "xyz".PadLeft(2) + "]");

            // Split / Join / Replace / Substring / IndexOf
            string csv = "id=4;name=Widget;;tags=a,b,c;price=12.50;note= spaced out ";
            string[] parts = csv.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries);
            Console.WriteLine("split count=" + parts.Length + " raw=" + csv.Split(';').Length);
            var kv = new SortedDictionary<string, string>(StringComparer.Ordinal);
            foreach (string p in parts)
            {
                int eq = p.IndexOf('=');
                kv[p.Substring(0, eq)] = p.Substring(eq + 1).Trim();
            }
            foreach (var pair in kv) Console.WriteLine("  " + pair.Key + " -> '" + pair.Value + "'");
            Console.WriteLine("join: " + string.Join("|", kv["tags"].Split(',')) + " rev=" + string.Join("", ReverseWords("the quick brown fox")));
            string text = "she sells sea shells by the sea shore";
            int count = 0, idx = -1;
            while ((idx = text.IndexOf("se", idx + 1, StringComparison.Ordinal)) >= 0) count++;
            Console.WriteLine("indexof: count=" + count + " last=" + text.LastIndexOf("sea", StringComparison.Ordinal) + " any=" + text.IndexOfAny(new[] { 'y', 'z' }) + " replaced=" + text.Replace("sea", "SEA").Replace(" ", ""));
            Console.WriteLine("starts=" + text.StartsWith("she", StringComparison.Ordinal) + " ends=" + text.EndsWith("ShOrE", StringComparison.OrdinalIgnoreCase) + " contains=" + text.Contains("shell"));

            // Char manipulation: Caesar shift and classification
            string plain = "Hello, World 2024!";
            var shifted = new char[plain.Length];
            int letters = 0, digits = 0, punct = 0, upper = 0;
            for (int i = 0; i < plain.Length; i++)
            {
                char c = plain[i];
                if (char.IsLetter(c))
                {
                    letters++;
                    char baseC = char.IsUpper(c) ? 'A' : 'a';
                    if (char.IsUpper(c)) upper++;
                    shifted[i] = (char)(baseC + (c - baseC + 13 + i) % 26);
                }
                else if (char.IsDigit(c)) { digits++; shifted[i] = (char)('0' + (c - '0' + 7) % 10); }
                else { if (char.IsPunctuation(c)) punct++; shifted[i] = c; }
            }
            Console.WriteLine("chars: " + new string(shifted) + " letters=" + letters + " digits=" + digits + " punct=" + punct + " upper=" + upper);

            // Ordinal vs invariant comparison
            string[] cmpA = { "apple", "Apple", "a-b", "\u00E9clair", "Zeta" };
            string[] cmpB = { "Apple", "apple", "ab", "eclair", "alpha" };
            for (int i = 0; i < cmpA.Length; i++)
            {
                int o = Math.Sign(string.CompareOrdinal(cmpA[i], cmpB[i]));
                int ic = Math.Sign(string.Compare(cmpA[i], cmpB[i], StringComparison.InvariantCulture));
                int oi = Math.Sign(string.Compare(cmpA[i], cmpB[i], StringComparison.OrdinalIgnoreCase));
                Console.WriteLine("cmp " + i + ": ordinal=" + o + " invariant=" + ic + " ordIgnore=" + oi + " eqInvIgnore=" + string.Equals(cmpA[i], cmpB[i], StringComparison.InvariantCultureIgnoreCase));
            }
            var sorted = new List<string>(cmpA);
            sorted.AddRange(cmpB);
            sorted.Sort(StringComparer.Ordinal);
            Console.WriteLine("ordinal sort: " + CodePoints(string.Join(",", sorted)).Length + " " + string.Join(",", sorted).Replace("\u00E9", "e'"));

            // Encodings, non-ASCII literals (printed as code points to keep console output ASCII)
            string uni = "caf\u00E9 \u65E5\u672C \U0001F600 \u03A9mega";
            string raw = "Größe";
            Console.WriteLine("unicode: len=" + uni.Length + " " + CodePoints(uni));
            Console.WriteLine("raw literal: " + CodePoints(raw) + " upper=" + CodePoints(raw.ToUpperInvariant()));
            byte[] utf8 = Encoding.UTF8.GetBytes(uni);
            byte[] utf16 = Encoding.Unicode.GetBytes(uni);
            Console.WriteLine("utf8 bytes=" + utf8.Length + " count=" + Encoding.UTF8.GetByteCount(raw) + " utf16 bytes=" + utf16.Length + " be=" + Encoding.BigEndianUnicode.GetByteCount(uni));
            Console.WriteLine("utf8 hex=" + Hex(utf8));
            Console.WriteLine("roundtrip utf8=" + (Encoding.UTF8.GetString(utf8) == uni) + " utf16=" + (Encoding.Unicode.GetString(utf16) == uni) + " ascii=" + Encoding.ASCII.GetString(Encoding.ASCII.GetBytes(raw)));
            string b64 = Convert.ToBase64String(utf8);
            Console.WriteLine("base64=" + b64 + " back=" + (Encoding.UTF8.GetString(Convert.FromBase64String(b64)) == uni));
            Console.WriteLine("base64 short: " + Convert.ToBase64String(new byte[] { 1 }) + " " + Convert.ToBase64String(new byte[] { 1, 2 }) + " " + Convert.ToBase64String(new byte[] { 1, 2, 3 }));

            // Verbatim strings
            string verbatim = @"C:\path\to\""file"".txt
second line	with tab";
            string[] vlines = verbatim.Replace("\r\n", "\n").Split('\n');
            Console.WriteLine("verbatim lines=" + vlines.Length + " first=" + vlines[0] + " tabAt=" + vlines[1].IndexOf('\t') + " quotes=" + (verbatim.Length - verbatim.Replace("\"", "").Length));

            // Tokenizer and evaluator
            var vars = new Dictionary<string, long> { { "x", 7 }, { "y", -3 }, { "rate_2", 12 } };
            string[] exprs = { "1 + 2 * 3", "(1 + 2) * 3", "2 ^ 3 ^ 2", "x * y - rate_2 / 5", "100 % 7 + -x", "((4))*(x+y)*2^4" };
            foreach (string e in exprs)
            {
                var toks = Evaluator.Tokenize(e);
                long value = new Evaluator(toks, vars).Parse();
                Console.WriteLine(string.Format(Inv, "expr {0,-20} = {1,6} tokens={2} [{3}]", e, value, toks.Count, string.Join(" ", toks)));
            }
            try { Evaluator.Tokenize("3 # 4"); }
            catch (FormatException fe) { Console.WriteLine("tokenize error: " + fe.Message); }

            // Repeated building with checksum
            var acc = new StringBuilder();
            uint hash = 0;
            for (int i = 0; i < 200; i++)
            {
                acc.Append(i.ToString("X", Inv));
                if (acc.Length > 40) { hash ^= Fnv(acc.ToString()); acc.Remove(0, 17); }
            }
            Console.WriteLine("build: tail=" + acc + " hash=" + hash.ToString("X8", Inv));
            Console.WriteLine("concat: " + string.Concat("a", 1, 'c', 2.5.ToString(Inv), true) + " " + string.Concat(new[] { "x", "y", "z" }) + " " + new string('=', 5));
            return 0;
        }

        static IEnumerable<string> ReverseWords(string s)
        {
            string[] w = s.Split(' ');
            for (int i = w.Length - 1; i >= 0; i--)
            {
                char[] arr = w[i].ToCharArray();
                Array.Reverse(arr);
                yield return new string(arr) + (i > 0 ? "_" : "");
            }
        }
    }
}
