using System.Globalization;
using System.Numerics;
using System.Text;

namespace Corvus.Native.Itanium;

/// <summary>Demangles Rust v0 (_R) symbol names into paths; text that is not v0 or is malformed yields null, no input throws.</summary>
public static class RustV0Demangler
{
    /// <summary>Deepest nesting of paths and types read.</summary>
    public const int MaxDepth = 128;

    /// <summary>Longest output, in characters.</summary>
    public const int MaxOutput = 8192;

    private const int MaxSteps = 1 << 20;

    private sealed class Bad : Exception;

    /// <summary>Whether <paramref name="name"/> starts like a v0 name: _R, then a version digit or a path tag.</summary>
    public static bool IsMangled(string? name) =>
        name is { Length: > 2 } && name[0] == '_' && name[1] == 'R'
        && (char.IsAsciiDigit(name[2]) || name[2] is 'C' or 'M' or 'X' or 'Y' or 'N' or 'I' or 'B');

    /// <summary>The path <paramref name="name"/> spells, or null when it is not a well-formed v0 name.</summary>
    public static string? Demangle(string? name)
    {
        if (!IsMangled(name) || name!.Length > ItaniumDemangler.MaxLength) return null;
        try
        {
            var p = new Reader(name);
            p.ParseTop();
            return p.Result;
        }
        catch (Bad) { return null; }
        catch (InsufficientExecutionStackException) { return null; }
    }

    private sealed class Reader(string s)
    {
        private readonly StringBuilder o = new();
        private int pos = 2;
        private int depth;
        private int steps;
        private int bound;
        private bool on = true;
        private bool endsGeneric;

        public string Result => o.ToString();

        public void ParseTop()
        {
            while (pos < s.Length && char.IsAsciiDigit(s[pos])) pos++;
            Path(false);
            if (pos < s.Length && s[pos] != '.')
            {
                var was = on;
                on = false;
                Path(false);
                on = was;
            }
            if (pos < s.Length && s[pos] != '.') throw new Bad();
        }

        private void Enter()
        {
            if (++depth > MaxDepth || ++steps > MaxSteps) throw new Bad();
            System.Runtime.CompilerServices.RuntimeHelpers.EnsureSufficientExecutionStack();
        }

        private void Emit(string text)
        {
            if (!on) return;
            o.Append(text);
            if (o.Length > MaxOutput) throw new Bad();
        }

        private char Peek() => pos < s.Length ? s[pos] : throw new Bad();

        private char Next() => pos < s.Length ? s[pos++] : throw new Bad();

        private long Base62()
        {
            if (Peek() == '_') { pos++; return 0; }
            long v = 0;
            while (true)
            {
                var c = Next();
                if (c == '_') return v + 1;
                var d = c switch
                {
                    >= '0' and <= '9' => c - '0',
                    >= 'a' and <= 'z' => c - 'a' + 10,
                    >= 'A' and <= 'Z' => c - 'A' + 36,
                    _ => throw new Bad(),
                };
                v = v * 62 + d;
                if (v > int.MaxValue) v = int.MaxValue;
            }
        }

        private long Disambiguator()
        {
            if (pos < s.Length && s[pos] == 's') { pos++; return Base62() + 1; }
            return 0;
        }

        private string Identifier()
        {
            var puny = false;
            if (Peek() == 'u') { pos++; puny = true; }
            if (!char.IsAsciiDigit(Peek())) throw new Bad();
            long len = 0;
            while (pos < s.Length && char.IsAsciiDigit(s[pos]))
            {
                len = len * 10 + (s[pos++] - '0');
                if (len > s.Length) throw new Bad();
            }
            if (pos < s.Length && s[pos] == '_') pos++;
            if (pos + len > s.Length) throw new Bad();
            var text = s.Substring(pos, (int)len);
            pos += (int)len;
            foreach (var c in text) if (c > 0x7f) throw new Bad();
            return puny ? Punycode(text) : text;
        }

        // RFC 3492 decoder; the basic code points precede the last underscore.
        private static string Punycode(string text)
        {
            var cut = text.LastIndexOf('_');
            var output = new List<int>();
            if (cut > 0) foreach (var c in text[..cut]) output.Add(c);
            var encoded = text[(cut + 1)..];
            const int baseN = 36, tMin = 1, tMax = 26, skew = 38, damp = 700;
            long n = 128, i = 0;
            var bias = 72;
            var at = 0;
            while (at < encoded.Length)
            {
                var oldI = i;
                long w = 1;
                for (var k = baseN; ; k += baseN)
                {
                    if (at >= encoded.Length) throw new Bad();
                    var c = encoded[at++];
                    var digit = c switch
                    {
                        >= 'a' and <= 'z' => c - 'a',
                        >= 'A' and <= 'Z' => c - 'A',
                        >= '0' and <= '9' => c - '0' + 26,
                        _ => throw new Bad(),
                    };
                    i += digit * w;
                    if (i > int.MaxValue) throw new Bad();
                    var t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
                    if (digit < t) break;
                    w *= baseN - t;
                    if (w > int.MaxValue) throw new Bad();
                }
                var count = output.Count + 1;
                var delta = oldI == 0 ? i / damp : (i - oldI) / 2;
                delta += delta / count;
                var kk = 0;
                while (delta > (baseN - tMin) * tMax / 2) { delta /= baseN - tMin; kk += baseN; }
                bias = (int)(kk + (baseN - tMin + 1) * delta / (delta + skew));
                n += i / count;
                i %= count;
                if (n > 0x10FFFF || n is >= 0xD800 and <= 0xDFFF) throw new Bad();
                output.Insert((int)i, (int)n);
                i++;
            }
            var sb = new StringBuilder();
            foreach (var cp in output) sb.Append(char.ConvertFromUtf32(cp));
            return sb.ToString();
        }

        // A back-reference counts from the first byte after the _R prefix.
        private void BackRef(Action read)
        {
            var at = pos - 1;
            var target = Base62() + 2;
            if (target >= at) throw new Bad();
            var back = pos;
            pos = (int)target;
            try { read(); }
            finally { pos = back; }
        }

        private void Path(bool inType)
        {
            Enter();
            try
            {
                var c = Next();
                var generic = false;
                switch (c)
                {
                    case 'C':
                        Disambiguator();
                        Emit(Identifier());
                        break;
                    case 'N':
                    {
                        var ns = Next();
                        if (!char.IsAsciiLetter(ns)) throw new Bad();
                        Path(inType);
                        var dis = Disambiguator();
                        var name = Identifier();
                        if (char.IsAsciiLetterUpper(ns))
                        {
                            var kind = ns == 'C' ? "closure" : ns == 'S' ? "shim" : ns.ToString();
                            Emit("::{" + kind + (name.Length > 0 ? ":" + name : "") + "#" + dis.ToString(CultureInfo.InvariantCulture) + "}");
                        }
                        else if (name.Length > 0) Emit("::" + name);
                        break;
                    }
                    case 'M':
                        ImplPath();
                        Emit("<");
                        Type();
                        Emit(">");
                        break;
                    case 'X':
                        ImplPath();
                        Emit("<");
                        Type();
                        Emit(" as ");
                        Path(true);
                        Emit(">");
                        break;
                    case 'Y':
                        Emit("<");
                        Type();
                        Emit(" as ");
                        Path(true);
                        Emit(">");
                        break;
                    case 'I':
                    {
                        Path(inType);
                        Emit(inType ? "<" : "::<");
                        var first = true;
                        while (Peek() != 'E')
                        {
                            if (!first) Emit(", ");
                            first = false;
                            GenericArg();
                        }
                        pos++;
                        Emit(">");
                        generic = true;
                        break;
                    }
                    case 'B':
                        BackRef(() => Path(inType));
                        generic = endsGeneric;
                        break;
                    default:
                        throw new Bad();
                }
                endsGeneric = generic;
            }
            finally { depth--; }
        }

        private void ImplPath()
        {
            Disambiguator();
            var was = on;
            on = false;
            Path(false);
            on = was;
        }

        private void GenericArg()
        {
            switch (Peek())
            {
                case 'L':
                    pos++;
                    Emit(Lifetime());
                    break;
                case 'K':
                    pos++;
                    Const();
                    break;
                default:
                    Type();
                    break;
            }
        }

        private string Lifetime()
        {
            var idx = Base62();
            if (idx == 0 || idx > bound) return "'_";
            var n = bound - (int)idx;
            return n < 26 ? "'" + (char)('a' + n) : "'_" + n.ToString(CultureInfo.InvariantCulture);
        }

        private static string? Basic(char c) => c switch
        {
            'a' => "i8", 'b' => "bool", 'c' => "char", 'd' => "f64", 'e' => "str", 'f' => "f32", 'h' => "u8", 'i' => "isize",
            'j' => "usize", 'l' => "i32", 'm' => "u32", 'n' => "i128", 'o' => "u128", 's' => "i16", 't' => "u16", 'u' => "()",
            'v' => "...", 'x' => "i64", 'y' => "u64", 'z' => "!", 'p' => "_", _ => null,
        };

        private void Binder()
        {
            if (Peek() != 'G') return;
            pos++;
            var n = Base62() + 1;
            if (n > 1024) throw new Bad();
            Emit("for<");
            for (var i = 0; i < n; i++)
            {
                if (i > 0) Emit(", ");
                var k = bound + i;
                Emit(k < 26 ? "'" + (char)('a' + k) : "'_" + k.ToString(CultureInfo.InvariantCulture));
            }
            Emit("> ");
            bound += (int)n;
        }

        private void Type()
        {
            Enter();
            try
            {
                var c = Peek();
                var basic = Basic(c);
                if (basic != null) { pos++; Emit(basic); return; }
                switch (c)
                {
                    case 'A':
                        pos++;
                        Emit("[");
                        Type();
                        Emit("; ");
                        Const();
                        Emit("]");
                        break;
                    case 'S':
                        pos++;
                        Emit("[");
                        Type();
                        Emit("]");
                        break;
                    case 'T':
                    {
                        pos++;
                        Emit("(");
                        var count = 0;
                        while (Peek() != 'E')
                        {
                            if (count++ > 0) Emit(", ");
                            Type();
                        }
                        pos++;
                        if (count == 1) Emit(",");
                        Emit(")");
                        break;
                    }
                    case 'R':
                    case 'Q':
                        pos++;
                        Emit("&");
                        if (Peek() == 'L')
                        {
                            pos++;
                            var lt = Lifetime();
                            if (lt != "'_") Emit(lt + " ");
                        }
                        if (c == 'Q') Emit("mut ");
                        Type();
                        break;
                    case 'P':
                        pos++;
                        Emit("*const ");
                        Type();
                        break;
                    case 'O':
                        pos++;
                        Emit("*mut ");
                        Type();
                        break;
                    case 'F':
                        pos++;
                        FnType();
                        break;
                    case 'D':
                        pos++;
                        DynBounds();
                        break;
                    case 'B':
                        pos++;
                        BackRef(Type);
                        break;
                    default:
                        Path(true);
                        break;
                }
            }
            finally { depth--; }
        }

        private void FnType()
        {
            var saved = bound;
            Binder();
            if (Peek() == 'U') { pos++; Emit("unsafe "); }
            if (Peek() == 'K')
            {
                pos++;
                string abi;
                if (Peek() == 'C') { pos++; abi = "C"; }
                else abi = Identifier().Replace('_', '-');
                Emit("extern \"" + abi + "\" ");
            }
            Emit("fn(");
            var count = 0;
            while (Peek() != 'E')
            {
                if (count++ > 0) Emit(", ");
                Type();
            }
            pos++;
            Emit(")");
            if (Peek() == 'u') pos++;
            else
            {
                Emit(" -> ");
                Type();
            }
            bound = saved;
        }

        private void DynBounds()
        {
            var saved = bound;
            Binder();
            Emit("dyn ");
            var first = true;
            while (Peek() != 'E')
            {
                if (!first) Emit(" + ");
                first = false;
                Path(true);
                var generic = endsGeneric;
                var opened = false;
                while (Peek() == 'p')
                {
                    pos++;
                    var name = Identifier();
                    if (!opened && generic && on) o.Length--;
                    Emit(opened || generic ? ", " : "<");
                    opened = true;
                    Emit(name + " = ");
                    Type();
                }
                if (opened) Emit(">");
            }
            pos++;
            if (Peek() == 'L')
            {
                pos++;
                var lt = Lifetime();
                if (lt != "'_") Emit(" + " + lt);
            }
            bound = saved;
        }

        private void Const()
        {
            Enter();
            try
            {
                var c = Peek();
                if (c == 'p') { pos++; Emit("_"); return; }
                if (c == 'B') { pos++; BackRef(Const); return; }
                var was = on;
                on = false;
                Type();
                on = was;
                var neg = false;
                if (Peek() == 'n') { pos++; neg = true; }
                var start = pos;
                while (Peek() != '_') pos++;
                var hex = s.Substring(start, pos - start);
                pos++;
                Emit(ConstValue(c, neg, hex));
            }
            finally { depth--; }
        }

        private static string ConstValue(char kind, bool neg, string hex)
        {
            if (hex.Length > 64) return "?";
            if (kind == 'b') return hex == "0" ? "false" : hex == "1" ? "true" : "?";
            var v = BigInteger.Zero;
            if (hex.Length > 0 && !BigInteger.TryParse("0" + hex, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out v)) return "?";
            if (kind == 'c')
            {
                if (neg || v > 0x10FFFF || v >= 0xD800 && v <= 0xDFFF) return "?";
                return "'" + char.ConvertFromUtf32((int)v) + "'";
            }
            if (kind is 'a' or 'i' or 'l' or 'n' or 's' or 'x') return (neg ? -v : v).ToString(CultureInfo.InvariantCulture);
            if (kind is 'h' or 'j' or 'm' or 'o' or 't' or 'y' && !neg) return v.ToString(CultureInfo.InvariantCulture);
            return "?";
        }
    }
}
