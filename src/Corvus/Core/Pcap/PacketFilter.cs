using System.Globalization;
using System.Net;
using System.Text.RegularExpressions;

namespace Corvus.Core.Pcap;

/// <summary>A filter syntax error: the message names the position and what was expected.</summary>
public sealed class PacketFilterException(string message) : Exception(message);

/// <summary>
/// A display filter in Wireshark syntax over the fields <see cref="PacketFields"/> decodes: comparisons (==, !=, &gt;, &lt;,
/// &gt;=, &lt;=, contains, matches, in {…}), bare fields and protocols as presence tests, and / or / not with parentheses.
/// Field names outside the in-process set are kept in <see cref="Unknown"/>, so the caller can pass the filter on to TShark.
/// </summary>
public sealed class PacketFilter
{
    /// <summary>The filter as given.</summary>
    public string Text { get; }
    /// <summary>The fields the filter names, in first-use order, aliases resolved.</summary>
    public IReadOnlyList<string> Fields => _fields;
    /// <summary>Names that are neither an in-process field nor a protocol.</summary>
    public IReadOnlyList<string> Unknown => _unknown;
    /// <summary>The protocols whose cross-frame state must be tracked for this filter.</summary>
    internal PacketLayers Layers { get; private set; }

    private readonly Node _root;
    private readonly List<string> _fields = [];
    private readonly List<string> _unknown = [];

    private PacketFilter(string text)
    {
        Text = text;
        var tokens = Tokenize(text);
        var parser = new Parser(this, tokens);
        _root = tokens.Count == 0 ? new All() : parser.Parse();
    }

    /// <summary>Parses <paramref name="text"/>; empty or "*" matches every frame.</summary>
    public static PacketFilter Parse(string? text)
    {
        var t = text?.Trim() ?? "";
        return new PacketFilter(t == "*" ? "" : t);
    }

    internal bool Matches(PacketView v) => _root.Eval(v);

    // ---- syntax tree ----

    private abstract class Node { public abstract bool Eval(PacketView v); }
    private sealed class All : Node { public override bool Eval(PacketView v) => true; }
    private sealed class And(Node a, Node b) : Node { public override bool Eval(PacketView v) => a.Eval(v) && b.Eval(v); }
    private sealed class Or(Node a, Node b) : Node { public override bool Eval(PacketView v) => a.Eval(v) || b.Eval(v); }
    private sealed class Not(Node a) : Node { public override bool Eval(PacketView v) => !a.Eval(v); }
    private sealed class Present(PacketField f) : Node { public override bool Eval(PacketView v) => f.Present(v); }

    /// <summary>Any value satisfies the test (all values for !=, Wireshark's "all not equal"); an absent field is false.</summary>
    private sealed class Compare(PacketField f, string op, Literal[] values) : Node
    {
        public override bool Eval(PacketView v)
        {
            var list = v.Values(f);
            if (list.Count == 0) return false;
            if (op == "!=")
            {
                foreach (var x in list)
                    foreach (var l in values) if (l.Equal(x)) return false;
                return true;
            }
            foreach (var x in list)
                foreach (var l in values)
                    if (op switch
                    {
                        "==" or "in" => l.Equal(x),
                        ">" => l.Order(x) > 0,
                        "<" => l.Order(x) < 0,
                        ">=" => l.Order(x) >= 0,
                        "<=" => l.Order(x) <= 0,
                        "contains" => x.Text is { } s && s.Contains(l.Text!, StringComparison.Ordinal),
                        "matches" => x.Text is { } s && l.Regex!.IsMatch(s),
                        _ => false,
                    }) return true;
            return false;
        }
    }

    /// <summary>A value to compare with: an address or network, a number, or text (with a regex for matches).</summary>
    private sealed class Literal
    {
        public UInt128 Address, Mask = UInt128.MaxValue;
        public bool V6;
        public long Number;
        public string? Text;
        public Regex? Regex;
        public FieldType Type;

        public bool Equal(in FieldValue x) => Type switch
        {
            FieldType.Address => x.V6 == V6 && (x.Address & Mask) == Address,
            FieldType.Number => x.Number == Number,
            _ => x.Text == Text,
        };

        /// <summary>The field value's order relative to this literal: &gt; 0 when the value is greater.</summary>
        public int Order(in FieldValue x) => Type == FieldType.Number ? x.Number.CompareTo(Number) : string.CompareOrdinal(x.Text, Text);
    }

    // ---- tokens ----

    private readonly record struct Token(string Text, int At, bool Quoted);

    private static List<Token> Tokenize(string s)
    {
        var tokens = new List<Token>();
        for (int i = 0; i < s.Length;)
        {
            char c = s[i];
            if (char.IsWhiteSpace(c)) { i++; continue; }
            int at = i;
            if (c == '"')
            {
                var sb = new System.Text.StringBuilder();
                for (i++; ; i++)
                {
                    if (i >= s.Length) throw new PacketFilterException($"unterminated string at {at}");
                    if (s[i] == '"') { i++; break; }
                    if (s[i] == '\\' && i + 1 < s.Length)
                    {
                        char e = s[++i];
                        if (e == 'x' && i + 2 < s.Length && byte.TryParse(s.AsSpan(i + 1, 2), NumberStyles.HexNumber, null, out var hex)) { sb.Append((char)hex); i += 2; }
                        else sb.Append(e switch { 'n' => '\n', 'r' => '\r', 't' => '\t', _ => e });
                    }
                    else sb.Append(s[i]);
                }
                tokens.Add(new Token(sb.ToString(), at, true));
                continue;
            }
            if (c is '(' or ')' or '{' or '}' or ',') { tokens.Add(new Token(c.ToString(), at, false)); i++; continue; }
            if (s.AsSpan(i).StartsWith("&&") || s.AsSpan(i).StartsWith("||") || s.AsSpan(i).StartsWith("==") || s.AsSpan(i).StartsWith("!=")
                || s.AsSpan(i).StartsWith(">=") || s.AsSpan(i).StartsWith("<="))
            {
                tokens.Add(new Token(s.Substring(i, 2), at, false));
                i += 2;
                continue;
            }
            if (c is '!' or '>' or '<' or '~') { tokens.Add(new Token(c.ToString(), at, false)); i++; continue; }
            while (i < s.Length && !char.IsWhiteSpace(s[i]) && s[i] is not ('(' or ')' or '{' or '}' or ',' or '"' or '=' or '!' or '>' or '<' or '&' or '|' or '~')) i++;
            if (i == at) throw new PacketFilterException($"unexpected '{c}' at {at}");
            tokens.Add(new Token(s[at..i], at, false));
        }
        return tokens;
    }

    private sealed class Parser(PacketFilter owner, List<Token> tokens)
    {
        private int _at;

        private Token? Peek => _at < tokens.Count ? tokens[_at] : null;
        private bool Is(params string[] words) => Peek is { Quoted: false } t && words.Any(w => string.Equals(t.Text, w, StringComparison.OrdinalIgnoreCase));
        private Token Next() => _at < tokens.Count ? tokens[_at++] : throw new PacketFilterException("the filter ends where a value or field was expected");

        public Node Parse()
        {
            var node = ParseOr();
            if (Peek is { } extra) throw new PacketFilterException($"unexpected '{extra.Text}' at {extra.At}");
            return node;
        }

        private Node ParseOr()
        {
            var node = ParseAnd();
            while (Is("or", "||")) { _at++; node = new Or(node, ParseAnd()); }
            return node;
        }

        private Node ParseAnd()
        {
            var node = ParseNot();
            while (Is("and", "&&")) { _at++; node = new And(node, ParseNot()); }
            return node;
        }

        private Node ParseNot()
        {
            if (Is("not", "!")) { _at++; return new Not(ParseNot()); }
            if (Is("("))
            {
                _at++;
                var inner = ParseOr();
                if (!Is(")")) throw new PacketFilterException($"missing ')' at {Peek?.At.ToString(CultureInfo.InvariantCulture) ?? "the end"}");
                _at++;
                return inner;
            }
            var name = Next();
            if (name.Quoted) throw new PacketFilterException($"a field name was expected at {name.At}, not a string");
            var field = PacketFields.Find(name.Text);
            string resolved = field?.Name ?? name.Text.ToLowerInvariant();
            if (!owner._fields.Contains(resolved)) owner._fields.Add(resolved);
            if (field == null && !owner._unknown.Contains(resolved)) owner._unknown.Add(resolved);
            if (field != null) owner.Layers |= field.Layers;
            var op = Peek is { Quoted: false } t ? Operator(t.Text) : null;
            if (op == null) return field == null ? new All() : new Present(field);
            _at++;
            var literals = new List<Token>();
            if (op == "in")
            {
                if (!Is("{")) throw new PacketFilterException($"'in' needs a set: {{value value}} at {Peek?.At ?? -1}");
                _at++;
                while (!Is("}")) { if (Is(",")) { _at++; continue; } literals.Add(Next()); }
                _at++;
                if (literals.Count == 0) throw new PacketFilterException("'in' needs at least one value");
            }
            else literals.Add(Next());
            if (field == null) return new All(); // passed to TShark; never evaluated in-process
            return new Compare(field, op, [.. literals.Select(l => Literal(field, op, l))]);
        }

        private static string? Operator(string t) => t.ToLowerInvariant() switch
        {
            "==" or "eq" => "==",
            "!=" or "ne" => "!=",
            ">" or "gt" => ">",
            "<" or "lt" => "<",
            ">=" or "ge" => ">=",
            "<=" or "le" => "<=",
            "contains" => "contains",
            "matches" or "~" => "matches",
            "in" => "in",
            _ => null,
        };

        private static Literal Literal(PacketField f, string op, Token t)
        {
            var l = new Literal { Type = f.Type };
            if (op is "contains" or "matches")
            {
                if (f.Type != FieldType.Text) throw new PacketFilterException($"{f.Name} is not text: '{op}' applies to text fields");
                l.Text = t.Text;
                if (op == "matches")
                {
                    try { l.Regex = new Regex(t.Text, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1)); }
                    catch (ArgumentException ex) { throw new PacketFilterException($"bad regular expression '{t.Text}': {ex.Message}"); }
                }
                return l;
            }
            switch (f.Type)
            {
                case FieldType.Address:
                    if (op is not ("==" or "!=" or "in")) throw new PacketFilterException($"{f.Name} is an address: use == or !=");
                    var text = t.Text;
                    int bits = -1;
                    if (text.IndexOf('/') is var slash and > 0)
                    {
                        if (!int.TryParse(text.AsSpan(slash + 1), NumberStyles.None, CultureInfo.InvariantCulture, out bits)) throw new PacketFilterException($"bad network '{text}'");
                        text = text[..slash];
                    }
                    if (!IPAddress.TryParse(text, out var ip)) throw new PacketFilterException($"{f.Name} needs an address, not '{t.Text}'");
                    l.V6 = ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;
                    if (l.V6 != f.V6) throw new PacketFilterException($"{f.Name} holds {(f.V6 ? "IPv6" : "IPv4")} addresses, not '{t.Text}'");
                    var bytes = ip.GetAddressBytes();
                    l.Address = l.V6 ? System.Buffers.Binary.BinaryPrimitives.ReadUInt128BigEndian(bytes) : System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(bytes);
                    int width = l.V6 ? 128 : 32;
                    if (bits > width) throw new PacketFilterException($"bad network '{t.Text}'");
                    if (bits >= 0)
                    {
                        l.Mask = bits == 0 ? UInt128.Zero : (UInt128.MaxValue << (width - bits)) & (l.V6 ? UInt128.MaxValue : uint.MaxValue);
                        l.Address &= l.Mask;
                    }
                    else if (!l.V6) l.Mask = uint.MaxValue;
                    return l;
                case FieldType.Number:
                    var n = t.Text;
                    bool ok = n.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
                        ? long.TryParse(n.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out l.Number)
                        : long.TryParse(n, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out l.Number);
                    if (!ok && f.Name.StartsWith("tcp.flags.", StringComparison.Ordinal) && bool.TryParse(n, out var b)) { l.Number = b ? 1 : 0; ok = true; }
                    if (!ok) throw new PacketFilterException($"{f.Name} needs a number, not '{t.Text}'");
                    return l;
                default:
                    if (op is ">" or "<" or ">=" or "<=" && f.Type != FieldType.Text) throw new PacketFilterException($"{f.Name} cannot be ordered");
                    l.Text = t.Text;
                    return l;
            }
        }
    }
}
