using System.Buffers.Binary;
using System.Globalization;
using System.Numerics;
using System.Text;
using System.Text.Json;
using System.Xml;
using Corvus.Native;

namespace Corvus.Core.Mobile;

/// <summary>A property list value.</summary>
public abstract record PlistNode;

/// <summary>A dictionary, in file order.</summary>
public sealed record PlistDict(IReadOnlyList<KeyValuePair<string, PlistNode>> Entries) : PlistNode
{
    public PlistNode? this[string key] => Entries.FirstOrDefault(e => e.Key == key).Value;
}

public sealed record PlistArray(IReadOnlyList<PlistNode> Items, bool IsSet = false) : PlistNode;
public sealed record PlistString(string Value) : PlistNode;
/// <summary>An integer, exact at any width (binary plists hold up to 128 bits, XML any number of digits).</summary>
public sealed record PlistInteger(BigInteger Value) : PlistNode;
public sealed record PlistReal(double Value) : PlistNode;
public sealed record PlistBool(bool Value) : PlistNode;
public sealed record PlistDate(DateTimeOffset Value) : PlistNode;
public sealed record PlistData(byte[] Value) : PlistNode;
/// <summary>An object reference of a keyed archive.</summary>
public sealed record PlistUid(ulong Value) : PlistNode;
public sealed record PlistNull : PlistNode
{
    public static readonly PlistNull Value = new();
}

/// <summary>A parsed property list: the root (null when nothing could be read), the format, and what could not be read.</summary>
public sealed record PlistDocument(PlistNode? Root, string Format, IReadOnlyList<ParseIssue> Issues);

/// <summary>
/// Property lists in binary (bplist00), XML and ASCII (OpenStep, GNUstep, .strings) form. Never throws: malformed
/// input gives what could be read plus issues.
/// </summary>
public static class Plist
{
    public const int MaxDepth = 512;
    public const int MaxObjects = 1_000_000;

    private static readonly DateTimeOffset Epoch2001 = new(2001, 1, 1, 0, 0, 0, TimeSpan.Zero);

    public static bool IsBinary(ReadOnlySpan<byte> data) => data.StartsWith("bplist0"u8);

    public static PlistDocument Read(ReadOnlySpan<byte> data)
    {
        if (IsBinary(data)) return new BinaryReader(data.ToArray()).Read();
        var text = Decode(data);
        var start = text.AsSpan().TrimStart();
        if (start.StartsWith("<?xml", StringComparison.Ordinal) || start.StartsWith("<!DOCTYPE", StringComparison.Ordinal) || start.StartsWith("<plist", StringComparison.Ordinal))
            return ReadXml(text);
        return new AsciiReader(text).Read();
    }

    private static string Decode(ReadOnlySpan<byte> data)
    {
        if (data.StartsWith((ReadOnlySpan<byte>)[0xEF, 0xBB, 0xBF])) return Encoding.UTF8.GetString(data[3..]);
        if (data.StartsWith((ReadOnlySpan<byte>)[0xFF, 0xFE])) return Encoding.Unicode.GetString(data[2..]);
        if (data.StartsWith((ReadOnlySpan<byte>)[0xFE, 0xFF])) return Encoding.BigEndianUnicode.GetString(data[2..]);
        return Encoding.UTF8.GetString(data);
    }

    // ---- binary ----

    private sealed class BinaryReader(byte[] data)
    {
        private readonly byte[] _d = data;
        private readonly List<ParseIssue> _issues = [];
        private int _refSize, _offsetSize, _objects;
        private long _offsetTable;
        private PlistNode?[] _cache = [];
        private bool[] _visiting = [];

        public PlistDocument Read()
        {
            const string Area = "bplist";
            if (_d.Length < 8 + 32) return Fail("too short for a binary plist");
            var trailer = _d.AsSpan(_d.Length - 32);
            _offsetSize = trailer[6];
            _refSize = trailer[7];
            ulong count = BinaryPrimitives.ReadUInt64BigEndian(trailer[8..]);
            ulong top = BinaryPrimitives.ReadUInt64BigEndian(trailer[16..]);
            ulong table = BinaryPrimitives.ReadUInt64BigEndian(trailer[24..]);
            if (_offsetSize is < 1 or > 8 || _refSize is < 1 or > 8)
                return Fail($"offset size {_offsetSize} or reference size {_refSize} is not 1 to 8");
            if (count == 0 || count > MaxObjects || table < 8 || table > (ulong)_d.Length || count * (ulong)_offsetSize > (ulong)_d.Length - 32 - table)
                return Fail($"{count} objects with an offset table at {table} do not fit the {_d.Length} bytes");
            if (top >= count) return Fail($"the top object {top} is not one of the {count} objects");
            _objects = (int)count;
            _offsetTable = (long)table;
            _cache = new PlistNode?[_objects];
            _visiting = new bool[_objects];
            var root = Object((int)top, 0);
            return new(root, "binary", _issues);

            PlistDocument Fail(string message)
            {
                _issues.Add(new(Area, message, 0));
                return new(null, "binary", _issues);
            }
        }

        private ulong Sized(long at, int size)
        {
            if (at < 0 || at + size > _d.Length) return ulong.MaxValue;
            ulong v = 0;
            for (int i = 0; i < size; i++) v = v << 8 | _d[(int)at + i];
            return v;
        }

        /// <summary>The object at <paramref name="index"/>; shared objects are read once, a cycle becomes null with an issue.</summary>
        private PlistNode Object(int index, int depth)
        {
            if (_cache[index] is { } done) return done;
            if (_visiting[index] || depth > MaxDepth)
            {
                _issues.Add(new("bplist", _visiting[index] ? $"object {index} contains itself" : $"nested deeper than {MaxDepth}", null));
                return PlistNull.Value;
            }
            _visiting[index] = true;
            var node = Parse(index, depth);
            _visiting[index] = false;
            return _cache[index] = node;
        }

        private PlistNode Parse(int index, int depth)
        {
            ulong offset = Sized(_offsetTable + (long)index * _offsetSize, _offsetSize);
            if (offset >= (ulong)_d.Length - 32) return Bad(index, "offset outside the object area");
            int at = (int)offset;
            byte marker = _d[at];
            int kind = marker >> 4, info = marker & 0xF;
            switch (kind)
            {
                case 0x0:
                    return info switch { 0x8 => new PlistBool(false), 0x9 => new PlistBool(true), 0x0 => PlistNull.Value, _ => Bad(index, $"marker 0x{marker:x2}") };
                case 0x1:
                    return Integer(at + 1, info) is { } integer ? new PlistInteger(integer) : Bad(index, "integer out of bounds");
                case 0x2:
                    if (info == 2 && at + 5 <= _d.Length) return new PlistReal(BinaryPrimitives.ReadSingleBigEndian(_d.AsSpan(at + 1)));
                    if (info == 3 && at + 9 <= _d.Length) return new PlistReal(BinaryPrimitives.ReadDoubleBigEndian(_d.AsSpan(at + 1)));
                    return Bad(index, $"real of 2^{info} bytes");
                case 0x3:
                    if (info != 3 || at + 9 > _d.Length) return Bad(index, "date out of bounds");
                    return Date(BinaryPrimitives.ReadDoubleBigEndian(_d.AsSpan(at + 1))) is { } date ? new PlistDate(date) : Bad(index, "date out of range");
                case 0x4 or 0x5 or 0x6 or 0x7:
                    var (length, start) = Count(at, info);
                    long bytes = kind == 0x6 ? length * 2 : length;
                    if (length < 0 || start + bytes > _d.Length) return Bad(index, "length past the end");
                    var span = _d.AsSpan((int)start, (int)bytes);
                    return kind switch
                    {
                        0x4 => new PlistData(span.ToArray()),
                        0x5 => new PlistString(Encoding.Latin1.GetString(span)),
                        0x6 => new PlistString(Encoding.BigEndianUnicode.GetString(span)),
                        _ => new PlistString(Encoding.UTF8.GetString(span)),
                    };
                case 0x8:
                    return info <= 7 && at + 2 + info <= _d.Length ? new PlistUid(Sized(at + 1, info + 1)) : Bad(index, "uid out of bounds");
                case 0xA or 0xB or 0xC:
                    var (n, first) = Count(at, info);
                    if (n < 0 || first + n * _refSize > _d.Length) return Bad(index, "array past the end");
                    var items = new List<PlistNode>((int)Math.Min(n, 4096));
                    for (long i = 0; i < n; i++) items.Add(Ref(first + i * _refSize, depth));
                    return new PlistArray(items, kind != 0xA);
                case 0xD:
                    var (pairs, keys) = Count(at, info);
                    if (pairs < 0 || keys + 2 * pairs * _refSize > _d.Length) return Bad(index, "dictionary past the end");
                    var entries = new List<KeyValuePair<string, PlistNode>>((int)Math.Min(pairs, 4096));
                    for (long i = 0; i < pairs; i++)
                    {
                        var key = Ref(keys + i * _refSize, depth);
                        var value = Ref(keys + (pairs + i) * _refSize, depth);
                        entries.Add(new(key is PlistString s ? s.Value : KeyText(key, index), value));
                    }
                    return new PlistDict(entries);
                default:
                    return Bad(index, $"marker 0x{marker:x2}");
            }
        }

        private string KeyText(PlistNode key, int index)
        {
            _issues.Add(new("bplist", $"object {index} has a key that is not a string", null));
            return key switch { PlistInteger i => i.Value.ToString(CultureInfo.InvariantCulture), PlistUid u => $"$uid {u.Value}", _ => "$key" };
        }

        private PlistNode Ref(long at, int depth)
        {
            ulong target = Sized(at, _refSize);
            if (target >= (ulong)_objects)
            {
                _issues.Add(new("bplist", $"reference {target} is not one of the {_objects} objects", at));
                return PlistNull.Value;
            }
            return Object((int)target, depth + 1);
        }

        /// <summary>The element count of a marker (from its low nibble, or an integer object after it) and where the content starts.</summary>
        private (long Count, long Start) Count(int at, int info)
        {
            if (info != 0xF) return (info, at + 1);
            if (at + 2 > _d.Length || _d[at + 1] >> 4 != 0x1) return (-1, 0);
            int size = 1 << (_d[at + 1] & 0xF);
            if (Integer(at + 2, _d[at + 1] & 0xF) is not { } n || n < 0 || n > int.MaxValue) return (-1, 0);
            return ((long)n, at + 2 + size);
        }

        /// <summary>A big-endian integer of 2^<paramref name="power"/> bytes: unsigned up to 4 bytes, signed at 8 and 16.</summary>
        private BigInteger? Integer(int at, int power)
        {
            if (power > 4) return null;
            int size = 1 << power;
            if (at + size > _d.Length) return null;
            var bytes = _d.AsSpan(at, size);
            return size <= 4 ? new BigInteger(bytes, isUnsigned: true, isBigEndian: true) : new BigInteger(bytes, isUnsigned: false, isBigEndian: true);
        }

        private PlistNode Bad(int index, string message)
        {
            _issues.Add(new("bplist", $"object {index}: {message}", null));
            return PlistNull.Value;
        }
    }

    private static DateTimeOffset? Date(double secondsSince2001)
    {
        if (double.IsNaN(secondsSince2001) || Math.Abs(secondsSince2001) > 3e11) return null; // about ±9,500 years
        return Epoch2001.AddTicks((long)Math.Round(secondsSince2001 * TimeSpan.TicksPerSecond));
    }

    // ---- XML ----

    private sealed class Frame(bool isDict)
    {
        public bool IsDict { get; } = isDict;
        public string? PendingKey { get; set; }
        public List<KeyValuePair<string, PlistNode>> Entries { get; } = [];
        public List<PlistNode> Items { get; } = [];
        public PlistNode Node => IsDict ? new PlistDict(Entries) : new PlistArray(Items);
    }

    private static PlistDocument ReadXml(string text)
    {
        const string Area = "xml plist";
        var issues = new List<ParseIssue>();
        var stack = new Stack<Frame>();
        PlistNode? root = null;
        int nodes = 0;

        void Add(PlistNode node)
        {
            if (stack.TryPeek(out var top))
            {
                if (!top.IsDict) top.Items.Add(node);
                else if (top.PendingKey is { } key) { top.Entries.Add(new(key, node)); top.PendingKey = null; }
                else issues.Add(new(Area, "a dictionary value without a key is ignored"));
            }
            else if (root == null) root = node;
            else issues.Add(new(Area, "a second top-level value is ignored"));
        }

        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Ignore, XmlResolver = null, IgnoreComments = true,
            IgnoreProcessingInstructions = true, MaxCharactersFromEntities = 1024,
        };
        try
        {
            using var reader = XmlReader.Create(new StringReader(text), settings);
            reader.MoveToContent();
            while (!reader.EOF)
            {
                if (reader.NodeType == XmlNodeType.EndElement)
                {
                    if (reader.LocalName is "dict" or "array" && stack.Count > 0) Add(Pop(stack));
                    reader.Read();
                    continue;
                }
                if (reader.NodeType != XmlNodeType.Element) { reader.Read(); continue; }
                if (++nodes > MaxObjects) { issues.Add(new(Area, $"more than {MaxObjects} values; the rest is not read")); break; }
                var name = reader.LocalName;
                switch (name)
                {
                    case "plist":
                        reader.Read();
                        break;
                    case "dict" or "array":
                        if (reader.IsEmptyElement) Add(name == "dict" ? new PlistDict([]) : new PlistArray([]));
                        else if (stack.Count >= MaxDepth) { issues.Add(new(Area, $"nested deeper than {MaxDepth}")); reader.Skip(); continue; }
                        else stack.Push(new Frame(name == "dict"));
                        reader.Read();
                        break;
                    case "true" or "false":
                        Add(new PlistBool(name == "true"));
                        reader.Skip();
                        break;
                    case "key":
                        var key = Content(reader);
                        if (stack.TryPeek(out var dict) && dict.IsDict) dict.PendingKey = key;
                        else issues.Add(new(Area, $"key '{key}' outside a dictionary"));
                        reader.Read();
                        break;
                    case "string" or "integer" or "real" or "date" or "data":
                        Add(XmlScalar(name, Content(reader), issues));
                        reader.Read(); // after the value is kept: past the end of a truncated file this throws
                        break;
                    default:
                        issues.Add(new(Area, $"unknown element <{name}> skipped"));
                        reader.Skip();
                        break;
                }
            }
        }
        catch (XmlException ex)
        {
            issues.Add(new(Area, ex.Message));
        }
        if (stack.Count > 0) issues.Add(new(Area, $"{stack.Count} container(s) not closed"));
        while (stack.Count > 0) Add(Pop(stack));
        if (root == null) issues.Add(new(Area, "no value"));
        return new(root, "xml", issues);
    }

    private static PlistNode Pop(Stack<Frame> stack) => stack.Pop().Node;

    /// <summary>The text of a scalar element, leaving the reader on its end tag (or on the element when it is empty).</summary>
    private static string Content(XmlReader reader)
    {
        if (reader.IsEmptyElement) return "";
        var sb = new StringBuilder();
        reader.Read();
        while (reader.NodeType is XmlNodeType.Text or XmlNodeType.CDATA or XmlNodeType.Whitespace or XmlNodeType.SignificantWhitespace)
        {
            sb.Append(reader.Value);
            reader.Read();
        }
        return sb.ToString();
    }

    private static PlistNode XmlScalar(string kind, string content, List<ParseIssue> issues)
    {
        const string Area = "xml plist";
        var t = content.Trim();
        switch (kind)
        {
            case "string":
                return new PlistString(content);
            case "integer":
                if (ParseInteger(t) is { } i) return new PlistInteger(i);
                break;
            case "real":
                if (ParseReal(t) is { } r) return new PlistReal(r);
                break;
            case "date":
                if (DateTimeOffset.TryParse(t, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var d)) return new PlistDate(d.ToUniversalTime());
                break;
            case "data":
                var compact = new string(t.Where(c => !char.IsWhiteSpace(c)).ToArray());
                var buffer = new byte[compact.Length * 3 / 4 + 3];
                if (Convert.TryFromBase64String(compact, buffer, out int written)) return new PlistData(buffer[..written]);
                break;
        }
        issues.Add(new(Area, $"<{kind}> '{(t.Length > 40 ? t[..40] + "..." : t)}' is not valid"));
        return new PlistString(content);
    }

    private static BigInteger? ParseInteger(string t)
    {
        bool negative = t.StartsWith('-');
        var digits = t.TrimStart('+', '-');
        if (digits.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            return BigInteger.TryParse("0" + digits[2..], NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out var h) ? negative ? -h : h : null;
        return digits.Length > 0 && digits.All(char.IsAsciiDigit) && BigInteger.TryParse(digits, NumberStyles.None, CultureInfo.InvariantCulture, out var v)
            ? negative ? -v : v : null;
    }

    private static double? ParseReal(string t) => t.ToLowerInvariant() switch
    {
        "nan" => double.NaN,
        "inf" or "+inf" or "infinity" or "+infinity" => double.PositiveInfinity,
        "-inf" or "-infinity" => double.NegativeInfinity,
        _ => double.TryParse(t, NumberStyles.Float, CultureInfo.InvariantCulture, out var v) ? v : null,
    };

    // ---- ASCII (OpenStep / GNUstep / .strings) ----

    private sealed class AsciiReader(string text)
    {
        private const string Area = "ascii plist";
        private readonly List<ParseIssue> _issues = [];
        private int _p;
        private int _values;

        public PlistDocument Read()
        {
            Skip();
            PlistNode? root = null;
            if (_p >= text.Length) _issues.Add(new(Area, "no value"));
            else if (StringsFile()) root = Entries('\0', 0);
            else
            {
                root = Value(0);
                Skip();
                if (_p < text.Length) _issues.Add(new(Area, "text after the top-level value is ignored", _p));
            }
            return new(root, "ascii", _issues);
        }

        /// <summary>A .strings file: "key" = "value"; at the top level, without braces.</summary>
        private bool StringsFile()
        {
            if (text[_p] is '{' or '(' or '<') return false;
            var (position, issues, values) = (_p, _issues.Count, _values);
            var probe = Value(0);
            Skip();
            bool isStrings = probe is PlistString && _p < text.Length && text[_p] is '=' or ';';
            (_p, _values) = (position, values);
            _issues.RemoveRange(issues, _issues.Count - issues);
            return isStrings;
        }

        private void Skip()
        {
            while (_p < text.Length)
            {
                if (char.IsWhiteSpace(text[_p])) _p++;
                else if (text.AsSpan(_p).StartsWith("//", StringComparison.Ordinal)) { while (_p < text.Length && text[_p] != '\n') _p++; }
                else if (text.AsSpan(_p).StartsWith("/*", StringComparison.Ordinal))
                {
                    int end = text.IndexOf("*/", _p + 2, StringComparison.Ordinal);
                    _p = end < 0 ? text.Length : end + 2;
                }
                else break;
            }
        }

        private PlistNode Value(int depth)
        {
            Skip();
            if (_p >= text.Length) return Missing("a value");
            if (depth > MaxDepth || ++_values > MaxObjects)
            {
                _issues.Add(new(Area, depth > MaxDepth ? $"nested deeper than {MaxDepth}" : $"more than {MaxObjects} values", _p));
                _p = text.Length;
                return PlistNull.Value;
            }
            char c = text[_p];
            if (c == '{') { _p++; return Entries('}', depth); }
            if (c == '(') { _p++; return Items(depth); }
            if (c == '<') return text.AsSpan(_p).StartsWith("<*", StringComparison.Ordinal) ? Typed() : Data();
            if (c is '"' or '\'') return new PlistString(Quoted());
            if (IsUnquoted(c))
            {
                int start = _p;
                while (_p < text.Length && IsUnquoted(text[_p])) _p++;
                return new PlistString(text[start.._p]);
            }
            _issues.Add(new(Area, $"unexpected '{c}'", _p));
            _p = text.Length;
            return PlistNull.Value;
        }

        private static int HexDigit(char c) => c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10;

        private static bool IsUnquoted(char c) => char.IsAsciiLetterOrDigit(c) || c is '_' or '$' or '+' or '/' or ':' or '.' or '-';

        private PlistNode Missing(string what)
        {
            _issues.Add(new(Area, $"{what} is missing at the end", _p));
            return PlistNull.Value;
        }

        /// <summary>key = value; pairs up to <paramref name="close"/> ('\0': the end of the text).</summary>
        private PlistDict Entries(char close, int depth)
        {
            var entries = new List<KeyValuePair<string, PlistNode>>();
            while (true)
            {
                Skip();
                if (_p >= text.Length) { if (close != '\0') Missing($"'{close}'"); break; }
                if (text[_p] == close) { _p++; break; }
                var key = Value(depth + 1);
                if (key is not PlistString k) { _issues.Add(new(Area, "a dictionary key is not a string", _p)); break; }
                Skip();
                if (_p < text.Length && text[_p] == ';') { _p++; entries.Add(new(k.Value, k)); continue; } // .strings shorthand: "key";
                if (_p >= text.Length || text[_p] != '=') { _issues.Add(new(Area, $"'=' expected after '{k.Value}'", _p)); break; }
                _p++;
                entries.Add(new(k.Value, Value(depth + 1)));
                Skip();
                if (_p < text.Length && text[_p] == ';') _p++;
                else if (!(_p < text.Length && text[_p] == close)) { _issues.Add(new(Area, $"';' expected after the value of '{k.Value}'", _p)); if (_p >= text.Length) break; }
            }
            return new PlistDict(entries);
        }

        private PlistArray Items(int depth)
        {
            var items = new List<PlistNode>();
            while (true)
            {
                Skip();
                if (_p >= text.Length) { Missing("')'"); break; }
                if (text[_p] == ')') { _p++; break; }
                items.Add(Value(depth + 1));
                Skip();
                if (_p < text.Length && text[_p] == ',') _p++;
                else if (!(_p < text.Length && text[_p] == ')')) { _issues.Add(new(Area, "',' or ')' expected", _p)); if (_p >= text.Length) break; _p++; }
            }
            return new PlistArray(items);
        }

        private PlistNode Data()
        {
            int start = ++_p;
            int end = text.IndexOf('>', start);
            if (end < 0) { _p = text.Length; return Missing("'>'"); }
            _p = end + 1;
            var hex = new string(text[start..end].Where(c => !char.IsWhiteSpace(c)).ToArray());
            if (hex.Length % 2 == 0 && hex.All(char.IsAsciiHexDigit)) return new PlistData(Convert.FromHexString(hex));
            _issues.Add(new(Area, "data is not hex digits", start));
            return new PlistData([]);
        }

        /// <summary>GNUstep typed values: &lt;*I12&gt;, &lt;*R1.5&gt;, &lt;*BY&gt;, &lt;*D2001-01-01 00:00:00 +0000&gt;.</summary>
        private PlistNode Typed()
        {
            int start = _p + 2;
            int end = text.IndexOf('>', start);
            if (end < 0 || end == start) { _p = text.Length; return Missing("'>'"); }
            _p = end + 1;
            var body = text[(start + 1)..end];
            switch (text[start])
            {
                case 'I' when ParseInteger(body) is { } i: return new PlistInteger(i);
                case 'R' when ParseReal(body) is { } r: return new PlistReal(r);
                case 'B' when body is "Y" or "N": return new PlistBool(body == "Y");
                // GNUstep writes the offset as +hhmm; zzz wants +hh:mm.
                case 'D' when DateTimeOffset.TryParseExact(body.Length > 5 && body[^5] is '+' or '-' ? body[..^2] + ":" + body[^2..] : body,
                        "yyyy-MM-dd HH:mm:ss zzz", CultureInfo.InvariantCulture, DateTimeStyles.None, out var d):
                    return new PlistDate(d.ToUniversalTime());
            }
            _issues.Add(new(Area, $"<*{text[start..end]}> is not a valid typed value", start));
            return new PlistString(text[start..end]);
        }

        private string Quoted()
        {
            char quote = text[_p++];
            var sb = new StringBuilder();
            while (_p < text.Length && text[_p] != quote)
            {
                char c = text[_p++];
                if (c != '\\' || _p >= text.Length) { sb.Append(c); continue; }
                char e = text[_p++];
                switch (e)
                {
                    case 'a': sb.Append('\a'); break;
                    case 'b': sb.Append('\b'); break;
                    case 'f': sb.Append('\f'); break;
                    case 'n': sb.Append('\n'); break;
                    case 'r': sb.Append('\r'); break;
                    case 't': sb.Append('\t'); break;
                    case 'v': sb.Append('\v'); break;
                    case 'U' or 'u':
                        int n = 0, v = 0;
                        while (n < 4 && _p < text.Length && char.IsAsciiHexDigit(text[_p])) { v = v * 16 + HexDigit(text[_p++]); n++; }
                        sb.Append((char)v);
                        break;
                    case >= '0' and <= '7':
                        int o = e - '0', digits = 1;
                        while (digits < 3 && _p < text.Length && text[_p] is >= '0' and <= '7') { o = o * 8 + (text[_p++] - '0'); digits++; }
                        sb.Append((char)(o & 0xFF));
                        break;
                    default: sb.Append(e); break;
                }
            }
            if (_p >= text.Length) _issues.Add(new(Area, "unterminated string", _p));
            else _p++;
            return sb.ToString();
        }
    }

    // ---- JSON ----

    /// <summary>
    /// Writes <paramref name="node"/> as JSON: integers as exact numbers, reals as numbers (non-finite as strings), data as
    /// {"$data": base64}, dates as {"$date": ISO 8601}, archive references as {"$uid": n}. Stops after
    /// <paramref name="maxValues"/> values, writing {"$truncated": true}; returns false when it did.
    /// </summary>
    public static bool WriteJson(Utf8JsonWriter writer, PlistNode node, int maxValues = MaxObjects)
    {
        int budget = maxValues;
        return Write(writer, node, ref budget, 0);
    }

    public static string ToJson(PlistNode node, bool indented = true, int maxValues = MaxObjects)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = indented, MaxDepth = MaxDepth + 8, SkipValidation = false }))
            WriteJson(writer, node, maxValues);
        return Encoding.UTF8.GetString(stream.ToArray());
    }

    private static bool Write(Utf8JsonWriter w, PlistNode node, ref int budget, int depth)
    {
        if (--budget < 0 || depth > MaxDepth)
        {
            w.WriteStartObject();
            w.WriteBoolean("$truncated", true);
            w.WriteEndObject();
            return false;
        }
        bool complete = true;
        switch (node)
        {
            case PlistDict d:
                w.WriteStartObject();
                foreach (var (k, v) in d.Entries)
                {
                    w.WritePropertyName(k);
                    complete &= Write(w, v, ref budget, depth + 1);
                }
                w.WriteEndObject();
                break;
            case PlistArray a:
                w.WriteStartArray();
                foreach (var item in a.Items) complete &= Write(w, item, ref budget, depth + 1);
                w.WriteEndArray();
                break;
            case PlistString s: w.WriteStringValue(s.Value); break;
            case PlistInteger i: w.WriteRawValue(i.Value.ToString(CultureInfo.InvariantCulture), skipInputValidation: true); break;
            case PlistReal r when double.IsFinite(r.Value): w.WriteNumberValue(r.Value); break;
            case PlistReal r: w.WriteStringValue(r.Value.ToString(CultureInfo.InvariantCulture)); break;
            case PlistBool b: w.WriteBooleanValue(b.Value); break;
            case PlistDate t:
                w.WriteStartObject();
                w.WriteString("$date", t.Value.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.FFFFFFFZ", CultureInfo.InvariantCulture));
                w.WriteEndObject();
                break;
            case PlistData data:
                w.WriteStartObject();
                w.WriteBase64String("$data", data.Value);
                w.WriteEndObject();
                break;
            case PlistUid u:
                w.WriteStartObject();
                w.WriteNumber("$uid", u.Value);
                w.WriteEndObject();
                break;
            default: w.WriteNullValue(); break;
        }
        return complete;
    }
}
