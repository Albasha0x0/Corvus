using System.Globalization;
using System.Text;

namespace Corvus.Core.Documents;

/// <summary>A PDF value: name, string, number, boolean, null, reference, array or dictionary.</summary>
internal abstract record PdfValue;

/// <summary>A name with its #xx escapes decoded; <see cref="Escaped"/> when the file wrote it with them.</summary>
internal sealed record PdfName(string Value, bool Escaped = false) : PdfValue
{
    public override string ToString() => "/" + Value;
}

internal sealed record PdfString(byte[] Bytes, bool Hex = false) : PdfValue
{
    /// <summary>The text: UTF-16 with a byte order mark, UTF-8 with one, else PDFDocEncoding read as Latin-1.</summary>
    public string Text => Bytes is [0xFE, 0xFF, ..] ? Encoding.BigEndianUnicode.GetString(Bytes, 2, Bytes.Length - 2)
        : Bytes is [0xFF, 0xFE, ..] ? Encoding.Unicode.GetString(Bytes, 2, Bytes.Length - 2)
        : Bytes is [0xEF, 0xBB, 0xBF, ..] ? Encoding.UTF8.GetString(Bytes, 3, Bytes.Length - 3) : Encoding.Latin1.GetString(Bytes);

    public override string ToString() => "(" + Text + ")";
}

internal sealed record PdfNumber(double Value) : PdfValue
{
    public override string ToString() => Value.ToString(CultureInfo.InvariantCulture);
}

internal sealed record PdfKeyword(string Value) : PdfValue
{
    public override string ToString() => Value;
}

internal sealed record PdfRef(int Number, int Generation) : PdfValue
{
    public override string ToString() => $"{Number} {Generation} R";
}

internal sealed record PdfArray(List<PdfValue> Items) : PdfValue
{
    public override string ToString() => "[" + string.Join(" ", Items.Take(20)) + (Items.Count > 20 ? " ..." : "") + "]";
}

internal sealed record PdfDict(List<KeyValuePair<string, PdfValue>> Entries) : PdfValue
{
    public PdfValue? this[string key] => Entries.LastOrDefault(e => e.Key == key).Value;

    public string? Name(string key) => this[key] is PdfName n ? n.Value : null;

    public override string ToString() => "<<" + string.Join(" ", Entries.Take(20).Select(e => "/" + e.Key + " " + e.Value)) + (Entries.Count > 20 ? " ..." : "") + ">>";
}

/// <summary>An indirect object: its number, generation, offset in the file (or the object stream holding it), value and raw stream data.</summary>
internal sealed record PdfObject(int Number, int Generation, long Offset, PdfValue Value)
{
    /// <summary>The stream bytes as stored (still filtered), or null for a plain object.</summary>
    public byte[]? Stream { get; init; }
    /// <summary>The object stream it was read from, or null for an object at a file offset.</summary>
    public int? InObjectStream { get; init; }
    public PdfDict? Dict => Value as PdfDict;
}

/// <summary>A PDF tokenizer and object parser; nesting is bounded and damaged input ends a value early.</summary>
internal sealed class PdfLexer(byte[] data, int start = 0, int end = -1)
{
    private readonly int _end = end < 0 ? data.Length : end;
    public int Pos = start;
    private const int MaxDepth = 64;
    /// <summary>Items kept of one array; the rest are read past.</summary>
    public const int MaxArrayItems = 4096;
    private static readonly PdfKeyword R = new("R"), Null = new("null");

    public static bool IsWhite(byte b) => b is 0 or 9 or 10 or 12 or 13 or 32;
    public static bool IsDelimiter(byte b) => b is (byte)'(' or (byte)')' or (byte)'<' or (byte)'>' or (byte)'[' or (byte)']' or (byte)'{' or (byte)'}' or (byte)'/' or (byte)'%';

    public bool AtEnd => Pos >= _end;

    public void SkipWhite()
    {
        while (Pos < _end)
        {
            byte b = data[Pos];
            if (IsWhite(b)) Pos++;
            else if (b == '%') { while (Pos < _end && data[Pos] is not (10 or 13)) Pos++; }
            else break;
        }
    }

    /// <summary>The next regular-character word without consuming it ("" at a delimiter).</summary>
    public string PeekWord()
    {
        SkipWhite();
        if (Pos >= _end) return "";
        int p = Pos;
        while (p < _end && !IsWhite(data[p]) && !IsDelimiter(data[p])) p++;
        return Encoding.Latin1.GetString(data, Pos, p - Pos);
    }

    public PdfValue? Value(int depth = 0)
    {
        SkipWhite();
        if (Pos >= _end || depth > MaxDepth) return null;
        byte b = data[Pos];
        switch (b)
        {
            case (byte)'/': return Name();
            case (byte)'(': return Literal();
            case (byte)'[':
            {
                Pos++;
                var items = new List<PdfValue>();
                while (true)
                {
                    SkipWhite();
                    if (Pos >= _end) break;
                    if (data[Pos] == ']') { Pos++; break; }
                    int before = Pos;
                    // Values past the kept items (glyph widths, coordinates) are stepped over.
                    if (items.Count >= MaxArrayItems)
                    {
                        Skip(depth + 1);
                        if (Pos == before) Pos++;
                        continue;
                    }
                    var v = Value(depth + 1);
                    if (v == null || Pos == before) { if (Pos == before) Pos++; break; }
                    if (items.Count < MaxArrayItems) items.Add(Reference(v, items));
                }
                return new PdfArray(items);
            }
            case (byte)'<':
                if (Pos + 1 < _end && data[Pos + 1] == '<')
                {
                    Pos += 2;
                    var entries = new List<KeyValuePair<string, PdfValue>>();
                    while (true)
                    {
                        SkipWhite();
                        if (Pos >= _end) break;
                        if (data[Pos] == '>' && Pos + 1 < _end && data[Pos + 1] == '>') { Pos += 2; break; }
                        if (data[Pos] != '/') { int before = Pos; var junk = Value(depth + 1); if (junk == null || Pos == before) Pos = Math.Max(Pos, before + 1); continue; }
                        var key = (PdfName)Name();
                        SkipWhite();
                        if (Pos < _end && data[Pos] == '>' ) { entries.Add(new(key.Value, new PdfKeyword("null"))); continue; }
                        var value = Value(depth + 1);
                        if (value == null) break;
                        if (value is PdfNumber && LooksLikeReference()) value = ReadReference((PdfNumber)value);
                        entries.Add(new(key.Value, value));
                    }
                    return new PdfDict(entries);
                }
                return Hex();
            case (byte)')' or (byte)'>' or (byte)']' or (byte)'}' or (byte)'{':
                Pos++;
                return new PdfKeyword(((char)b).ToString());
            default:
            {
                int p = Pos;
                while (p < _end && !IsWhite(data[p]) && !IsDelimiter(data[p])) p++;
                var token = data.AsSpan(Pos, p - Pos);
                Pos = p;
                if (token[0] is (byte)'+') token = token[1..];
                if (token.Length > 0 && token[0] is >= (byte)'0' and <= (byte)'9' or (byte)'-' or (byte)'.'
                    && System.Buffers.Text.Utf8Parser.TryParse(token, out double n, out int used) && used == token.Length)
                    return new PdfNumber(n);
                return token.Length switch { 1 when token[0] == 'R' => R, 4 when token.SequenceEqual("null"u8) => Null, _ => new PdfKeyword(Encoding.Latin1.GetString(token)) };
            }
        }
    }

    /// <summary>Steps over one value without building it.</summary>
    private void Skip(int depth)
    {
        SkipWhite();
        if (Pos >= _end) return;
        byte b = data[Pos];
        if (depth > MaxDepth) { Pos++; return; }
        switch (b)
        {
            case (byte)'[':
                Pos++;
                while (true)
                {
                    SkipWhite();
                    if (Pos >= _end) return;
                    if (data[Pos] == ']') { Pos++; return; }
                    int before = Pos;
                    Skip(depth + 1);
                    if (Pos == before) Pos++;
                }
            case (byte)'<' when Pos + 1 < _end && data[Pos + 1] == '<':
                Pos += 2;
                while (true)
                {
                    SkipWhite();
                    if (Pos >= _end) return;
                    if (data[Pos] == '>' && Pos + 1 < _end && data[Pos + 1] == '>') { Pos += 2; return; }
                    int before = Pos;
                    Skip(depth + 1);
                    if (Pos == before) Pos++;
                }
            case (byte)'<':
                while (Pos < _end && data[Pos] != '>') Pos++;
                Pos++;
                return;
            case (byte)'(':
                Literal();
                return;
            case (byte)'/':
                Pos++;
                while (Pos < _end && !IsWhite(data[Pos]) && !IsDelimiter(data[Pos])) Pos++;
                return;
            default:
                if (IsDelimiter(b)) { Pos++; return; }
                while (Pos < _end && !IsWhite(data[Pos]) && !IsDelimiter(data[Pos])) Pos++;
                return;
        }
    }

    /// <summary>In an array, "n g R" read as numbers turns into a reference.</summary>
    private static PdfValue Reference(PdfValue v, List<PdfValue> items)
    {
        if (v is PdfKeyword { Value: "R" } && items.Count >= 2 && items[^1] is PdfNumber g && items[^2] is PdfNumber n)
        {
            items.RemoveRange(items.Count - 2, 2);
            return new PdfRef((int)n.Value, (int)g.Value);
        }
        return v;
    }

    private bool LooksLikeReference()
    {
        int save = Pos;
        try
        {
            SkipWhite();
            int p = Pos;
            while (p < _end && data[p] is >= (byte)'0' and <= (byte)'9') p++;
            if (p == Pos) return false;
            Pos = p;
            SkipWhite();
            return Pos < _end && data[Pos] == 'R' && (Pos + 1 >= _end || IsWhite(data[Pos + 1]) || IsDelimiter(data[Pos + 1]));
        }
        finally { Pos = save; }
    }

    private PdfRef ReadReference(PdfNumber number)
    {
        var g = (PdfNumber)Value()!;
        SkipWhite();
        Pos++; // R
        return new PdfRef((int)number.Value, (int)g.Value);
    }

    private PdfValue Name()
    {
        Pos++;
        var sb = new StringBuilder();
        bool escaped = false;
        while (Pos < _end && !IsWhite(data[Pos]) && !IsDelimiter(data[Pos]))
        {
            if (data[Pos] == '#' && Pos + 2 < _end && Uri.IsHexDigit((char)data[Pos + 1]) && Uri.IsHexDigit((char)data[Pos + 2]))
            {
                sb.Append((char)Convert.ToByte(Encoding.Latin1.GetString(data, Pos + 1, 2), 16));
                Pos += 3;
                escaped = true;
                continue;
            }
            sb.Append((char)data[Pos++]);
        }
        return new PdfName(sb.ToString(), escaped);
    }

    private PdfValue Literal()
    {
        Pos++;
        var o = new List<byte>();
        int depth = 1;
        while (Pos < _end)
        {
            byte b = data[Pos++];
            if (b == '\\' && Pos < _end)
            {
                byte e = data[Pos++];
                switch (e)
                {
                    case (byte)'n': o.Add(10); break;
                    case (byte)'r': o.Add(13); break;
                    case (byte)'t': o.Add(9); break;
                    case (byte)'b': o.Add(8); break;
                    case (byte)'f': o.Add(12); break;
                    case 13: if (Pos < _end && data[Pos] == 10) Pos++; break;
                    case 10: break;
                    case >= (byte)'0' and <= (byte)'7':
                        int v = e - '0';
                        for (int k = 0; k < 2 && Pos < _end && data[Pos] is >= (byte)'0' and <= (byte)'7'; k++) v = v * 8 + (data[Pos++] - '0');
                        o.Add((byte)v);
                        break;
                    default: o.Add(e); break;
                }
                continue;
            }
            if (b == '(') depth++;
            else if (b == ')' && --depth == 0) break;
            o.Add(b);
        }
        return new PdfString([.. o]);
    }

    private PdfValue Hex()
    {
        Pos++;
        var o = new List<byte>();
        int high = -1;
        while (Pos < _end && data[Pos] != '>')
        {
            int d = HexValue(data[Pos++]);
            if (d < 0) continue;
            if (high < 0) high = d;
            else { o.Add((byte)(high * 16 + d)); high = -1; }
        }
        if (high >= 0) o.Add((byte)(high * 16));
        Pos++;
        return new PdfString([.. o], Hex: true);
    }

    public static int HexValue(byte c) => c switch
    {
        >= (byte)'0' and <= (byte)'9' => c - '0',
        >= (byte)'a' and <= (byte)'f' => c - 'a' + 10,
        >= (byte)'A' and <= (byte)'F' => c - 'A' + 10,
        _ => -1,
    };
}
