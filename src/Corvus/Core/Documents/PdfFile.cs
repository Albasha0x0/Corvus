using System.Text;

namespace Corvus.Core.Documents;

/// <summary>
/// A PDF read the way pdf-parser reads it: every "n g obj" in the file in order (so objects outside the cross-reference
/// table and earlier versions from incremental updates are seen), trailers and xref sections counted, then the objects
/// inside object streams. The newest version of an object number is the one resolved; streams are decoded on demand.
/// </summary>
internal sealed class PdfFile
{
    private readonly byte[] _data;
    private readonly Dictionary<int, PdfObject> _current = [];

    public string Name { get; }
    public string? Version { get; private set; }
    public long HeaderOffset { get; private set; }
    /// <summary>Every object in file order, older versions included.</summary>
    public List<PdfObject> Objects { get; } = [];
    public List<PdfDict> Trailers { get; } = [];
    public int XrefSections { get; private set; }
    public int EofMarkers { get; private set; }
    /// <summary>Bytes after the last %%EOF (beyond trailing whitespace).</summary>
    public long AfterLastEof { get; private set; }
    public List<string> Notes { get; } = [];
    public PdfSecurity? Security { get; private set; }

    private const int MaxObjects = 1_000_000;

    public static bool Looks(ReadOnlySpan<byte> b) => b[..Math.Min(b.Length, 1024)].IndexOf("%PDF-"u8) >= 0;

    private PdfFile(byte[] data, string name)
    {
        _data = data;
        Name = name;
    }

    public static PdfFile Read(byte[] data, string name, CancellationToken ct)
    {
        var pdf = new PdfFile(data, name);
        pdf.Scan(ct);
        pdf.Security = PdfSecurity.Open(pdf);
        pdf.ReadObjectStreams(ct);
        return pdf;
    }

    private void Scan(CancellationToken ct)
    {
        int header = _data.AsSpan(0, Math.Min(_data.Length, 1024)).IndexOf("%PDF-"u8);
        if (header >= 0)
        {
            HeaderOffset = header;
            int e = header + 5;
            while (e < _data.Length && e < header + 12 && _data[e] is >= (byte)'0' and <= (byte)'9' or (byte)'.') e++;
            Version = Encoding.Latin1.GetString(_data, header + 5, e - header - 5);
        }
        var lex = new PdfLexer(_data);
        // the last two numbers seen, with their positions, to recognize "n g obj"
        long n1 = -1, n2 = -1;
        int n1At = 0, n2At = 0;
        int steps = 0;
        while (!lex.AtEnd)
        {
            if ((++steps & 0xFFFF) == 0) ct.ThrowIfCancellationRequested();
            lex.SkipWhite();
            if (lex.AtEnd) break;
            int at = lex.Pos;
            byte b = _data[at];
            if (b is >= (byte)'0' and <= (byte)'9')
            {
                int p = at;
                while (p < _data.Length && _data[p] is >= (byte)'0' and <= (byte)'9') p++;
                if (p < _data.Length && !PdfLexer.IsWhite(_data[p]) && !PdfLexer.IsDelimiter(_data[p])) { lex.Pos = p; SkipWord(lex); n1 = n2 = -1; continue; }
                if (!long.TryParse(Encoding.Latin1.GetString(_data, at, Math.Min(p - at, 18)), out var v)) v = -1;
                (n1, n1At, n2, n2At) = (n2, n2At, v, at);
                lex.Pos = p;
                continue;
            }
            if (b is (byte)'(' or (byte)'<' or (byte)'[' or (byte)'/')
            {
                lex.Value(); // strings and dictionaries outside objects (trailers handled below)
                n1 = n2 = -1;
                continue;
            }
            var word = lex.PeekWord();
            if (word.Length == 0) { lex.Pos++; n1 = n2 = -1; continue; }
            lex.Pos += word.Length;
            switch (word)
            {
                case "obj" when n1 >= 0 && n2 >= 0:
                    ReadObject(lex, (int)Math.Min(n1, int.MaxValue), (int)Math.Min(n2, int.MaxValue), n1At);
                    break;
                case "xref": XrefSections++; break;
                case "trailer":
                    if (lex.Value() is PdfDict t) Trailers.Add(t);
                    break;
                default:
                    if (word.StartsWith("%%EOF", StringComparison.Ordinal)) EofMarkers++;
                    break;
            }
            n1 = n2 = -1;
            if (Objects.Count >= MaxObjects) { Notes.Add($"stopped at {MaxObjects:N0} objects"); break; }
        }
        // comments are skipped by the lexer: count %%EOF markers in the bytes
        EofMarkers = 0;
        int last = -1;
        for (int i = _data.AsSpan().IndexOf("%%EOF"u8); i >= 0; )
        {
            EofMarkers++;
            last = i;
            int next = _data.AsSpan(i + 5).IndexOf("%%EOF"u8);
            i = next < 0 ? -1 : i + 5 + next;
        }
        if (last >= 0)
        {
            int tail = last + 5;
            while (tail < _data.Length && PdfLexer.IsWhite(_data[tail])) tail++;
            AfterLastEof = _data.Length - tail;
        }
    }

    private static void SkipWord(PdfLexer lex) => lex.Pos += Math.Max(1, lex.PeekWord().Length);

    private void ReadObject(PdfLexer lex, int number, int generation, int at)
    {
        var value = lex.Value() ?? new PdfKeyword("null");
        if (value is PdfNumber num && lex.PeekWord() is var g && int.TryParse(g, out var gen))
        {
            int save = lex.Pos;
            lex.Pos += g.Length;
            if (lex.PeekWord() == "R") { lex.Pos += 1; value = new PdfRef((int)num.Value, gen); }
            else lex.Pos = save;
        }
        byte[]? stream = null;
        if (value is PdfDict dict && lex.PeekWord() == "stream")
        {
            lex.Pos += 6;
            int start = lex.Pos;
            if (start < _data.Length && _data[start] == 13) start++;
            if (start < _data.Length && _data[start] == 10) start++;
            int end = -1;
            if (dict["Length"] is PdfNumber len && len.Value >= 0 && start + (long)len.Value <= _data.Length)
            {
                int candidate = start + (int)len.Value;
                int k = candidate;
                while (k < _data.Length && PdfLexer.IsWhite(_data[k])) k++;
                if (_data.AsSpan(k).StartsWith("endstream"u8)) end = candidate;
            }
            if (end < 0)
            {
                int found = _data.AsSpan(start).IndexOf("endstream"u8);
                end = found < 0 ? _data.Length : start + found;
                // the end-of-line before endstream is not data
                if (end > start && _data[end - 1] == 10) end--;
                if (end > start && _data[end - 1] == 13) end--;
            }
            stream = _data.AsSpan(start, end - start).ToArray();
            lex.Pos = end;
            int es = _data.AsSpan(end).IndexOf("endstream"u8);
            if (es >= 0) lex.Pos = end + es + 9;
        }
        if (lex.PeekWord() == "endobj") lex.Pos += 6;
        Add(new PdfObject(number, generation, at, value) { Stream = stream });
    }

    private void Add(PdfObject o)
    {
        Objects.Add(o);
        _current[o.Number] = o;
    }

    /// <summary>The objects compressed into object streams (/Type /ObjStm), each read from its decoded stream.</summary>
    private void ReadObjectStreams(CancellationToken ct)
    {
        foreach (var stm in Objects.Where(o => o.InObjectStream == null && o.Dict?.Name("Type") == "ObjStm" && o.Stream != null).ToList())
        {
            ct.ThrowIfCancellationRequested();
            var data = Decoded(stm, out var stopped);
            if (stopped != null) { Notes.Add($"object stream {stm.Number}: filter {stopped} not decoded"); continue; }
            int count = (int)Math.Clamp((Resolve(stm.Dict!["N"]) as PdfNumber)?.Value ?? 0, 0, 1_000_000);
            int first = (int)Math.Clamp((Resolve(stm.Dict!["First"]) as PdfNumber)?.Value ?? 0, 0, data.Length);
            var lex = new PdfLexer(data, 0, first);
            var pairs = new List<(int Number, int Offset)>();
            for (int i = 0; i < count; i++)
            {
                if (lex.Value() is not PdfNumber num || lex.Value() is not PdfNumber off) break;
                pairs.Add(((int)num.Value, (int)off.Value));
            }
            foreach (var (number, offset) in pairs)
            {
                if (first + offset < 0 || first + offset >= data.Length) continue;
                var inner = new PdfLexer(data, first + offset);
                var value = inner.Value() ?? new PdfKeyword("null");
                // an object in a stream is current unless a later object at a file offset replaced it
                var o = new PdfObject(number, 0, stm.Offset, value) { InObjectStream = stm.Number };
                Objects.Add(o);
                if (!_current.TryGetValue(number, out var existing) || existing.InObjectStream != null || existing.Offset < stm.Offset) _current[number] = o;
                if (Objects.Count >= MaxObjects) return;
            }
        }
    }

    public PdfObject? Get(int number) => _current.GetValueOrDefault(number);

    /// <summary>The current object numbers and objects.</summary>
    public IEnumerable<PdfObject> Current => _current.Values.OrderBy(o => o.Number);

    /// <summary>A reference followed to its value (chains of references up to 32 deep); other values unchanged.</summary>
    public PdfValue? Resolve(PdfValue? v)
    {
        for (int i = 0; i < 32 && v is PdfRef r; i++) v = Get(r.Number)?.Value;
        return v is PdfRef ? null : v;
    }

    public PdfDict? Trailer => Trailers.LastOrDefault() ?? Objects.LastOrDefault(o => o.Dict?.Name("Type") == "XRef")?.Dict;

    /// <summary>A stream decrypted and decoded through its filters; <paramref name="stopped"/> names a filter left undone.</summary>
    public byte[] Decoded(PdfObject o, out string? stopped, long max = 256L << 20)
    {
        stopped = null;
        if (o.Stream == null || o.Dict == null) return [];
        var raw = o.InObjectStream == null && Security != null && o.Dict.Name("Type") != "XRef" ? Security.Decrypt(o.Stream, o.Number, o.Generation, stream: true) : o.Stream;
        try
        {
            var (data, left) = PdfFilters.Decode(raw, o.Dict, Resolve, max);
            stopped = left;
            return data;
        }
        catch (InvalidDataException ex)
        {
            stopped = "damaged data: " + ex.Message;
            return raw;
        }
    }

    /// <summary>A string value's text, decrypted when the file is encrypted (strings inside object streams are not encrypted separately).</summary>
    public string Text(PdfValue? v, PdfObject owner)
    {
        if (v is PdfRef r && Get(r.Number) is { } target) owner = target;
        if (Resolve(v) is not PdfString s) return "";
        if (Security == null || owner.InObjectStream != null) return s.Text;
        return new PdfString(Security.Decrypt(s.Bytes, owner.Number, owner.Generation, stream: false)).Text;
    }

    public byte[] Bytes => _data;
}
