using System.Buffers.Binary;
using System.Globalization;
using System.IO.Hashing;
using System.Text;

namespace Corvus.Core.Logs;

/// <summary>
/// A Windows event log file (.evtx, format 3.1 and 3.2) read without the event log service: the file header, each
/// 64 KB chunk with its checksums, and every record rendered from its binary XML with the chunk's templates, as
/// wevtutil renders it. Records found in a chunk's free space after its last record are reported as recovered. Damaged
/// chunks and records are notes; <see cref="Read"/> throws <see cref="InvalidDataException"/> only when the file is not
/// an event log.
/// </summary>
public sealed class EvtxFile
{
    public const int ChunkSize = 0x10000, HeaderSize = 0x1000;
    private const int MaxDepth = 64, MaxNotes = 200;

    /// <summary>The file header: chunk range, next record id, version, chunk count, dirty and full flags, checksum verdict.</summary>
    public sealed record FileHeader(ulong FirstChunk, ulong LastChunk, ulong NextRecordId, int Major, int Minor, int ChunkCount, bool Dirty, bool Full,
        bool ChecksumMatches);

    /// <summary>
    /// One event: its record header's number, write time, chunk and file offset, the rendered XML, the System fields
    /// (EventRecordID is the event's own number, which an exported log keeps) and the event data (Data name to value, or
    /// UserData's elements). Recovered is true for a record found in free space.
    /// </summary>
    public sealed record Event(ulong RecordId, DateTime Written, int Chunk, long Offset, bool Recovered, string Xml, string? Provider, int? EventId,
        int? Level, DateTime? Created, string? Channel, string? Computer, int? ProcessId, int? ThreadId, string? UserId,
        IReadOnlyList<KeyValuePair<string, string>> Data)
    {
        public ulong? EventRecordId { get; init; }
    }

    public FileHeader Header { get; private set; } = null!;
    public int Chunks { get; private set; }
    public long Records { get; private set; }
    public long Recovered { get; private set; }
    public List<string> Notes { get; } = [];

    /// <summary>True when the bytes start with the file header signature.</summary>
    public static bool Looks(ReadOnlySpan<byte> head) => head.Length >= 8 && head[..8].SequenceEqual("ElfFile\0"u8);

    /// <summary>Reads every chunk of <paramref name="stream"/> in order and passes each event to <paramref name="sink"/>.</summary>
    public static EvtxFile Read(Stream stream, Action<Event> sink, CancellationToken ct)
    {
        var f = new EvtxFile();
        var header = new byte[HeaderSize];
        if (Fill(stream, header) < 128 || !Looks(header)) throw new InvalidDataException("not an event log file (no ElfFile header)");
        uint flags = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(120));
        f.Header = new FileHeader(BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(8)), BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(16)),
            BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(24)), BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(38)),
            BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(36)), BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(42)), (flags & 1) != 0, (flags & 2) != 0,
            Crc32.HashToUInt32(header.AsSpan(0, 120)) == BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(124)));
        if (!f.Header.ChecksumMatches) f.Note("file header: checksum does not match");
        var chunk = new byte[ChunkSize];
        for (int index = 0; ; index++)
        {
            ct.ThrowIfCancellationRequested();
            int got = Fill(stream, chunk);
            if (got == 0) break;
            if (got < ChunkSize) { f.Note($"chunk {index}: {got} of {ChunkSize} bytes; the file ends inside it"); break; }
            if (!chunk.AsSpan(0, 8).SequenceEqual("ElfChnk\0"u8))
            {
                if (chunk.AsSpan().IndexOfAnyExcept((byte)0) >= 0) f.Note($"chunk {index}: no ElfChnk signature; not read");
                continue;
            }
            f.Chunks++;
            new ChunkReader(f, chunk, index, HeaderSize + (long)index * ChunkSize, sink, ct).Run();
        }
        if (f.Chunks != f.Header.ChunkCount) f.Note($"the header counts {f.Header.ChunkCount} chunk(s); {f.Chunks} found");
        return f;
    }

    private static int Fill(Stream s, byte[] buffer)
    {
        int done = 0;
        while (done < buffer.Length)
        {
            int n = s.Read(buffer, done, buffer.Length - done);
            if (n <= 0) break;
            done += n;
        }
        return done;
    }

    private void Note(string note)
    {
        if (Notes.Count < MaxNotes) Notes.Add(note);
        else if (Notes.Count == MaxNotes) Notes.Add("further notes not kept");
    }

    // Binary XML: element and attribute names are offsets into the chunk, written in place the first time; templates
    // are fragments with numbered substitutions, also defined in place the first time and referenced by offset later.
    private abstract record Node;
    private sealed record Element(string Name, List<(string Name, List<Node> Value)> Attributes, List<Node> Children) : Node;
    private sealed record Text(string Value, bool Raw = false) : Node;
    private sealed record Substitution(int Index, bool Optional) : Node;

    private sealed class ChunkReader(EvtxFile file, byte[] c, int index, long origin, Action<Event> sink, CancellationToken ct)
    {
        private readonly Dictionary<int, string> _names = [];
        private readonly Dictionary<int, Element?> _templates = [];

        public void Run()
        {
            uint lastOffset = BinaryPrimitives.ReadUInt32LittleEndian(c.AsSpan(44));
            uint free = BinaryPrimitives.ReadUInt32LittleEndian(c.AsSpan(48));
            uint headerCrc = BinaryPrimitives.ReadUInt32LittleEndian(c.AsSpan(124));
            var crc = new Crc32();
            crc.Append(c.AsSpan(0, 120));
            crc.Append(c.AsSpan(128, 384));
            if (crc.GetCurrentHashAsUInt32() != headerCrc) file.Note($"chunk {index}: header checksum does not match");
            if (free < 0x200 || free > ChunkSize) { file.Note($"chunk {index}: free space offset {free} outside the chunk; records read to its end"); free = ChunkSize; }
            else if (Crc32.HashToUInt32(c.AsSpan(0x200, (int)free - 0x200)) != BinaryPrimitives.ReadUInt32LittleEndian(c.AsSpan(52)))
                file.Note($"chunk {index}: record checksum does not match");
            int at = 0x200;
            while (at + 24 <= free)
            {
                ct.ThrowIfCancellationRequested();
                int size = RecordSize(at, (int)free);
                if (size < 0) { file.Note($"chunk {index} +0x{at:x}: no record where one should start; the rest of the chunk is scanned"); break; }
                Record(at, size, recovered: false);
                at += size;
            }
            if (at <= lastOffset) file.Note($"chunk {index}: records end at 0x{at:x}, before the last record offset 0x{lastOffset:x}");
            // Free space: records an earlier pass wrote before the chunk was reused.
            for (int scan = Math.Max(at, (int)Math.Min(free, ChunkSize)); scan + 24 <= ChunkSize; scan += 8)
            {
                if (c[scan] != 0x2A || c[scan + 1] != 0x2A || c[scan + 2] != 0 || c[scan + 3] != 0) continue;
                int size = RecordSize(scan, ChunkSize);
                if (size < 0) continue;
                if (Record(scan, size, recovered: true)) scan += size - 8;
            }
        }

        /// <summary>The record's size when a valid record starts at <paramref name="at"/> and ends before <paramref name="end"/>; else -1.</summary>
        private int RecordSize(int at, int end)
        {
            if (at + 28 > end || BinaryPrimitives.ReadUInt32LittleEndian(c.AsSpan(at)) != 0x00002A2A) return -1;
            int size = BinaryPrimitives.ReadInt32LittleEndian(c.AsSpan(at + 4));
            if (size < 28 || at + size > end || BinaryPrimitives.ReadInt32LittleEndian(c.AsSpan(at + size - 4)) != size) return -1;
            return size;
        }

        private bool Record(int at, int size, bool recovered)
        {
            ulong id = BinaryPrimitives.ReadUInt64LittleEndian(c.AsSpan(at + 8));
            long ticks = BinaryPrimitives.ReadInt64LittleEndian(c.AsSpan(at + 16));
            try
            {
                int pos = at + 24;
                var root = Fragment(ref pos, at + size - 4, out var values, 0);
                var element = Resolve(root, values, 0);
                if (element.Count == 0) throw new InvalidDataException("no element");
                var sb = new StringBuilder();
                foreach (var n in element) Render(n, sb);
                var ev = Facts(element.OfType<Element>().FirstOrDefault(), id, FileTime(ticks), at, recovered, sb.ToString());
                if (recovered) file.Recovered++;
                else file.Records++;
                sink(ev);
                return true;
            }
            catch (Exception ex) when (ex is InvalidDataException or ArgumentOutOfRangeException or IndexOutOfRangeException or OverflowException)
            {
                if (!recovered) file.Note($"chunk {index} record {id}: not read ({ex.Message})");
                return false;
            }
        }

        private Event Facts(Element? root, ulong id, DateTime written, int at, bool recovered, string xml)
        {
            Element? system = root?.Children.OfType<Element>().FirstOrDefault(e => e.Name == "System");
            Element? Child(Element? e, string name) => e?.Children.OfType<Element>().FirstOrDefault(x => x.Name == name);
            string? Attr(Element? e, string name) => e?.Attributes.FirstOrDefault(a => a.Name == name) is { Name: not null } a ? Plain(a.Value) : null;
            string? Value(Element? e) => e == null ? null : Plain(e.Children);
            int? Int(string? s) => int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) ? v : null;
            DateTime? created = DateTime.TryParse(Attr(Child(system, "TimeCreated"), "SystemTime"), CultureInfo.InvariantCulture,
                DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var t) ? t : null;
            var data = new List<KeyValuePair<string, string>>();
            if (Child(root, "EventData") is { } eventData)
            {
                // An unnamed Data value is named by its position.
                var items = eventData.Children.OfType<Element>().ToList();
                for (int n = 0; n < items.Count; n++)
                    data.Add(new(Attr(items[n], "Name") ?? (items[n].Name == "Data" ? $"#{n}" : items[n].Name), Value(items[n]) ?? ""));
            }
            else if (Child(root, "UserData")?.Children.OfType<Element>().FirstOrDefault() is { } user)
                foreach (var d in user.Children.OfType<Element>()) data.Add(new(d.Name, Value(d) ?? ""));
            var execution = Child(system, "Execution");
            return new Event(id, written, index, origin + at, recovered, xml, Attr(Child(system, "Provider"), "Name"), Int(Value(Child(system, "EventID"))),
                Int(Value(Child(system, "Level"))), created, Value(Child(system, "Channel")), Value(Child(system, "Computer")),
                Int(Attr(execution, "ProcessID")), Int(Attr(execution, "ThreadID")), Attr(Child(system, "Security"), "UserID"), data)
            {
                EventRecordId = ulong.TryParse(Value(Child(system, "EventRecordID")), NumberStyles.None, CultureInfo.InvariantCulture, out var number) ? number : null,
            };
        }

        private static string Plain(List<Node> nodes)
        {
            var sb = new StringBuilder();
            foreach (var n in nodes)
                if (n is Text t) sb.Append(t.Raw ? Unescape(t.Value) : t.Value);
            return sb.ToString();
        }

        private static string Unescape(string entity) => entity switch
        {
            "&amp;" => "&", "&lt;" => "<", "&gt;" => ">", "&quot;" => "\"", "&apos;" => "'",
            _ when entity.StartsWith("&#x", StringComparison.Ordinal) && int.TryParse(entity.AsSpan(3, entity.Length - 4), NumberStyles.HexNumber, null, out var v) => char.ConvertFromUtf32(v),
            _ => entity,
        };

        /// <summary>A fragment (optional header, then a template instance or elements) up to EOF; substitution values come back in <paramref name="values"/>.</summary>
        private List<Node> Fragment(ref int pos, int end, out List<object?>? values, int depth)
        {
            if (depth > MaxDepth) throw new InvalidDataException("binary XML nested too deep");
            values = null;
            var nodes = new List<Node>();
            while (pos < end)
            {
                byte token = c[pos];
                switch (token & 0xBF)
                {
                    case 0x00: pos++; return nodes;
                    case 0x0F: pos += 4; break;
                    case 0x0C:
                    {
                        var template = Instance(ref pos, end, out values, depth);
                        if (template != null) nodes.Add(template);
                        break;
                    }
                    case 0x01: nodes.Add(ElementAt(ref pos, end, depth)); break;
                    default: throw new InvalidDataException($"token 0x{token:x2} at chunk offset 0x{pos:x} where a fragment continues");
                }
            }
            return nodes;
        }

        private Element? Instance(ref int pos, int end, out List<object?> values, int depth)
        {
            int start = pos;
            int offset = BinaryPrimitives.ReadInt32LittleEndian(c.AsSpan(pos + 6));
            pos += 10;
            if (offset == pos)
            {
                int length = BinaryPrimitives.ReadInt32LittleEndian(c.AsSpan(pos + 20));
                pos += 24 + length;
            }
            var template = Template(offset, depth);
            int count = BinaryPrimitives.ReadInt32LittleEndian(c.AsSpan(pos));
            if (count < 0 || count > 4096 || pos + 4 + count * 4 > end) throw new InvalidDataException($"template instance at 0x{start:x}: {count} values");
            pos += 4;
            var sizes = new (int Size, byte Type)[count];
            for (int i = 0; i < count; i++) sizes[i] = (BinaryPrimitives.ReadUInt16LittleEndian(c.AsSpan(pos + i * 4)), c[pos + i * 4 + 2]);
            pos += count * 4;
            values = new List<object?>(count);
            foreach (var (size, type) in sizes)
            {
                if (pos + size > end) throw new InvalidDataException("a substitution value runs past the record");
                values.Add(ValueOf(pos, size, type, depth));
                pos += size;
            }
            return template;
        }

        private Element? Template(int offset, int depth)
        {
            if (_templates.TryGetValue(offset, out var known)) return known;
            if (offset < 0x200 || offset + 24 > ChunkSize) throw new InvalidDataException($"template offset 0x{offset:x} outside the chunk");
            _templates[offset] = null; // a template that refers to itself reads as empty
            int length = BinaryPrimitives.ReadInt32LittleEndian(c.AsSpan(offset + 20));
            int pos = offset + 24, end = offset + 24 + length;
            if (length < 0 || end > ChunkSize) throw new InvalidDataException($"template at 0x{offset:x}: length {length}");
            var nodes = Fragment(ref pos, end, out _, depth + 1);
            var element = nodes.OfType<Element>().FirstOrDefault();
            _templates[offset] = element;
            return element;
        }

        private Element ElementAt(ref int pos, int end, int depth)
        {
            if (depth > MaxDepth) throw new InvalidDataException("elements nested too deep");
            bool hasAttributes = (c[pos] & 0x40) != 0;
            int nameOffset = BinaryPrimitives.ReadInt32LittleEndian(c.AsSpan(pos + 7));
            pos += 11;
            // A name defined in place comes before the attribute list size.
            var name = Name(nameOffset, ref pos);
            if (hasAttributes) pos += 4;
            var element = new Element(name, [], []);
            while (pos < end && (c[pos] & 0xBF) == 0x06)
            {
                bool more = (c[pos] & 0x40) != 0;
                int attrName = BinaryPrimitives.ReadInt32LittleEndian(c.AsSpan(pos + 1));
                pos += 5;
                var attr = Name(attrName, ref pos);
                var value = new List<Node>();
                while (pos < end && (c[pos] & 0xBF) is not (0x02 or 0x03 or 0x06)) ContentInto(value, ref pos, end, attribute: true, depth);
                element.Attributes.Add((attr, value));
                if (!more) break;
            }
            if (pos >= end) throw new InvalidDataException("element ends with the record");
            switch (c[pos])
            {
                case 0x03: pos++; return element;
                case 0x02: pos++; break;
                default: throw new InvalidDataException($"token 0x{c[pos]:x2} at 0x{pos:x} where a start element closes");
            }
            while (pos < end && c[pos] != 0x04) ContentInto(element.Children, ref pos, end, attribute: false, depth + 1);
            pos++;
            return element;
        }

        /// <summary>One content item: text, a substitution, a reference or (outside attributes) a child element.</summary>
        private void ContentInto(List<Node> into, ref int pos, int end, bool attribute, int depth)
        {
            byte token = c[pos];
            switch (token & 0xBF)
            {
                case 0x05:
                {
                    byte type = c[pos + 1];
                    if (type != 0x01) throw new InvalidDataException($"value token of type 0x{type:x2}");
                    int chars = BinaryPrimitives.ReadUInt16LittleEndian(c.AsSpan(pos + 2));
                    into.Add(new Text(Encoding.Unicode.GetString(c, pos + 4, chars * 2)));
                    pos += 4 + chars * 2;
                    break;
                }
                case 0x0D or 0x0E:
                    into.Add(new Substitution(BinaryPrimitives.ReadUInt16LittleEndian(c.AsSpan(pos + 1)), (token & 0xBF) == 0x0E));
                    pos += 4;
                    break;
                case 0x07:
                {
                    int chars = BinaryPrimitives.ReadUInt16LittleEndian(c.AsSpan(pos + 1));
                    into.Add(new Text("<![CDATA[" + Encoding.Unicode.GetString(c, pos + 3, chars * 2) + "]]>", Raw: true));
                    pos += 3 + chars * 2;
                    break;
                }
                case 0x08:
                    into.Add(new Text($"&#{BinaryPrimitives.ReadUInt16LittleEndian(c.AsSpan(pos + 1))};", Raw: true));
                    pos += 3;
                    break;
                case 0x09:
                {
                    int offset = BinaryPrimitives.ReadInt32LittleEndian(c.AsSpan(pos + 1));
                    pos += 5;
                    into.Add(new Text("&" + Name(offset, ref pos) + ";", Raw: true));
                    break;
                }
                case 0x0A:
                {
                    int offset = BinaryPrimitives.ReadInt32LittleEndian(c.AsSpan(pos + 1));
                    pos += 5;
                    var target = Name(offset, ref pos);
                    string data = "";
                    if (pos < end && c[pos] == 0x0B)
                    {
                        int chars = BinaryPrimitives.ReadUInt16LittleEndian(c.AsSpan(pos + 1));
                        data = Encoding.Unicode.GetString(c, pos + 3, chars * 2);
                        pos += 3 + chars * 2;
                    }
                    into.Add(new Text($"<?{target} {data}?>", Raw: true));
                    break;
                }
                case 0x01 when !attribute: into.Add(ElementAt(ref pos, end, depth)); break;
                default: throw new InvalidDataException($"token 0x{token:x2} at chunk offset 0x{pos:x}");
            }
        }

        /// <summary>The name at a chunk offset; a name defined in place at <paramref name="pos"/> is skipped over.</summary>
        private string Name(int offset, ref int pos)
        {
            if (offset == pos)
            {
                int chars = BinaryPrimitives.ReadUInt16LittleEndian(c.AsSpan(pos + 6));
                pos += 8 + chars * 2 + 2;
            }
            if (_names.TryGetValue(offset, out var known)) return known;
            if (offset < 0 || offset + 8 > ChunkSize) throw new InvalidDataException($"name offset 0x{offset:x} outside the chunk");
            int n = BinaryPrimitives.ReadUInt16LittleEndian(c.AsSpan(offset + 6));
            if (offset + 8 + n * 2 > ChunkSize) throw new InvalidDataException($"name at 0x{offset:x} runs past the chunk");
            return _names[offset] = Encoding.Unicode.GetString(c, offset + 8, n * 2);
        }

        /// <summary>A substitution value: a string, an array's items, or a nested fragment (binary XML) as nodes; null for the null type or an empty value.</summary>
        private object? ValueOf(int pos, int size, byte type, int depth)
        {
            if (size == 0 || type == 0x00) return null;
            var b = c.AsSpan(pos, size);
            if (type == 0x21)
            {
                int p = pos;
                var nodes = Fragment(ref p, pos + size, out var values, depth + 1);
                return Resolve(nodes, values, depth + 1);
            }
            if ((type & 0x80) != 0) return Array(b, (byte)(type & 0x7F));
            return Scalar(b, type);
        }

        private static string[] Array(ReadOnlySpan<byte> b, byte type)
        {
            var items = new List<string>();
            // Each item ends in a null; empty items count.
            if (type is 0x01 or 0x02)
            {
                var text = type == 0x01 ? Encoding.Unicode.GetString(b) : Encoding.Latin1.GetString(b);
                items.AddRange((text.EndsWith('\0') ? text[..^1] : text).Split('\0'));
            }
            else
            {
                int width = type switch { 0x03 or 0x04 => 1, 0x05 or 0x06 => 2, 0x07 or 0x08 or 0x0B or 0x0D or 0x14 => 4, 0x0F => 16, 0x12 => 16, _ => 8 };
                for (int i = 0; i + width <= b.Length; i += width) items.Add(Scalar(b.Slice(i, width), type));
            }
            return [.. items];
        }

        private static string Scalar(ReadOnlySpan<byte> b, byte type)
        {
            var inv = CultureInfo.InvariantCulture;
            switch (type)
            {
                case 0x01: return Encoding.Unicode.GetString(b).TrimEnd('\0');
                case 0x02: return Encoding.Latin1.GetString(b).TrimEnd('\0');
                case 0x03: return ((sbyte)b[0]).ToString(inv);
                case 0x04: return b[0].ToString(inv);
                case 0x05: return BinaryPrimitives.ReadInt16LittleEndian(b).ToString(inv);
                case 0x06: return BinaryPrimitives.ReadUInt16LittleEndian(b).ToString(inv);
                case 0x07: return BinaryPrimitives.ReadInt32LittleEndian(b).ToString(inv);
                case 0x08: return BinaryPrimitives.ReadUInt32LittleEndian(b).ToString(inv);
                case 0x09: return BinaryPrimitives.ReadInt64LittleEndian(b).ToString(inv);
                case 0x0A: return BinaryPrimitives.ReadUInt64LittleEndian(b).ToString(inv);
                case 0x0B: return BinaryPrimitives.ReadSingleLittleEndian(b).ToString("R", inv);
                case 0x0C: return BinaryPrimitives.ReadDoubleLittleEndian(b).ToString("R", inv);
                case 0x0D: return BinaryPrimitives.ReadInt32LittleEndian(b) != 0 ? "true" : "false";
                case 0x0E: return Convert.ToHexString(b);
                case 0x0F: return new Guid(b[..16]).ToString("B");
                case 0x10: return "0x" + (b.Length >= 8 ? BinaryPrimitives.ReadUInt64LittleEndian(b) : BinaryPrimitives.ReadUInt32LittleEndian(b)).ToString("x", inv);
                case 0x11:
                {
                    var t = FileTime(BinaryPrimitives.ReadInt64LittleEndian(b));
                    return t.ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", inv);
                }
                case 0x12:
                {
                    var s = new int[8];
                    for (int i = 0; i < 8; i++) s[i] = BinaryPrimitives.ReadUInt16LittleEndian(b[(i * 2)..]);
                    return $"{s[0]:D4}-{s[1]:D2}-{s[3]:D2}T{s[4]:D2}:{s[5]:D2}:{s[6]:D2}.{s[7]:D3}Z";
                }
                case 0x13: return Sid(b);
                case 0x14: return "0x" + BinaryPrimitives.ReadUInt32LittleEndian(b).ToString("x", inv);
                case 0x15: return "0x" + BinaryPrimitives.ReadUInt64LittleEndian(b).ToString("x", inv);
                default: return Convert.ToHexString(b);
            }
        }

        private static string Sid(ReadOnlySpan<byte> b)
        {
            if (b.Length < 8) return Convert.ToHexString(b);
            int count = b[1];
            ulong authority = 0;
            for (int i = 2; i < 8; i++) authority = authority << 8 | b[i];
            var sb = new StringBuilder($"S-{b[0]}-{authority}");
            for (int i = 0; i < count && 8 + i * 4 + 4 <= b.Length; i++) sb.Append('-').Append(BinaryPrimitives.ReadUInt32LittleEndian(b[(8 + i * 4)..]));
            return sb.ToString();
        }

        /// <summary>The nodes with substitutions replaced by their values; empty optional values drop their attribute or element, as wevtutil does.</summary>
        private List<Node> Resolve(List<Node> nodes, List<object?>? values, int depth)
        {
            if (depth > MaxDepth) throw new InvalidDataException("substitutions nested too deep");
            var output = new List<Node>();
            foreach (var n in nodes)
            {
                switch (n)
                {
                    // An element holding one array value is written once per item.
                    case Element e when e.Children is [Substitution only] && Value(values, only.Index) is string[] items:
                        foreach (var item in items)
                        {
                            var copy = new Element(e.Name, [], [new Text(item)]);
                            foreach (var (name, value) in e.Attributes) copy.Attributes.Add((name, Resolve(value, values, depth + 1)));
                            output.Add(copy);
                        }
                        break;
                    case Element e:
                        var element = new Element(e.Name, [], Resolve(e.Children, values, depth + 1));
                        foreach (var (name, value) in e.Attributes)
                        {
                            if (value is [Substitution { Optional: true } s] && Value(values, s.Index) == null) continue;
                            element.Attributes.Add((name, Resolve(value, values, depth + 1)));
                        }
                        // An element whose content is only empty optional values is dropped, attributes and all; one that only lost
                        // attributes stays.
                        if (e.Children.Count > 0 && element.Children.Count == 0 && e.Children.All(c => c is Substitution { Optional: true })) break;
                        output.Add(element);
                        break;
                    case Substitution s:
                        switch (Value(values, s.Index))
                        {
                            case string text: output.Add(new Text(text)); break;
                            case string[] items: output.Add(new Text(string.Join(",", items))); break;
                            case List<Node> fragment: output.AddRange(fragment); break;
                        }
                        break;
                    default:
                        output.Add(n);
                        break;
                }
            }
            return output;
        }

        private static object? Value(List<object?>? values, int index) => values != null && index < values.Count ? values[index] : null;

        private static void Render(Node n, StringBuilder sb)
        {
            switch (n)
            {
                case Text t: sb.Append(t.Raw ? t.Value : Escape(t.Value, attribute: false)); break;
                case Element e:
                    sb.Append('<').Append(e.Name);
                    foreach (var (name, value) in e.Attributes)
                    {
                        sb.Append(' ').Append(name).Append("='");
                        foreach (var v in value) if (v is Text t) sb.Append(t.Raw ? t.Value : Escape(t.Value, attribute: true));
                        sb.Append('\'');
                    }
                    if (e.Children.Count == 0) { sb.Append("/>"); break; }
                    sb.Append('>');
                    foreach (var child in e.Children) Render(child, sb);
                    sb.Append("</").Append(e.Name).Append('>');
                    break;
            }
        }

        private static string Escape(string s, bool attribute)
        {
            if (s.AsSpan().IndexOfAny("&<>'\"") < 0) return s;
            var sb = new StringBuilder(s.Length + 8);
            foreach (var ch in s)
                sb.Append(ch switch
                {
                    '&' => "&amp;", '<' => "&lt;", '>' => "&gt;",
                    '\'' when attribute => "&apos;", '"' when attribute => "&quot;",
                    _ => ch.ToString(),
                });
            return sb.ToString();
        }
    }

    private static DateTime FileTime(long ticks) =>
        ticks >= 0 && ticks <= DateTime.MaxValue.ToFileTimeUtc() ? DateTime.FromFileTimeUtc(ticks) : DateTime.MinValue;
}
