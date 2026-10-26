using System.Buffers.Binary;
using System.Text;

namespace Corvus.Core.Pri;

/// <summary>
/// A package resource index (resources.pri, the file MakePri.exe writes for a UWP, WinUI or MSIX package), read without
/// the MRT API: the header and table of contents, then its sections. The decision info section holds the qualifiers
/// (language, scale, contrast and the rest) grouped into qualifier sets and decisions; the hierarchical schema holds the
/// resource names as a tree of scopes and items; a resource map gives each item a decision and one candidate per
/// qualifier set; data item sections hold the candidates' strings, paths and embedded files.
/// </summary>
internal sealed class PriFile
{
    /// <summary>A qualifier of a candidate: name (Language, Scale, ...), value, priority and the score it has as the default.</summary>
    public sealed record Qualifier(string Name, string Value, int Priority, double ScoreAsDefault);

    /// <summary>
    /// One candidate value: its qualifiers (none for the neutral one), type (String, Path, EmbeddedData), the text of a
    /// string or path, the size and bytes of embedded data, and a note when its value is in a referenced file not read.
    /// </summary>
    public sealed record Candidate(IReadOnlyList<Qualifier> Qualifiers, string Type, string? Text, byte[]? Data, string? Note);

    /// <summary>A named resource: its path under the map ("Resources/AppName", "Files/Assets/Logo.png") and candidates.</summary>
    public sealed record Resource(string Name, IReadOnlyList<Candidate> Candidates);

    /// <summary>A resource map: name (the package name), unique name (ms-appx://Name/), whether it is primary, and resources in item order.</summary>
    public sealed record ResourceMap(string Name, string UniqueName, bool Primary, IReadOnlyList<Resource> Resources);

    /// <summary>A section in the table of contents: its identifier ("[mrm_decn_info]") and file offset and length.</summary>
    public sealed record Section(string Identifier, long Offset, long Length);

    private const int HeaderSize = 32, TocEntrySize = 32, SectionHeaderSize = 32, SectionTrailerSize = 8, MaxNotes = 20;
    private const uint TrailerMark = 0xDEF5FADE;

    private static readonly string[] Magics = ["mrm_pri0", "mrm_pri1", "mrm_pri2", "mrm_pri3", "mrm_prif"];

    // The qualifier types, in the order the decision info section numbers them.
    private static readonly string[] QualifierNames =
        ["Language", "Contrast", "Scale", "HomeRegion", "TargetSize", "LayoutDirection", "Theme", "AlternateForm", "DXFeatureLevel", "Configuration", "DeviceFamily", "Custom"];

    // The resource value types a map's value type table names.
    private static readonly string[] ValueTypes = ["String", "Path", "EmbeddedData", "AsciiString", "Utf8String", "AsciiPath", "Utf8Path"];

    private readonly byte[] _b;

    public string Format { get; }
    public IReadOnlyList<Section> Sections { get; }
    public List<ResourceMap> Maps { get; } = [];
    public List<string> Notes { get; } = [];

    /// <summary>The distinct qualifiers the decision info sections declare, in their order.</summary>
    public List<Qualifier> DeclaredQualifiers { get; } = [];

    /// <summary>A known "mrm_pri" magic at offset 0.</summary>
    public static bool Looks(ReadOnlySpan<byte> b) => b.Length >= 8 && Magics.Contains(Encoding.ASCII.GetString(b[..8]));

    private PriFile(byte[] b, string format, IReadOnlyList<Section> sections)
    {
        _b = b;
        Format = format;
        Sections = sections;
    }

    /// <summary>Reads the header, table of contents and every resource map; throws <see cref="InvalidDataException"/> when the header or table does not read.</summary>
    public static PriFile Read(byte[] data)
    {
        if (!Looks(data) || data.Length < HeaderSize) throw new InvalidDataException("no mrm_pri header");
        var b = data.AsSpan();
        uint tocOffset = U32(b, 16), sectionStart = U32(b, 20);
        int count = U16(b, 24);
        if (tocOffset + (long)count * TocEntrySize > data.Length || sectionStart > data.Length)
            throw new InvalidDataException($"the table of contents ({count} sections at 0x{tocOffset:X}) is outside the file");
        var sections = new List<Section>(count);
        for (int i = 0; i < count; i++)
        {
            int at = (int)tocOffset + i * TocEntrySize;
            sections.Add(new(Encoding.ASCII.GetString(b.Slice(at, 16)).TrimEnd('\0', ' '), sectionStart + (long)U32(b, at + 24), U32(b, at + 28)));
        }
        var pri = new PriFile(data, Encoding.ASCII.GetString(b[..8]), sections);
        pri.ReadMaps();
        return pri;
    }

    private void ReadMaps()
    {
        var decisions = new Dictionary<int, Decisions>();
        var schemas = new Dictionary<int, Schema>();
        for (int i = 0; i < Sections.Count; i++)
        {
            var s = Sections[i];
            if (!s.Identifier.StartsWith("[mrm_res_map", StringComparison.Ordinal)) continue;
            try
            {
                var body = Body(i);
                int schema = U16(body, 4), decision = U16(body, 8);
                if (!schemas.TryGetValue(schema, out var names)) schemas[schema] = names = ReadSchema(schema);
                if (!decisions.TryGetValue(decision, out var info)) decisions[decision] = info = ReadDecisions(decision);
                Maps.Add(ReadMap(i, body, names, info));
            }
            catch (Exception ex) when (ex is InvalidDataException or ArgumentOutOfRangeException or IndexOutOfRangeException)
            {
                Note($"section {i} {s.Identifier}: not read ({ex.Message})");
            }
        }
        if (Maps.Count == 0 && !Sections.Any(s => s.Identifier.StartsWith("[mrm_res_map", StringComparison.Ordinal)))
            Note("no resource map section");
    }

    /// <summary>The content of section <paramref name="index"/>, between its 32-byte header and 8-byte trailer.</summary>
    private ReadOnlySpan<byte> Body(int index)
    {
        if (index < 0 || index >= Sections.Count) throw new InvalidDataException($"section {index} is not in the table of contents");
        var s = Sections[index];
        if (s.Offset < 0 || s.Length < SectionHeaderSize + SectionTrailerSize || s.Offset + s.Length > _b.Length)
            throw new InvalidDataException($"section {index} at 0x{s.Offset:X} ({s.Length} bytes) is outside the file");
        var all = _b.AsSpan((int)s.Offset, (int)s.Length);
        if (U32(all, all.Length - 8) != TrailerMark) Note($"section {index} {s.Identifier}: no trailer mark");
        return all[SectionHeaderSize..^SectionTrailerSize];
    }

    private sealed record Decisions(List<List<Qualifier>> Sets, List<List<int>> DecisionSets);

    private Decisions ReadDecisions(int index)
    {
        var b = Body(index);
        int distinct = U16(b, 0), qualifiers = U16(b, 2), sets = U16(b, 4), decisions = U16(b, 6), indexEntries = U16(b, 8), dataChars = U16(b, 10);
        int at = 12;
        var decisionRanges = Ranges(b, ref at, decisions);
        var setRanges = Ranges(b, ref at, sets);
        var qualifierRows = new List<(int Distinct, int Priority, int Fallback)>(qualifiers);
        for (int i = 0; i < qualifiers; i++, at += 8) qualifierRows.Add((U16(b, at), U16(b, at + 2), U16(b, at + 4)));
        var distinctRows = new List<(int Type, int Offset)>(distinct);
        for (int i = 0; i < distinct; i++, at += 12) distinctRows.Add((U16(b, at + 2), (int)U32(b, at + 8)));
        var table = new int[indexEntries];
        for (int i = 0; i < indexEntries; i++, at += 2) table[i] = U16(b, at);
        var text = b.Slice(at, dataChars * 2).ToArray();
        var declared = distinctRows.Select(d => (Name: d.Type < QualifierNames.Length ? QualifierNames[d.Type] : $"type {d.Type}", Value: Chars(text, d.Offset))).ToList();
        var all = qualifierRows.Select(q => new Qualifier(declared[q.Distinct].Name, declared[q.Distinct].Value, q.Priority, q.Fallback / 1000.0)).ToList();
        foreach (var q in all.Where(q => q.Value.Length > 0 && !DeclaredQualifiers.Contains(q))) DeclaredQualifiers.Add(q);
        var setList = setRanges.Select(r => Enumerable.Range(r.First, r.Count).Select(i => all[table[i]]).ToList()).ToList();
        var decisionList = decisionRanges.Select(r => Enumerable.Range(r.First, r.Count).Select(i => table[i]).ToList()).ToList();
        return new(setList, decisionList);
    }

    private static List<(int First, int Count)> Ranges(ReadOnlySpan<byte> b, ref int at, int count)
    {
        var list = new List<(int, int)>(count);
        for (int i = 0; i < count; i++, at += 4) list.Add((U16(b, at), U16(b, at + 2)));
        return list;
    }

    private sealed record Schema(string Name, string UniqueName, string[] ItemNames);

    private Schema ReadSchema(int index)
    {
        var b = Body(index);
        bool extended = Sections[index].Identifier == "[mrm_hschemaex]";
        int uniqueChars = U16(b, 2), nameChars = U16(b, 4);
        // After the extended form's "[def_hnamesx]": version (two ushorts and a reserved uint), checksum, scope and item counts.
        int at = 8 + (extended ? 16 : 0) + 20;
        string unique = Chars(b.Slice(at, uniqueChars * 2), 0);
        at += uniqueChars * 2;
        string name = Chars(b.Slice(at, nameChars * 2), 0);
        at += nameChars * 2;
        // A reserved ushort, the longest full path and a reserved ushort; then entry, scope and item counts, the unicode
        // name length in characters and a reserved uint (two in the extended form).
        at += 6;
        int entries = (int)U32(b, at), scopes = (int)U32(b, at + 4), items = (int)U32(b, at + 8), unicodeChars = (int)U32(b, at + 12);
        at += 20 + (extended ? 4 : 0);
        var rows = new List<(int Parent, int NameLength, int Flags, int NameOffset, int Index)>(entries);
        for (int i = 0; i < entries; i++, at += 12)
        {
            int flags = b[at + 7];
            rows.Add((U16(b, at), b[at + 6], flags, U16(b, at + 8) | ((flags & 0xF) << 16), U16(b, at + 10)));
        }
        // Each scope's child range; not needed to name items.
        at += scopes * 8;
        var itemEntries = new int[items];
        for (int i = 0; i < items; i++, at += 2) itemEntries[i] = U16(b, at);
        var unicode = b.Slice(at, unicodeChars * 2).ToArray();
        var ascii = b[(at + unicodeChars * 2)..].ToArray();
        var names = new string[rows.Count];
        string Own(int i)
        {
            var r = rows[i];
            if (r.NameLength == 0) return "";
            return (r.Flags & 0x20) != 0
                ? Encoding.ASCII.GetString(ascii, r.NameOffset, r.NameLength)
                : Encoding.Unicode.GetString(unicode, r.NameOffset * 2, r.NameLength * 2);
        }
        string Full(int i, int depth)
        {
            if (names[i] != null) return names[i];
            var own = Own(i);
            if (depth > 256) throw new InvalidDataException("the scope tree is deeper than 256 levels");
            int parent = rows[i].Parent;
            var full = parent == i || i == 0 ? own : Full(parent, depth + 1) is { Length: > 0 } p ? p + "/" + own : own;
            return names[i] = full;
        }
        var itemNames = itemEntries.Select(e => e < rows.Count ? Full(e, 0) : $"item entry {e}").ToArray();
        return new(name, unique, itemNames);
    }

    private ResourceMap ReadMap(int index, ReadOnlySpan<byte> b, Schema schema, Decisions info)
    {
        int envLength = U16(b, 0), schemaRefLength = U16(b, 6), valueTypeCount = U16(b, 10), groupMapCount = U16(b, 12), groupCount = U16(b, 14);
        int itemInfoCount = (int)U32(b, 16), candidateCount = (int)U32(b, 20), dataLength = (int)U32(b, 24), largeLength = (int)U32(b, 28);
        int at = 32 + envLength + schemaRefLength;
        var valueTypes = new int[valueTypeCount];
        for (int i = 0; i < valueTypeCount; i++, at += 8) valueTypes[i] = (int)U32(b, at + 4);
        var groupMap = new List<(int FirstItem, int Group)>();
        for (int i = 0; i < groupMapCount; i++, at += 4) groupMap.Add((U16(b, at), U16(b, at + 2)));
        var groups = new List<(int Size, int First)>();
        for (int i = 0; i < groupCount; i++, at += 4) groups.Add((U16(b, at), U16(b, at + 2)));
        var itemInfos = new List<(int Decision, int FirstCandidate)>();
        for (int i = 0; i < itemInfoCount; i++, at += 4) itemInfos.Add((U16(b, at), U16(b, at + 2)));
        if (largeLength > 0)
        {
            int large = at;
            int largeMaps = (int)U32(b, at), largeGroups = (int)U32(b, at + 4), largeInfos = (int)U32(b, at + 8);
            at += 12;
            for (int i = 0; i < largeMaps; i++, at += 8) groupMap.Add(((int)U32(b, at), (int)U32(b, at + 4)));
            for (int i = 0; i < largeGroups; i++, at += 8) groups.Add(((int)U32(b, at), (int)U32(b, at + 4)));
            for (int i = 0; i < largeInfos; i++, at += 8) itemInfos.Add(((int)U32(b, at), (int)U32(b, at + 4)));
            at = large + largeLength;
        }
        int candidatesAt = at;
        int dataAt = candidatesAt + candidateCount * 8;
        var data = b.Slice(dataAt, dataLength);
        var dataSections = new Dictionary<int, DataItems>();
        var resources = new SortedDictionary<int, Resource>();
        foreach (var (firstItem, groupIndex) in groupMap)
        {
            // An index past the groups (small, then large) names one item info directly.
            var (size, first) = groupIndex < groups.Count ? groups[groupIndex] : (1, groupIndex - groups.Count);
            for (int i = 0; i < size; i++)
            {
                var (decision, firstCandidate) = itemInfos[first + i];
                int item = firstItem + i;
                var candidates = new List<Candidate>();
                var setsOfDecision = info.DecisionSets[decision];
                for (int c = 0; c < setsOfDecision.Count; c++)
                {
                    int ca = candidatesAt + (firstCandidate + c) * 8;
                    int kind = b[ca], typeIndex = b[ca + 1];
                    string type = typeIndex < valueTypes.Length && valueTypes[typeIndex] < ValueTypes.Length ? ValueTypes[valueTypes[typeIndex]] : $"type {typeIndex}";
                    var qualifiers = info.Sets[setsOfDecision[c]];
                    if (kind == 0x01)
                    {
                        int sourceFile = U16(b, ca + 2), dataItem = U16(b, ca + 4), section = U16(b, ca + 6);
                        if (sourceFile != 0)
                        {
                            candidates.Add(new(qualifiers, Shown(type), null, null, $"in referenced file {sourceFile}, not read"));
                            continue;
                        }
                        if (!dataSections.TryGetValue(section, out var items)) dataSections[section] = items = ReadDataItems(section);
                        candidates.Add(Value(qualifiers, type, items.Get(dataItem)));
                    }
                    else if (kind == 0x00)
                    {
                        int length = U16(b, ca + 2), offset = (int)U32(b, ca + 4);
                        candidates.Add(Value(qualifiers, type, data.Slice(offset, length).ToArray()));
                    }
                    else candidates.Add(new(qualifiers, Shown(type), null, null, $"candidate kind 0x{kind:X2} not read"));
                }
                resources[item] = new(item < schema.ItemNames.Length ? schema.ItemNames[item] : $"item {item}", candidates);
            }
        }
        // A name with no candidate here keeps its place: a split file (resources.en-US.pri) holds its candidates.
        for (int item = 0; item < schema.ItemNames.Length; item++) resources.TryAdd(item, new(schema.ItemNames[item], []));
        return new(schema.Name, schema.UniqueName, PrimaryMap() == index, [.. resources.Values]);
    }

    /// <summary>The primary resource map's section index from the descriptor section, or -1.</summary>
    private int PrimaryMap()
    {
        int descriptor = Sections.ToList().FindIndex(s => s.Identifier is "[mrm_pridescex]" or "[mrm_pridesc]");
        if (descriptor < 0) return -1;
        var b = Body(descriptor);
        int primary = U16(b, 12);
        return primary == 0xFFFF ? -1 : primary;
    }

    /// <summary>The value type as MakePri names it: String, Path or EmbeddedData whatever the encoding.</summary>
    private static string Shown(string type) => type switch { "AsciiString" or "Utf8String" => "String", "AsciiPath" or "Utf8Path" => "Path", _ => type };

    private static Candidate Value(IReadOnlyList<Qualifier> qualifiers, string type, byte[] bytes) => type switch
    {
        "String" or "Path" => new(qualifiers, type, Chars(bytes, 0), null, null),
        "AsciiString" or "AsciiPath" => new(qualifiers, Shown(type), Encoding.ASCII.GetString(Terminated(bytes)), null, null),
        "Utf8String" or "Utf8Path" => new(qualifiers, Shown(type), Encoding.UTF8.GetString(Terminated(bytes)), null, null),
        _ => new(qualifiers, type, null, bytes, null),
    };

    private sealed record DataItems(byte[] Bytes, List<(int Offset, int Length)> Items)
    {
        public byte[] Get(int i) => i < Items.Count ? Bytes.AsSpan(Items[i].Offset, Items[i].Length).ToArray() : throw new InvalidDataException($"data item {i} of {Items.Count}");
    }

    private DataItems ReadDataItems(int index)
    {
        var b = Body(index);
        int strings = U16(b, 4), blobs = U16(b, 6);
        int dataLength = (int)U32(b, 8);
        int at = 12;
        var items = new List<(int, int)>(strings + blobs);
        for (int i = 0; i < strings; i++, at += 4) items.Add((U16(b, at), U16(b, at + 2)));
        for (int i = 0; i < blobs; i++, at += 8) items.Add(((int)U32(b, at), (int)U32(b, at + 4)));
        var data = b.Slice(at, dataLength).ToArray();
        foreach (var (o, l) in items)
            if (o < 0 || l < 0 || (long)o + l > data.Length) throw new InvalidDataException($"a data item ({o}, {l}) is outside section {index}");
        return new(data, items);
    }

    private void Note(string text)
    {
        if (Notes.Count < MaxNotes) Notes.Add(text);
    }

    private static ReadOnlySpan<byte> Terminated(byte[] b) => b.AsSpan(0, Array.IndexOf(b, (byte)0) is var z && z >= 0 ? z : b.Length);

    /// <summary>The NUL-terminated UTF-16 string at character <paramref name="offset"/>.</summary>
    private static string Chars(ReadOnlySpan<byte> b, int offset)
    {
        var s = b[(offset * 2)..];
        int end = 0;
        while (end + 1 < s.Length && (s[end] | s[end + 1]) != 0) end += 2;
        return Encoding.Unicode.GetString(s[..end]);
    }

    private static ushort U16(ReadOnlySpan<byte> b, int at) => BinaryPrimitives.ReadUInt16LittleEndian(b[at..]);

    private static uint U32(ReadOnlySpan<byte> b, int at) => BinaryPrimitives.ReadUInt32LittleEndian(b[at..]);
}
