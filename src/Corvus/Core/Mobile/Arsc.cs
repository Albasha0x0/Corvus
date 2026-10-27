using System.Text;
using Corvus.Native;

namespace Corvus.Core.Mobile;

/// <summary>A resource configuration (ResTable_config) with its aapt qualifier string; "" is the default.</summary>
public sealed record ArscConfig(byte[] Raw)
{
    public static readonly ArscConfig Default = new(new byte[64]);

    private byte B(int at) => at < Raw.Length ? Raw[at] : (byte)0;
    private ushort U16(int at) => (ushort)(B(at) | B(at + 1) << 8);

    public ushort Mcc => U16(4);
    public ushort Mnc => U16(6);
    public ushort Density => U16(14);
    public ushort SdkVersion => U16(24);

    /// <summary>Language and region, unpacking the 3-letter form ("fil", "419").</summary>
    public string Language => Unpack(B(8), B(9), 'a');
    public string Region => Unpack(B(10), B(11), '0');
    public string Script => Ascii(36, 4);
    public string Variant => Ascii(40, 8);

    private string Ascii(int at, int length)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < length && B(at + i) != 0; i++) sb.Append((char)B(at + i));
        return sb.ToString();
    }

    private static string Unpack(byte b0, byte b1, char basis)
    {
        if (b0 == 0) return "";
        if ((b0 & 0x80) == 0) return new string([(char)b0, (char)b1]);
        int first = b1 & 0x1F, second = ((b1 & 0xE0) >> 5) + ((b0 & 0x03) << 3), third = (b0 & 0x7C) >> 2;
        return new string([(char)(basis + first), (char)(basis + second), (char)(basis + third)]);
    }

    public string Qualifiers => _qualifiers ??= Build();
    private string? _qualifiers;

    public override string ToString() => Qualifiers.Length == 0 ? "default" : Qualifiers;

    private string Build()
    {
        var q = new List<string>();
        if (Mcc != 0) q.Add($"mcc{Mcc}");
        if (Mnc != 0) q.Add(Mnc == 0xFFFF ? "mnc00" : $"mnc{Mnc}");
        string lang = Language, region = Region, script = Script, variant = Variant;
        if (lang.Length > 0)
        {
            if (script.Length > 0 || variant.Length > 0 || lang.Length == 3 || region.Length == 3)
                q.Add("b+" + string.Join('+', new[] { lang, script, region, variant }.Where(s => s.Length > 0)));
            else q.Add(region.Length > 0 ? $"{lang}-r{region}" : lang);
        }
        byte layout = B(28), ui = B(29), layout2 = B(48), color = B(49), input = B(18);
        Add(q, layout & 0xC0, (0x40, "ldltr"), (0x80, "ldrtl"));
        if (U16(30) != 0) q.Add($"sw{U16(30)}dp");
        if (U16(32) != 0) q.Add($"w{U16(32)}dp");
        if (U16(34) != 0) q.Add($"h{U16(34)}dp");
        Add(q, layout & 0x0F, (1, "small"), (2, "normal"), (3, "large"), (4, "xlarge"));
        Add(q, layout & 0x30, (0x10, "notlong"), (0x20, "long"));
        Add(q, layout2 & 0x03, (1, "notround"), (2, "round"));
        Add(q, color & 0x03, (1, "nowidecg"), (2, "widecg"));
        Add(q, color & 0x0C, (4, "lowdr"), (8, "highdr"));
        Add(q, B(12), (1, "port"), (2, "land"), (3, "square"));
        Add(q, ui & 0x0F, (2, "desk"), (3, "car"), (4, "television"), (5, "appliance"), (6, "watch"), (7, "vrheadset"));
        Add(q, ui & 0x30, (0x10, "notnight"), (0x20, "night"));
        if (Density != 0)
            q.Add(Density switch
            {
                120 => "ldpi", 160 => "mdpi", 213 => "tvdpi", 240 => "hdpi", 320 => "xhdpi", 480 => "xxhdpi", 640 => "xxxhdpi",
                0xFFFE => "anydpi", 0xFFFF => "nodpi", var d => $"{d}dpi",
            });
        Add(q, B(13), (1, "notouch"), (2, "stylus"), (3, "finger"));
        Add(q, input & 0x03, (1, "keysexposed"), (2, "keyshidden"), (3, "keyssoft"));
        Add(q, B(16), (1, "nokeys"), (2, "qwerty"), (3, "12key"));
        Add(q, input & 0x0C, (4, "navexposed"), (8, "navhidden"));
        Add(q, B(17), (1, "nonav"), (2, "dpad"), (3, "trackball"), (4, "wheel"));
        if (U16(20) != 0 || U16(22) != 0) q.Add($"{Math.Max(U16(20), U16(22))}x{Math.Min(U16(20), U16(22))}");
        if (SdkVersion != 0) q.Add($"v{SdkVersion}");
        return string.Join('-', q);
    }

    private static void Add(List<string> q, int value, params (int Value, string Name)[] names)
    {
        foreach (var (v, n) in names)
            if (v == value) { q.Add(n); return; }
    }
}

/// <summary>One resource value in one configuration; a bag has <see cref="Map"/> and <see cref="Parent"/> instead of <see cref="Value"/>.</summary>
public sealed record ArscEntry(uint Id, string Type, string Key, ArscConfig Config, ushort Flags, ResValue? Value, uint Parent,
    IReadOnlyList<(uint Name, ResValue Value)>? Map)
{
    public bool IsPublic => (Flags & 0x0002) != 0;
}

public sealed record ArscPackage(uint Id, string Name, IReadOnlyList<ArscEntry> Entries);

/// <summary>An APK's compiled resource table (resources.arsc); never throws, problems go to <see cref="Issues"/>.</summary>
public sealed class ArscTable
{
    public const int MaxEntries = 4_000_000;

    public ResStringPool Strings { get; private set; } = ResStringPool.Empty;
    public IReadOnlyList<ArscPackage> Packages => _packages;
    public IReadOnlyList<ParseIssue> Issues => _issues;

    private readonly List<ArscPackage> _packages = [];
    private readonly List<ParseIssue> _issues = [];
    private readonly Dictionary<uint, List<ArscEntry>> _byId = [];
    private readonly Dictionary<uint, string> _packageNames = [];
    private int _entryCount;

    private ArscTable() { }

    public static bool IsArsc(ReadOnlySpan<byte> data) => data.Length >= 12 && ResChunk.U16(data, 0) == ResChunk.Table && ResChunk.U16(data, 2) == 12;

    public static ArscTable Read(ReadOnlySpan<byte> data)
    {
        var table = new ArscTable();
        table.Parse(data);
        return table;
    }

    /// <summary>Every value of resource <paramref name="id"/>, one per configuration.</summary>
    public IReadOnlyList<ArscEntry> Values(uint id) => _byId.TryGetValue(id, out var list) ? list : [];

    /// <summary>"@type/name" for the app's own resources, "@package:type/name" for others (android); null when unknown.</summary>
    public string? Name(uint id)
    {
        if (!_byId.TryGetValue(id, out var list)) return null;
        var e = list[0];
        var package = _packageNames.GetValueOrDefault(id >> 24);
        return id >> 24 == 0x7F || string.IsNullOrEmpty(package) ? $"@{e.Type}/{e.Key}" : $"@{package}:{e.Type}/{e.Key}";
    }

    /// <summary>A reference resolver for <see cref="ResValue.Format"/> and <see cref="AxmlDocument.ToXml"/>.</summary>
    public Func<uint, string?> Resolver => Name;

    /// <summary>The value of a simple entry as text (strings from the table pool, references by name).</summary>
    public string Format(ResValue value) => value.Format(Strings, Name);

    /// <summary>The default value of <paramref name="id"/>, references followed a few levels; null when none or a bag.</summary>
    public string? DefaultText(uint id)
    {
        for (int depth = 0; depth < 8; depth++)
        {
            var values = Values(id);
            var pick = values.FirstOrDefault(v => v.Config.Qualifiers.Length == 0) ?? values.FirstOrDefault();
            if (pick?.Value is not { } value) return null;
            if (!value.IsReference || value.Data == 0) return Format(value);
            id = value.Data;
        }
        return null;
    }

    private void Parse(ReadOnlySpan<byte> data)
    {
        const string Area = "arsc";
        if (ResChunk.Outer(data, Area, _issues) is not { } top) return;
        if (top.Type != ResChunk.Table) { _issues.Add(new(Area, $"not a resource table (chunk type 0x{top.Type:x4})", 0)); return; }
        for (int at = top.HeaderSize; at < top.Size;)
        {
            if (ResChunk.Header(data, at, top.Size, Area, _issues) is not { } chunk) break;
            if (chunk.Type == ResChunk.StringPool) Strings = ResStringPool.Read(data, at, chunk.HeaderSize, chunk.Size, Area, _issues);
            else if (chunk.Type == ResChunk.TablePackage) { if (!Package(data.Slice(at, chunk.Size), chunk.HeaderSize, at)) return; }
            else _issues.Add(new(Area, $"unknown chunk 0x{chunk.Type:x4} skipped", at));
            at += chunk.Size;
        }
        if (_packages.Count == 0) _issues.Add(new(Area, "no package", 0));
    }

    /// <summary>Reads one package chunk; false when the entry limit stops reading.</summary>
    private bool Package(ReadOnlySpan<byte> p, int headerSize, int baseOffset)
    {
        const string Area = "arsc package";
        uint id = ResChunk.U32(p, 8);
        var name = headerSize >= 268 ? Encoding.Unicode.GetString(p.Slice(12, 256)).Split('\0')[0] : "";
        _packageNames.TryAdd(id, name);
        uint typeStringsAt = ResChunk.U32(p, 268), keyStringsAt = ResChunk.U32(p, 276);
        uint typeIdOffset = headerSize >= 288 ? ResChunk.U32(p, 284) : 0;
        ResStringPool types = ResStringPool.Empty, keys = ResStringPool.Empty;
        var entries = new List<ArscEntry>();
        _packages.Add(new ArscPackage(id, name, entries));
        for (int at = headerSize; at < p.Length;)
        {
            if (ResChunk.Header(p, at, p.Length, Area, _issues) is not { } chunk) break;
            switch (chunk.Type)
            {
                case ResChunk.StringPool:
                    var pool = ResStringPool.Read(p, at, chunk.HeaderSize, chunk.Size, Area, _issues);
                    if (at == typeStringsAt) types = pool;
                    else if (at == keyStringsAt) keys = pool;
                    break;
                case ResChunk.TableType:
                    if (!TypeChunk(p.Slice(at, chunk.Size), chunk.HeaderSize, id, typeIdOffset, types, keys, entries, baseOffset + at)) return false;
                    break;
                case ResChunk.TableTypeSpec or ResChunk.TableLibrary or ResChunk.TableOverlayable or ResChunk.TableOverlayablePolicy or ResChunk.TableStagedAlias:
                    break;
                default:
                    _issues.Add(new(Area, $"unknown chunk 0x{chunk.Type:x4} skipped", baseOffset + at));
                    break;
            }
            at += chunk.Size;
        }
        return true;
    }

    private const byte SparseFlag = 0x01, Offset16Flag = 0x02;
    private const ushort ComplexEntry = 0x0001, CompactEntry = 0x0008;

    private bool TypeChunk(ReadOnlySpan<byte> t, int headerSize, uint package, uint typeIdOffset, ResStringPool types, ResStringPool keys,
        List<ArscEntry> entries, long fileOffset)
    {
        const string Area = "arsc type";
        byte typeId = t.Length > 8 ? t[8] : (byte)0;
        byte flags = t.Length > 9 ? t[9] : (byte)0;
        uint count = ResChunk.U32(t, 12), entriesStart = ResChunk.U32(t, 16);
        int configSize = (int)Math.Min(ResChunk.U32(t, 20), (uint)Math.Max(0, headerSize - 20));
        var config = new ArscConfig(t.Slice(20, Math.Max(0, Math.Min(configSize, t.Length - 20))).ToArray());
        var typeName = types.Get((uint)(typeId - 1 + typeIdOffset)) ?? $"type{typeId}";
        int slot = (flags & SparseFlag) != 0 ? 4 : (flags & Offset16Flag) != 0 ? 2 : 4;
        if (typeId == 0 || entriesStart > t.Length || headerSize + (long)count * slot > entriesStart)
        {
            _issues.Add(new(Area, $"type {typeName}: {count} entries do not fit the chunk", fileOffset));
            return true;
        }
        for (int i = 0; i < count; i++)
        {
            int at = headerSize + i * slot;
            uint index, offset;
            if ((flags & SparseFlag) != 0) { index = ResChunk.U16(t, at); offset = ResChunk.U16(t, at + 2) * 4u; }
            else if ((flags & Offset16Flag) != 0)
            {
                index = (uint)i;
                var v = ResChunk.U16(t, at);
                if (v == 0xFFFF) continue;
                offset = v * 4u;
            }
            else
            {
                index = (uint)i;
                offset = ResChunk.U32(t, at);
                if (offset == 0xFFFFFFFF) continue;
            }
            if (++_entryCount > MaxEntries)
            {
                _issues.Add(new(Area, $"more than {MaxEntries} entries; the rest is not read", fileOffset));
                return false;
            }
            long e = (long)entriesStart + offset;
            if (e + 8 > t.Length) { _issues.Add(new(Area, $"type {typeName}: entry {index} lies outside the chunk", fileOffset)); continue; }
            if (Entry(t, (int)e, package << 24 | (uint)typeId << 16 | index, typeName, config, keys) is { } entry)
            {
                entries.Add(entry);
                if (!_byId.TryGetValue(entry.Id, out var list)) _byId[entry.Id] = list = [];
                list.Add(entry);
            }
            else _issues.Add(new(Area, $"type {typeName}: entry {index} is malformed", fileOffset + e));
        }
        return true;
    }

    private static ArscEntry? Entry(ReadOnlySpan<byte> t, int e, uint id, string type, ArscConfig config, ResStringPool keys)
    {
        ushort size = ResChunk.U16(t, e), flags = ResChunk.U16(t, e + 2);
        if ((flags & CompactEntry) != 0)
            // Compact: the key index takes the size field, the data type the high byte of the flags.
            return new(id, type, keys.Get(size) ?? $"0x{id:x8}", config, (ushort)(flags & 0xFF), new ResValue((byte)(flags >> 8), ResChunk.U32(t, e + 4)), 0, null);
        var key = keys.Get(ResChunk.U32(t, e + 4)) ?? $"0x{id:x8}";
        if ((flags & ComplexEntry) == 0)
            return ResValue.Read(t, e + size) is { } value && size >= 8 ? new(id, type, key, config, flags, value, 0, null) : null;
        if (size < 16 || e + 16 > t.Length) return null;
        uint parent = ResChunk.U32(t, e + 8), count = ResChunk.U32(t, e + 12);
        if (e + size + (long)count * 12 > t.Length) return null;
        var map = new List<(uint, ResValue)>((int)count);
        for (int i = 0; i < count; i++)
        {
            int m = e + size + i * 12;
            map.Add((ResChunk.U32(t, m), ResValue.Read(t, m + 4)!.Value));
        }
        return new(id, type, key, config, flags, null, parent, map);
    }
}
