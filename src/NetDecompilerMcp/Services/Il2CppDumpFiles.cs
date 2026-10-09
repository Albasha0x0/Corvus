using System.Buffers;
using System.Globalization;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace NetDecompilerMcp.Services;

/// <summary>
/// The files Il2CppDumper writes beside its DummyDll folder: script.json (function names, signatures, metadata
/// addresses), stringliteral.json (string literals and their slots), and the game binary they describe.
/// </summary>
public sealed record Il2CppDumpFiles(string Directory, string? ScriptJson, string? StringLiteralJson, string? GameAssembly)
{
    public const string ScriptFileName = "script.json";
    public const string StringLiteralFileName = "stringliteral.json";
    public const string GameAssemblyFileName = "GameAssembly.dll";

    /// <summary>Size and write time of every file when located, to notice a dump written again.</summary>
    public string Stamp { get; } = string.Join("|", new[] { ScriptJson, StringLiteralJson, GameAssembly }.Select(p =>
        p != null && new FileInfo(p) is { Exists: true } f ? $"{f.Length}:{f.LastWriteTimeUtc.Ticks}" : "-"));

    /// <summary>
    /// The dump files for an assembly folder: script.json / stringliteral.json in the folder or its parent (the nearest
    /// folder with either), GameAssembly.dll in that folder or its parent. Null when there are no JSON files.
    /// </summary>
    public static Il2CppDumpFiles? Locate(string assemblyDirectory)
    {
        foreach (var dir in SelfAndParent(assemblyDirectory))
        {
            var script = Existing(dir, ScriptFileName);
            var strings = Existing(dir, StringLiteralFileName);
            if (script == null && strings == null) continue;
            var binary = SelfAndParent(dir).Select(d => Existing(d, GameAssemblyFileName)).FirstOrDefault(p => p != null);
            return new Il2CppDumpFiles(Path.GetFullPath(dir), script, strings, binary);
        }
        return null;
    }

    private static IEnumerable<string> SelfAndParent(string dir)
    {
        yield return dir;
        if (Path.GetDirectoryName(Path.TrimEndingDirectorySeparator(dir)) is { Length: > 0 } parent) yield return parent;
    }

    private static string? Existing(string dir, string name) => Path.Combine(dir, name) is var p && File.Exists(p) ? Path.GetFullPath(p) : null;
}

/// <summary>
/// Compact view of a script.json: the sorted function starts; the ScriptMethod entries by address, each with its name
/// as two pooled parts (type and method, split at "$$") and the file offset of its object, so signatures are read from
/// the file only when asked for; and the ScriptMetadata / ScriptMetadataMethod slots by address, findable by name.
/// Addresses that cannot be RVAs (beyond 32 bits) are dropped.
/// </summary>
public sealed class Il2CppScript
{
    private readonly uint[] _methodAddresses;
    private readonly long[] _methodOffsets;
    private readonly int[] _methodTypes, _methodNames;
    private readonly uint[] _metadataAddresses;
    private readonly long[] _metadataOffsets;
    private readonly NameHashes _metadataByName;
    private readonly uint[] _methodInfoAddresses, _methodInfoTargets;
    private readonly long[] _methodInfoOffsets;
    private readonly NameHashes _methodInfoByName;

    private Il2CppScript(string path, Builder b, TimeSpan loadTime)
    {
        Path = path;
        DroppedAddresses = b.Dropped;
        LoadTime = loadTime;

        // ScriptMethod entries by address; entries of one address keep file order.
        var order = SortedOrder(b.MethodAddresses);
        _methodAddresses = Permute(b.MethodAddresses, order);
        _methodOffsets = Permute(b.MethodOffsets, order);
        _methodTypes = Permute(b.MethodTypes, order);
        _methodNames = Permute(b.MethodNameIds, order);
        TypeNames = Utf8Strings.From(b.TypeNames);
        MethodNames = Utf8Strings.From(b.MethodNameList);

        var metadataOrder = SortedOrder(b.MetadataAddresses);
        _metadataAddresses = Permute(b.MetadataAddresses, metadataOrder);
        _metadataOffsets = Permute(b.MetadataOffsets, metadataOrder);
        MetadataNames = Utf8Strings.From(metadataOrder.Select(i => b.MetadataNames[i]).ToList());
        _metadataByName = new NameHashes(Enumerable.Range(0, MetadataNames.Count).Select(i => MetadataNames[i].GetHashCode()).ToArray());

        var infoOrder = SortedOrder(b.MethodInfoAddresses);
        _methodInfoAddresses = Permute(b.MethodInfoAddresses, infoOrder);
        _methodInfoTargets = Permute(b.MethodInfoTargets, infoOrder);
        _methodInfoOffsets = Permute(b.MethodInfoOffsets, infoOrder);
        _methodInfoByName = new NameHashes(Permute(b.MethodInfoHashes, infoOrder));

        b.Starts.AddRange(b.MethodAddresses);
        FunctionStarts = b.Starts.Distinct().Order().ToArray();
    }

    public string Path { get; }
    /// <summary>Distinct RVAs from Addresses and ScriptMethod, ascending.</summary>
    public uint[] FunctionStarts { get; }
    public int MethodCount => _methodAddresses.Length;
    public int DroppedAddresses { get; }
    public TimeSpan LoadTime { get; }

    /// <summary>Distinct type parts ("Ns.Type&lt;args&gt;") and method parts of the ScriptMethod names.</summary>
    public Utf8Strings TypeNames { get; }
    public Utf8Strings MethodNames { get; }
    /// <summary>ScriptMetadata names, in address order.</summary>
    public Utf8Strings MetadataNames { get; }
    public int MetadataCount => _metadataAddresses.Length;
    public int MethodInfoCount => _methodInfoAddresses.Length;

    /// <summary>Approximate size of the arrays kept.</summary>
    public long RetainedBytes =>
        FunctionStarts.Length * 4L + _methodAddresses.Length * (4L + 8 + 4 + 4)
        + TypeNames.Size + MethodNames.Size + MetadataNames.Size + _metadataAddresses.Length * (4L + 8 + 8)
        + _methodInfoAddresses.Length * (4L + 4 + 8 + 8);

    private sealed class Builder
    {
        public int Dropped;
        public readonly List<uint> Starts = [], MethodAddresses = [], MetadataAddresses = [], MethodInfoAddresses = [], MethodInfoTargets = [];
        public readonly List<long> MethodOffsets = [], MetadataOffsets = [], MethodInfoOffsets = [];
        public readonly List<int> MethodTypes = [], MethodNameIds = [], MethodInfoHashes = [];
        public readonly List<string> TypeNames = [], MethodNameList = [], MetadataNames = [];
        public readonly Dictionary<string, int> TypeIds = new(StringComparer.Ordinal), MethodIds = new(StringComparer.Ordinal);

        public static int Intern(Dictionary<string, int> ids, List<string> list, string value)
        {
            if (!ids.TryGetValue(value, out var id)) { ids[value] = id = list.Count; list.Add(value); }
            return id;
        }
    }

    public static Il2CppScript Load(string path, CancellationToken ct = default)
    {
        var watch = System.Diagnostics.Stopwatch.StartNew();
        var b = new Builder();
        static bool Valid(ulong a) => a != 0 && a <= uint.MaxValue;
        new ScriptJsonReader
        {
            MethodSignatures = false,
            Method = (m, offset) =>
            {
                if (!Valid(m.Address)) { b.Dropped++; return; }
                b.MethodAddresses.Add((uint)m.Address);
                b.MethodOffsets.Add(offset);
                int split = m.Name.IndexOf("$$", StringComparison.Ordinal);
                b.MethodTypes.Add(Builder.Intern(b.TypeIds, b.TypeNames, split >= 0 ? m.Name[..split] : m.Name));
                b.MethodNameIds.Add(Builder.Intern(b.MethodIds, b.MethodNameList, split >= 0 ? m.Name[(split + 2)..] : ""));
            },
            Metadata = (m, offset) =>
            {
                if (!Valid(m.Address)) return;
                b.MetadataAddresses.Add((uint)m.Address);
                b.MetadataOffsets.Add(offset);
                b.MetadataNames.Add(m.Name);
            },
            MetadataMethod = (m, offset) =>
            {
                if (!Valid(m.Address)) return;
                b.MethodInfoAddresses.Add((uint)m.Address);
                b.MethodInfoTargets.Add(Valid(m.MethodAddress) ? (uint)m.MethodAddress : 0);
                b.MethodInfoOffsets.Add(offset);
                b.MethodInfoHashes.Add(m.Name.GetHashCode());
            },
            Address = a =>
            {
                if (!Valid(a)) { b.Dropped++; return; }
                b.Starts.Add((uint)a);
            },
        }.Read(path, ct);
        b.TypeIds.Clear();
        b.MethodIds.Clear();
        return new Il2CppScript(path, b, watch.Elapsed);
    }

    /// <summary>Indexes ordered by key; equal keys keep their original order.</summary>
    private static int[] SortedOrder(List<uint> keys)
    {
        var composite = new ulong[keys.Count];
        for (int i = 0; i < composite.Length; i++) composite[i] = (ulong)keys[i] << 32 | (uint)i;
        Array.Sort(composite);
        return Array.ConvertAll(composite, k => (int)(uint)k);
    }

    private static T[] Permute<T>(List<T> values, int[] order)
    {
        var result = new T[order.Length];
        for (int i = 0; i < order.Length; i++) result[i] = values[order[i]];
        return result;
    }

    /// <summary>The nearest function start at or before <paramref name="rva"/>, within <paramref name="maxSpan"/> bytes.</summary>
    public uint? FunctionContaining(uint rva, ulong maxSpan = Il2CppService.MaxFunctionSpan)
    {
        int i = Array.BinarySearch(FunctionStarts, rva);
        if (i < 0) i = ~i - 1;
        return i >= 0 && rva - FunctionStarts[i] < maxSpan ? FunctionStarts[i] : null;
    }

    /// <summary>The ScriptMethod entries whose function starts at <paramref name="address"/>, in file order.</summary>
    public List<ScriptMethod> MethodsAt(uint address)
    {
        var (first, count) = MethodRange(address);
        var list = new List<ScriptMethod>(count);
        if (count == 0) return list;
        using var file = OpenFile();
        for (int i = first; i < first + count; i++)
            list.Add(ScriptJsonReader.ReadMethodAt(file, _methodOffsets[i]));
        return list;
    }

    /// <summary>The ScriptMethod entries (indexes) whose function starts at <paramref name="address"/>.</summary>
    public (int First, int Count) MethodRange(uint address)
    {
        int i = Array.BinarySearch(_methodAddresses, address);
        if (i < 0) return (0, 0);
        int start = i, end = i + 1;
        while (start > 0 && _methodAddresses[start - 1] == address) start--;
        while (end < _methodAddresses.Length && _methodAddresses[end] == address) end++;
        return (start, end - start);
    }

    public uint MethodAddress(int entry) => _methodAddresses[entry];
    public string MethodTypeName(int entry) => TypeNames[_methodTypes[entry]];
    public string MethodShortName(int entry) => MethodNames[_methodNames[entry]];
    /// <summary>The ScriptMethod name: "Ns.Type&lt;args&gt;$$Method&lt;args&gt;".</summary>
    public string MethodName(int entry) => MethodNames.Length(_methodNames[entry]) == 0
        ? MethodTypeName(entry) : MethodTypeName(entry) + "$$" + MethodShortName(entry);

    /// <summary>Reads one entry from the file, with its signature.</summary>
    public ScriptMethod ReadMethod(int entry)
    {
        using var file = OpenFile();
        return ScriptJsonReader.ReadMethodAt(file, _methodOffsets[entry]);
    }

    /// <summary>Reads entries with their signatures through one open file handle.</summary>
    public MethodReader OpenMethods() => new(this);

    public sealed class MethodReader(Il2CppScript script) : IDisposable
    {
        private readonly SafeFileHandle _file = script.OpenFile();
        public ScriptMethod Read(int entry) => ScriptJsonReader.ReadMethodAt(_file, script._methodOffsets[entry]);
        public void Dispose() => _file.Dispose();
    }

    /// <summary>The entries whose type part satisfies <paramref name="type"/> and method part <paramref name="method"/>, by address.</summary>
    public List<int> FindMethods(Func<string, bool> type, Func<string, bool>? method = null, CancellationToken ct = default)
    {
        var result = new List<int>();
        var types = new bool[TypeNames.Count];
        bool any = false;
        for (int t = 0; t < types.Length; t++)
        {
            if ((t & 0xFFF) == 0) ct.ThrowIfCancellationRequested();
            any |= types[t] = type(TypeNames[t]);
        }
        if (!any) return result;
        var methods = new sbyte[MethodNames.Count]; // 0 unknown, 1 matches, -1 does not
        for (int i = 0; i < _methodAddresses.Length; i++)
        {
            if (!types[_methodTypes[i]]) continue;
            if (method != null)
            {
                ref var known = ref methods[_methodNames[i]];
                if (known == 0) known = method(MethodNames[_methodNames[i]]) ? (sbyte)1 : (sbyte)-1;
                if (known < 0) continue;
            }
            result.Add(i);
        }
        return result;
    }

    /// <summary>The ScriptMetadata slot covering <paramref name="rva"/> (slots are pointer-sized).</summary>
    public int? MetadataAt(uint rva) => SlotAt(_metadataAddresses, rva);
    public uint MetadataAddress(int entry) => _metadataAddresses[entry];
    public string MetadataName(int entry) => MetadataNames[entry];

    /// <summary>Reads one ScriptMetadata entry from the file, with its signature (the C type of the slot).</summary>
    public ScriptMetadata ReadMetadata(int entry)
    {
        using var file = OpenFile();
        return ScriptJsonReader.ReadMetadataAt(file, _metadataOffsets[entry]);
    }

    /// <summary>ScriptMetadata entries with exactly this name.</summary>
    public List<int> MetadataNamed(string name) => _metadataByName.Find(name.GetHashCode(), e => MetadataNames.Equals(e, name));

    /// <summary>The ScriptMetadataMethod slot (MethodInfo) covering <paramref name="rva"/>.</summary>
    public int? MethodInfoAt(uint rva) => SlotAt(_methodInfoAddresses, rva);
    public uint MethodInfoAddress(int entry) => _methodInfoAddresses[entry];
    /// <summary>The function a MethodInfo describes; 0 when it has no code.</summary>
    public uint MethodInfoTarget(int entry) => _methodInfoTargets[entry];

    public ScriptMetadataMethod ReadMethodInfo(int entry)
    {
        using var file = OpenFile();
        return ScriptJsonReader.ReadMetadataMethodAt(file, _methodInfoOffsets[entry]);
    }

    /// <summary>ScriptMetadataMethod entries with exactly this name ("Method$Ns.Type.Method()").</summary>
    public List<int> MethodInfosNamed(string name)
    {
        var candidates = _methodInfoByName.Find(name.GetHashCode(), _ => true);
        if (candidates.Count == 0) return candidates;
        using var file = OpenFile();
        return candidates.Where(e => ScriptJsonReader.ReadMetadataMethodAt(file, _methodInfoOffsets[e]).Name == name).ToList();
    }

    private static int? SlotAt(uint[] addresses, uint rva)
    {
        int i = Array.BinarySearch(addresses, rva);
        if (i >= 0) { while (i > 0 && addresses[i - 1] == rva) i--; return i; }
        i = ~i - 1;
        return i >= 0 && rva - addresses[i] < 8 ? i : null;
    }

    private SafeFileHandle OpenFile() => File.OpenHandle(Path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);

    /// <summary>Name hashes sorted, with the entry of each: candidates for an exact-name lookup.</summary>
    private sealed class NameHashes
    {
        private readonly int[] _hashes, _entries;

        public NameHashes(int[] hashByEntry)
        {
            _hashes = (int[])hashByEntry.Clone();
            _entries = Enumerable.Range(0, hashByEntry.Length).ToArray();
            Array.Sort(_hashes, _entries);
        }

        public List<int> Find(int hash, Func<int, bool> matches)
        {
            var result = new List<int>();
            int i = Array.BinarySearch(_hashes, hash);
            if (i < 0) return result;
            while (i > 0 && _hashes[i - 1] == hash) i--;
            for (; i < _hashes.Length && _hashes[i] == hash; i++)
                if (matches(_entries[i])) result.Add(_entries[i]);
            result.Sort();
            return result;
        }
    }
}

/// <summary>Strings stored as UTF-8 in one array; decoded when read.</summary>
public sealed class Utf8Strings
{
    private readonly byte[] _data;
    private readonly int[] _starts;

    private Utf8Strings(byte[] data, int[] starts) { _data = data; _starts = starts; }

    public static Utf8Strings From(IReadOnlyList<string> values)
    {
        var starts = new int[values.Count + 1];
        long total = 0;
        for (int i = 0; i < values.Count; i++) total += System.Text.Encoding.UTF8.GetByteCount(values[i]);
        var data = new byte[total];
        int at = 0;
        for (int i = 0; i < values.Count; i++)
        {
            starts[i] = at;
            at += System.Text.Encoding.UTF8.GetBytes(values[i], data.AsSpan(at));
        }
        starts[values.Count] = at;
        return new Utf8Strings(data, starts);
    }

    public int Count => _starts.Length - 1;
    public long Size => _data.Length + _starts.Length * 4L;
    public int Length(int i) => _starts[i + 1] - _starts[i];
    public ReadOnlySpan<byte> Bytes(int i) => _data.AsSpan(_starts[i], _starts[i + 1] - _starts[i]);
    public string this[int i] => System.Text.Encoding.UTF8.GetString(Bytes(i));

    public bool Equals(int i, string value)
    {
        var bytes = Bytes(i);
        if (System.Text.Encoding.UTF8.GetMaxByteCount(value.Length) < bytes.Length || value.Length > bytes.Length) return false;
        Span<byte> buffer = bytes.Length <= 512 ? stackalloc byte[bytes.Length] : new byte[bytes.Length];
        return System.Text.Encoding.UTF8.TryGetBytes(value, buffer, out int written) && written == bytes.Length && buffer.SequenceEqual(bytes);
    }
}

/// <summary>A script.json ScriptMethod: a native function and the managed method (or instantiation) it implements.</summary>
public readonly record struct ScriptMethod(ulong Address, string Name, string? Signature, string? TypeSignature);

/// <summary>A string literal and the RVA of the slot its users load it from.</summary>
public readonly record struct ScriptString(ulong Address, string Value);

/// <summary>A ScriptMetadata entry: the slot of a type, field or other runtime metadata item.</summary>
public readonly record struct ScriptMetadata(ulong Address, string Name, string? Signature);

/// <summary>A ScriptMetadataMethod entry: the slot of a MethodInfo, and the function it describes (0 when none).</summary>
public readonly record struct ScriptMetadataMethod(ulong Address, string Name, ulong MethodAddress);

/// <summary>
/// Streaming reader for Il2CppDumper's script.json and stringliteral.json. script.json reaches hundreds of MB, so it is
/// read token by token from the file and only the sections with a handler are materialized.
/// </summary>
public sealed class ScriptJsonReader
{
    /// <summary>Each ScriptMethod with the file offset of its object (see <see cref="ReadMethodAt"/>).</summary>
    public Action<ScriptMethod, long>? Method { get; init; }
    /// <summary>False to skip the Signature and TypeSignature strings of ScriptMethod entries.</summary>
    public bool MethodSignatures { get; init; } = true;
    public Action<ScriptString>? String { get; init; }
    /// <summary>Each ScriptMetadata entry with the file offset of its object (see <see cref="ReadMetadataAt"/>).</summary>
    public Action<ScriptMetadata, long>? Metadata { get; init; }
    /// <summary>Each ScriptMetadataMethod entry with the file offset of its object (see <see cref="ReadMetadataMethodAt"/>).</summary>
    public Action<ScriptMetadataMethod, long>? MetadataMethod { get; init; }
    /// <summary>Each entry of Addresses: function starts (method pointers, invokers and other generated code).</summary>
    public Action<ulong>? Address { get; init; }

    private enum Section { None, Method, String, Metadata, MetadataMethod, Addresses }

    private sealed class Record
    {
        public long Offset;
        public ulong Address, MethodAddress;
        public string? Name, Value, Signature, TypeSignature;
        public void Clear() { Address = MethodAddress = 0; Name = Value = Signature = TypeSignature = null; }
    }

    public void Read(string path, CancellationToken ct = default)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1, FileOptions.SequentialScan);
        var section = Section.None;
        string? property = null;
        var record = new Record();
        Parse(stream, 0, ct, 1 << 20, (ref Utf8JsonReader r, long tokenOffset) =>
        {
            switch (r.TokenType)
            {
                case JsonTokenType.PropertyName when r.CurrentDepth == 1:
                    section = r.ValueTextEquals("ScriptMethod"u8) ? (Method != null ? Section.Method : Section.None)
                        : r.ValueTextEquals("ScriptString"u8) ? (String != null ? Section.String : Section.None)
                        : r.ValueTextEquals("ScriptMetadata"u8) ? (Metadata != null ? Section.Metadata : Section.None)
                        : r.ValueTextEquals("ScriptMetadataMethod"u8) ? (MetadataMethod != null ? Section.MetadataMethod : Section.None)
                        : r.ValueTextEquals("Addresses"u8) ? (Address != null ? Section.Addresses : Section.None)
                        : Section.None;
                    break;
                case JsonTokenType.Number or JsonTokenType.String when r.CurrentDepth == 2 && section == Section.Addresses:
                    if (Number(ref r) is { } a) Address!(a);
                    break;
                case JsonTokenType.StartObject when r.CurrentDepth == 2 && section != Section.None:
                    record.Clear();
                    record.Offset = tokenOffset;
                    break;
                case JsonTokenType.PropertyName when r.CurrentDepth == 3 && section != Section.None:
                    property = r.GetString();
                    break;
                case JsonTokenType.String or JsonTokenType.Number when r.CurrentDepth == 3 && section != Section.None:
                    Assign(record, property, ref r, section != Section.Method || MethodSignatures);
                    break;
                case JsonTokenType.EndObject when r.CurrentDepth == 2 && section != Section.None:
                    Emit(section, record);
                    break;
            }
            return true;
        });
    }

    private void Emit(Section section, Record r)
    {
        switch (section)
        {
            case Section.Method: Method!(new ScriptMethod(r.Address, r.Name ?? "", r.Signature, r.TypeSignature), r.Offset); break;
            case Section.String: String!(new ScriptString(r.Address, r.Value ?? "")); break;
            case Section.Metadata: Metadata!(new ScriptMetadata(r.Address, r.Name ?? "", r.Signature), r.Offset); break;
            case Section.MetadataMethod: MetadataMethod!(new ScriptMetadataMethod(r.Address, r.Name ?? "", r.MethodAddress), r.Offset); break;
        }
    }

    private static void Assign(Record record, string? property, ref Utf8JsonReader r, bool signatures)
    {
        switch (property?.ToLowerInvariant())
        {
            case "address": record.Address = Number(ref r) ?? 0; break;
            case "methodaddress": record.MethodAddress = Number(ref r) ?? 0; break;
            case "name": record.Name = r.GetString(); break;
            case "value": record.Value = r.GetString(); break;
            case "signature" when signatures: record.Signature = r.GetString(); break;
            case "typesignature" when signatures: record.TypeSignature = r.GetString(); break;
        }
    }

    /// <summary>A number token, or a string holding a decimal or 0x-prefixed hex number.</summary>
    private static ulong? Number(ref Utf8JsonReader r)
    {
        if (r.TokenType == JsonTokenType.Number) return r.TryGetUInt64(out var n) ? n : null;
        var s = r.GetString();
        if (s == null) return null;
        return s.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            ? ulong.TryParse(s.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var h) ? h : null
            : ulong.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var d) ? d : null;
    }

    /// <summary>Reads the ScriptMethod object that starts at <paramref name="offset"/> of script.json.</summary>
    public static ScriptMethod ReadMethodAt(SafeFileHandle file, long offset)
    {
        var r = ReadRecordAt(file, offset);
        return new ScriptMethod(r.Address, r.Name ?? "", r.Signature, r.TypeSignature);
    }

    /// <summary>Reads the ScriptMetadata object that starts at <paramref name="offset"/> of script.json.</summary>
    public static ScriptMetadata ReadMetadataAt(SafeFileHandle file, long offset)
    {
        var r = ReadRecordAt(file, offset);
        return new ScriptMetadata(r.Address, r.Name ?? "", r.Signature);
    }

    /// <summary>Reads the ScriptMetadataMethod object that starts at <paramref name="offset"/> of script.json.</summary>
    public static ScriptMetadataMethod ReadMetadataMethodAt(SafeFileHandle file, long offset)
    {
        var r = ReadRecordAt(file, offset);
        return new ScriptMetadataMethod(r.Address, r.Name ?? "", r.MethodAddress);
    }

    private static Record ReadRecordAt(SafeFileHandle file, long offset)
    {
        var record = new Record();
        string? property = null;
        using var stream = new HandleStream(file, offset);
        Parse(stream, offset, default, initialBuffer: 4096, (ref Utf8JsonReader r, long _) =>
        {
            if (r.TokenType == JsonTokenType.PropertyName && r.CurrentDepth == 1) property = r.GetString();
            else if (r.TokenType is JsonTokenType.String or JsonTokenType.Number && r.CurrentDepth == 1) Assign(record, property, ref r, true);
            return !(r.TokenType == JsonTokenType.EndObject && r.CurrentDepth == 0);
        });
        return record;
    }

    /// <summary>stringliteral.json: an array of { "value": "...", "address": "0x..." }.</summary>
    public static List<ScriptString> ReadStringLiterals(string path, CancellationToken ct = default)
    {
        var list = new List<ScriptString>();
        var record = new Record();
        string? property = null;
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1, FileOptions.SequentialScan);
        Parse(stream, 0, ct, 1 << 20, (ref Utf8JsonReader r, long _) =>
        {
            switch (r.TokenType)
            {
                case JsonTokenType.StartObject when r.CurrentDepth == 1: record.Clear(); break;
                case JsonTokenType.PropertyName when r.CurrentDepth == 2: property = r.GetString(); break;
                case JsonTokenType.String or JsonTokenType.Number when r.CurrentDepth == 2: Assign(record, property, ref r, false); break;
                case JsonTokenType.EndObject when r.CurrentDepth == 1: list.Add(new ScriptString(record.Address, record.Value ?? "")); break;
            }
            return true;
        });
        return list;
    }

    private delegate bool TokenHandler(ref Utf8JsonReader reader, long tokenOffset);

    /// <summary>
    /// Feeds every token to <paramref name="handle"/> (until it returns false) from a buffer refilled as the reader
    /// consumes it; the buffer grows only when a single token is larger than it.
    /// </summary>
    private static void Parse(Stream stream, long origin, CancellationToken ct, int initialBuffer, TokenHandler handle)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(initialBuffer);
        try
        {
            var state = new JsonReaderState(new JsonReaderOptions { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true });
            int length = 0, start = 0;
            long bufferStart = origin;
            bool final = false, first = true;
            while (true)
            {
                ct.ThrowIfCancellationRequested();
                while (!final && length < buffer.Length)
                {
                    int n = stream.Read(buffer, length, buffer.Length - length);
                    if (n == 0) final = true;
                    length += n;
                }
                if (first && length >= 3 && buffer[0] == 0xEF && buffer[1] == 0xBB && buffer[2] == 0xBF) start = 3; // byte order mark
                first = false;
                var reader = new Utf8JsonReader(buffer.AsSpan(start, length - start), final, state);
                long readerBase = bufferStart + start;
                while (reader.Read())
                    if (!handle(ref reader, readerBase + reader.TokenStartIndex)) return;
                if (final) return;
                int consumed = start + (int)reader.BytesConsumed;
                start = 0;
                state = reader.CurrentState;
                if (consumed == 0 && length == buffer.Length)
                {
                    var larger = ArrayPool<byte>.Shared.Rent(buffer.Length * 2);
                    Buffer.BlockCopy(buffer, 0, larger, 0, length);
                    ArrayPool<byte>.Shared.Return(buffer);
                    buffer = larger;
                    continue;
                }
                Buffer.BlockCopy(buffer, consumed, buffer, 0, length - consumed);
                length -= consumed;
                bufferStart += consumed;
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>Forward-only reads from a file handle at an offset, without moving a shared file position.</summary>
    private sealed class HandleStream(SafeFileHandle file, long position) : Stream
    {
        public override int Read(byte[] buffer, int offset, int count)
        {
            int n = RandomAccess.Read(file, buffer.AsSpan(offset, Math.Min(count, 64 * 1024)), position);
            position += n;
            return n;
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => position; set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
