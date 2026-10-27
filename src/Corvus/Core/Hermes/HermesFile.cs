using System.Buffers.Binary;
using System.Text;

namespace Corvus.Core.Hermes;

/// <summary>A function header: where its bytecode is, its frame and name, and its flags.</summary>
public sealed record HermesFunction(int Index, int Offset, int Size, int ParamCount, int FrameSize, int EnvironmentSize, int NameId,
    int InfoOffset, byte Flags)
{
    /// <summary>0 call prohibited (constructor only), 1 construct prohibited (arrows, methods), 2 neither.</summary>
    public int ProhibitInvoke => Flags & 3;
    public bool Strict => (Flags & 4) != 0;
    public bool HasExceptionHandlers => (Flags & 8) != 0;
    public bool HasDebugInfo => (Flags & 16) != 0;
    public bool Overflowed => (Flags & 32) != 0;
}

/// <summary>An exception handler: the protected range [Start, End) and the catch target, as bytecode offsets in the function.</summary>
public readonly record struct HermesHandler(int Start, int End, int Target);

/// <summary>A Hermes bytecode file, versions 59 to 96; problems go to <see cref="Issues"/> and nothing throws past <see cref="Read"/>.</summary>
public sealed class HermesFile
{
    public const ulong Magic = 0x1F1903C103BC1FC6;
    private const ulong DeltaMagic = ~Magic;
    public const int HeaderSize = 128;

    private readonly byte[] _data;
    private string?[]? _strings;
    private (int Offset, int Length, bool Utf16)[] _stringEntries = [];
    private bool[] _identifier = [];

    public ReadOnlyMemory<byte> Bytes => _data;
    public int Version { get; }
    public string SourceHash { get; }
    public uint FileLength { get; }
    public int GlobalCodeIndex { get; }
    public int SegmentId { get; private set; }
    public bool StaticBuiltins { get; private set; }
    public bool CjsModulesStaticallyResolved { get; private set; }
    public bool HasAsync { get; private set; }
    public int IdentifierCount { get; private set; }
    public int BigIntCount { get; private set; }
    public int RegExpCount { get; private set; }
    public int DebugInfoOffset { get; private set; }

    /// <summary>The opcode table read with: the version's own, or the nearest older one (<see cref="TableExact"/> false); null when unsupported.</summary>
    public HermesOpcodeTable? Opcodes { get; }
    public bool TableExact { get; }

    public IReadOnlyList<HermesFunction> Functions { get; private set; } = [];
    public int StringCount => _stringEntries.Length;

    private int _stringsDecoded, _codeDecodes;

    /// <summary>Strings decoded so far: each once, on its first use.</summary>
    internal int StringsDecoded => Volatile.Read(ref _stringsDecoded);

    /// <summary>Function bodies decoded so far (<see cref="HermesCode.Decode"/> calls).</summary>
    internal int CodeDecodes => Volatile.Read(ref _codeDecodes);

    internal void CountCodeDecode() => Interlocked.Increment(ref _codeDecodes);
    public List<string> Issues { get; } = [];

    /// <summary>Literal buffers (serialized literal format) and the bigint and regexp tables, as file ranges.</summary>
    public (int Start, int Length) ArrayBuffer { get; private set; }
    public (int Start, int Length) ObjectKeyBuffer { get; private set; }
    public (int Start, int Length) ObjectValueBuffer { get; private set; }
    public IReadOnlyList<(int Offset, int Length)> BigInts { get; private set; } = [];
    public int BigIntStorage { get; private set; }

    /// <summary>CommonJS modules: (filename string id or module id when statically resolved, function index).</summary>
    public IReadOnlyList<(int Key, int Function)> CjsModules { get; private set; } = [];

    /// <summary>Functions whose source text is kept (Function.prototype.toString): (function index, string id).</summary>
    public IReadOnlyList<(int Function, int String)> FunctionSources { get; private set; } = [];

    /// <summary>Debug info: file names, regions of the location data that each names, and the location data range.</summary>
    public IReadOnlyList<string> DebugFiles { get; private set; } = [];
    public IReadOnlyList<(int From, int File, int SourceMap)> DebugRegions { get; private set; } = [];
    public (int Start, int Length) DebugData { get; private set; }

    public static bool Looks(ReadOnlySpan<byte> head) => head.Length >= 12 && BinaryPrimitives.ReadUInt64LittleEndian(head) == Magic;

    /// <summary>The bytecode version of an HBC file's head, or null.</summary>
    public static int? VersionOf(ReadOnlySpan<byte> head) => Looks(head) ? (int)BinaryPrimitives.ReadUInt32LittleEndian(head[8..]) : null;

    private HermesFile(byte[] data)
    {
        _data = data;
        var h = data.AsSpan();
        Version = (int)U32(8);
        SourceHash = Convert.ToHexStringLower(h.Slice(12, 20));
        FileLength = U32(32);
        GlobalCodeIndex = (int)U32(36);
        Opcodes = HermesOpcodes.For(Version, out var exact);
        TableExact = exact;
    }

    private uint U32(long at) => at >= 0 && at + 4 <= _data.Length ? BinaryPrimitives.ReadUInt32LittleEndian(_data.AsSpan((int)at)) : 0;

    /// <summary>Reads <paramref name="data"/>; throws <see cref="ToolError"/> only when it is not an HBC file at all.</summary>
    public static HermesFile Read(byte[] data)
    {
        if (data.Length >= 8 && BinaryPrimitives.ReadUInt64LittleEndian(data) == DeltaMagic)
            throw new ToolError(ErrorCode.Unsupported, "a Hermes delta bytecode file (a hot-reload patch, not a bundle).");
        if (data.Length < HeaderSize || !Looks(data))
            throw new ToolError(ErrorCode.MalformedInput, "not a Hermes bytecode file (no HBC magic or a header shorter than 128 bytes).");
        var f = new HermesFile(data);
        if (f.Opcodes == null)
        {
            f.Issues.Add($"bytecode version {f.Version} is outside 59–96: the header is read, the code is not decoded");
            return f;
        }
        if (!f.TableExact) f.Issues.Add($"bytecode version {f.Version} has no table of its own; read with version {f.Opcodes.Version}'s opcodes");
        try { f.ReadBody(); }
        catch (FormatException ex) { f.Issues.Add(ex.Message); }
        return f;
    }

    private sealed class Cursor(byte[] data, int at)
    {
        public int At = at;

        public void Align() => At = (At + 3) & ~3;

        public int Take(long bytes, string what)
        {
            Align();
            if (bytes < 0 || At + bytes > data.Length) throw new FormatException($"{what} runs past the end of the file ({bytes:N0} bytes at 0x{At:x})");
            int start = At;
            At += (int)bytes;
            return start;
        }
    }

    private HermesFile ReadBody()
    {
        int v = Version;
        int p = 40;
        uint Next() { var x = U32(p); p += 4; return x; }
        uint functionCount = Next(), stringKindCount = Next(), identifierCount = Next(), stringCount = Next(), overflowCount = Next(), storageSize = Next();
        uint bigIntCount = 0, bigIntStorage = 0;
        if (v >= 87) { bigIntCount = Next(); bigIntStorage = Next(); }
        uint regExpCount = Next(), regExpStorage = Next(), arraySize = Next(), keySize = Next(), valueSize = Next();
        SegmentId = (int)Next();
        uint cjsCount = Next();
        uint sourceCount = v >= 84 ? Next() : 0;
        DebugInfoOffset = (int)Next();
        byte options = _data[p];
        StaticBuiltins = (options & 1) != 0;
        CjsModulesStaticallyResolved = (options & 2) != 0;
        HasAsync = (options & 4) != 0;
        IdentifierCount = (int)identifierCount;
        BigIntCount = (int)bigIntCount;
        RegExpCount = (int)regExpCount;
        if (FileLength > _data.Length) Issues.Add($"the header gives {FileLength:N0} bytes; the file has {_data.Length:N0} (truncated)");

        var c = new Cursor(_data, HeaderSize);
        int headers = c.Take(functionCount * 16L, "function headers");
        int kinds = c.Take(stringKindCount * 4L, "string kinds");
        c.Take(identifierCount * 4L, "identifier hashes");
        int small = c.Take(stringCount * 4L, "string table");
        int overflow = c.Take(overflowCount * 8L, "overflow string table");
        int storage = c.Take(storageSize, "string storage");
        ArrayBuffer = (c.Take(arraySize, "array buffer"), (int)arraySize);
        ObjectKeyBuffer = (c.Take(keySize, "object key buffer"), (int)keySize);
        ObjectValueBuffer = (c.Take(valueSize, "object value buffer"), (int)valueSize);
        if (v >= 87)
        {
            int table = c.Take(bigIntCount * 8L, "bigint table");
            BigInts = [.. Enumerable.Range(0, (int)bigIntCount).Select(i => ((int)U32(table + i * 8), (int)U32(table + i * 8 + 4)))];
            BigIntStorage = c.Take(bigIntStorage, "bigint storage");
        }
        c.Take(regExpCount * 8L, "regexp table");
        c.Take(regExpStorage, "regexp storage");
        bool pairs = !CjsModulesStaticallyResolved || v >= 77;
        int cjs = c.Take(cjsCount * (pairs ? 8L : 4L), "CommonJS module table");
        CjsModules = [.. Enumerable.Range(0, (int)cjsCount).Select(i => pairs ? ((int)U32(cjs + i * 8), (int)U32(cjs + i * 8 + 4)) : (i, (int)U32(cjs + i * 4)))];
        if (v >= 84)
        {
            int sources = c.Take(sourceCount * 8L, "function source table");
            FunctionSources = [.. Enumerable.Range(0, (int)sourceCount).Select(i => ((int)U32(sources + i * 8), (int)U32(sources + i * 8 + 4)))];
        }

        ReadStrings(kinds, (int)stringKindCount, small, (int)stringCount, overflow, (int)overflowCount, storage, (int)storageSize);
        ReadFunctions(headers, (int)functionCount);
        if (DebugInfoOffset > 0) ReadDebugInfo();
        return this;
    }

    private void ReadStrings(int kinds, int kindCount, int small, int count, int overflow, int overflowCount, int storage, int storageSize)
    {
        _identifier = new bool[count];
        int s = 0;
        for (int i = 0; i < kindCount && s < count; i++)
        {
            uint e = U32(kinds + i * 4);
            // StringKind::Entry: count in the low 31 bits and the kind in the top bit since version 71, 30 and 2 before.
            int n = (int)(Version >= 71 ? e & 0x7FFF_FFFF : e & 0x3FFF_FFFF);
            bool identifier = Version >= 71 ? e >> 31 == 1 : e >> 30 == 1;
            for (int k = 0; k < n && s < count; k++) _identifier[s++] = identifier;
        }
        _stringEntries = new (int, int, bool)[count];
        for (int i = 0; i < count; i++)
        {
            uint e = U32(small + i * 4);
            bool utf16 = (e & 1) != 0;
            int offset = (int)((e >> 1) & 0x7F_FFFF), length = (int)(e >> 24);
            if (length == 0xFF)
            {
                if (offset >= overflowCount) { Issues.Add($"string {i}: overflow entry {offset} is past the overflow table"); continue; }
                length = (int)U32(overflow + offset * 8 + 4);
                offset = (int)U32(overflow + offset * 8);
            }
            long bytes = (long)length * (utf16 ? 2 : 1);
            if (offset < 0 || offset + bytes > storageSize) { Issues.Add($"string {i} runs past the string storage"); continue; }
            _stringEntries[i] = (storage + offset, length, utf16);
        }
        _strings = new string?[count];
    }

    /// <summary>String <paramref name="id"/> (Latin-1 or UTF-16 as stored), or null when out of range.</summary>
    public string? String(long id)
    {
        if (_strings == null || id < 0 || id >= _strings.Length) return null;
        if (_strings[id] is { } cached) return cached;
        var (at, length, utf16) = _stringEntries[id];
        Interlocked.Increment(ref _stringsDecoded);
        string text = utf16 ? Encoding.Unicode.GetString(_data, at, length * 2) : Encoding.Latin1.GetString(_data, at, length);
        return _strings[id] = text;
    }

    public bool IsIdentifier(long id) => id >= 0 && id < _identifier.Length && _identifier[id];

    private void ReadFunctions(int headers, int count)
    {
        var list = new HermesFunction[count];
        for (int i = 0; i < count; i++)
        {
            int at = headers + i * 16;
            uint w0 = U32(at), w1 = U32(at + 4), w2 = U32(at + 8);
            byte env = _data[at + 12], flags = _data[at + 15];
            var fn = new HermesFunction(i, (int)(w0 & 0x1FF_FFFF), (int)(w1 & 0x7FFF), (int)(w0 >> 25), (int)(w2 >> 25), env, (int)(w1 >> 15),
                (int)(w2 & 0x1FF_FFFF), flags);
            if (fn.Overflowed)
            {
                int large = (int)((w2 & 0x1FF_FFFF) << 16 | (w0 & 0xFFFF));
                if (large < 0 || large + 31 > _data.Length) { Issues.Add($"function {i}: its large header at 0x{large:x} is past the end"); fn = fn with { Size = 0 }; }
                else
                    fn = new HermesFunction(i, (int)U32(large), (int)U32(large + 8), (int)U32(large + 4), (int)U32(large + 20), (int)U32(large + 24),
                        (int)U32(large + 12), large + 31, _data[large + 30]);
            }
            if (fn.Offset < 0 || fn.Size < 0 || (long)fn.Offset + fn.Size > _data.Length)
            {
                Issues.Add($"function {i}: bytecode 0x{fn.Offset:x}+{fn.Size} is past the end of the file");
                fn = fn with { Size = 0 };
            }
            list[i] = fn;
        }
        Functions = list;
    }

    /// <summary>The exception handlers of <paramref name="f"/>, in table order (innermost first).</summary>
    public IReadOnlyList<HermesHandler> Handlers(HermesFunction f)
    {
        if (!f.HasExceptionHandlers) return [];
        int at = (f.InfoOffset + 3) & ~3;
        uint count = U32(at);
        if (count > 100_000 || at + 4 + count * 12L > _data.Length) return [];
        return [.. Enumerable.Range(0, (int)count).Select(i => new HermesHandler((int)U32(at + 4 + i * 12), (int)U32(at + 8 + i * 12), (int)U32(at + 12 + i * 12)))];
    }

    /// <summary>The offset of <paramref name="f"/>'s source locations in the debug data, or null.</summary>
    public int? SourceLocations(HermesFunction f)
    {
        if (!f.HasDebugInfo) return null;
        int at = (f.InfoOffset + 3) & ~3;
        if (f.HasExceptionHandlers) at = (at + 4 + (int)Math.Min(U32(at), 100_000) * 12 + 3) & ~3;
        uint offset = U32(at);
        return offset == uint.MaxValue || offset >= DebugData.Length ? null : (int)offset;
    }

    private void ReadDebugInfo()
    {
        int at = DebugInfoOffset;
        if (at < HeaderSize || at + 20L > _data.Length) { Issues.Add($"debug info offset 0x{at:x} is outside the file"); return; }
        uint files = U32(at), storageSize = U32(at + 4), regions = U32(at + 8);
        int headerSize = Version >= 91 ? 28 : 20;
        uint dataSize = U32(at + headerSize - 4);
        long table = at + headerSize, storageAt = table + files * 8L, regionAt = storageAt + storageSize, dataAt = regionAt + regions * 12L;
        if (files > 1_000_000 || regions > 10_000_000 || dataAt + dataSize > _data.Length) { Issues.Add("debug info runs past the end of the file"); return; }
        int storage = (int)storageAt, regionStart = (int)regionAt, data = (int)dataAt;
        var names = new List<string>();
        for (int i = 0; i < files; i++)
        {
            uint offset = U32((int)table + i * 8), length = U32((int)table + i * 8 + 4);
            bool utf16 = (length & 0x8000_0000) != 0;
            length &= 0x7FFF_FFFF;
            long bytes = utf16 ? length * 2L : length;
            names.Add(offset + bytes <= storageSize
                ? utf16 ? Encoding.Unicode.GetString(_data, storage + (int)offset, (int)bytes) : Encoding.Latin1.GetString(_data, storage + (int)offset, (int)bytes)
                : "?");
        }
        DebugFiles = names;
        DebugRegions = [.. Enumerable.Range(0, (int)regions).Select(i => ((int)U32(regionStart + i * 12), (int)U32(regionStart + i * 12 + 4), (int)U32(regionStart + i * 12 + 8)))];
        DebugData = (data, (int)dataSize);
    }

    /// <summary>A source position from the debug info: file, 1-based line and column, and the bytecode offset it starts at.</summary>
    public readonly record struct Location(int Offset, string? File, int Line, int Column);

    /// <summary>The source positions of <paramref name="f"/> in bytecode order; the first is the function's own start.</summary>
    public IReadOnlyList<Location> Locations(HermesFunction f, int max = int.MaxValue)
    {
        if (SourceLocations(f) is not { } offset) return [];
        var (start, length) = DebugData;
        string? file = null;
        foreach (var (from, id, _) in DebugRegions)
            if (from <= offset) file = id >= 0 && id < DebugFiles.Count ? DebugFiles[id] : null;
        var list = new List<Location>();
        int at = start + offset, end = start + length;
        if (!Leb(ref at, end, out _) || !Leb(ref at, end, out var line) || !Leb(ref at, end, out var column)) return list;
        list.Add(new Location(0, file, (int)line, (int)column));
        long address = 0;
        while (list.Count < max && Leb(ref at, end, out var delta) && delta != -1)
        {
            if (!Leb(ref at, end, out var lineDelta) || !Leb(ref at, end, out var columnDelta)) break;
            if (Version >= 91 && (!Leb(ref at, end, out _) || !Leb(ref at, end, out _))) break;
            if ((lineDelta & 1) != 0 && !Leb(ref at, end, out _)) break;
            address += delta;
            line += lineDelta >> 1;
            column += columnDelta;
            list.Add(new Location((int)address, file, (int)line, (int)column));
        }
        return list;
    }

    private bool Leb(ref int at, int end, out long value)
    {
        value = 0;
        int shift = 0;
        while (at >= 0 && at < end && at < _data.Length && shift < 64)
        {
            byte b = _data[at++];
            value |= (long)(b & 0x7F) << shift;
            shift += 7;
            if ((b & 0x80) == 0)
            {
                if (shift < 64 && (b & 0x40) != 0) value |= -1L << shift;
                return true;
            }
        }
        return false;
    }

    /// <summary>The display name of function <paramref name="index"/>: its name string, else "" (anonymous).</summary>
    public string FunctionName(int index) =>
        index >= 0 && index < Functions.Count ? String(Functions[index].NameId) ?? "" : "";
}
