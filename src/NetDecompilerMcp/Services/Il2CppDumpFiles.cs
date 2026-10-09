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
/// Compact view of a script.json: the sorted function starts, and the ScriptMethod entries by address with the file
/// offset of each, so names and signatures are read from the file only when asked for. Addresses that cannot be RVAs
/// (beyond 32 bits) are dropped.
/// </summary>
public sealed class Il2CppScript
{
    private readonly uint[] _methodAddresses;
    private readonly long[] _methodOffsets;

    private Il2CppScript(string path, uint[] functionStarts, uint[] methodAddresses, long[] methodOffsets, int dropped, TimeSpan loadTime)
    {
        Path = path;
        FunctionStarts = functionStarts;
        _methodAddresses = methodAddresses;
        _methodOffsets = methodOffsets;
        DroppedAddresses = dropped;
        LoadTime = loadTime;
    }

    public string Path { get; }
    /// <summary>Distinct RVAs from Addresses and ScriptMethod, ascending.</summary>
    public uint[] FunctionStarts { get; }
    public int MethodCount => _methodAddresses.Length;
    public int DroppedAddresses { get; }
    public TimeSpan LoadTime { get; }

    public static Il2CppScript Load(string path, CancellationToken ct = default)
    {
        var watch = System.Diagnostics.Stopwatch.StartNew();
        var starts = new List<uint>();
        var addresses = new List<uint>();
        var offsets = new List<long>();
        int dropped = 0;
        new ScriptJsonReader
        {
            MethodSignatures = false,
            Method = (m, offset) =>
            {
                if (m.Address == 0 || m.Address > uint.MaxValue) { dropped++; return; }
                addresses.Add((uint)m.Address);
                offsets.Add(offset);
            },
            Address = a =>
            {
                if (a == 0 || a > uint.MaxValue) { dropped++; return; }
                starts.Add((uint)a);
            },
        }.Read(path, ct);

        var methodAddresses = addresses.ToArray();
        var methodOffsets = offsets.ToArray();
        Array.Sort(methodAddresses, methodOffsets); // offsets ascend within an address: entries keep file order
        for (int i = 0, j; i < methodAddresses.Length; i = j)
        {
            for (j = i + 1; j < methodAddresses.Length && methodAddresses[j] == methodAddresses[i]; j++) { }
            if (j - i > 1) Array.Sort(methodOffsets, i, j - i);
        }
        starts.AddRange(methodAddresses);
        var functionStarts = starts.Distinct().Order().ToArray();
        return new Il2CppScript(path, functionStarts, methodAddresses, methodOffsets, dropped, watch.Elapsed);
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
        int i = Array.BinarySearch(_methodAddresses, address);
        if (i < 0) return [];
        while (i > 0 && _methodAddresses[i - 1] == address) i--;
        var list = new List<ScriptMethod>();
        using var file = File.OpenHandle(Path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        for (; i < _methodAddresses.Length && _methodAddresses[i] == address; i++)
            list.Add(ScriptJsonReader.ReadMethodAt(file, _methodOffsets[i]));
        return list;
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
    public Action<ScriptMetadata>? Metadata { get; init; }
    public Action<ScriptMetadataMethod>? MetadataMethod { get; init; }
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
            case Section.Metadata: Metadata!(new ScriptMetadata(r.Address, r.Name ?? "", r.Signature)); break;
            case Section.MetadataMethod: MetadataMethod!(new ScriptMetadataMethod(r.Address, r.Name ?? "", r.MethodAddress)); break;
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
        var record = new Record();
        string? property = null;
        using var stream = new HandleStream(file, offset);
        Parse(stream, offset, default, initialBuffer: 4096, (ref Utf8JsonReader r, long _) =>
        {
            if (r.TokenType == JsonTokenType.PropertyName && r.CurrentDepth == 1) property = r.GetString();
            else if (r.TokenType is JsonTokenType.String or JsonTokenType.Number && r.CurrentDepth == 1) Assign(record, property, ref r, true);
            return !(r.TokenType == JsonTokenType.EndObject && r.CurrentDepth == 0);
        });
        return new ScriptMethod(record.Address, record.Name ?? "", record.Signature, record.TypeSignature);
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
