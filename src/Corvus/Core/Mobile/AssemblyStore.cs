using System.Buffers.Binary;
using System.Globalization;
using System.Text;
using Corvus.Native;
using Corvus.Native.Elf;

namespace Corvus.Core.Mobile;

/// <summary>One assembly of a store: its name, image (decompressed), optional debug symbols and .config, and how it was stored.</summary>
public sealed record AssemblyStoreEntry(int Index, string Name, string? Abi, byte[] Image, byte[]? Debug, byte[]? Config, string Compression, bool Ignored);

/// <summary>A .NET for Android assembly store ("XABA"), versions 1 to 3, raw or in a shared library; never throws.</summary>
public sealed class AssemblyStore
{
    public const uint Magic = 0x41424158; // "XABA"
    private const uint AbiMask = 0x00FF0000, VersionMask = 0x0000FFFF, Is64Flag = 0x80000000;

    public int Version { get; private set; }
    public string? Abi { get; private set; }
    public bool Is64Bit { get; private set; }
    /// <summary>Version 1: the store's id (0 is the shared store holding the global index).</summary>
    public uint StoreId { get; private set; }
    /// <summary>Where the store was found: "file", "payload section" or "_assembly_store symbol".</summary>
    public string Location { get; private set; } = "file";
    public IReadOnlyList<AssemblyStoreEntry> Entries => _entries;
    public IReadOnlyList<ParseIssue> Issues => _issues;

    private readonly List<AssemblyStoreEntry> _entries = [];
    private readonly List<ParseIssue> _issues = [];

    private AssemblyStore() { }

    /// <summary>Reads a store from a store file or shared library; null when <paramref name="data"/> holds none.</summary>
    public static AssemblyStore? TryRead(byte[] data, string path, AnalysisLimits limits, IReadOnlyDictionary<(uint StoreId, int Index), string>? v1Names = null)
    {
        var store = new AssemblyStore();
        int start = store.Locate(data);
        if (start < 0 || BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(start)) != Magic) return null;
        store.Parse(data, start, path, limits, v1Names);
        return store;
    }

    private int Locate(byte[] data)
    {
        if (data.Length < 20) return -1;
        if (BinaryPrimitives.ReadUInt32LittleEndian(data) == Magic) return 0;
        if (!Blob.StartsWith(data, [0x7F, (byte)'E', (byte)'L', (byte)'F'])) return -1;
        ElfFile elf;
        try { elf = ElfFile.FromBytes(data); }
        catch (Exception ex) when (ex is InvalidDataException or ArgumentException or ToolError) { return -1; }
        if (elf.DynamicSymbol("_assembly_store") is { IsDefined: true } symbol && elf.TryVaToRva(symbol.Value, out var rva) && elf.TryRvaToFileOffset(rva, out var at)
            && at + 20 <= data.Length)
        {
            Location = "_assembly_store symbol";
            return (int)at;
        }
        if (elf.Section("payload") is { } payload && payload.Offset + 20 <= (ulong)data.Length)
        {
            Location = "payload section";
            return (int)payload.Offset;
        }
        return -1;
    }

    private void Parse(byte[] data, int start, string path, AnalysisLimits limits, IReadOnlyDictionary<(uint, int), string>? v1Names)
    {
        var d = data.AsSpan(start);
        uint version = U32(d, 4);
        Version = (int)(version & VersionMask);
        if (Version == 1) ParseV1(data, start, path, limits, v1Names);
        else if (Version is 2 or 3) ParseV2(data, start, version, limits);
        else _issues.Add(new("assembly store", $"unsupported store version 0x{version:x8}", start));
    }

    private static uint U32(ReadOnlySpan<byte> d, long at) => at >= 0 && at + 4 <= d.Length ? BinaryPrimitives.ReadUInt32LittleEndian(d[(int)at..]) : 0;

    /// <summary>Header: magic, version, local count, global count, store id; then 24-byte descriptors; store 0 adds two global hash tables.</summary>
    private void ParseV1(byte[] data, int start, string path, AnalysisLimits limits, IReadOnlyDictionary<(uint, int), string>? names)
    {
        var d = data.AsSpan(start);
        uint count = U32(d, 8);
        StoreId = U32(d, 16);
        Abi = AbiFromPath(path);
        Is64Bit = Abi is "arm64-v8a" or "x86_64";
        if (count > (uint)limits.MaxItems || 20 + count * 24L > d.Length)
        {
            _issues.Add(new("assembly store", $"{count} entries do not fit the {d.Length}-byte store", start));
            return;
        }
        for (int i = 0; i < count; i++)
        {
            long at = 20 + i * 24L;
            var name = names?.GetValueOrDefault((StoreId, i));
            Add(data, start, i, name, U32(d, at), U32(d, at + 4), U32(d, at + 8), U32(d, at + 12), U32(d, at + 16), U32(d, at + 20), false, limits);
        }
    }

    /// <summary>Header: magic, version (ABI and 64-bit flags), entry count, index entry count, index size; index; 28-byte descriptors; names.</summary>
    private void ParseV2(byte[] data, int start, uint version, AnalysisLimits limits)
    {
        var d = data.AsSpan(start);
        uint count = U32(d, 8), indexCount = U32(d, 12), indexSize = U32(d, 16);
        Is64Bit = (version & Is64Flag) != 0;
        Abi = (version & AbiMask) switch { 0x00010000 => "arm64-v8a", 0x00020000 => "armeabi-v7a", 0x00030000 => "x86_64", 0x00040000 => "x86", _ => null };
        long stride = indexCount == 0 ? 0 : indexSize / indexCount;
        if (count > (uint)limits.MaxItems || indexCount > count * 4L + 4 || (indexCount > 0 && indexSize % indexCount != 0) || stride is not (0 or 8 or 9 or 12 or 13))
        {
            _issues.Add(new("assembly store", $"header claims {count} entries and {indexCount} index entries of {indexSize} bytes", start));
            return;
        }
        long descriptors = 20L + indexSize, names = descriptors + count * 28L;
        if (names > d.Length) { _issues.Add(new("assembly store", $"{count} descriptors do not fit the {d.Length}-byte store", start)); return; }
        var ignored = new HashSet<uint>();
        if (stride is 9 or 13)
            for (long i = 0, at = 20; i < indexCount; i++, at += stride)
                if (d[(int)(at + stride - 1)] != 0) ignored.Add(U32(d, at + stride - 5));
        var nameList = new List<string?>();
        for (long i = 0, at = names; i < count; i++)
        {
            uint length = U32(d, at);
            if (at + 4 + length > d.Length) { _issues.Add(new("assembly store", $"name {i} lies outside the store", start + at)); break; }
            nameList.Add(Encoding.UTF8.GetString(d.Slice((int)at + 4, (int)length)));
            at += 4 + length;
        }
        for (int i = 0; i < count; i++)
        {
            long at = descriptors + i * 28L;
            var name = i < nameList.Count ? nameList[i] : null;
            if (name != null && !name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) && !name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) name += ".dll";
            Add(data, start, i, name, U32(d, at + 4), U32(d, at + 8), U32(d, at + 12), U32(d, at + 16), U32(d, at + 20), U32(d, at + 24), ignored.Contains((uint)i), limits);
        }
    }

    private void Add(byte[] data, int start, int index, string? name, uint offset, uint size, uint debugOffset, uint debugSize, uint configOffset, uint configSize,
        bool ignore, AnalysisLimits limits)
    {
        byte[]? Slice(uint at, uint length) =>
            at == 0 || length == 0 ? null : (long)start + at + length <= data.Length ? data.AsSpan(start + (int)at, (int)length).ToArray() : null;
        var raw = Slice(offset, size);
        if (raw == null) { _issues.Add(new("assembly store", $"entry {index} ({name ?? "unnamed"}) lies outside the store", start)); return; }
        var (decoded, compression) = Blob.TryDecompressAssembly(raw, limits.MaxItemBytes);
        if (compression != null && decoded == null)
        {
            _issues.Add(new("assembly store", $"entry {index} ({name ?? "unnamed"}): corrupt {compression} data", start + offset));
            return;
        }
        var image = decoded ?? raw;
        name ??= MetadataName(image) ?? $"store{StoreId}_{index}.dll";
        _entries.Add(new(index, name, Abi, image, Slice(debugOffset, debugSize), Slice(configOffset, configSize), compression ?? "none", ignore));
    }

    /// <summary>"Name.dll" from the image's assembly table, for entries the store does not name.</summary>
    private static string? MetadataName(byte[] image)
    {
        try
        {
            using var module = dnlib.DotNet.ModuleDefMD.Load(image);
            return module.Assembly?.Name is { Length: > 0 } n ? n + (module.Kind == dnlib.DotNet.ModuleKind.Windows || module.Kind == dnlib.DotNet.ModuleKind.Console ? ".exe" : ".dll") : null;
        }
        // dnlib throws several types on malformed images.
        catch (Exception) { return null; }
    }

    /// <summary>The Android ABI named in a store's path: lib/&lt;abi&gt;/... or assemblies.&lt;abi with _&gt;.blob.</summary>
    public static string? AbiFromPath(string path)
    {
        var parts = path.Replace('\\', '/').Split('/');
        foreach (var abi in Abis)
            if (parts.Contains(abi) || path.Contains("." + abi.Replace('-', '_') + ".", StringComparison.Ordinal)) return abi;
        return null;
    }

    public static readonly string[] Abis = ["arm64-v8a", "armeabi-v7a", "x86_64", "x86"];

    /// <summary>Entry names from a version 1 assemblies.manifest, with ".dll" added.</summary>
    public static Dictionary<(uint StoreId, int Index), string> ReadV1Manifest(string text)
    {
        var result = new Dictionary<(uint, int), string>();
        foreach (var line in text.Split('\n').Skip(1))
        {
            var f = line.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (f.Length != 5 || !uint.TryParse(f[2], NumberStyles.Integer, CultureInfo.InvariantCulture, out var id)
                || !int.TryParse(f[3], NumberStyles.Integer, CultureInfo.InvariantCulture, out var index)) continue;
            result.TryAdd((id, index), f[4].EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ? f[4] : f[4] + ".dll");
        }
        return result;
    }
}
