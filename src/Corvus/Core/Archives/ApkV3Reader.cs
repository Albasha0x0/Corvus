using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;

namespace Corvus.Core.Archives;

/// <summary>apk-tools v3 packages and indexes (ADB format, doc/apk-v3.5): a package lists and extracts its files, an index its packages.</summary>
internal sealed class ApkV3Reader : IContainerReader
{
    // adb.h: value types in the top nibble, the value or blob offset below.
    private const uint TypeMask = 0xF0000000, ValueMask = 0x0FFFFFFF;
    private const uint TypeInt = 0x10000000, TypeInt32 = 0x20000000, TypeInt64 = 0x30000000, TypeBlob8 = 0x80000000, TypeBlob16 = 0x90000000,
        TypeBlob32 = 0xA0000000, TypeArray = 0xD0000000, TypeObject = 0xE0000000;
    private const uint BlockAdb = 0, BlockSig = 1, BlockData = 2, BlockExt = 3;
    private const uint SchemaPackage = 0x676B6370, SchemaIndex = 0x78646E69; // "pckg", "indx"

    // apk_adb.h field slots.
    private const int PkgInfo = 1, PkgPaths = 2, PkgScripts = 3, IndexDescription = 1, IndexPackages = 2;
    private const int PiName = 1, PiVersion = 2, PiDescription = 4, PiArch = 5, PiLicense = 6, PiOrigin = 7, PiMaintainer = 8, PiInstalledSize = 12,
        PiFileSize = 13, PiDepends = 15, PiProvides = 16, PiInstallIf = 18;
    private const int DepName = 1, DepVersion = 2, DepMatch = 3, DiName = 1, DiFiles = 3, FiName = 1, FiSize = 3, FiTarget = 6;

    /// <summary>The script slots of a package, named as apk v2 names its control files.</summary>
    private static readonly string[] Scripts = ["", ".trigger", ".pre-install", ".post-install", ".pre-deinstall", ".post-deinstall", ".pre-upgrade", ".post-upgrade"];

    public string Kind => "apk v3";

    public bool Accepts(ReadOnlySpan<byte> data, string name) =>
        data.Length >= 8 && data.StartsWith("ADB"u8) && (data[3] is (byte)'d' or (byte)'c' || data[3] == '.' && BinaryPrimitives.ReadUInt32LittleEndian(data[4..]) is SchemaPackage or SchemaIndex);

    public ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        var db = Decompress(data, name, limits);
        if (db.Length < 8 || !db.AsSpan().StartsWith("ADB."u8)) throw Malformed(name, "no ADB header after decompression");
        uint schema = BinaryPrimitives.ReadUInt32LittleEndian(db.AsSpan(4));
        if (schema is not (SchemaPackage or SchemaIndex)) throw Malformed(name, $"schema 0x{schema:X8} is neither a package nor an index");
        Adb? adb = null;
        var files = new Dictionary<(uint Path, uint File), (int At, int Length)>();
        int signatures = 0;
        for (long p = 8; p + 4 <= db.Length;)
        {
            ct.ThrowIfCancellationRequested();
            uint head = BinaryPrimitives.ReadUInt32LittleEndian(db.AsSpan((int)p));
            uint type = head >> 30;
            long raw = head & 0x3FFFFFFF, header = 4;
            if (type == BlockExt)
            {
                if (p + 16 > db.Length) throw Malformed(name, "truncated block header");
                type = head & 0x3FFFFFFF;
                raw = (long)Math.Min(BinaryPrimitives.ReadUInt64LittleEndian(db.AsSpan((int)p + 8)), long.MaxValue);
                header = 16;
            }
            if (raw < header || raw > db.Length - p) throw Malformed(name, $"a block at 0x{p:X} runs past the end");
            int at = (int)(p + header), length = (int)(raw - header);
            if (type == BlockAdb && adb == null) adb = new Adb(db.AsSpan(at, length).ToArray());
            else if (type == BlockSig) signatures++;
            else if (type == BlockData && length >= 8)
                files[(BinaryPrimitives.ReadUInt32LittleEndian(db.AsSpan(at)), BinaryPrimitives.ReadUInt32LittleEndian(db.AsSpan(at + 4)))] = (at + 8, length - 8);
            p += (raw + 7) & ~7L;
        }
        if (adb == null || adb.Root is not { } root) throw Malformed(name, "no ADB tree block");
        var notes = new List<string> { signatures > 0 ? $"{signatures} signature block(s), not verified" : "unsigned" };
        return schema == SchemaIndex ? Index(adb, root, notes, ct) : Package(adb, root, db, files, notes, allFiles, limits, ct);
    }

    private static ContainerContents Index(Adb adb, uint[] root, List<string> notes, CancellationToken ct)
    {
        var entries = new List<ContainerEntry>();
        foreach (var v in adb.Items(adb.Slot(root, IndexPackages)))
        {
            ct.ThrowIfCancellationRequested();
            if (adb.Object(v) is not { } pi) continue;
            var depends = Dependencies(adb, adb.Slot(pi, PiDepends));
            entries.Add(new ContainerEntry($"{adb.Text(adb.Slot(pi, PiName))}-{adb.Text(adb.Slot(pi, PiVersion))}.apk", (long)adb.Int(adb.Slot(pi, PiFileSize)),
                adb.Text(adb.Slot(pi, PiArch)) + (depends.Length > 0 ? $"; depends {depends}" : "")));
        }
        var description = adb.Text(adb.Slot(root, IndexDescription));
        notes.Insert(0, $"package index{(description.Length > 0 ? $" '{description}'" : "")}: {entries.Count:N0} packages; it holds no files, nothing extracted");
        return new ContainerContents("apk v3 index", [], notes) { Entries = entries };
    }

    private static ContainerContents Package(Adb adb, uint[] root, byte[] db, Dictionary<(uint, uint), (int At, int Length)> data, List<string> notes, bool allFiles,
        AnalysisLimits limits, CancellationToken ct)
    {
        var tree = new Firmware.FsTree("apk v3 package", allFiles, limits, ct);
        var paths = adb.Items(adb.Slot(root, PkgPaths));
        for (int d = 0; d < paths.Count; d++)
        {
            if (adb.Object(paths[d]) is not { } dir) continue;
            var folder = adb.Text(adb.Slot(dir, DiName)).Trim('/');
            var entries = adb.Items(adb.Slot(dir, DiFiles));
            for (int f = 0; f < entries.Count; f++)
            {
                if (adb.Object(entries[f]) is not { } file) continue;
                var fileName = adb.Text(adb.Slot(file, FiName));
                if (!Firmware.FsTree.UsableName(fileName) || folder.Split('/').Contains("..")) continue;
                var path = folder.Length > 0 ? folder + "/" + fileName : fileName;
                // A target holds the file mode (u16), then a link's target.
                if (adb.Blob(adb.Slot(file, FiTarget)) is { Length: >= 2 } target)
                {
                    if ((BinaryPrimitives.ReadUInt16LittleEndian(target) & 0xF000) == 0xA000) tree.Link(path, Encoding.UTF8.GetString(target, 2, target.Length - 2));
                    continue;
                }
                long size = (long)Math.Min(adb.Int(adb.Slot(file, FiSize)), long.MaxValue);
                // Data blocks name a file by its 1-based path and file slots.
                if (data.TryGetValue(((uint)d + 1, (uint)f + 1), out var stored)) tree.File(path, stored.Length, n => db.AsSpan(stored.At, (int)n).ToArray());
                else if (size == 0) tree.File(path, 0, _ => []);
                else tree.Notes.Add($"{path}: {size:N0} bytes listed, no data block");
            }
        }
        if (adb.Object(adb.Slot(root, PkgScripts)) is { } scripts)
            for (int i = 1; i < Scripts.Length; i++)
                if (adb.Blob(adb.Slot(scripts, i)) is { Length: > 0 } script) tree.File(Scripts[i], script.Length, n => script[..(int)n]);
        var contents = tree.Done();
        contents.Notes.InsertRange(0, notes);
        if (adb.Object(adb.Slot(root, PkgInfo)) is { } pi) contents.Notes.Insert(0, Describe(adb, pi, tree.Count));
        return contents;
    }

    /// <summary>The package's identity and relations in one line.</summary>
    private static string Describe(Adb adb, uint[] pi, int files)
    {
        string Field(int slot, string label) => adb.Text(adb.Slot(pi, slot)) is { Length: > 0 } t ? $"; {label} {t}" : "";
        string Relation(int slot, string label) => Dependencies(adb, adb.Slot(pi, slot)) is { Length: > 0 } t ? $"; {label} {t}" : "";
        var line = $"package {adb.Text(adb.Slot(pi, PiName))} {adb.Text(adb.Slot(pi, PiVersion))} ({adb.Text(adb.Slot(pi, PiArch))})";
        if (adb.Text(adb.Slot(pi, PiDescription)) is { Length: > 0 } d) line += $": {d}";
        return line + Field(PiLicense, "license") + Field(PiOrigin, "origin") + Field(PiMaintainer, "maintainer") + Relation(PiDepends, "depends")
               + Relation(PiProvides, "provides") + Relation(PiInstallIf, "install_if") + $"; installed size {adb.Int(adb.Slot(pi, PiInstalledSize)):N0} bytes; {files:N0} files";
    }

    /// <summary>Dependencies as apk writes them: name, operator, version ("!" for a conflict).</summary>
    private static string Dependencies(Adb adb, uint array) =>
        string.Join(", ", adb.Items(array).Select(adb.Object).OfType<uint[]>().Select(dep =>
        {
            var version = adb.Text(adb.Slot(dep, DepVersion));
            uint match = (uint)adb.Int(adb.Slot(dep, DepMatch));
            var name = ((match & 16) != 0 ? "!" : "") + adb.Text(adb.Slot(dep, DepName));
            if (version.Length == 0) return name;
            // apk_version.h: EQUAL 1, LESS 2, GREATER 4, FUZZY 8, CONFLICT 16.
            var op = ((match & ~16u) is 0 ? 1 : match & ~16u) switch { 2 => "<", 3 => "<=", 11 => "<~", 8 or 9 => "~", 1 => "=", 5 => ">=", 13 => ">~", 4 => ">", 6 => "><", _ => "?" };
            return name + op + version;
        }));

    private static byte[] Decompress(byte[] data, string name, AnalysisLimits limits)
    {
        long max = Math.Min(limits.MaxTotalBytes, Array.MaxLength);
        int alg = data[3] switch { (byte)'.' => -1, (byte)'d' => 1, _ => data.Length >= 6 ? data[4] : throw Malformed(name, "truncated compression header") };
        if (alg == -1) return data;
        int from = data[3] == 'd' ? 4 : 6;
        if (alg == 0) return data[from..];
        try
        {
            using var input = new MemoryStream(data, from, data.Length - from, writable: false);
            using Stream z = alg switch
            {
                1 => new DeflateStream(input, CompressionMode.Decompress),
                2 => new ZstdSharp.DecompressionStream(input),
                _ => throw Malformed(name, $"compression {alg} is not deflate or zstd"),
            };
            return Blob.ReadBounded(z, max) ?? throw new ToolError(ErrorCode.LimitExceeded, $"{name} decompresses past the {max:N0}-byte limit.", "raise the limits");
        }
        catch (Exception ex) when (ex is InvalidDataException or IOException or ZstdSharp.ZstdException) { throw Malformed(name, $"unreadable compressed data ({ex.Message})"); }
    }

    private static ToolError Malformed(string name, string what) => new(ErrorCode.MalformedInput, $"{name}: not a readable apk v3 file: {what}.");

    /// <summary>The ADB tree: values resolved against the block; a value out of range reads as absent.</summary>
    private sealed class Adb(byte[] b)
    {
        public uint[]? Root => b.Length >= 8 ? Object(BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(4))) : null;

        /// <summary>An object's or array's slots (slot 0 holds the count), or null.</summary>
        public uint[]? Object(uint v)
        {
            if ((v & TypeMask) is not (TypeArray or TypeObject)) return null;
            long at = v & ValueMask;
            if (at + 4 > b.Length) return null;
            uint count = BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan((int)at));
            if (count == 0 || count > (b.Length - at) / 4) return null;
            var slots = new uint[count];
            for (int i = 0; i < count; i++) slots[i] = BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan((int)at + 4 * i));
            return slots;
        }

        public uint Slot(uint[] o, int i) => i < o.Length ? o[i] : 0;

        public List<uint> Items(uint v) => Object(v) is { } o ? [.. o.Skip(1)] : [];

        public ulong Int(uint v)
        {
            long at = v & ValueMask;
            return (v & TypeMask) switch
            {
                TypeInt => v & ValueMask,
                TypeInt32 when at + 4 <= b.Length => BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan((int)at)),
                TypeInt64 when at + 8 <= b.Length => BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan((int)at)),
                _ => 0,
            };
        }

        public byte[]? Blob(uint v)
        {
            long at = v & ValueMask;
            int width = (v & TypeMask) switch { TypeBlob8 => 1, TypeBlob16 => 2, TypeBlob32 => 4, _ => 0 };
            if (width == 0 || at + width > b.Length) return null;
            long length = width == 1 ? b[at] : width == 2 ? BinaryPrimitives.ReadUInt16LittleEndian(b.AsSpan((int)at)) : BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan((int)at));
            return length > b.Length - at - width ? null : b.AsSpan((int)(at + width), (int)length).ToArray();
        }

        public string Text(uint v) => Blob(v) is { } t ? Encoding.UTF8.GetString(t) : "";
    }
}
