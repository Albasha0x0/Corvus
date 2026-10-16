using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;
using Corvus.Core;
using Microsoft.Win32.SafeHandles;

namespace Corvus.Native.Dwarf;

/// <summary>Random-access bytes of a debug file: an in-memory snapshot, or a file read on demand (never whole).</summary>
internal abstract class DebugBytes : IDisposable
{
    public abstract long Length { get; }

    /// <summary>Reads up to <paramref name="destination"/>.Length bytes at <paramref name="offset"/>; returns the count read.</summary>
    public abstract int Read(long offset, Span<byte> destination);

    /// <summary>The bytes [offset, offset + count): a slice of the snapshot, or a copy read from the file.</summary>
    public virtual ReadOnlyMemory<byte> Slice(long offset, int count)
    {
        if (offset < 0 || offset >= Length || count <= 0) return ReadOnlyMemory<byte>.Empty;
        var bytes = new byte[(int)Math.Min(count, Length - offset)];
        int got = Read(offset, bytes);
        return bytes.AsMemory(0, got);
    }

    public virtual void Dispose() { }

    public static DebugBytes Of(ReadOnlyMemory<byte> bytes) => new MemoryBytes(bytes);

    /// <summary>Opens <paramref name="path"/> for reading; deleting or replacing the file meanwhile is allowed.</summary>
    public static DebugBytes Open(string path)
    {
        try { return new FileBytes(File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete)); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { throw new ToolError(ErrorCode.IoError, $"cannot read {path}: {ex.Message}"); }
    }

    private sealed class MemoryBytes(ReadOnlyMemory<byte> bytes) : DebugBytes
    {
        public override long Length => bytes.Length;

        public override int Read(long offset, Span<byte> destination)
        {
            if (offset < 0 || offset >= bytes.Length) return 0;
            var src = bytes.Span[(int)offset..];
            int n = Math.Min(src.Length, destination.Length);
            src[..n].CopyTo(destination);
            return n;
        }

        public override ReadOnlyMemory<byte> Slice(long offset, int count) =>
            offset < 0 || offset >= bytes.Length || count <= 0 ? ReadOnlyMemory<byte>.Empty : bytes.Slice((int)offset, (int)Math.Min(count, bytes.Length - offset));
    }

    private sealed class FileBytes(SafeFileHandle handle) : DebugBytes
    {
        public override long Length { get; } = RandomAccess.GetLength(handle);

        public override int Read(long offset, Span<byte> destination)
        {
            if (offset < 0 || offset >= Length) return 0;
            int total = 0;
            while (total < destination.Length)
            {
                int n = RandomAccess.Read(handle, destination[total..], offset + total);
                if (n <= 0) break;
                total += n;
            }
            return total;
        }

        public override void Dispose()
        {
            handle.Dispose();
            base.Dispose();
        }
    }
}

/// <summary>A debug section: where its bytes are in the file, and how they are compressed (0 none, 1 zlib, 2 zstd).</summary>
internal sealed record DebugSectionInfo(string Name, long Offset, long Size, int Compression = 0, long UncompressedSize = 0, int HeaderSize = 0);

/// <summary>
/// The DWARF sections of an ELF or Mach-O file (a thin slice of a universal one) read through its headers only: section
/// names, offsets and compression, the byte order and address size, and the identity a debug file is matched by (GNU
/// build-id, Mach-O LC_UUID, .gnu_debuglink). Nothing past the headers is read until a section is asked for.
/// </summary>
internal sealed class DebugContainer : IDisposable
{
    /// <summary>Largest section kept whole in memory when read from a file; larger ones are read a unit or a page at a time.</summary>
    public const int WholeSectionBytes = 64 << 20;
    /// <summary>Largest compressed section inflated (compressed sections are inflated whole).</summary>
    public const long MaxInflatedBytes = 1L << 30;
    private const int MaxSectionHeaders = 65536;
    private const int MaxLoadCommands = 4096;

    private readonly DebugBytes _bytes;
    private readonly long _base;
    private readonly Dictionary<string, DebugSectionInfo> _sections = new(StringComparer.Ordinal);
    private readonly Dictionary<string, DwarfSection> _opened = new(StringComparer.Ordinal);
    private readonly object _gate = new();
    private bool _ownsBytes;

    public string Path { get; }
    public ImageFormat Format { get; private set; }
    public bool BigEndian { get; private set; }
    public bool Is64 { get; private set; }
    /// <summary>GNU build-id (ELF) or LC_UUID (Mach-O), lowercase hex; null when the file has none.</summary>
    public string? BuildId { get; private set; }
    /// <summary>.gnu_debuglink: the debug file's name and the CRC-32 of its contents.</summary>
    public (string Name, uint Crc)? DebugLink { get; private set; }
    /// <summary>.gnu_debugaltlink: the dwz supplementary file's path and build-id.</summary>
    public (string Name, string? BuildId)? AltLink { get; private set; }
    /// <summary>ELF e_type (1 relocatable) or Mach-O filetype (10 dSYM companion).</summary>
    public uint FileType { get; private set; }
    public IReadOnlyCollection<DebugSectionInfo> Sections => _sections.Values;
    public long FileLength => _bytes.Length;
    public List<string> Notes { get; } = [];

    private DebugContainer(string path, DebugBytes bytes, long baseOffset, bool ownsBytes)
    {
        Path = path;
        _bytes = bytes;
        _base = baseOffset;
        _ownsBytes = ownsBytes;
    }

    /// <summary>Opens a debug file; <paramref name="wantedId"/> picks the slice of a universal Mach-O (else the first).</summary>
    public static DebugContainer Open(string path, string? wantedId = null, string? cpuName = null)
    {
        var bytes = DebugBytes.Open(path);
        try { return Read(path, bytes, ownsBytes: true, wantedId, cpuName); }
        catch
        {
            bytes.Dispose();
            throw;
        }
    }

    /// <summary>The DWARF sections of an image already in memory (a thin file).</summary>
    public static DebugContainer FromMemory(string path, ReadOnlyMemory<byte> bytes) => Read(path, DebugBytes.Of(bytes), ownsBytes: true, null, null);

    private static DebugContainer Read(string path, DebugBytes bytes, bool ownsBytes, string? wantedId, string? cpuName)
    {
        Span<byte> magic = stackalloc byte[8];
        if (bytes.Read(0, magic) < 8) throw Malformed(path, "shorter than any ELF or Mach-O header");
        uint be = BinaryPrimitives.ReadUInt32BigEndian(magic);
        if (magic[0] == 0x7F && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F')
        {
            var c = new DebugContainer(path, bytes, 0, ownsBytes);
            c.ReadElf();
            return c;
        }
        if (be is 0xCAFEBABE or 0xCAFEBABF && BinaryPrimitives.ReadUInt32BigEndian(magic[4..]) is > 0 and < 64)
            return ReadFat(path, bytes, ownsBytes, be == 0xCAFEBABF, wantedId, cpuName);
        if (be is 0xFEEDFACE or 0xFEEDFACF or 0xCEFAEDFE or 0xCFFAEDFE)
        {
            var c = new DebugContainer(path, bytes, 0, ownsBytes);
            c.ReadMachO();
            return c;
        }
        throw Malformed(path, "not an ELF or Mach-O file");
    }

    private static ToolError Malformed(string path, string why) => new(ErrorCode.MalformedInput, $"{path}: {why}");

    private static DebugContainer ReadFat(string path, DebugBytes bytes, bool ownsBytes, bool fat64, string? wantedId, string? cpuName)
    {
        int count = (int)BinaryPrimitives.ReadUInt32BigEndian(bytes.Slice(4, 4).Span);
        int entry = fat64 ? 32 : 20;
        var header = bytes.Slice(8, count * entry).ToArray();
        DebugContainer? first = null;
        for (int i = 0; i + entry <= header.Length; i += entry)
        {
            var h = header.AsSpan(i);
            long offset = fat64 ? (long)BinaryPrimitives.ReadUInt64BigEndian(h[8..]) : BinaryPrimitives.ReadUInt32BigEndian(h[8..]);
            var c = new DebugContainer(path, bytes, offset, ownsBytes: false);
            try { c.ReadMachO(); }
            catch (ToolError) { continue; }
            if (wantedId != null && c.BuildId == wantedId || wantedId == null && cpuName != null && c.CpuName == cpuName)
                return c.Own(ownsBytes);
            first ??= c;
        }
        return first?.Own(ownsBytes) ?? throw Malformed(path, "no readable slice in the universal file");
    }

    /// <summary>The chosen slice of a universal file takes over the file.</summary>
    private DebugContainer Own(bool owns)
    {
        _ownsBytes = owns;
        return this;
    }

    /// <summary>The Mach-O CPU as LoadedNative names slices (x86_64, arm64, ...).</summary>
    public string? CpuName { get; private set; }

    public void Dispose()
    {
        if (_ownsBytes) _bytes.Dispose();
    }

    private ReadOnlySpan<byte> Head(long offset, int count) => _bytes.Slice(_base + offset, count).Span;

    private ulong U(ReadOnlySpan<byte> s, int at, int size)
    {
        if (at < 0 || at + size > s.Length) return 0;
        return size switch
        {
            1 => s[at],
            2 => BigEndian ? BinaryPrimitives.ReadUInt16BigEndian(s[at..]) : BinaryPrimitives.ReadUInt16LittleEndian(s[at..]),
            4 => BigEndian ? BinaryPrimitives.ReadUInt32BigEndian(s[at..]) : BinaryPrimitives.ReadUInt32LittleEndian(s[at..]),
            _ => BigEndian ? BinaryPrimitives.ReadUInt64BigEndian(s[at..]) : BinaryPrimitives.ReadUInt64LittleEndian(s[at..]),
        };
    }

    private void ReadElf()
    {
        Format = ImageFormat.Elf;
        var e = Head(0, 64).ToArray();
        Is64 = e[4] == 2;
        BigEndian = e[5] == 2;
        FileType = (uint)U(e, 16, 2);
        long shoff = (long)(Is64 ? U(e, 0x28, 8) : U(e, 0x20, 4));
        int shentsize = (int)U(e, Is64 ? 0x3A : 0x2E, 2);
        long shnum = (long)U(e, Is64 ? 0x3C : 0x30, 2);
        long shstrndx = (long)U(e, Is64 ? 0x3E : 0x32, 2);
        if (shoff <= 0 || shentsize < (Is64 ? 64 : 40)) { Notes.Add("no section headers: no DWARF sections"); return; }
        var first = Head(shoff, shentsize).ToArray();
        if (shnum == 0) shnum = (long)(Is64 ? U(first, 0x20, 8) : U(first, 0x14, 4));
        if (shstrndx == 0xFFFF) shstrndx = (long)U(first, Is64 ? 0x28 : 0x18, 4);
        if (shnum > MaxSectionHeaders) { Notes.Add($"{shnum} section headers; the first {MaxSectionHeaders} are read"); shnum = MaxSectionHeaders; }
        var table = Head(shoff, (int)(shnum * shentsize)).ToArray();
        (long Offset, long Size, uint Type, ulong Flags, uint NameAt, uint Link, uint Info, ulong Address) Section(long i)
        {
            int at = (int)(i * shentsize);
            return Is64
                ? ((long)U(table, at + 0x18, 8), (long)U(table, at + 0x20, 8), (uint)U(table, at + 4, 4), U(table, at + 8, 8), (uint)U(table, at, 4),
                    (uint)U(table, at + 0x28, 4), (uint)U(table, at + 0x2C, 4), U(table, at + 0x10, 8))
                : ((long)U(table, at + 0x10, 4), (long)U(table, at + 0x14, 4), (uint)U(table, at + 4, 4), U(table, at + 8, 4), (uint)U(table, at, 4),
                    (uint)U(table, at + 0x18, 4), (uint)U(table, at + 0x1C, 4), U(table, at + 0x0C, 4));
        }
        if (shstrndx >= table.Length / shentsize) { Notes.Add("the section name table index is out of range"); return; }
        var names = Section(shstrndx);
        var nameBytes = Head(names.Offset, (int)Math.Min(names.Size, 16 << 20)).ToArray();
        var relocatable = FileType == 1 ? new List<DebugRelocations.Header>() : null;
        for (long i = 1; i < table.Length / shentsize; i++)
        {
            var s = Section(i);
            string name = CString(nameBytes, (int)s.NameAt);
            relocatable?.Add(new DebugRelocations.Header((int)i, name, s.Type, s.Offset, s.Size, s.Link, s.Info, s.Address));
            if (s.Type == 8) continue; // SHT_NOBITS: an executable's sections in a debug-only file
            if (s.Type == 7 && (name == ".note.gnu.build-id" || BuildId == null)) ReadNotes(s.Offset, s.Size);
            if (name == ".gnu_debuglink")
            {
                var d = Head(s.Offset, (int)Math.Min(s.Size, 4096)).ToArray();
                int z = Array.IndexOf(d, (byte)0);
                if (z > 0)
                {
                    int crcAt = (z + 4) & ~3;
                    DebugLink = (Encoding.UTF8.GetString(d, 0, z), (uint)U(d, crcAt, 4));
                }
                continue;
            }
            if (name == ".gnu_debugaltlink")
            {
                var d = Head(s.Offset, (int)Math.Min(s.Size, 4096)).ToArray();
                int z = Array.IndexOf(d, (byte)0);
                if (z > 0) AltLink = (Encoding.UTF8.GetString(d, 0, z), z + 1 < d.Length ? Convert.ToHexStringLower(d, z + 1, d.Length - z - 1) : null);
                continue;
            }
            bool gnuCompressed = name.StartsWith(".zdebug_", StringComparison.Ordinal);
            if (!name.StartsWith(".debug_", StringComparison.Ordinal) && !gnuCompressed) continue;
            var key = gnuCompressed ? "." + name[2..] : name;
            if (s.Offset < 0 || s.Size <= 0 || s.Offset + s.Size > _bytes.Length - _base)
            {
                Notes.Add($"{name}: offset 0x{s.Offset:X} size 0x{s.Size:X} runs past the end of the file; not read");
                continue;
            }
            if ((s.Flags & 0x800) != 0) // SHF_COMPRESSED
            {
                var ch = Head(s.Offset, Is64 ? 24 : 12).ToArray();
                int type = (int)U(ch, 0, 4);
                long size = (long)(Is64 ? U(ch, 8, 8) : U(ch, 4, 4));
                _sections[key] = new DebugSectionInfo(key, s.Offset, s.Size, type is 1 or 2 ? type : -type, size, Is64 ? 24 : 12);
            }
            else if (gnuCompressed)
            {
                var zh = Head(s.Offset, 12).ToArray();
                bool zlib = zh.Length == 12 && zh[0] == 'Z' && zh[1] == 'L' && zh[2] == 'I' && zh[3] == 'B';
                _sections[key] = zlib ? new DebugSectionInfo(key, s.Offset, s.Size, 1, (long)BinaryPrimitives.ReadUInt64BigEndian(zh.AsSpan(4)), 12)
                    : new DebugSectionInfo(key, s.Offset, s.Size);
            }
            else _sections.TryAdd(key, new DebugSectionInfo(key, s.Offset, s.Size));
        }
        if (relocatable != null) _relocations = DebugRelocations.Of(relocatable, (ushort)U(e, 18, 2), Is64, BigEndian, (o, n) => Head(o, n).ToArray(), Notes);
    }

    private DebugRelocations? _relocations;

    private void ReadNotes(long offset, long size)
    {
        var d = Head(offset, (int)Math.Min(size, 1 << 16)).ToArray();
        for (int at = 0; at + 12 <= d.Length;)
        {
            int nameSize = (int)U(d, at, 4), descSize = (int)U(d, at + 4, 4);
            uint type = (uint)U(d, at + 8, 4);
            int name = at + 12, desc = name + ((nameSize + 3) & ~3);
            if (nameSize < 0 || descSize < 0 || desc + descSize > d.Length) return;
            if (type == 3 && nameSize == 4 && d[name] == 'G' && d[name + 1] == 'N' && d[name + 2] == 'U')
            {
                BuildId = Convert.ToHexStringLower(d, desc, descSize);
                return;
            }
            at = desc + ((descSize + 3) & ~3);
        }
    }

    private void ReadMachO()
    {
        Format = ImageFormat.MachO;
        var h = Head(0, 32).ToArray();
        if (h.Length < 28) throw Malformed(Path, "truncated Mach-O header");
        uint magic = BinaryPrimitives.ReadUInt32LittleEndian(h);
        BigEndian = magic is 0xCEFAEDFE or 0xCFFAEDFE;
        Is64 = magic is 0xFEEDFACF or 0xCFFAEDFE;
        if (magic is not (0xFEEDFACE or 0xFEEDFACF or 0xCEFAEDFE or 0xCFFAEDFE)) throw Malformed(Path, "not a Mach-O slice");
        uint cpu = (uint)U(h, 4, 4);
        CpuName = cpu switch { 0x01000007 => "x86_64", 7 => "i386", 0x0100000C => "arm64", 12 => "arm", 0x0200000C => "arm64_32", _ => null };
        FileType = (uint)U(h, 12, 4);
        int ncmds = (int)U(h, 16, 4);
        long sizeofcmds = (long)U(h, 20, 4);
        int at0 = Is64 ? 32 : 28;
        if (ncmds > MaxLoadCommands || sizeofcmds > 64 << 20) throw Malformed(Path, $"{ncmds} load commands in {sizeofcmds} bytes");
        var cmds = Head(at0, (int)sizeofcmds).ToArray();
        for (int i = 0, at = 0; i < ncmds && at + 8 <= cmds.Length; i++)
        {
            uint cmd = (uint)U(cmds, at, 4);
            int size = (int)U(cmds, at + 4, 4);
            if (size < 8 || at + size > cmds.Length) { Notes.Add($"load command {i} has size {size}; the rest are not read"); break; }
            if (cmd == 0x1B && size >= 24) BuildId = Convert.ToHexStringLower(cmds, at + 8, 16);
            else if (cmd is 0x1 or 0x19)
            {
                bool is64 = cmd == 0x19;
                int nsects = (int)U(cmds, at + (is64 ? 64 : 48), 4);
                int sectAt = at + (is64 ? 72 : 56), sectSize = is64 ? 80 : 68;
                for (int k = 0; k < nsects && sectAt + sectSize <= at + size; k++, sectAt += sectSize)
                {
                    string sect = CString(cmds.AsSpan(sectAt, 16), 0);
                    long sz = (long)(is64 ? U(cmds, sectAt + 40, 8) : U(cmds, sectAt + 36, 4));
                    long off = (long)U(cmds, sectAt + (is64 ? 48 : 40), 4);
                    if (!sect.StartsWith("__debug_", StringComparison.Ordinal) && !sect.StartsWith("__zdebug_", StringComparison.Ordinal)) continue;
                    var key = MachOSectionName(sect);
                    if (off <= 0 || sz <= 0 || _base + off + sz > _bytes.Length) continue;
                    _sections.TryAdd(key, new DebugSectionInfo(key, off, sz));
                }
            }
            at += size;
        }
    }

    /// <summary>"__debug_str_offs" (Mach-O names stop at 16 bytes) to ".debug_str_offsets".</summary>
    private static string MachOSectionName(string sect)
    {
        var name = "." + sect[2..];
        return name switch
        {
            ".debug_str_offs" => ".debug_str_offsets",
            _ => name,
        };
    }

    private static string CString(ReadOnlySpan<byte> s, int at)
    {
        if (at < 0 || at >= s.Length) return "";
        var rest = s[at..];
        int z = rest.IndexOf((byte)0);
        return Encoding.UTF8.GetString(z < 0 ? rest : rest[..z]);
    }

    public bool Has(string name) => _sections.ContainsKey(name);

    /// <summary>A section's bytes, null when the file has none (or it could not be inflated; see <see cref="Notes"/>).</summary>
    public DwarfSection? Section(string name)
    {
        lock (_gate)
        {
            if (_opened.TryGetValue(name, out var open)) return open;
            if (!_sections.TryGetValue(name, out var info)) return null;
            DwarfSection? section;
            if (info.Compression != 0) section = Inflate(info);
            else if (info.Size <= WholeSectionBytes || _relocations?.Has(name) == true) section = new DwarfSection(name, _bytes.Slice(_base + info.Offset, (int)Math.Min(info.Size, int.MaxValue)));
            else section = new DwarfSection(name, _bytes, _base + info.Offset, info.Size);
            // a relocatable object's DWARF holds zeros where the linker writes offsets and addresses
            if (section != null && _relocations?.Has(name) == true) section = new DwarfSection(name, _relocations.Apply(name, section.Slice(0, section.Length).ToArray()));
            if (section != null) _opened[name] = section;
            return section;
        }
    }

    private DwarfSection? Inflate(DebugSectionInfo info)
    {
        if (info.Compression < 0) { Notes.Add($"{info.Name}: compression type {-info.Compression} is not supported"); return null; }
        if (info.UncompressedSize <= 0 || info.UncompressedSize > MaxInflatedBytes || info.Size > int.MaxValue)
        {
            Notes.Add($"{info.Name}: {info.UncompressedSize:N0} bytes uncompressed; compressed sections up to {MaxInflatedBytes:N0} bytes are read");
            return null;
        }
        var packed = _bytes.Slice(_base + info.Offset + info.HeaderSize, (int)(info.Size - info.HeaderSize));
        var output = new byte[info.UncompressedSize];
        try
        {
            using var input = new MemoryStream(packed.ToArray(), writable: false);
            using Stream inflater = info.Compression == 1 ? new ZLibStream(input, CompressionMode.Decompress) : new ZstdSharp.DecompressionStream(input);
            int total = 0;
            while (total < output.Length)
            {
                int n = inflater.Read(output, total, output.Length - total);
                if (n <= 0) break;
                total += n;
            }
            if (total < output.Length) Notes.Add($"{info.Name}: inflated to {total:N0} of {output.Length:N0} bytes");
        }
        catch (Exception ex) when (ex is InvalidDataException or IOException or ZstdSharp.ZstdException)
        {
            Notes.Add($"{info.Name}: cannot be inflated ({ex.Message})");
            return null;
        }
        return new DwarfSection(info.Name, output);
    }

    /// <summary>CRC-32 of the whole file, the value .gnu_debuglink records (read in 1 MB blocks).</summary>
    public uint FileCrc32()
    {
        var crc = new System.IO.Hashing.Crc32();
        var buffer = new byte[1 << 20];
        for (long at = 0; at < _bytes.Length;)
        {
            int n = _bytes.Read(at, buffer);
            if (n <= 0) break;
            crc.Append(buffer.AsSpan(0, n));
            at += n;
        }
        return crc.GetCurrentHashAsUInt32();
    }
}

/// <summary>
/// One DWARF section's bytes: whole in memory, or read from the file on demand (<see cref="Slice"/> per unit,
/// <see cref="CString"/> through a page cache of <see cref="CachedPages"/> pages of <see cref="PageSize"/> bytes).
/// Reads past the end return fewer bytes, never throw. Thread-safe.
/// </summary>
internal sealed class DwarfSection
{
    public const int PageSize = 1 << 20;
    public const int CachedPages = 32;
    private const int MaxString = 1 << 16;

    private readonly ReadOnlyMemory<byte> _memory;
    private readonly DebugBytes? _file;
    private readonly long _offset;
    private readonly Dictionary<long, byte[]> _pages = [];
    private readonly Queue<long> _order = new();

    public string Name { get; }
    public long Length { get; }
    public bool InMemory => _file == null;

    public DwarfSection(string name, ReadOnlyMemory<byte> bytes)
    {
        Name = name;
        _memory = bytes;
        Length = bytes.Length;
    }

    public DwarfSection(string name, DebugBytes file, long offset, long length)
    {
        Name = name;
        _file = file;
        _offset = offset;
        Length = length;
    }

    /// <summary>[offset, offset + count) clipped to the section.</summary>
    public ReadOnlyMemory<byte> Slice(long offset, long count)
    {
        if (offset < 0 || offset >= Length || count <= 0) return ReadOnlyMemory<byte>.Empty;
        int n = (int)Math.Min(Math.Min(count, Length - offset), int.MaxValue);
        if (_file == null) return _memory.Slice((int)offset, n);
        lock (_pages) return _file.Slice(_offset + offset, n);
    }

    /// <summary>The bytes from <paramref name="offset"/> to the end of the section, at most <paramref name="max"/>.</summary>
    public ReadOnlyMemory<byte> From(long offset, long max) => Slice(offset, Math.Min(max, Length - offset));

    /// <summary>A NUL-terminated UTF-8 string; null when the offset is outside the section.</summary>
    public string? CString(long offset)
    {
        if (offset < 0 || offset >= Length) return null;
        if (_file == null)
        {
            var rest = _memory.Span[(int)offset..];
            int z = rest.IndexOf((byte)0);
            if (z < 0) z = rest.Length;
            return Encoding.UTF8.GetString(rest[..Math.Min(z, MaxString)]);
        }
        lock (_pages)
        {
            long page = offset / PageSize;
            var bytes = Page(page);
            int at = (int)(offset - page * PageSize);
            int z = bytes.AsSpan(at).IndexOf((byte)0);
            if (z >= 0) return Encoding.UTF8.GetString(bytes, at, Math.Min(z, MaxString));
            // crosses into the next pages
            var sb = new List<byte>(bytes.AsSpan(at).ToArray());
            while (sb.Count < MaxString && (page + 1) * PageSize < Length)
            {
                var next = Page(++page);
                int z2 = Array.IndexOf(next, (byte)0);
                sb.AddRange(z2 < 0 ? next : next.AsSpan(0, z2).ToArray());
                if (z2 >= 0) break;
            }
            return Encoding.UTF8.GetString(sb.ToArray(), 0, Math.Min(sb.Count, MaxString));
        }
    }

    private byte[] Page(long page)
    {
        if (_pages.TryGetValue(page, out var cached)) return cached;
        if (_pages.Count >= CachedPages) _pages.Remove(_order.Dequeue());
        long start = page * PageSize;
        var bytes = new byte[(int)Math.Min(PageSize, Length - start)];
        _file!.Read(_offset + start, bytes);
        _pages[page] = bytes;
        _order.Enqueue(page);
        return bytes;
    }
}
