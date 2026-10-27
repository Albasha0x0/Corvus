using System.Security.Cryptography;
using Corvus.Core;
using Corvus.Native.Pe;

namespace Corvus.Native.Elf;

/// <summary>A program header.</summary>
public sealed record ElfSegment(int Index, uint Type, uint Flags, ulong Offset, ulong VirtualAddress, ulong FileSize, ulong MemorySize, ulong Align)
{
    public string TypeName => ElfNames.SegmentType(Type);
    public bool IsLoad => Type == 1;
    public bool Readable => (Flags & 4) != 0;
    public bool Writable => (Flags & 2) != 0;
    public bool Executable => (Flags & 1) != 0;
}

/// <summary>A section header; <see cref="Address"/> is 0 for sections that are not loaded.</summary>
public sealed record ElfSection(int Index, string Name, uint Type, ulong Flags, ulong Address, ulong Offset, ulong Size, uint Link, uint Info, ulong Align, ulong EntrySize)
{
    public string TypeName => ElfNames.SectionType(Type);
    public bool IsAllocated => (Flags & 2) != 0;
    public bool IsExecutable => (Flags & 4) != 0;
    public bool IsWritable => (Flags & 1) != 0;
    public bool HasFileData => Type != 8;
}

/// <summary>An ELF32/ELF64 image as the loader maps it; throws only when not ELF, other problems go to <see cref="Issues"/>. Without section headers, sections come from the segments. Thread-safe for reading.</summary>
public sealed partial class ElfFile : INativeImage
{
    private const ulong PageSize = 0x1000;
    private const int MaxSegments = 4096;
    private const int MaxSections = 65536;
    private const int MaxNameLength = 4096;

    private readonly byte[] data;
    private readonly ByteView view;
    private readonly IssueLog headerLog = new("headers");
    private readonly IReadOnlyList<ParseIssue> headerIssues;
    private readonly List<ElfSegment> segments = [];
    private readonly List<ElfSection> sectionHeaders = [];
    private readonly List<NativeSection> sections = [];

    public static ElfFile Open(string path)
    {
        FileInfo info;
        try { info = new FileInfo(InputFiles.RequireRegularFile(path, "image file")); }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            throw new ToolError(ErrorCode.InvalidArgument, $"invalid path '{path}': {ex.Message}");
        }
        if (!info.Exists) throw Targets.FileNotFound(path);
        if (info.Length > PeLimits.MaxFileSize)
            throw new ToolError(ErrorCode.LimitExceeded, $"{path} is {info.Length} bytes; native images up to {PeLimits.MaxFileSize} bytes are read");
        byte[] bytes;
        try { bytes = File.ReadAllBytes(info.FullName); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new ToolError(ErrorCode.IoError, $"cannot read {path}: {ex.Message}");
        }
        return new ElfFile(bytes, info.FullName);
    }

    /// <summary>Parses a copy of <paramref name="bytes"/>; <paramref name="path"/> is only reported back.</summary>
    public static ElfFile FromBytes(ReadOnlySpan<byte> bytes, string path = "")
    {
        if (bytes.Length > PeLimits.MaxFileSize)
            throw new ToolError(ErrorCode.LimitExceeded, $"image is {bytes.Length} bytes; native images up to {PeLimits.MaxFileSize} bytes are read");
        return new ElfFile(bytes.ToArray(), path);
    }

    private ElfFile(byte[] bytes, string path)
    {
        data = bytes;
        Path = path;
        if (bytes.Length < 16 || bytes[0] != 0x7F || bytes[1] != 'E' || bytes[2] != 'L' || bytes[3] != 'F')
            throw new ToolError(ErrorCode.MalformedInput, $"{(path.Length > 0 ? path : "the image")} is not an ELF file: no \\x7FELF signature");
        Sha256 = Convert.ToHexStringLower(SHA256.HashData(bytes));

        byte cls = bytes[4], encoding = bytes[5];
        if (cls is not (1 or 2)) headerLog.Add($"EI_CLASS {cls} is neither ELFCLASS32 nor ELFCLASS64; read as {(bytes.Length >= 64 ? "64" : "32")}-bit", 4);
        if (encoding is not (1 or 2)) headerLog.Add($"EI_DATA {encoding} is neither little nor big endian; read as little endian", 5);
        Is64Bit = cls == 2 || (cls != 1 && bytes.Length >= 64);
        BigEndian = encoding == 2;
        view = new ByteView(bytes, BigEndian);
        OsAbi = bytes[7];
        ReadHeader();
        ReadProgramHeaders();
        ReadSectionHeaders();
        BuildLayout();
        BuildSections();
        headerIssues = headerLog.ToList();
        InitAreas();
    }

    public ImageFormat Format => ImageFormat.Elf;
    public string Path { get; }
    public string Sha256 { get; }
    public long FileSize => data.Length;
    /// <summary>The file snapshot.</summary>
    public ReadOnlyMemory<byte> FileBytes => data;
    public bool Is64Bit { get; }
    public bool BigEndian { get; }
    public byte OsAbi { get; }
    /// <summary>e_type: ET_EXEC 2, ET_DYN 3, ...</summary>
    public ushort Type { get; private set; }
    /// <summary>e_machine.</summary>
    public ushort Machine { get; private set; }
    public uint Flags { get; private set; }
    /// <summary>e_entry as a virtual address.</summary>
    public ulong Entry { get; private set; }
    public NativeArch Arch => ElfNames.Arch(Machine);
    public string MachineName => ElfNames.Machine(Machine);
    public string TypeName => ElfNames.FileType(Type);
    /// <summary>The file type in words; ET_DYN with an interpreter is a position-independent executable.</summary>
    public string KindName => Type switch
    {
        3 => Interpreter != null ? "position-independent executable" : "shared object",
        2 => "executable",
        1 => "relocatable object",
        4 => "core dump",
        _ => TypeName,
    };

    /// <summary>Shared object rather than executable: ET_DYN without an interpreter (a PIE executable has PT_INTERP).</summary>
    public bool IsDll => Type == 3 && Interpreter == null;
    public string? Interpreter { get; private set; }
    /// <summary>The file is a memory image (a process dump): segments sit at file offset = address - base.</summary>
    public bool IsMappedDump { get; private set; }

    /// <summary>Lowest PT_LOAD address rounded down to the page size.</summary>
    public ulong ImageBase { get; private set; }
    public uint SizeOfImage { get; private set; }
    public uint EntryPointRva => CodeAddress(Entry) is var e && e >= ImageBase && e - ImageBase < SizeOfImage ? (uint)((e - ImageBase) & (Machine == ElfNames.EmArm ? ~1UL : ~0UL)) : 0;

    /// <summary>The code address of a function address: the .opd descriptor's first doubleword on PPC64 ELFv1, else the address.</summary>
    public ulong CodeAddress(ulong va)
    {
        // Keyed on .opd, not e_flags: ld.lld writes ABI 2 over v1 objects.
        if (Machine != ElfNames.EmPpc64 || Section(".opd") is not { } opd || va < opd.Address || va - opd.Address + 8 > opd.Size || !TryVaToRva(va, out uint rva)) return va;
        Span<byte> b = stackalloc byte[8];
        if (Read(rva, b) != 8) return va;
        return BigEndian ? System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(b) : System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(b);
    }

    public IReadOnlyList<ElfSegment> Segments => segments;
    public IReadOnlyList<ElfSegment> LoadSegments => [.. segments.Where(s => s.IsLoad)];
    /// <summary>Section headers in table order (index 0 is the null section); empty when the file has none or they are unusable.</summary>
    public IReadOnlyList<ElfSection> SectionHeaders => sectionHeaders;
    public IReadOnlyList<NativeSection> Sections => sections;

    /// <summary>The first section header named <paramref name="name"/>; null without section headers.</summary>
    public ElfSection? Section(string name) => sectionHeaders.FirstOrDefault(s => s.Name == name);

    public IReadOnlyList<RuntimeFunction> RuntimeFunctions => [];
    public IReadOnlyList<uint> TlsCallbackRvas => [];

    public IReadOnlyList<ParseIssue> Issues
    {
        get
        {
            var all = new List<ParseIssue>(headerIssues);
            all.AddRange(dynamic.Issues);
            all.AddRange(relocations.Issues);
            all.AddRange(symbols.Issues);
            all.AddRange(notes.Issues);
            all.AddRange(unwind.Issues);
            all.AddRange(plt.Issues);
            return all;
        }
    }

    public bool TryVaToRva(ulong va, out uint rva)
    {
        rva = (uint)(va - ImageBase);
        return va >= ImageBase && va - ImageBase < SizeOfImage;
    }

    private void ReadHeader()
    {
        int min = Is64Bit ? 64 : 52;
        if (data.Length < min) headerLog.Add($"the ELF header is truncated ({data.Length} of {min} bytes)", 0);
        Type = view.U16(16);
        Machine = view.U16(18);
        if (view.U32(20) != 1) headerLog.Add($"e_version is {view.U32(20)}, not EV_CURRENT", 20);
        Entry = Is64Bit ? view.U64(24) : view.U32(24);
        Flags = view.U32(Is64Bit ? 48 : 36);
        if (Type is 1) headerLog.Add("ET_REL: a relocatable object has no load segments; only section headers are read");
        if (Type is 4) headerLog.Add("ET_CORE: a core dump; only its segments are read");
    }

    private (long Offset, int Count, int Size) Table(int offsetAt, int countAt, int sizeAt, int standard)
    {
        long offset = (long)Math.Min(Is64Bit ? view.U64(offsetAt) : view.U32(offsetAt), long.MaxValue / 2);
        int count = view.U16(countAt);
        int size = view.U16(sizeAt);
        return (offset, count, size == 0 && count == 0 ? standard : size);
    }

    private void ReadProgramHeaders()
    {
        int standard = Is64Bit ? 56 : 32;
        var (phoff, phnum, phentsize) = Table(Is64Bit ? 32 : 28, Is64Bit ? 56 : 44, Is64Bit ? 54 : 42, standard);
        if (phnum == 0xFFFF)
        {
            // PN_XNUM: the real count is the first section header's sh_info.
            long shoff = (long)Math.Min(Is64Bit ? view.U64(40) : view.U32(32), long.MaxValue / 2);
            phnum = (int)Math.Min(view.U32(shoff + (Is64Bit ? 44 : 28)), MaxSegments);
        }
        if (phnum == 0) return;
        if (phentsize < standard)
        {
            headerLog.Add($"e_phentsize {phentsize} is below {standard}; program headers read at the standard size", Is64Bit ? 54 : 42);
            phentsize = standard;
        }
        if (phnum > MaxSegments)
        {
            headerLog.Add($"{phnum} program headers; the first {MaxSegments} are read");
            phnum = MaxSegments;
        }
        for (int i = 0; i < phnum; i++)
        {
            long at = phoff + (long)i * phentsize;
            if (!view.Has(at, standard))
            {
                headerLog.Add($"program header {i} lies past the end of the file; {i} of {phnum} read", at);
                break;
            }
            segments.Add(Is64Bit
                ? new ElfSegment(i, view.U32(at), view.U32(at + 4), view.U64(at + 8), view.U64(at + 16), view.U64(at + 32), view.U64(at + 40), view.U64(at + 48))
                : new ElfSegment(i, view.U32(at), view.U32(at + 24), view.U32(at + 4), view.U32(at + 8), view.U32(at + 16), view.U32(at + 20), view.U32(at + 28)));
        }
        if (segments.FirstOrDefault(s => s.Type == 3) is { } interp)
            Interpreter = view.CString((long)Math.Min(interp.Offset, long.MaxValue), (int)Math.Min(interp.FileSize, MaxNameLength)) is { Length: > 0 } s ? s : null;
    }

    private void ReadSectionHeaders()
    {
        int standard = Is64Bit ? 64 : 40;
        var (shoff, shnum, shentsize) = Table(Is64Bit ? 40 : 32, Is64Bit ? 60 : 48, Is64Bit ? 58 : 46, standard);
        int shstrndx = view.U16(Is64Bit ? 62 : 50);
        if (shoff == 0) return;
        if (shentsize < standard)
        {
            headerLog.Add($"e_shentsize {shentsize} is below {standard}; section headers ignored", Is64Bit ? 58 : 46);
            return;
        }
        if (!view.Has(shoff, standard))
        {
            headerLog.Add($"section headers at 0x{shoff:X} lie past the end of the file; ignored", Is64Bit ? 40 : 32);
            return;
        }
        // Extended numbering: section 0 holds the real count and string table index.
        if (shnum == 0) shnum = (int)Math.Min(Is64Bit ? view.U64(shoff + 32) : view.U32(shoff + 20), MaxSections);
        if (shstrndx == 0xFFFF) shstrndx = (int)view.U32(shoff + (Is64Bit ? 40 : 24));
        if (shnum > MaxSections)
        {
            headerLog.Add($"{shnum} section headers; the first {MaxSections} are read");
            shnum = MaxSections;
        }
        var raw = new List<(uint Name, ElfSection Section)>();
        for (int i = 0; i < shnum; i++)
        {
            long at = shoff + (long)i * shentsize;
            if (!view.Has(at, standard))
            {
                headerLog.Add($"section header {i} lies past the end of the file; {i} of {shnum} read", at);
                break;
            }
            var s = Is64Bit
                ? new ElfSection(i, "", view.U32(at + 4), view.U64(at + 8), view.U64(at + 16), view.U64(at + 24), view.U64(at + 32), view.U32(at + 40), view.U32(at + 44), view.U64(at + 48), view.U64(at + 56))
                : new ElfSection(i, "", view.U32(at + 4), view.U32(at + 8), view.U32(at + 12), view.U32(at + 16), view.U32(at + 20), view.U32(at + 24), view.U32(at + 28), view.U32(at + 32), view.U32(at + 36));
            raw.Add((view.U32(at), s));
        }
        ElfSection? strtab = shstrndx > 0 && shstrndx < raw.Count ? raw[shstrndx].Section : null;
        if (strtab == null && raw.Count > 1) headerLog.Add($"e_shstrndx {shstrndx} names no section; sections are unnamed", Is64Bit ? 62 : 50);
        int badNames = 0;
        foreach (var (name, s) in raw)
        {
            string text = "";
            if (strtab != null && name < strtab.Size)
            {
                long at = (long)Math.Min(strtab.Offset + name, long.MaxValue);
                text = view.CString(at, (int)Math.Min(strtab.Size - name, MaxNameLength)) ?? "";
            }
            else if (strtab != null && name != 0) badNames++;
            sectionHeaders.Add(s with { Name = text });
        }
        if (badNames > 0) headerLog.Add($"{badNames} section names lie outside the section name table");
    }
}
