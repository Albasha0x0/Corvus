using System.Security.Cryptography;
using System.Text;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native.Pe;

namespace NetDecompilerMcp.Native.MachO;

/// <summary>
/// A thin Mach-O image (32 or 64-bit, either byte order), or one slice of a universal file, parsed from an in-memory
/// snapshot. Construction throws only when the bytes are not Mach-O; anything else that cannot be read is reported in
/// <see cref="Issues"/>. Addresses are RVAs from the __TEXT segment (the image base); __PAGEZERO is not mapped. The
/// image view applies rebases (chained fixups and rebase opcodes, PAC bits stripped) and reads bind slots as 0;
/// <see cref="Fixups"/> tells what each slot binds to. File offsets are relative to the slice. Thread-safe for reading.
/// </summary>
public sealed partial class MachOFile : INativeImage
{
    private const int MaxCommands = 1 << 16;
    private const int MaxSectionsPerSegment = 1 << 12;
    private const int MaxNameLength = 4096;

    private readonly byte[] data;
    private readonly ByteView view;
    private readonly IssueLog headerLog = new("headers");
    private readonly IReadOnlyList<ParseIssue> headerIssues;
    private readonly List<MachOLoadCommand> commands = [];
    private readonly List<MachOSegment> segments = [];
    private readonly List<NativeSection> sections = [];

    public static MachOFile Open(string path, string? slice = null)
    {
        FileInfo info;
        try { info = new FileInfo(InputFiles.RequireRegularFile(path, "image file")); }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            throw new ToolError(ErrorCode.InvalidArgument, $"invalid path '{path}': {ex.Message}");
        }
        if (!info.Exists) throw new ToolError(ErrorCode.NotFound, $"file not found: {path}");
        if (info.Length > PeLimits.MaxFileSize)
            throw new ToolError(ErrorCode.LimitExceeded, $"{path} is {info.Length} bytes; native images up to {PeLimits.MaxFileSize} bytes are read");
        byte[] bytes;
        try { bytes = File.ReadAllBytes(info.FullName); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new ToolError(ErrorCode.IoError, $"cannot read {path}: {ex.Message}");
        }
        return FromBytes(bytes, info.FullName, slice);
    }

    /// <summary>
    /// Parses a copy of <paramref name="bytes"/>: a thin image, or the slice of a universal file chosen by
    /// <paramref name="slice"/> (see <see cref="MachOFat.Select"/>). <paramref name="path"/> is only reported back.
    /// </summary>
    public static MachOFile FromBytes(ReadOnlySpan<byte> bytes, string path = "", string? slice = null)
    {
        if (bytes.Length > PeLimits.MaxFileSize)
            throw new ToolError(ErrorCode.LimitExceeded, $"image is {bytes.Length} bytes; native images up to {PeLimits.MaxFileSize} bytes are read");
        if (MachOFat.IsFat(bytes))
        {
            var slices = MachOFat.Read(bytes);
            var chosen = MachOFat.Select(slices, slice);
            return new MachOFile(bytes.Slice((int)chosen.Offset, (int)chosen.Size).ToArray(), path, slices, chosen);
        }
        if (slice != null) throw new ToolError(ErrorCode.InvalidArgument, $"slice '{slice}' applies to universal files only", "omit slice");
        return new MachOFile(bytes.ToArray(), path, [], null);
    }

    private MachOFile(byte[] bytes, string path, IReadOnlyList<MachOSlice> slices, MachOSlice? slice)
    {
        data = bytes;
        Path = path;
        Slices = slices;
        Slice = slice;
        uint magic = bytes.Length >= 4 ? (uint)(bytes[0] << 24 | bytes[1] << 16 | bytes[2] << 8 | bytes[3]) : 0;
        (Is64Bit, BigEndian) = magic switch
        {
            0xFEEDFACE => (false, true),
            0xFEEDFACF => (true, true),
            0xCEFAEDFE => (false, false),
            0xCFFAEDFE => (true, false),
            _ => throw new ToolError(ErrorCode.MalformedInput, $"{(path.Length > 0 ? path : "the image")}{(slice != null ? $" ({slice.Name} slice)" : "")} is not a Mach-O file: no Mach-O magic"),
        };
        view = new ByteView(bytes, BigEndian);
        Sha256 = Convert.ToHexStringLower(SHA256.HashData(bytes));
        CpuType = view.U32(4);
        CpuSubType = view.U32(8);
        FileType = view.U32(12);
        HeaderFlags = view.U32(24);
        if (slice != null && (slice.CpuType != CpuType || (slice.CpuSubType & 0x00FFFFFF) != (CpuSubType & 0x00FFFFFF)))
            headerLog.Add($"the fat header says {slice.Name} but the slice's header says {MachONames.CpuName(CpuType, CpuSubType)}");
        ReadCommands();
        BuildLayout();
        headerIssues = headerLog.ToList();
        InitAreas();
    }

    public ImageFormat Format => ImageFormat.MachO;
    public string Path { get; }
    /// <summary>SHA-256 of the image's own bytes (the slice for a universal file).</summary>
    public string Sha256 { get; }
    public long FileSize => data.Length;
    /// <summary>The image's bytes (the slice for a universal file).</summary>
    public ReadOnlyMemory<byte> FileBytes => data;
    /// <summary>All slices of the universal file this image came from; empty for a thin file.</summary>
    public IReadOnlyList<MachOSlice> Slices { get; }
    /// <summary>The slice this image is, or null for a thin file.</summary>
    public MachOSlice? Slice { get; }
    public bool Is64Bit { get; }
    public bool BigEndian { get; }
    public uint CpuType { get; }
    public uint CpuSubType { get; }
    public uint FileType { get; }
    public uint HeaderFlags { get; }
    public NativeArch Arch => MachONames.Arch(CpuType);
    public string MachineName => MachONames.CpuName(CpuType, CpuSubType);
    public string FileTypeName => MachONames.FileType(FileType);
    /// <summary>MH_DYLIB, MH_BUNDLE, MH_DYLIB_STUB.</summary>
    public bool IsDll => FileType is 6 or 8 or 9;

    /// <summary>__TEXT's address (0 for dylibs, 0x100000000 for 64-bit executables).</summary>
    public ulong ImageBase { get; private set; }
    public uint SizeOfImage { get; private set; }

    public IReadOnlyList<MachOLoadCommand> LoadCommands => commands;
    public IReadOnlyList<MachOSegment> Segments => segments;
    public IReadOnlyList<NativeSection> Sections => sections;
    /// <summary>Every section in load command order; n_sect in symbols is the 1-based index into this list.</summary>
    public IReadOnlyList<MachOSection> AllSections { get; private set; } = [];

    public MachOSegment? Segment(string name) => segments.FirstOrDefault(s => s.SegmentName == name);
    public MachOSection? Section(string segment, string section) => AllSections.FirstOrDefault(s => s.SegmentName == segment && s.Name == section);

    /// <summary>The file bytes of a section (empty for zero-fill sections or data outside the file).</summary>
    public ReadOnlyMemory<byte> Bytes(MachOSection section) =>
        section.IsZeroFill || section.Offset >= data.Length ? ReadOnlyMemory<byte>.Empty : data.AsMemory((int)section.Offset, (int)Math.Min(section.Size, (ulong)(data.Length - section.Offset)));

    /// <summary>The file bytes of a segment.</summary>
    public ReadOnlyMemory<byte> Bytes(MachOSegment segment) =>
        segment.FileOffset >= (ulong)data.Length ? ReadOnlyMemory<byte>.Empty : data.AsMemory((int)segment.FileOffset, (int)Math.Min(segment.FileSize, (ulong)data.Length - segment.FileOffset));

    public IReadOnlyList<MachODylibCommand> Dylibs => [.. commands.OfType<MachODylibCommand>().Where(d => d.Kind != MachODylibKind.Id)];
    public string? InstallName => commands.OfType<MachODylibCommand>().FirstOrDefault(d => d.Kind == MachODylibKind.Id)?.Path;
    public IReadOnlyList<string> Rpaths => [.. commands.OfType<MachOStringCommand>().Where(c => c.Command == 0x8000001C).Select(c => c.Value)];
    /// <summary>Dependent libraries in load order (the two-level namespace ordinals count from 1 over this list).</summary>
    public IReadOnlyList<string> Dependencies => [.. Dylibs.Select(d => d.Path)];
    public MachOBuildVersionCommand? BuildVersion => commands.OfType<MachOBuildVersionCommand>().FirstOrDefault();
    /// <summary>LC_UUID as lowercase hex.</summary>
    public string? BuildId => commands.OfType<MachOUuidCommand>().FirstOrDefault() is { } u ? Convert.ToHexStringLower(u.Uuid) : null;

    public uint EntryPointRva
    {
        get
        {
            if (commands.OfType<MachOMainCommand>().FirstOrDefault() is { } main)
                return main.EntryOffset <= long.MaxValue && TryFileOffsetToRva((long)main.EntryOffset, out uint rva) ? rva : 0;
            if (commands.OfType<MachOThreadCommand>().FirstOrDefault(t => t.ProgramCounter != null) is { ProgramCounter: { } pc })
                return TryVaToRva(Arch == NativeArch.Arm ? pc & ~1UL : pc, out uint rva) ? rva : 0;
            return 0;
        }
    }

    /// <summary>File ranges with a nonzero LC_ENCRYPTION_INFO cryptid, as RVAs.</summary>
    public IReadOnlyList<EncryptedRange> EncryptedRanges =>
        [.. commands.OfType<MachOEncryptionCommand>().Where(e => e.CryptId != 0 && TryFileOffsetToRva(e.CryptOffset, out _))
            .Select(e => { TryFileOffsetToRva(e.CryptOffset, out uint rva); return new EncryptedRange(rva, e.CryptSize, e.CryptId); })];

    public IReadOnlyList<RuntimeFunction> RuntimeFunctions => [];
    public IReadOnlyList<uint> TlsCallbackRvas => [];

    public IReadOnlyList<ParseIssue> Issues
    {
        get
        {
            var all = new List<ParseIssue>(headerIssues);
            all.AddRange(symbolArea.Issues);
            all.AddRange(fixupArea.Issues);
            all.AddRange(exportArea.Issues);
            all.AddRange(unwindArea.Issues);
            all.AddRange(signatureArea.Issues);
            return all;
        }
    }

    public bool TryVaToRva(ulong va, out uint rva)
    {
        rva = (uint)(va - ImageBase);
        return va >= ImageBase && va - ImageBase < SizeOfImage;
    }

    private void ReadCommands()
    {
        long at = Is64Bit ? 32 : 28;
        uint ncmds = view.U32(16), sizeofcmds = view.U32(20);
        if (!view.Has(0, at)) headerLog.Add("the Mach-O header is truncated", 0);
        long end = at + sizeofcmds;
        if (end > data.Length)
        {
            headerLog.Add($"sizeofcmds 0x{sizeofcmds:X} extends past the end of the file", 20);
            end = data.Length;
        }
        if (ncmds > MaxCommands)
        {
            headerLog.Add($"{ncmds} load commands; the first {MaxCommands} are read", 16);
            ncmds = MaxCommands;
        }
        var all = new List<MachOSection>();
        for (uint i = 0; i < ncmds; i++)
        {
            if (at + 8 > end)
            {
                headerLog.Add($"load command {i} lies past sizeofcmds; {i} of {ncmds} read", at);
                break;
            }
            uint cmd = view.U32(at), size = view.U32(at + 4);
            if (size < 8 || at + size > end)
            {
                headerLog.Add($"load command {i} ({MachONames.Command(cmd)}) has size {size}, outside the load command area; the rest are not read", at);
                break;
            }
            var c = ReadCommand(cmd, at, size);
            commands.Add(c);
            if (c is MachOSegment seg)
            {
                segments.Add(seg);
                all.AddRange(seg.Sections);
            }
            at += size;
        }
        AllSections = all;
    }

    private MachOLoadCommand ReadCommand(uint cmd, long at, uint size)
    {
        string Str(uint offsetField) => view.U32(at + offsetField) is var o && o >= 8 && o < size
            ? view.CString(at + o, (int)Math.Min(size - o, MaxNameLength)) ?? "" : "";
        switch (cmd)
        {
            case 0x1 or 0x19: return ReadSegment(cmd, at, size);
            case 0xC or 0xD or 0x18 or 0x20 or 0x80000018 or 0x8000001F or 0x80000023:
                var kind = cmd switch { 0xD => MachODylibKind.Id, 0x80000018 => MachODylibKind.Weak, 0x8000001F => MachODylibKind.Reexport, 0x80000023 => MachODylibKind.Upward, 0x20 => MachODylibKind.Lazy, _ => MachODylibKind.Load };
                return new MachODylibCommand(cmd, at, size, kind, Str(8), view.U32(at + 12), view.U32(at + 16), view.U32(at + 20));
            case 0xE or 0xF or 0x27 or 0x8000001C: return new MachOStringCommand(cmd, at, size, Str(8));
            case 0x1B: return new MachOUuidCommand(cmd, at, size, view.Span(at + 8, 16).ToArray());
            case 0x32:
            {
                var tools = new List<(uint, uint)>();
                for (uint t = 0, n = Math.Min(view.U32(at + 20), (size - 24) / 8); t < n; t++) tools.Add((view.U32(at + 24 + t * 8), view.U32(at + 28 + t * 8)));
                return new MachOBuildVersionCommand(cmd, at, size, view.U32(at + 8), view.U32(at + 12), view.U32(at + 16), tools);
            }
            case 0x24 or 0x25 or 0x2F or 0x30:
                uint platform = cmd switch { 0x24 => 1u, 0x25 => 2u, 0x2F => 3u, _ => 4u };
                return new MachOBuildVersionCommand(cmd, at, size, platform, view.U32(at + 8), view.U32(at + 12), []);
            case 0x80000028: return new MachOMainCommand(cmd, at, size, view.U64(at + 8), view.U64(at + 16));
            case 0x4 or 0x5: return ReadThread(cmd, at, size);
            case 0x1D or 0x1E or 0x26 or 0x29 or 0x2B or 0x2E or 0x80000033 or 0x80000034:
                return new MachOLinkEditCommand(cmd, at, size, view.U32(at + 8), view.U32(at + 12));
            case 0x22 or 0x80000022:
                return new MachODyldInfoCommand(cmd, at, size, view.U32(at + 8), view.U32(at + 12), view.U32(at + 16), view.U32(at + 20),
                    view.U32(at + 24), view.U32(at + 28), view.U32(at + 32), view.U32(at + 36), view.U32(at + 40), view.U32(at + 44));
            case 0x2: return new MachOSymtabCommand(cmd, at, size, view.U32(at + 8), view.U32(at + 12), view.U32(at + 16), view.U32(at + 20));
            case 0xB:
                return new MachODysymtabCommand(cmd, at, size, view.U32(at + 8), view.U32(at + 12), view.U32(at + 16), view.U32(at + 20),
                    view.U32(at + 24), view.U32(at + 28), view.U32(at + 56), view.U32(at + 60));
            case 0x21 or 0x2C: return new MachOEncryptionCommand(cmd, at, size, view.U32(at + 8), view.U32(at + 12), view.U32(at + 16));
            case 0x80000035: return new MachOFilesetEntryCommand(cmd, at, size, view.U64(at + 8), view.U64(at + 16), Str(24));
            default: return new MachOLoadCommand(cmd, at, size);
        }
    }

    private MachOSegment ReadSegment(uint cmd, long at, uint size)
    {
        bool wide = cmd == 0x19;
        string name = Fixed(at + 8);
        long p = at + 24;
        ulong vm = view.Word(p, wide), vmSize = view.Word(p + (wide ? 8 : 4), wide), fileOff = view.Word(p + (wide ? 16 : 8), wide), fileSize = view.Word(p + (wide ? 24 : 12), wide);
        p += wide ? 32 : 16;
        uint maxProt = view.U32(p), initProt = view.U32(p + 4), nsects = view.U32(p + 8), flags = view.U32(p + 12);
        p += 16;
        int sectionSize = wide ? 80 : 68;
        long fits = (at + size - p) / sectionSize;
        if (nsects > fits || nsects > MaxSectionsPerSegment)
        {
            headerLog.Add($"segment {name} declares {nsects} sections; {Math.Min(fits, MaxSectionsPerSegment)} fit its command", at);
            nsects = (uint)Math.Min(fits, MaxSectionsPerSegment);
        }
        var list = new List<MachOSection>((int)nsects);
        for (int i = 0; i < nsects; i++, p += sectionSize)
        {
            string sect = Fixed(p), seg = Fixed(p + 16);
            long q = p + 32;
            ulong addr = view.Word(q, wide), sz = view.Word(q + (wide ? 8 : 4), wide);
            q += wide ? 16 : 8;
            list.Add(new MachOSection(seg, sect, addr, sz, view.U32(q), view.U32(q + 4), view.U32(q + 8), view.U32(q + 12), view.U32(q + 16), view.U32(q + 20), view.U32(q + 24)));
        }
        return new MachOSegment(cmd, at, size, name, vm, vmSize, fileOff, fileSize, maxProt, initProt, flags, list);
    }

    private string Fixed(long at)
    {
        var raw = view.Span(at, 16);
        int nul = raw.IndexOf((byte)0);
        return Encoding.UTF8.GetString(nul < 0 ? raw : raw[..nul]);
    }

    /// <summary>The program counter of an ARM64, x86-64, ARM or x86 thread state.</summary>
    private MachOThreadCommand ReadThread(uint cmd, long at, uint size)
    {
        uint flavor = view.U32(at + 8);
        (int Offset, int Width)? pc = (CpuType, flavor) switch
        {
            (MachONames.CpuArm64, 6) => (256, 8),
            (MachONames.CpuX64, 4) => (128, 8),
            (MachONames.CpuArm, 1) => (60, 4),
            (MachONames.CpuX86, 1) => (40, 4),
            _ => null,
        };
        long state = at + 16;
        ulong? value = pc is { } p && state + p.Offset + p.Width <= at + size ? view.Word(state + p.Offset, p.Width == 8) : null;
        return new MachOThreadCommand(cmd, at, size, flavor, value);
    }
}
