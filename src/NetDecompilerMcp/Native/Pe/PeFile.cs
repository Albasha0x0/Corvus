using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Native.Pe;

/// <summary>
/// A PE32 / PE32+ image parsed from an in-memory snapshot of the file. Construction throws only when the file is not a
/// PE at all (no MZ or PE signature); anything else that cannot be read is reported in <see cref="Issues"/> and the rest
/// is still returned. Headers and sections are read on construction, directories on first use; every area is bounded
/// by <see cref="PeLimits"/>. Thread-safe for reading.
/// </summary>
public sealed partial class PeFile : INativeImage
{
    private const uint PageSize = 0x1000;
    private const ushort MagicPe32 = 0x10b;
    private const ushort MagicPe32Plus = 0x20b;

    private readonly byte[] data;
    private readonly IssueLog headerLog = new("headers");
    private readonly IReadOnlyList<ParseIssue> headerIssues;
    private readonly List<NativeSection> sections = [];
    private readonly List<PeSectionLayout> layouts = [];
    private readonly PeDataDirectory[] directories;

    public static PeFile Open(string path)
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
        return new PeFile(bytes, info.FullName);
    }

    /// <summary>Parses a copy of <paramref name="bytes"/>; <paramref name="path"/> is only reported back.</summary>
    public static PeFile FromBytes(ReadOnlySpan<byte> bytes, string path = "")
    {
        if (bytes.Length > PeLimits.MaxFileSize)
            throw new ToolError(ErrorCode.LimitExceeded, $"image is {bytes.Length} bytes; native images up to {PeLimits.MaxFileSize} bytes are read");
        return new PeFile(bytes.ToArray(), path);
    }

    private static ToolError NotPe(string path, string why) =>
        new(ErrorCode.MalformedInput, $"{(path.Length > 0 ? path : "the image")} is not a PE file: {why}");

    private PeFile(byte[] bytes, string path)
    {
        data = bytes;
        Path = path;
        if (bytes.Length < 2 || bytes[0] != 'M' || bytes[1] != 'Z') throw NotPe(path, "no MZ signature");
        if (bytes.Length < 0x40) throw NotPe(path, "the DOS header is truncated");
        uint lfanew = U32(0x3C);
        if (lfanew > bytes.Length - 4 || U32(lfanew) != 0x00004550)
            throw NotPe(path, "no PE signature at e_lfanew (a DOS program or a damaged header)");
        PeHeaderOffset = lfanew;
        Sha256 = Convert.ToHexStringLower(SHA256.HashData(bytes));

        directories = ReadHeaders();
        ReadSectionTable();
        BuildLayout();
        uint entry = Optional.AddressOfEntryPoint;
        if (entry != 0 && Locate(entry) < 0)
            headerLog.Add($"entry point 0x{entry:X} is outside the mapped image");
        headerIssues = headerLog.ToList();
        InitAreas();
    }

    public string Path { get; }
    public string Sha256 { get; }
    /// <summary>Length of the file snapshot.</summary>
    public long FileSize => data.Length;
    /// <summary>The file snapshot.</summary>
    public ReadOnlyMemory<byte> FileBytes => data;
    /// <summary>e_lfanew: file offset of the "PE\0\0" signature.</summary>
    public uint PeHeaderOffset { get; }
    public PeCoffHeader Coff { get; private set; } = null!;
    public PeOptionalHeader Optional { get; private set; } = null!;
    /// <summary>File offset of the optional header.</summary>
    public long OptionalHeaderOffset => PeHeaderOffset + 24L;
    /// <summary>File offset of the first section header.</summary>
    public long SectionTableOffset => OptionalHeaderOffset + Coff.SizeOfOptionalHeader;
    /// <summary>The first min(NumberOfRvaAndSizes, 16) data directories.</summary>
    public IReadOnlyList<PeDataDirectory> DataDirectories => directories;

    public NativeArch Arch => PeNames.Arch(Coff.Machine);
    public string MachineName => PeNames.Machine(Coff.Machine);
    public bool Is64Bit { get; private set; }
    public bool IsDll => (Coff.Characteristics & 0x2000) != 0;
    public bool IsDotNet => Directory(PeDirectory.ClrRuntimeHeader).Rva != 0;
    public ulong ImageBase => Optional.ImageBase;
    public uint EntryPointRva => Optional.AddressOfEntryPoint;
    public uint SizeOfImage => Optional.SizeOfImage;
    public string SubsystemName => PeNames.Subsystem(Optional.Subsystem);
    public IReadOnlyList<string> CharacteristicNames => PeNames.FileCharacteristics(Coff.Characteristics);
    public IReadOnlyList<string> DllCharacteristicNames => PeNames.DllCharacteristics(Optional.DllCharacteristics);

    public IReadOnlyList<NativeSection> Sections => sections;
    /// <summary>Loader view of each section, in section table order.</summary>
    public IReadOnlyList<PeSectionLayout> SectionLayouts => layouts;

    /// <summary>Header issues, then every directory's issues (parses all directories on first use).</summary>
    public IReadOnlyList<ParseIssue> Issues
    {
        get
        {
            var all = new List<ParseIssue>(headerIssues);
            foreach (var area in AllAreas()) all.AddRange(area.Issues);
            return all;
        }
    }

    /// <summary>Directory entry <paramref name="index"/>, or an empty one when the header has fewer.</summary>
    public PeDataDirectory Directory(int index) =>
        index >= 0 && index < directories.Length ? directories[index] : new PeDataDirectory(index, PeDirectory.Name(index), 0, 0);

    public bool TryVaToRva(ulong va, out uint rva)
    {
        ulong delta = va - ImageBase;
        rva = (uint)delta;
        return va >= ImageBase && delta <= uint.MaxValue;
    }

    public PeMitigations Mitigations
    {
        get
        {
            ushort dll = Optional.DllCharacteristics;
            var lc = LoadConfig;
            uint guard = lc?.GuardFlags ?? 0;
            bool aslr = (dll & 0x0040) != 0 && (Coff.Characteristics & 0x0001) == 0;
            return new PeMitigations(
                Aslr: aslr,
                HighEntropyVa: aslr && Is64Bit && (dll & 0x0020) != 0,
                Dep: (dll & 0x0100) != 0 || Is64Bit,
                ControlFlowGuard: (dll & 0x4000) != 0 && (guard & 0x100) != 0,
                SafeSeh: Arch == NativeArch.X86 && lc is { SeHandlerTable: not 0 },
                NoSeh: (dll & 0x0400) != 0,
                GsCookie: lc is { SecurityCookie: not 0 },
                ForceIntegrity: (dll & 0x0080) != 0,
                AppContainer: (dll & 0x1000) != 0,
                CetCompatible: (ExDllCharacteristics & 0x1) != 0,
                Xfg: (guard & 0x00800000) != 0,
                EhContinuation: (guard & 0x00400000) != 0);
        }
    }

    /// <summary>Authenticode signature of the file (security directory).</summary>
    public CertificateInfo Certificate => certificate.Value;

    private PeDataDirectory[] ReadHeaders()
    {
        long coff = PeHeaderOffset + 4L;
        if (coff + 20 > data.Length) headerLog.Add("the COFF file header is truncated", coff);
        Coff = new PeCoffHeader(U16(coff), U16(coff + 2), U32(coff + 4), U32(coff + 8), U32(coff + 12), U16(coff + 16), U16(coff + 18));

        long opt = coff + 20;
        ushort magic = U16(opt);
        bool is64;
        if (magic == MagicPe32Plus) is64 = true;
        else if (magic == MagicPe32) is64 = false;
        else
        {
            is64 = Coff.Machine is 0x8664 or 0xaa64 or 0xa641 or 0xa64e or 0x0200 or 0x5064;
            headerLog.Add($"unknown optional header magic 0x{magic:X4}; read as {(is64 ? "PE32+" : "PE32")} from the machine type", opt);
        }
        Is64Bit = is64;
        int fixedSize = is64 ? 112 : 96;
        if (Coff.SizeOfOptionalHeader < fixedSize)
            headerLog.Add($"SizeOfOptionalHeader {Coff.SizeOfOptionalHeader} is below the {fixedSize} bytes of fixed fields; they are read at their usual offsets", coff + 16);
        if (opt + fixedSize > data.Length) headerLog.Add("the optional header is truncated", opt);

        Optional = is64
            ? new PeOptionalHeader(magic, U8(opt + 2), U8(opt + 3), U32(opt + 4), U32(opt + 8), U32(opt + 12), U32(opt + 16), U32(opt + 20), 0,
                U64(opt + 24), U32(opt + 32), U32(opt + 36), U16(opt + 40), U16(opt + 42), U16(opt + 44), U16(opt + 46), U16(opt + 48), U16(opt + 50),
                U32(opt + 52), U32(opt + 56), U32(opt + 60), U32(opt + 64), U16(opt + 68), U16(opt + 70),
                U64(opt + 72), U64(opt + 80), U64(opt + 88), U64(opt + 96), U32(opt + 104), U32(opt + 108))
            : new PeOptionalHeader(magic, U8(opt + 2), U8(opt + 3), U32(opt + 4), U32(opt + 8), U32(opt + 12), U32(opt + 16), U32(opt + 20), U32(opt + 24),
                U32(opt + 28), U32(opt + 32), U32(opt + 36), U16(opt + 40), U16(opt + 42), U16(opt + 44), U16(opt + 46), U16(opt + 48), U16(opt + 50),
                U32(opt + 52), U32(opt + 56), U32(opt + 60), U32(opt + 64), U16(opt + 68), U16(opt + 70),
                U32(opt + 72), U32(opt + 76), U32(opt + 80), U32(opt + 84), U32(opt + 88), U32(opt + 92));

        uint declared = Optional.NumberOfRvaAndSizes;
        int count = (int)Math.Min(declared, 16u);
        if (declared > 16) headerLog.Add($"NumberOfRvaAndSizes is {declared}; the loader reads 16", opt + fixedSize - 4);
        long dirs = opt + fixedSize;
        if (dirs + count * 8L > opt + Coff.SizeOfOptionalHeader)
            headerLog.Add("data directories extend past SizeOfOptionalHeader into the section table", dirs);
        if (dirs + count * 8L > data.Length)
        {
            headerLog.Add("data directories extend past the end of the file", dirs);
            count = (int)Math.Max(0, (data.Length - dirs) / 8);
        }
        var result = new PeDataDirectory[count];
        for (int i = 0; i < count; i++)
            result[i] = new PeDataDirectory(i, PeDirectory.Name(i), U32(dirs + i * 8), U32(dirs + i * 8 + 4));
        return result;
    }

    private void ReadSectionTable()
    {
        long table = SectionTableOffset;
        int count = Coff.NumberOfSections;
        if (count > PeLimits.MaxSections)
        {
            headerLog.Add($"{count} sections declared; the first {PeLimits.MaxSections} are read", PeHeaderOffset + 6);
            count = PeLimits.MaxSections;
        }
        for (int i = 0; i < count; i++)
        {
            long at = table + i * 40L;
            if (at + 40 > data.Length)
            {
                headerLog.Add($"the section table extends past the end of the file; {i} of {Coff.NumberOfSections} section headers read", at);
                break;
            }
            uint characteristics = U32(at + 36);
            var access = SectionAccess.None;
            if ((characteristics & 0x40000000) != 0) access |= SectionAccess.Read;
            if ((characteristics & 0x80000000) != 0) access |= SectionAccess.Write;
            if ((characteristics & 0x20000000) != 0) access |= SectionAccess.Execute;
            if ((characteristics & 0x00000020) != 0) access |= SectionAccess.Code;
            sections.Add(new NativeSection(SectionName(at), U32(at + 12), U32(at + 8), U32(at + 20), U32(at + 16), access, characteristics));
        }
    }

    /// <summary>Section name: up to 8 bytes, or "/n" naming an offset into the COFF string table (MinGW long names).</summary>
    private string SectionName(long at)
    {
        var raw = data.AsSpan((int)at, 8);
        int len = raw.IndexOf((byte)0);
        var name = Encoding.UTF8.GetString(raw[..(len < 0 ? 8 : len)]);
        if (name.Length > 1 && name[0] == '/' && Coff.PointerToSymbolTable != 0 && uint.TryParse(name.AsSpan(1), out uint offset))
        {
            long strings = Coff.PointerToSymbolTable + Coff.NumberOfSymbols * 18L;
            long start = strings + offset;
            if (offset >= 4 && start < data.Length)
            {
                var rest = data.AsSpan((int)start, (int)Math.Min(data.Length - start, PeLimits.MaxNameLength));
                int end = rest.IndexOf((byte)0);
                if (end > 0) return Encoding.UTF8.GetString(rest[..end]);
            }
        }
        return name;
    }

    private byte U8(long offset) => offset >= 0 && offset < data.Length ? data[offset] : (byte)0;

    private ushort U16(long offset) =>
        offset >= 0 && offset <= data.Length - 2 ? BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan((int)offset)) : (ushort)0;

    private uint U32(long offset) =>
        offset >= 0 && offset <= data.Length - 4 ? BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan((int)offset)) : 0;

    private ulong U64(long offset) =>
        offset >= 0 && offset <= data.Length - 8 ? BinaryPrimitives.ReadUInt64LittleEndian(data.AsSpan((int)offset)) : 0;
}
