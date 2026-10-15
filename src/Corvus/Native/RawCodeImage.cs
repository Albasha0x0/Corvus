using System.Security.Cryptography;
using Corvus.Core;
using Corvus.Native.Pe;

namespace Corvus.Native;

/// <summary>
/// An instruction set a headerless file can be read as, with the engines' names for it. <see cref="Thumb"/> marks ARM
/// code as Thumb throughout (Cortex-M firmware has no A32 state). Architectures our index does not decode go to IDA or Ghidra.
/// </summary>
/// <see cref="GhidraLoader"/> names a Ghidra format loader that maps the file itself (DOS MZ); otherwise the bytes load
/// as one block at the base. An empty <see cref="IdaProcessor"/> means IDA is not used.
public sealed record RawArch(string Name, NativeArch Arch, bool Thumb, bool BigEndian, int Bits, string IdaProcessor, string GhidraLanguage,
    string? GhidraLoader = null)
{
    // The engines' processor and language ids, kept in this one table.
    public static readonly IReadOnlyList<RawArch> All =
    [
        new("x86", NativeArch.X86, false, false, 32, "metapc", "x86:LE:32:default"),
        new("x64", NativeArch.X64, false, false, 64, "metapc", "x86:LE:64:default"),
        new("arm", NativeArch.Arm, false, false, 32, "arm", "ARM:LE:32:v8"),
        new("thumb", NativeArch.Arm, true, false, 32, "arm:ARMv7-M", "ARM:LE:32:Cortex"),
        new("arm64", NativeArch.Arm64, false, false, 64, "arm", "AARCH64:LE:64:v8A"),
        new("mips", NativeArch.Mips, false, true, 32, "mipsb", "MIPS:BE:32:default"),
        new("mipsel", NativeArch.Mips, false, false, 32, "mipsl", "MIPS:LE:32:default"),
        new("mips64", NativeArch.Mips, false, true, 64, "mipsb", "MIPS:BE:64:default"),
        new("ppc", NativeArch.PowerPc, false, true, 32, "ppc", "PowerPC:BE:32:default"),
        new("ppc64", NativeArch.PowerPc, false, true, 64, "ppc", "PowerPC:BE:64:default"),
        new("riscv32", NativeArch.RiscV, false, false, 32, "riscv", "RISCV:LE:32:RV32GC"),
        new("riscv64", NativeArch.RiscV, false, false, 64, "riscv", "RISCV:LE:64:RV64GC"),
        new("6502", NativeArch.Other, false, false, 16, "m6502", "6502:LE:16:default"),
        new("x86-16", NativeArch.Other, false, false, 16, "metapc", "x86:LE:16:Real Mode"),
        new("dos-mz", NativeArch.Other, false, false, 16, "", "x86:LE:16:Real Mode", "MzLoader"),
    ];

    private static readonly Dictionary<string, string> Aliases = new(StringComparer.OrdinalIgnoreCase)
    {
        ["i386"] = "x86", ["x86_64"] = "x64", ["amd64"] = "x64", ["arm32"] = "arm", ["aarch64"] = "arm64", ["mipsbe"] = "mips",
        ["mipsle"] = "mipsel", ["powerpc"] = "ppc", ["riscv"] = "riscv64", ["dos-com"] = "x86-16", ["x86_16"] = "x86-16",
    };

    public static RawArch Find(string? name)
    {
        var key = name?.Trim() ?? "";
        if (Aliases.TryGetValue(key, out var alias)) key = alias;
        return All.FirstOrDefault(a => a.Name.Equals(key, StringComparison.OrdinalIgnoreCase))
               ?? throw new ToolError(ErrorCode.InvalidArgument, key.Length == 0 ? "format=raw needs arch." : $"unknown arch '{name}'.",
                   $"pass arch={string.Join("|", All.Select(a => a.Name))}");
    }
}

/// <summary>How a headerless file maps: instruction set, load address and entry (an offset into the file).</summary>
public sealed record RawLayout(RawArch Isa, ulong Base, uint EntryOffset)
{
    public NativeArch Arch => Isa.Arch;
    public bool Thumb => Isa.Thumb;

    /// <summary><paramref name="head"/>: the file's first bytes; a Thumb image starting with a Cortex-M vector table enters at its reset handler.</summary>
    public static RawLayout Parse(string? arch, string? baseAddress, string? entry, long fileSize, ReadOnlySpan<byte> head = default)
    {
        var isa = RawArch.Find(arch);
        ulong load = baseAddress is { Length: > 0 } ? Number(baseAddress, "base") : 0;
        // 16-bit code loads at a paragraph (a DOS .COM at 0x100)
        if (isa.Bits == 16 && load % 16 != 0)
            throw new ToolError(ErrorCode.InvalidArgument, $"base 0x{load:X} is not a paragraph (16-byte) boundary.", "pass a base that is a multiple of 0x10, e.g. base=0x100");
        if (isa.Bits > 16 && load % 0x1000 != 0)
            throw new ToolError(ErrorCode.InvalidArgument, $"base 0x{load:X} is not 4 KiB aligned.", "pass a page-aligned base, e.g. base=0x8000000");
        if (isa.Bits < 64 && load + (ulong)fileSize > 1UL << isa.Bits)
            throw new ToolError(ErrorCode.InvalidArgument, $"base 0x{load:X} puts a {fileSize}-byte image past the {isa.Bits}-bit address space.", "pass a lower base");
        ulong start = entry is { Length: > 0 } ? Number(entry, "entry") : ResetVector(isa, load, fileSize, head) ?? load;
        // entry is an address at or above base, or an offset into the file below it
        ulong offset = start >= load ? start - load : start;
        if (offset >= (ulong)Math.Max(fileSize, 1))
            throw new ToolError(ErrorCode.InvalidArgument, $"entry 0x{start:X} is outside the {fileSize}-byte image at 0x{load:X}.", "pass an address inside the image or a file offset");
        return new RawLayout(isa, load, (uint)offset);
    }

    /// <summary>
    /// The reset handler of a Cortex-M vector table at the start of a Thumb image: word 0 a word-aligned initial stack
    /// pointer outside the image, word 1 an odd (Thumb) address inside it past the table's first two words; else null.
    /// </summary>
    private static ulong? ResetVector(RawArch isa, ulong load, long fileSize, ReadOnlySpan<byte> head)
    {
        if (!isa.Thumb || isa.BigEndian || head.Length < 8) return null;
        uint sp = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(head);
        uint reset = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(head[4..]);
        ulong target = reset & ~1u;
        bool spOutside = sp != 0 && (sp & 3) == 0 && (sp < load || sp - load > (ulong)fileSize);
        return spOutside && (reset & 1) == 1 && target >= load + 8 && target - load < (ulong)fileSize ? target : null;
    }

    /// <summary>The identity of the layout among entries of the same file, e.g. <c>thumb@0x8000000</c>.</summary>
    public string Key => $"{Isa.Name}@0x{Base:X}";

    private static ulong Number(string text, string name)
    {
        var s = text.Trim();
        bool hex = s.StartsWith("0x", StringComparison.OrdinalIgnoreCase);
        if (ulong.TryParse(hex ? s[2..] : s, hex ? System.Globalization.NumberStyles.HexNumber : System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture, out var value)) return value;
        throw new ToolError(ErrorCode.InvalidArgument, $"{name} '{text}' is not a number.", $"pass {name} as decimal or 0x hex");
    }
}

/// <summary>A headerless file (shellcode, firmware, a memory region) mapped as one executable section at a chosen base.</summary>
public sealed class RawCodeImage : INativeImage
{
    private readonly byte[] _data;

    public RawLayout Layout { get; }
    public ReadOnlyMemory<byte> FileBytes => _data;
    public ImageFormat Format => ImageFormat.Raw;
    public string Path { get; }
    public string Sha256 { get; }
    public NativeArch Arch => Layout.Arch;
    public bool Is64Bit => Layout.Isa.Bits == 64;
    public string MachineName => Layout.Isa.Name;
    public long FileSize => _data.Length;
    public bool IsDll => false;
    public ulong ImageBase => Layout.Base;
    public uint EntryPointRva => Layout.EntryOffset;
    public uint SizeOfImage { get; }
    public IReadOnlyList<NativeSection> Sections { get; }
    public IReadOnlyList<NativeImport> Imports => [];
    public IReadOnlyList<NativeExport> Exports => [];
    public IReadOnlyList<RuntimeFunction> RuntimeFunctions => [];
    public IReadOnlyList<uint> RelocationRvas => [];
    public IReadOnlyList<uint> TlsCallbackRvas => [];
    public IReadOnlyList<ParseIssue> Issues => [];
    /// <summary>The entry, also at offset 0 (where <see cref="EntryPointRva"/> alone reads as "none").</summary>
    public IReadOnlyList<DeclaredFunction> DeclaredFunctions { get; }

    public static RawCodeImage Open(string path, RawLayout layout)
    {
        var full = InputFiles.RequireRegularFile(path, "image file");
        var info = new FileInfo(full);
        if (info.Length > PeLimits.MaxFileSize)
            throw new ToolError(ErrorCode.LimitExceeded, $"{path} is {info.Length} bytes; native images up to {PeLimits.MaxFileSize} bytes are read");
        byte[] bytes;
        try { bytes = File.ReadAllBytes(full); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new ToolError(ErrorCode.IoError, $"cannot read {path}: {ex.Message}");
        }
        return new RawCodeImage(bytes, full, layout);
    }

    public RawCodeImage(byte[] bytes, string path, RawLayout layout)
    {
        if (bytes.Length == 0) throw new ToolError(ErrorCode.MalformedInput, $"{path} is empty.");
        _data = bytes;
        Path = path;
        Layout = layout;
        Sha256 = Convert.ToHexStringLower(SHA256.HashData(bytes));
        SizeOfImage = (uint)((bytes.Length + 0xFFFL) & ~0xFFFL);
        Sections = [new NativeSection("raw", 0, (uint)bytes.Length, 0, (uint)bytes.Length,
            SectionAccess.Read | SectionAccess.Write | SectionAccess.Execute | SectionAccess.Code, 0)];
        DeclaredFunctions = [new DeclaredFunction(layout.EntryOffset, null, DeclaredSource.Symbol)];
    }

    public int Read(uint rva, Span<byte> destination)
    {
        if (rva >= _data.Length) return 0;
        int n = Math.Min(destination.Length, _data.Length - (int)rva);
        _data.AsSpan((int)rva, n).CopyTo(destination);
        return n;
    }

    public bool TryRvaToFileOffset(uint rva, out long fileOffset)
    {
        fileOffset = rva;
        return rva < _data.Length;
    }

    public bool TryFileOffsetToRva(long fileOffset, out uint rva)
    {
        rva = (uint)fileOffset;
        return fileOffset >= 0 && fileOffset < _data.Length;
    }

    public NativeSection? SectionAt(uint rva) => rva < _data.Length ? Sections[0] : null;
}
