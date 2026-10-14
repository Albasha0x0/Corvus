using System.Security.Cryptography;
using Corvus.Core;
using Corvus.Native.Pe;

namespace Corvus.Native;

/// <summary>
/// How a headerless file maps: instruction set, load address and entry. <see cref="Thumb"/> marks ARM code as Thumb
/// throughout (Cortex-M firmware has no A32 state).
/// </summary>
public sealed record RawLayout(NativeArch Arch, bool Thumb, ulong Base, uint EntryOffset)
{
    /// <summary>The arch names load_assembly takes.</summary>
    public static readonly string[] ArchNames = ["x86", "x64", "arm", "thumb", "arm64"];

    public static RawLayout Parse(string? arch, string? baseAddress, string? entry, long fileSize)
    {
        var (a, thumb) = arch?.Trim().ToLowerInvariant() switch
        {
            "x86" or "i386" => (NativeArch.X86, false),
            "x64" or "x86_64" or "amd64" => (NativeArch.X64, false),
            "arm" or "arm32" => (NativeArch.Arm, false),
            "thumb" => (NativeArch.Arm, true),
            "arm64" or "aarch64" => (NativeArch.Arm64, false),
            null or "" => throw new ToolError(ErrorCode.InvalidArgument, "format=raw needs arch.", $"pass arch={string.Join("|", ArchNames)}"),
            _ => throw new ToolError(ErrorCode.InvalidArgument, $"unknown arch '{arch}'.", $"pass arch={string.Join("|", ArchNames)}"),
        };
        ulong load = baseAddress is { Length: > 0 } ? Number(baseAddress, "base") : 0;
        if (load % 0x1000 != 0)
            throw new ToolError(ErrorCode.InvalidArgument, $"base 0x{load:X} is not 4 KiB aligned.", "pass a page-aligned base, e.g. base=0x8000000");
        if (a is NativeArch.X86 or NativeArch.Arm && load + (ulong)fileSize > 0x1_0000_0000)
            throw new ToolError(ErrorCode.InvalidArgument, $"base 0x{load:X} puts a {fileSize}-byte image past the 32-bit address space.", "pass a lower base");
        ulong start = entry is { Length: > 0 } ? Number(entry, "entry") : load;
        // entry is an address at or above base, or an offset into the file below it
        ulong offset = start >= load ? start - load : start;
        if (offset >= (ulong)Math.Max(fileSize, 1))
            throw new ToolError(ErrorCode.InvalidArgument, $"entry 0x{start:X} is outside the {fileSize}-byte image at 0x{load:X}.", "pass an address inside the image or a file offset");
        return new RawLayout(a, thumb, load, (uint)offset);
    }

    /// <summary>The identity of the layout among entries of the same file, e.g. <c>thumb@0x8000000</c>.</summary>
    public string Key => $"{(Thumb ? "thumb" : Arch.ToString().ToLowerInvariant())}@0x{Base:X}";

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
    public bool Is64Bit => Layout.Arch is NativeArch.X64 or NativeArch.Arm64;
    public string MachineName => Layout.Thumb ? "Thumb" : Layout.Arch.ToString();
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
