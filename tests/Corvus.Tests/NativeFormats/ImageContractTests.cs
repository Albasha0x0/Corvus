using System.Reflection.PortableExecutable;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Pe;

namespace Corvus.Tests.NativeFormats;

/// <summary>The format-neutral image contract: format detection, PE members of the new contract, and the pe_only guard.</summary>
public sealed class ImageContractTests
{
    [Fact]
    public void Detect_RecognizesEveryContainer()
    {
        Assert.Equal(NativeFileKind.Pe, NativeImageLoader.Detect("MZ\x90\0"u8));
        Assert.Equal(NativeFileKind.Elf, NativeImageLoader.Detect([0x7F, (byte)'E', (byte)'L', (byte)'F', 2, 1]));
        Assert.Equal(NativeFileKind.MachO, NativeImageLoader.Detect([0xCF, 0xFA, 0xED, 0xFE]));
        Assert.Equal(NativeFileKind.MachO, NativeImageLoader.Detect([0xFE, 0xED, 0xFA, 0xCE]));
        Assert.Equal(NativeFileKind.MachOFat, NativeImageLoader.Detect([0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 2, 1, 0, 0, 12]));
        // A Java class file shares 0xCAFEBABE: version 52 reads as 52 slices, but the "CPU type" is no Mach-O one.
        Assert.Equal(NativeFileKind.Unknown, NativeImageLoader.Detect([0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 52, 0, 0x2A, 0x0A, 0]));
        Assert.Equal(NativeFileKind.Unknown, NativeImageLoader.Detect("ab"u8));
    }

    [Fact]
    public void Open_ReadsEveryFormat()
    {
        Assert.Equal(ImageFormat.Elf, NativeImageLoader.Open(NativeFixtures.LinuxArm64DbgShim).Format);
        Assert.Equal(ImageFormat.MachO, NativeImageLoader.Open(NativeFixtures.OsxFatSkia).Format);
        Assert.Equal(ImageFormat.Pe, NativeImageLoader.Open(NativeFixtures.WinArm64DbgShim).Format);
        Assert.Equal(ErrorCode.InvalidArgument, Assert.Throws<ToolError>(() => NativeImageLoader.Open(NativeFixtures.WinArm64DbgShim, "arm64")).Code);
        using var ws = new AssemblyWorkspace(new ServerOptions());
        Assert.Equal(ImageFormat.Elf, ws.LoadAny(NativeFixtures.LinuxArm64DbgShim).Native!.Image.Format);
        Assert.Equal(ErrorCode.InvalidArgument, Assert.Throws<ToolError>(() => ws.LoadAny(NativeFixtures.WinArm64DbgShim, "arm64")).Code);
    }

    [Fact]
    public void PeFile_FillsTheFormatNeutralMembers()
    {
        var pe = PeFile.Open(NativeFixtures.WinArm64DbgShim);
        INativeImage image = pe;
        Assert.Equal(ImageFormat.Pe, image.Format);
        Assert.Equal(NativeArch.Arm64, image.Arch);
        Assert.Equal(pe.ImportModules.Select(m => m.Name).Distinct(StringComparer.OrdinalIgnoreCase), image.Dependencies);
        Assert.Equal(new FileInfo(NativeFixtures.WinArm64DbgShim).Length, image.FileSize);
        Assert.Empty(image.Symbols);
        Assert.Empty(image.EncryptedRanges);

        using var reader = new PEReader(File.OpenRead(Env.FixturePath));
        var cv = reader.ReadCodeViewDebugDirectoryData(reader.ReadDebugDirectory().First(d => d.Type == DebugDirectoryEntryType.CodeView));
        Assert.Equal(cv.Guid.ToString("N") + cv.Age.ToString("x"), PeFile.Open(Env.FixturePath).BuildId);
    }

    [Fact]
    public void RequirePe_RefusesOtherFormatsWithReason()
    {
        var elf = new FormatImage(PeFile.FromBytes(NativePeTests.KitchenSink(true), "lib.so"), ImageFormat.Elf);
        var native = new LoadedNative("lib.so", "lib.so", elf);
        Assert.Null(native.Pe);
        var e = Assert.Throws<ToolError>(() => native.RequirePe("get_pe_info"));
        Assert.Equal(ErrorCode.Unsupported, e.Code);
        Assert.Contains("\"reason\":\"pe_only\"", e.ToJson());
        Assert.Contains("an ELF image", e.Message);
        Assert.Throws<ToolError>(() => native.Patches);
    }

    /// <summary>An image that reports another format; every other member is the inner image's.</summary>
    private sealed class FormatImage(INativeImage inner, ImageFormat format) : INativeImage
    {
        public ImageFormat Format => format;
        public string Path => inner.Path;
        public string Sha256 => inner.Sha256;
        public NativeArch Arch => inner.Arch;
        public bool Is64Bit => inner.Is64Bit;
        public bool IsDll => inner.IsDll;
        public ulong ImageBase => inner.ImageBase;
        public uint EntryPointRva => inner.EntryPointRva;
        public uint SizeOfImage => inner.SizeOfImage;
        public IReadOnlyList<NativeSection> Sections => inner.Sections;
        public IReadOnlyList<NativeImport> Imports => inner.Imports;
        public IReadOnlyList<NativeExport> Exports => inner.Exports;
        public IReadOnlyList<RuntimeFunction> RuntimeFunctions => inner.RuntimeFunctions;
        public IReadOnlyList<uint> RelocationRvas => inner.RelocationRvas;
        public IReadOnlyList<uint> TlsCallbackRvas => inner.TlsCallbackRvas;
        public IReadOnlyList<ParseIssue> Issues => inner.Issues;
        public int Read(uint rva, Span<byte> destination) => inner.Read(rva, destination);
        public bool TryRvaToFileOffset(uint rva, out long fileOffset) => inner.TryRvaToFileOffset(rva, out fileOffset);
        public bool TryFileOffsetToRva(long fileOffset, out uint rva) => inner.TryFileOffsetToRva(fileOffset, out rva);
        public NativeSection? SectionAt(uint rva) => inner.SectionAt(rva);
    }

    /// <summary>Opening by content on damaged images of every format: an image, or a malformed-input refusal.</summary>
    [Fact]
    [FuzzEntry(typeof(NativeImageLoader))]
    public void Fuzzed_images_of_every_format_open_or_are_refused()
    {
        var seeds = new List<byte[]> { NativePeTests.KitchenSink(true), FormatWriterTests.SampleElf().Build(), FormatWriterTests.SampleMachO().Build(), WasmTests.Sample() };
        var failures = FormatFuzz.Run(seeds, 200, 20261015, b => FormatFuzz.Touch(NativeImageLoader.FromBytes(b, "fuzz.bin"), _ => { }));
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(5)));
    }
}
