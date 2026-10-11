using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Elf;
using NetDecompilerMcp.Services;
using NetDecompilerMcp.Tests.NativeFormats;
using Xunit.Abstractions;

namespace NetDecompilerMcp.Tests;

/// <summary>
/// Il2Cpp builds for Android, iOS, macOS and Linux: the binary layout the reader uses on ELF and Mach-O (code and data
/// areas, Thumb pointers, memory images, encrypted and universal binaries) on real runtime libraries and synthetic images.
/// </summary>
public sealed class Il2CppMobileTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    [Fact]
    public void ElfLayoutHasCodeAndDataAreasAndFileOffsets()
    {
        var bytes = File.ReadAllBytes(NativeFixtures.LinuxArm64DbgShim);
        var opened = Il2CppBinaryLayout.Open(bytes, "libdbgshim.so");
        var layout = opened.Layout;
        Assert.False(opened.MemoryImage);
        Assert.Equal((ImageFormat.Elf, NativeArch.Arm64, true, 0UL), (layout.Format, layout.Arch, layout.Is64, layout.ImageBase));
        Assert.False(layout.ThumbPointers);
        var text = Assert.Single(layout.Areas, a => a.Name == ".text");
        Assert.True(text.Executable && !text.InitializedData);
        Assert.True(layout.InCode(layout.ImageBase + text.Rva + 4));
        Assert.Contains(layout.Areas, a => a.Name.StartsWith(".data", StringComparison.Ordinal) && a.InitializedData);
        Assert.DoesNotContain(layout.Areas, a => (a.Name.StartsWith(".rela", StringComparison.Ordinal) || a.Name == ".dynsym") && a.InitializedData);
        var image = ElfFile.FromBytes(bytes);
        Assert.True(image.TryRvaToFileOffset(text.Rva + 8, out var offset));
        Assert.Equal((ulong)offset, layout.FileOffset(text.Rva + 8));
        Assert.Equal(image.BuildId, layout.BuildId);
    }

    [Fact]
    public void Arm32CodePointersLoseTheThumbBit()
    {
        var layout = Il2CppBinaryLayout.Open(File.ReadAllBytes(NativeFixtures.LinuxArmDbgShim), "libdbgshim.so").Layout;
        Assert.True(layout.ThumbPointers);
        var text = Assert.Single(layout.Areas, a => a.Name == ".text");
        ulong thumb = layout.ImageBase + text.Rva + 0x11;
        Assert.Equal(text.Rva + 0x10, layout.CodeRva(thumb));
        Assert.Equal(text.Rva + 0x11, layout.Rva(thumb)); // data pointers keep every bit
    }

    [Fact]
    public void ElfMemoryImageIsReadAtItsAddresses()
    {
        var file = File.ReadAllBytes(NativeFixtures.LinuxArm64DbgShim);
        var image = ElfFile.FromBytes(file);
        // The loaded-library layout: every PT_LOAD at its address, the file as long as the image.
        var dump = new byte[image.SizeOfImage];
        foreach (var s in image.LoadSegments)
            file.AsSpan((int)s.Offset, (int)s.FileSize).CopyTo(dump.AsSpan((int)(s.VirtualAddress - image.ImageBase)));
        var opened = Il2CppBinaryLayout.Open(dump, "libdbgshim.so");
        Assert.True(opened.MemoryImage);
        Assert.Contains("memory image", opened.Note);
        var text = Assert.Single(opened.Layout.Areas, a => a.Executable);
        Assert.True(image.TryRvaToFileOffset(text.Rva + 0x20, out var built));
        Assert.Equal((ulong)built, opened.Layout.FileOffset(text.Rva + 0x20)); // offsets in the file as built
        // The bytes handed to the library describe the image at its addresses and no longer name the file's sections.
        var normalized = ElfFile.FromBytes(opened.Bytes);
        Assert.All(normalized.LoadSegments, s => Assert.Equal(s.VirtualAddress - normalized.ImageBase, s.Offset));
        Assert.Empty(normalized.SectionHeaders);
        var expected = new byte[64];
        var actual = new byte[64];
        image.Read(text.Rva, expected);
        normalized.Read(text.Rva, actual);
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void MachOLayoutRefusesEncryptedCodeAndReadsTheChosenSlice()
    {
        var w = new MachOWriter { Encryption = (MachOWriter.TextOffset, 0x2000, 1) };
        var error = Assert.Throws<ToolError>(() => Il2CppBinaryLayout.Open(w.Build(), "UnityFramework"));
        Assert.Equal(ErrorCode.Unsupported, error.Code);
        Assert.Contains("encrypted_fairplay", error.Message);
        Assert.Contains("decrypted", error.Remediation);

        w.Encryption = null;
        var thin = w.Build();
        var fat = MachOWriter.Fat([(MachOWriter.CpuX64, 3, new MachOWriter { CpuType = MachOWriter.CpuX64 }.Build()), (MachOWriter.CpuArm64, 0, thin)]);
        var opened = Il2CppBinaryLayout.Open(fat, "GameAssembly.dylib", "arm64");
        Assert.Equal(thin, opened.Bytes);
        Assert.Equal((ImageFormat.MachO, NativeArch.Arm64), (opened.Layout.Format, opened.Layout.Arch));
        Assert.Contains("slice arm64", opened.Note);
        Assert.Contains(opened.Layout.Areas, a => a.Name.StartsWith("__TEXT", StringComparison.Ordinal) && a.Executable);
        Assert.All(opened.Layout.Areas.Where(a => a.InitializedData), a => Assert.StartsWith("__DATA", a.Name, StringComparison.Ordinal));

        var other = Assert.Throws<ToolError>(() => Il2CppBinaryLayout.Open([0xCA, 0xFE, 0xD0, 0x0D, 0, 0, 0, 0], "x.bin"));
        Assert.Contains("binary_format_unsupported", other.Message);
    }

    [Fact]
    public void MetadataVersionsUpToUnity6AreAccepted()
    {
        foreach (var version in new[] { 24, 31, 39 })
        {
            var path = _dir.File($"v{version}.dat");
            var bytes = new byte[0x100];
            BitConverter.TryWriteBytes(bytes.AsSpan(0), 0xFAB11BAF);
            BitConverter.TryWriteBytes(bytes.AsSpan(4), version);
            File.WriteAllBytes(path, bytes);
            Assert.Equal(version, Il2CppMetadataReader.CheckHeader(path));
        }
        output.WriteLine($"versions {Il2CppMetadataReader.MinVersion}-{Il2CppMetadataReader.MaxVersion}");
    }
}
