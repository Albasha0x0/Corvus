using System.Buffers.Binary;
using System.Text;
using Corvus.Native;
using Corvus.Native.Elf;
using Corvus.Native.Go;
using Corvus.Core;
using Corvus.Services.Analysis;

namespace Corvus.Tests.NativeFormats;

public sealed class GoBuildInfoTests
{
    private static readonly byte[] Start = Convert.FromHexString("3077af0c9274080241e1c107e6d618e6");
    private static readonly byte[] End = Convert.FromHexString("f932433186182072008242104116d8f2");

    private const string ModInfo =
        "path\texample.com/tool/cmd/tool\n" +
        "mod\texample.com/tool\tv1.4.2\th1:mainsum=\n" +
        "dep\tgolang.org/x/sys\tv0.20.0\th1:syssum=\n" +
        "dep\texample.com/old\tv1.0.0\n" +
        "=>\texample.com/fork\tv1.0.1\th1:forksum=\n" +
        "build\t-ldflags=\"-s -w -X main.version=1.4.2\"\n" +
        "build\tCGO_ENABLED=0\n" +
        "build\tGOARCH=amd64\n" +
        "build\tGOOS=linux\n" +
        "build\tvcs.revision=0123abcd\n" +
        "build\tvcs.modified=true\n";

    private static byte[] Wrapped() => [.. Start, .. Encoding.UTF8.GetBytes(ModInfo), .. End];

    private static byte[] Header(byte flags, int ptr)
    {
        var h = new byte[32];
        h[0] = 0xFF;
        Encoding.ASCII.GetBytes(" Go buildinf:").CopyTo(h, 1);
        h[14] = (byte)ptr;
        h[15] = flags;
        return h;
    }

    /// <summary>Go 1.18+: varint-prefixed strings after the header.</summary>
    internal static byte[] Inline(string version = "go1.22.5")
    {
        var s = new MemoryStream();
        s.Write(Header(2, 8));
        void Str(byte[] b)
        {
            for (ulong v = (ulong)b.Length; ; v >>= 7) { s.WriteByte((byte)(v < 0x80 ? v : (v & 0x7F) | 0x80)); if (v < 0x80) break; }
            s.Write(b);
        }
        Str(Encoding.UTF8.GetBytes(version));
        Str(Wrapped());
        return s.ToArray();
    }

    /// <summary>Go 1.13 to 1.17: pointers to Go string headers; <paramref name="va"/> is where the blob is mapped.</summary>
    private static byte[] Pointers(ulong va, int ptr)
    {
        var version = Encoding.UTF8.GetBytes("go1.16.15");
        var mod = Wrapped();
        var b = new byte[0x40 + version.Length + mod.Length];
        Header(0, ptr).CopyTo(b, 0);
        void P(int at, ulong v) { if (ptr == 8) BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(at), v); else BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(at), (uint)v); }
        // String headers at 0x20 and 0x30, bytes after them.
        P(16, va + 0x20);
        P(16 + ptr, va + 0x30);
        P(0x20, va + 0x40); P(0x20 + ptr, (ulong)version.Length);
        P(0x30, va + 0x40 + (ulong)version.Length); P(0x30 + ptr, (ulong)mod.Length);
        version.CopyTo(b, 0x40);
        mod.CopyTo(b, 0x40 + version.Length);
        return b;
    }

    private static ElfFile Elf(byte[] data, bool is64 = true, string section = ".go.buildinfo") => ElfFile.FromBytes(new ElfWriter
    {
        Machine = is64 ? ElfWriter.EmX64 : ElfWriter.EmX86, Is64 = is64, Type = 2, Base = 0x400000, Entry = ElfWriter.TextRva, Text = [0xC3],
        Hash = ElfWriter.HashKind.None, DataSectionName = section, Data = data,
    }.Build(), "gobin");

    private static void AssertFull(GoBuildInfo? b, string version)
    {
        Assert.NotNull(b);
        Assert.Equal(version, b.GoVersion);
        Assert.Equal("example.com/tool/cmd/tool", b.Path);
        Assert.Equal(new GoModule("example.com/tool", "v1.4.2", "h1:mainsum="), b.Main);
        Assert.Equal([new GoModule("golang.org/x/sys", "v0.20.0", "h1:syssum="),
                      new GoModule("example.com/old", "v1.0.0", null, new GoModule("example.com/fork", "v1.0.1", "h1:forksum="))], b.Dependencies);
        Assert.Equal("-s -w -X main.version=1.4.2", b.Setting("-ldflags"));
        Assert.Equal(("linux", "amd64", "0123abcd", "true"), (b.Setting("GOOS"), b.Setting("GOARCH"), b.Setting("vcs.revision"), b.Setting("vcs.modified")));
    }

    [Fact]
    public void Inline_strings_of_go_1_18_and_later() => AssertFull(GoBuildInfo.Of(Elf(Inline())), "go1.22.5");

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void String_pointers_of_go_1_13_to_1_17(bool is64) =>
        AssertFull(GoBuildInfo.Of(Elf(Pointers(0x400000 + ElfWriter.DataRva, is64 ? 8 : 4), is64)), "go1.16.15");

    [Fact]
    public void Pe_data_without_a_named_section_is_scanned_at_16_byte_alignment()
    {
        var data = new byte[0x400];
        Inline().CopyTo(data, 0x70);
        AssertFull(GoBuildInfo.Of(CodeTestImage.Synthetic(NativeArch.X64, [0xC3], data)), "go1.22.5");
        // Off alignment it is not the header.
        var shifted = new byte[0x400];
        Inline().CopyTo(shifted, 0x74);
        Assert.Null(GoBuildInfo.Of(CodeTestImage.Synthetic(NativeArch.X64, [0xC3], shifted)));
        Assert.Null(GoBuildInfo.Of(Elf(new byte[64], section: ".data")));
    }

    [Fact]
    public async Task Pe_info_and_summary_show_the_build()
    {
        using var dir = new TempDir();
        var path = dir.File("gobin");
        File.WriteAllBytes(path, new ElfWriter
        {
            Machine = ElfWriter.EmX64, Type = 2, Base = 0x400000, Entry = ElfWriter.TextRva, Text = [0xC3], Hash = ElfWriter.HashKind.None,
            DataSectionName = ".go.buildinfo", Data = Inline(),
        }.Build());
        using var h = new NativeToolHarness(backgroundIndexing: false);
        var info = await h.Native.GetPeInfo(path);
        Assert.Contains("Go build: go1.22.5, package example.com/tool/cmd/tool, module example.com/tool v1.4.2 h1:mainsum=", info);
        Assert.Contains("settings: -ldflags=-s -w -X main.version=1.4.2, CGO_ENABLED=0, GOARCH=amd64, GOOS=linux, vcs.revision=0123abcd, vcs.modified=true", info);
        Assert.Contains("    example.com/old v1.0.0 => example.com/fork v1.0.1 h1:forksum=", info);

        using var workspace = new AssemblyWorkspace(new ServerOptions());
        var summary = new InspectionService(workspace).Summarize(null, path, default);
        Assert.Equal(("go1.22.5", 2), (summary.Go?.GoVersion, summary.Go?.DependencyTotal));
        Assert.Contains("Go program built with go1.22.5, module example.com/tool v1.4.2, 2 dependencies, linux/amd64, revision 0123abcd (modified).", summary.Highlights);
    }

    [Fact]
    [FuzzEntry(typeof(GoBuildInfo))]
    public void Fuzzed_build_info_never_throws()
    {
        var failures = Corvus.Tests.FormatFuzz.Run(Inline(), b =>
        {
            if (GoBuildInfo.Of(Elf(b)) is { } info) _ = (info.GoVersion, info.Main, info.Dependencies.Count, info.Settings.Count);
        }, 500);
        failures.AddRange(Corvus.Tests.FormatFuzz.Run(Pointers(0x400000 + ElfWriter.DataRva, 8), b => GoBuildInfo.Of(Elf(b)), 500));
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(5)));
    }
}
