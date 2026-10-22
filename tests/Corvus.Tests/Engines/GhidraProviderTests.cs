using System.Buffers.Binary;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Ghidra;

namespace Corvus.Tests;

/// <summary>Ghidra provider plumbing without Ghidra: availability, header reading and language mapping.</summary>
public class GhidraProviderTests
{
    [Fact]
    public void A_thunk_named_as_its_target_is_called_thunk_name()
    {
        var named = GhidraSession.NameThunks([
            new(0x1000, 0x1005, "CheckPreview", NativeFunctionFlags.Thunk), new(0x2000, 0x2100, "CheckPreview", NativeFunctionFlags.None),
            new(0x3000, 0x3006, "CreateFileW", NativeFunctionFlags.Thunk), new(0x4000, 0x4005, "thunk_FUN_00405000", NativeFunctionFlags.Thunk)]);
        Assert.Equal(["thunk_CheckPreview", "CheckPreview", "CreateFileW", "thunk_FUN_00405000"], named.Select(f => f.Name));
    }

    [Fact]
    public void A_worker_keeps_its_temporary_files_and_start_lock_in_its_own_folder()
    {
        var dirs = new GhidraDirectories(Path.Combine(Path.GetTempPath(), "corvus-ghidra-env"));
        var environment = GhidraProvider.WorkerEnvironment(dirs);
        Assert.All(new[] { "TEMP", "TMP", "TMPDIR" }, name => Assert.Equal(dirs.Temp, environment[name]));
        Assert.Null(environment["JAVA_TOOL_OPTIONS"]);
    }

    [Fact]
    public async Task Missing_install_is_unavailable_with_remediation()
    {
        using var tmp = new TempDir();
        using var provider = new GhidraProvider(new GhidraProviderOptions { InstallDirectory = tmp.File("absent"), CacheRoot = tmp.File("cache") });
        var a = provider.CheckAvailability();
        Assert.False(a.IsAvailable);
        Assert.Equal("ghidra", a.ProviderId);
        Assert.Contains(GhidraOptions.DirectoryVariable, a.Remediation);
        Assert.Equal(ErrorCode.ProviderUnavailable, (await Assert.ThrowsAsync<ToolError>(() => provider.OpenAsync(Env.FixturePath))).Code);
        Assert.False((await provider.ProbeAsync()).IsAvailable);
    }

    [Fact]
    public void Bad_configuration_is_reported_by_the_availability_check()
    {
        using var tmp = new TempDir();
        using var provider = new GhidraProvider(new GhidraProviderOptions
        {
            InstallDirectory = GhidraSetupTests.FakeInstall(tmp),
            JavaHome = GhidraSetupTests.FakeJdk(tmp, "jdk", "24"),
            CacheRoot = tmp.File("cache"),
            ExtraOptions = "no equals sign",
        });
        var a = provider.CheckAvailability();
        Assert.False(a.IsAvailable);
        Assert.Contains(GhidraOptions.OptionsVariable, a.Reason);
    }

    [Fact]
    public void Decompiler_limits_parse_and_the_retry_fits_the_request()
    {
        Assert.Equal(TimeSpan.FromSeconds(60), GhidraOptions.DecompileTimeout(null));
        Assert.Equal(TimeSpan.FromSeconds(90), GhidraOptions.DecompileTimeout(" 90 "));
        Assert.Equal(200, GhidraOptions.DecompilePayloadMb(""));
        Assert.Equal(512, GhidraOptions.DecompilePayloadMb("512"));
        foreach (var bad in new[] { "0", "601", "1m" })
            Assert.Contains(GhidraOptions.DecompileTimeoutVariable, Assert.Throws<ToolError>(() => GhidraOptions.DecompileTimeout(bad)).Remediation);
        foreach (var bad in new[] { "8", "4096", "x" })
            Assert.Contains(GhidraOptions.DecompilePayloadVariable, Assert.Throws<ToolError>(() => GhidraOptions.DecompilePayloadMb(bad)).Remediation);
        Assert.Equal(TimeSpan.FromSeconds(240), GhidraOptions.RetryTimeout(TimeSpan.FromSeconds(60)));
        Assert.Equal(TimeSpan.FromSeconds(600), GhidraOptions.RetryTimeout(TimeSpan.FromSeconds(300)));
        Assert.Equal(TimeSpan.FromSeconds(330), GhidraOptions.DecompileRequestTimeout(TimeSpan.FromSeconds(60), TimeSpan.FromMinutes(2)));
        Assert.Equal(TimeSpan.FromMinutes(2), GhidraOptions.DecompileRequestTimeout(TimeSpan.FromSeconds(5), TimeSpan.FromMinutes(2)));
    }

    [Fact]
    public void A_worker_stopped_by_the_memory_cap_points_at_both_limits()
    {
        var fix = GhidraProvider.Remediation(ErrorCode.ProviderUnavailable, $"Ghidra worker exited after reaching its memory limit of 4096 MB ({EngineMemoryLimit.Variable})");
        Assert.Contains(EngineMemoryLimit.Variable, fix);
        Assert.Contains(GhidraOptions.MaxMemoryVariable, fix);
        Assert.DoesNotContain(EngineMemoryLimit.Variable, GhidraProvider.Remediation(ErrorCode.ProviderUnavailable, "exited"));
    }

    [Fact]
    public void Pe_header_gives_arch_and_base_and_rejects_il_only()
    {
        var dll = Path.Combine(Environment.SystemDirectory, "kernel32.dll");
        if (File.Exists(dll))
        {
            var h = GhidraSession.ReadHeader(dll, dll);
            Assert.Equal(Environment.Is64BitOperatingSystem ? NativeArch.X64 : NativeArch.X86, h.Arch);
            Assert.NotNull(h.ImageBase);
            Assert.False(h.IsElf);
        }
        Assert.Equal(ErrorCode.Unsupported, Assert.Throws<ToolError>(() => GhidraSession.ReadHeader(Env.FixturePath, Env.FixturePath)).Code);
    }

    [Theory]
    [InlineData(true, 183, NativeArch.Arm64)]
    [InlineData(false, 40, NativeArch.Arm)]
    [InlineData(true, 62, NativeArch.X64)]
    public void Elf_base_is_the_lowest_load_segment(bool is64, ushort machine, NativeArch arch)
    {
        using var tmp = new TempDir();
        var path = tmp.File("lib.so");
        File.WriteAllBytes(path, Elf(is64, machine, [(6, 0x40UL), (1, 0x20000UL), (1, 0x10000UL), (2, 0x0UL)]));
        var h = GhidraSession.ReadHeader(path, path);
        Assert.True(h.IsElf);
        Assert.Equal(arch, h.Arch);
        Assert.Equal(0x10000UL, h.ImageBase);

        File.WriteAllBytes(path, Elf(is64, machine, [(1, 0UL)]));
        Assert.Equal(0UL, GhidraSession.ReadHeader(path, path).ImageBase);
    }

    [Fact]
    public void Unknown_formats_are_left_to_ghidra()
    {
        using var tmp = new TempDir();
        var path = tmp.File("blob.bin");
        File.WriteAllBytes(path, [0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 2]);
        Assert.Equal(new GhidraSession.Header(NativeArch.Unknown, null, false), GhidraSession.ReadHeader(path, path));
    }

    [Theory]
    [InlineData("x86:LE:64:default", NativeArch.X64)]
    [InlineData("x86:LE:32:default", NativeArch.X86)]
    [InlineData("AARCH64:LE:64:v8A", NativeArch.Arm64)]
    [InlineData("ARM:LE:32:v8T", NativeArch.Arm)]
    [InlineData("MIPS:BE:32:default", NativeArch.Unknown)]
    [InlineData("garbage", NativeArch.Unknown)]
    public void Languages_map_to_architectures(string language, NativeArch arch) => Assert.Equal(arch, GhidraSession.ArchOf(language));

    /// <summary>A little-endian ELF header with program headers (type, vaddr) only.</summary>
    private static byte[] Elf(bool is64, ushort machine, (uint Type, ulong Vaddr)[] segments)
    {
        int ehsize = is64 ? 64 : 52, phentsize = is64 ? 56 : 32;
        var b = new byte[ehsize + phentsize * segments.Length];
        b[0] = 0x7F; b[1] = (byte)'E'; b[2] = (byte)'L'; b[3] = (byte)'F';
        b[4] = (byte)(is64 ? 2 : 1);
        b[5] = 1;
        b[6] = 1;
        BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(16), 3); // ET_DYN
        BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(18), machine);
        if (is64)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(32), (ulong)ehsize);
            BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(54), (ushort)phentsize);
            BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(56), (ushort)segments.Length);
        }
        else
        {
            BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(28), (uint)ehsize);
            BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(42), (ushort)phentsize);
            BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(44), (ushort)segments.Length);
        }
        for (int i = 0; i < segments.Length; i++)
        {
            var at = ehsize + i * phentsize;
            BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(at), segments[i].Type);
            if (is64) BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(at + 16), segments[i].Vaddr);
            else BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(at + 8), (uint)segments[i].Vaddr);
        }
        return b;
    }
}
