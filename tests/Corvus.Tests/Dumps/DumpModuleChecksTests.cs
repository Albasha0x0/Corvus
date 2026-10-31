using System.Buffers.Binary;
using System.Diagnostics;
using Corvus.Core;
using Corvus.Native.Dump;
using Corvus.Native.Pe;
using Corvus.Services;

namespace Corvus.Tests;

/// <summary>Module rows of a dump or a running process: load path class, local file signer, and code sections against that file.</summary>
public sealed class DumpModuleChecksTests : IDisposable
{
    private const uint Stamp = 0x5F5E4321, TextRva = 0x1000, PointerRva = 0x1080, PatchRva = 0x1010;
    private const ulong ImageBase = 0x1_8000_0000;
    private readonly TempDir _dir = new();
    private uint _pointerRva = PointerRva;

    public void Dispose() => _dir.Dispose();

    [Theory]
    [InlineData(@"C:\Windows\System32\ntdll.dll", "system")]
    [InlineData(@"C:\Windows\Temp\a.dll", "temp")]
    [InlineData(@"C:\Users\x\AppData\Local\Temp\a.dll", "temp")]
    [InlineData(@"C:\Users\x\Downloads\a.dll", "user_writable")]
    [InlineData(@"C:\ProgramData\v\a.dll", "user_writable")]
    [InlineData(@"C:\Program Files (x86)\v\a.dll", "program_files")]
    [InlineData(@"\\server\share\a.dll", "network")]
    [InlineData(@"\\?\UNC\server\share\a.dll", "network")]
    [InlineData(@"\\?\C:\Windows\System32\a.dll", "system")]
    [InlineData(@"D:\tools\a.dll", "other")]
    [InlineData("/tmp/x/liba.so", "temp")]
    [InlineData("/usr/lib/liba.so", "system")]
    public void A_module_path_is_classed_by_its_folder(string path, string expected) => Assert.Equal(expected, ModuleChecks.PathClass(path));

    /// <summary>A DLL whose .text holds code and one 8-byte pointer to its own image base, relocated by the loader.</summary>
    private byte[] File()
    {
        var b = new PeBuilder { ImageBase = ImageBase, Characteristics = 0x2022 };
        var text = new byte[Math.Max(0x200, _pointerRva - TextRva + 0x20)];
        for (int i = 0; i < text.Length; i++) text[i] = (byte)(0x90 + i % 7);
        BinaryPrimitives.WriteUInt64LittleEndian(text.AsSpan((int)(_pointerRva - TextRva)), ImageBase + 0x2000);
        b.Add(".text", text, 0x60000020);
        var reloc = new byte[12];
        BinaryPrimitives.WriteUInt32LittleEndian(reloc, _pointerRva & ~0xFFFu);
        BinaryPrimitives.WriteUInt32LittleEndian(reloc.AsSpan(4), 12);
        BinaryPrimitives.WriteUInt16LittleEndian(reloc.AsSpan(8), (ushort)((10 << 12) | (_pointerRva & 0xFFF)));
        var section = b.Add(".reloc", reloc, 0x42000040);
        b.Directories[PeDirectory.BaseRelocation] = (section.Rva, 12);
        var bytes = b.Build();
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(0x3C)) + 8), Stamp);
        return bytes;
    }

    /// <summary>A dump with the DLL loaded at <paramref name="moduleBase"/>; <paramref name="change"/> edits the mapped image, which is then captured except where <paramref name="skipFrom"/> starts.</summary>
    private string Dump(Action<byte[]>? change = null, ulong moduleBase = ImageBase, uint? skipFrom = null)
    {
        var file = File();
        var pe = PeFile.FromBytes(file);
        var mapped = new byte[pe.SizeOfImage];
        for (uint page = 0; page < mapped.Length; page += 0x1000) pe.Read(page, mapped.AsSpan((int)page, 0x1000));
        var delta = moduleBase - ImageBase;
        BinaryPrimitives.WriteUInt64LittleEndian(mapped.AsSpan((int)_pointerRva), ImageBase + 0x2000 + delta);
        change?.Invoke(mapped);
        var folder = Directory.CreateDirectory(_dir.File("bin")).FullName;
        System.IO.File.WriteAllBytes(Path.Combine(folder, "probe.dll"), file);
        var b = new MinidumpBuilder { FullMemory = true };
        b.Modules.Add(new MinidumpBuilder.Module(moduleBase, pe.SizeOfImage, Stamp, @"Z:\nowhere\probe.dll"));
        b.Memory.Add((moduleBase, skipFrom is { } cut ? mapped[..(int)cut] : mapped));
        var path = _dir.File("probe.dmp");
        System.IO.File.WriteAllBytes(path, b.Build());
        return path;
    }

    private MinidumpService.CheckedModule Module(string dump) =>
        Assert.Single(new MinidumpService().Modules(dump, _dir.File("bin"), 0, 10).Rows);

    [Fact]
    public void Code_equal_to_the_local_file_is_reported_as_same()
    {
        var m = Module(Dump());
        Assert.Equal("matches", m.LocalImage);
        Assert.Equal("same", m.CodeState);
    }

    [Fact]
    public void A_relocated_pointer_in_code_is_not_a_difference()
    {
        var m = Module(Dump(moduleBase: ImageBase + 0x40_0000));
        Assert.Equal("same", m.CodeState);
    }

    [Fact]
    public void A_relocated_pointer_across_a_64_KB_boundary_is_not_a_difference()
    {
        _pointerRva = TextRva + 0xFFFC;
        var m = Module(Dump(moduleBase: ImageBase + 0x1_0000_0000));
        Assert.Equal("same", m.CodeState);
    }

    [Fact]
    public void A_pointer_the_loader_did_not_relocate_is_a_difference()
    {
        var moved = ImageBase + 0x40_0000;
        var m = Module(Dump(mapped => BinaryPrimitives.WriteUInt64LittleEndian(mapped.AsSpan((int)PointerRva), ImageBase + 0x2000), moved));
        Assert.Equal("differs", m.CodeState);
        Assert.Contains($"first at RVA 0x{PointerRva + 2:X}", m.CodeDetail);
    }

    [Fact]
    public void A_patched_code_byte_is_reported_as_differs_with_its_rva()
    {
        var m = Module(Dump(mapped => mapped[PatchRva] ^= 0xFF));
        Assert.Equal("differs", m.CodeState);
        Assert.Contains("1 differing byte(s) in 1 page(s), first at RVA 0x1010 in .text", m.CodeDetail);
    }

    [Fact]
    public void Code_pages_the_dump_lacks_are_reported_as_partial()
    {
        var m = Module(Dump(skipFrom: TextRva));
        Assert.Equal("partial", m.CodeState);
        Assert.Contains("0 of 1 page(s)", m.CodeDetail);
    }

    [Fact]
    public void A_module_without_a_local_file_has_unknown_signature_and_code()
    {
        var dump = Dump();
        var m = Assert.Single(new MinidumpService().Modules(dump, null, 0, 10).Rows);
        Assert.Equal("missing", m.LocalImage);
        Assert.Equal("unknown", m.SignatureState);
        Assert.Null(m.Signer);
        Assert.Equal("unknown", m.CodeState);
        Assert.Equal("other", m.LoadPath);
    }

    [Fact]
    public void An_unsigned_local_file_is_reported_as_unsigned()
    {
        var m = Module(Dump());
        Assert.Equal("unsigned", m.SignatureState);
        Assert.Null(m.Signer);
    }

    [Fact]
    [FuzzEntry(typeof(ModuleChecks))]
    public void Mutated_dumps_never_throw_from_the_module_checks()
    {
        var seed = System.IO.File.ReadAllBytes(Dump());
        int n = 0;
        var failures = FormatFuzz.Run(seed, bytes =>
        {
            var path = _dir.File($"fuzz{n % 2}.dmp");
            System.IO.File.WriteAllBytes(path, bytes);
            try { new MinidumpService().Modules(path, _dir.File("bin"), 0, 10); }
            catch (ToolError) { }
            n++;
        }, 250);
        Assert.Empty(failures);
    }

    [Fact]
    public async Task A_system_module_of_a_running_process_names_Microsoft_as_its_signer()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var child = Process.Start(new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "findstr.exe"), "x")
        {
            RedirectStandardInput = true, RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true,
        })!;
        try
        {
            using var dumps = new MinidumpService();
            // The loader lists the modules a moment after the process starts.
            List<MinidumpService.CheckedModule> rows = [];
            for (var clock = Stopwatch.StartNew(); rows.All(m => !m.Name.Equals("ntdll.dll", StringComparison.OrdinalIgnoreCase)) && clock.Elapsed < TimeSpan.FromSeconds(30); await Task.Delay(100))
                rows = [.. (await new LiveProcessService(dumps).Inspect(child.Id.ToString(), "modules", null, 0, 1000, null, 64, null, 60, default)).Items!.Cast<MinidumpService.CheckedModule>()];
            var ntdll = rows.Single(m => m.Name.Equals("ntdll.dll", StringComparison.OrdinalIgnoreCase));
            Assert.Equal("system", ntdll.LoadPath);
            Assert.Contains("Microsoft", ntdll.Signer);
            Assert.Contains(ntdll.SignatureState, new[] { "signed", "catalog" });
            Assert.True(ntdll.CodeState == "same", ntdll.CodeDetail);
        }
        finally
        {
            try { child.Kill(); } catch (InvalidOperationException) { }
        }
    }
}
