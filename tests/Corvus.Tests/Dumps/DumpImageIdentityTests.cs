using System.Buffers.Binary;
using Corvus.Core;
using Corvus.Native.Dump;
using Corvus.Native.Pdb;
using Corvus.Services;

namespace Corvus.Tests;

/// <summary>A dump module whose file is not at its recorded path or under its name is found by timestamp and size: renamed in a folder, in a symbol store, or loaded.</summary>
[Collection(ExternalToolEnvironmentCollection.Name)]
public sealed class DumpImageIdentityTests : IDisposable
{
    private const uint Stamp = 0x5F5E1234;
    private readonly TempDir _dir = new();
    private readonly EnvironmentScope _env = new();

    public DumpImageIdentityTests() => _env.Set("_NT_SYMBOL_PATH", null).Set("_NT_ALT_SYMBOL_PATH", null);

    public void Dispose()
    {
        _env.Dispose();
        _dir.Dispose();
    }

    /// <summary>synth.dll with the dump module's timestamp; the dump does not hold the module's memory, so names need the file.</summary>
    private static byte[] File()
    {
        var bytes = SyntheticCrash.FileImage();
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(0x3C)) + 8), Stamp);
        return bytes;
    }

    private string Dump()
    {
        var b = SyntheticCrash.Builder();
        var module = b.Modules[0];
        b.Modules[0] = module with { TimeDateStamp = Stamp };
        b.Memory.RemoveAll(m => m.Start == SyntheticCrash.Base);
        var path = Path.Combine(Directory.CreateDirectory(_dir.File("dumps")).FullName, "crash.dmp");
        System.IO.File.WriteAllBytes(path, b.Build());
        return path;
    }

    private static async Task<(MinidumpService.ModuleSummary Module, MinidumpService.StackReport Stack)> Open(MinidumpService service, string dump, string? dirs)
    {
        var summary = await service.Summarize(dump, dirs, default);
        return (Assert.Single(service.Modules(dump, dirs, 0, 50).Rows), await service.Stack(dump, null, true, 64, 0, 64, dirs, default));
    }

    [Fact]
    public async Task RenamedCopyInAnImageFolder()
    {
        var dump = Dump();
        var folder = Directory.CreateDirectory(_dir.File("bin")).FullName;
        System.IO.File.WriteAllBytes(Path.Combine(folder, "other.dll"), new byte[600]); // not a PE file
        System.IO.File.WriteAllBytes(Path.Combine(folder, "synth_1.2.3.dll"), File());
        var (module, stack) = await Open(new MinidumpService(), dump, folder);
        Assert.Equal("matches", module.LocalImage);
        Assert.EndsWith("synth_1.2.3.dll", module.LocalPath);
        Assert.Contains("another file name", module.LocalDetail);
        Assert.Equal("synth!Crash+0x5", stack.Items[0].Symbol);
        Assert.Contains(stack.Notes, n => n.StartsWith("synth.dll: image disk", StringComparison.Ordinal));

        var missing = new MinidumpService().Modules(Dump(), null, 0, 50).Rows; // no folder given: not found
        Assert.Equal("missing", missing[0].LocalImage);
    }

    /// <summary>dump_stack after open_minidump with imageDirectories: the dump's folders are kept, so the stack is named without passing them again.</summary>
    [Fact]
    public async Task LaterCallsReuseTheImageFolders()
    {
        var dump = Dump();
        var folder = Directory.CreateDirectory(_dir.File("bin")).FullName;
        System.IO.File.WriteAllBytes(Path.Combine(folder, "synth_1.2.3.dll"), File());
        using var service = new MinidumpService();
        var summary = await service.Summarize(dump, folder, default);
        Assert.Equal("matches", service.Modules(summary.Id, null, 0, 50).Rows[0].LocalImage);
        Assert.Equal("synth!Crash+0x5", (await service.Stack(summary.Id, null, true, 64, 0, 64, null, default)).Items[0].Symbol);
        Assert.Equal("synth!Crash+0x5", (await service.Stack(dump, null, true, 64, 0, 64, null, default)).Items[0].Symbol);
    }

    /// <summary>read_dump_memory fills what the dump lacks from the module image unless dumpOnly (the default of the former imageFallback=true).</summary>
    [Fact]
    public async Task ReadDumpMemoryFillsFromTheImageUnlessDumpOnly()
    {
        var dump = Dump();
        var folder = Directory.CreateDirectory(_dir.File("bin")).FullName;
        System.IO.File.WriteAllBytes(Path.Combine(folder, "synth.dll"), File());
        using var service = new MinidumpService();
        var id = (await service.Summarize(dump, folder, default)).Id;
        var tools = new Corvus.Tools.MinidumpTools(service);
        Assert.Contains("16 of 16 bytes, module_image", await tools.ReadDumpMemory(id, "synth+0x1000", 16));
        Assert.Contains("0 of 16 bytes, none", await tools.ReadDumpMemory(id, "synth+0x1000", 16, dumpOnly: true));
    }

    [Fact]
    public async Task SymbolStoreByKeyAndUnderAnotherName()
    {
        var dump = Dump();
        var store = Directory.CreateDirectory(_dir.File("store")).FullName;
        _env.Set("_NT_SYMBOL_PATH", $"srv*{store}*https://example.invalid/symbols");
        var key = PdbLocator.ImageKey(Stamp, (uint)SyntheticCrash.Image().Length);
        var keyed = Directory.CreateDirectory(Path.Combine(store, "synth.dll", key)).FullName;
        System.IO.File.WriteAllBytes(Path.Combine(keyed, "synth.dll"), File());
        var (module, stack) = await Open(new MinidumpService(), dump, null);
        Assert.Equal("matches", module.LocalImage);
        Assert.Contains($"symbol store {store}", module.LocalDetail);
        Assert.Equal("synth!Crash+0x5", stack.Items[0].Symbol);

        Directory.Delete(Path.Combine(store, "synth.dll"), recursive: true);
        var renamed = Directory.CreateDirectory(Path.Combine(store, "synth64.dll", key)).FullName;
        System.IO.File.WriteAllBytes(Path.Combine(renamed, "synth64.dll"), File());
        var check = DumpImages.ByIdentity("synth.dll", Stamp, (uint)SyntheticCrash.Image().Length, []);
        Assert.NotNull(check);
        Assert.Equal(Path.Combine(renamed, "synth64.dll"), check.Path);
        Assert.Contains("as synth64.dll", check.Detail);
        Assert.Null(DumpImages.ByIdentity("synth.dll", 0, 0x5000, []));
    }

    [Fact]
    public async Task LoadedImageUnderAnotherName()
    {
        var dump = Dump();
        var copy = _dir.File("app_copy.bin");
        System.IO.File.WriteAllBytes(copy, File());
        using var ws = new AssemblyWorkspace();
        ws.LoadAny(copy);
        var (module, stack) = await Open(new MinidumpService(ws), dump, null);
        Assert.Equal("matches", module.LocalImage);
        Assert.Contains("a loaded image (app_copy.bin)", module.LocalDetail);
        Assert.Equal("synth!Crash+0x5", stack.Items[0].Symbol);
    }
}
