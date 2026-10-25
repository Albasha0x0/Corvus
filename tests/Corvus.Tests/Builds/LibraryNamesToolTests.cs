using Corvus.Core;
using Corvus.Native.Annotations;

namespace Corvus.Tests;

/// <summary>migrate_native_names with an object file holding a function of the image as its old side.</summary>
public sealed class LibraryNamesToolTests
{
    // push rbx; sub rsp,20h; mov rbx,rcx; lea rcx,[rip+disp32]; call rel32; mov eax,[rbx+8]; add rsp,20h; pop rbx; ret
    private static byte[] RoutineBytes(int lea, int call)
    {
        byte[] b = [0x40, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0xD9, 0x48, 0x8D, 0x0D, 0, 0, 0, 0, 0xE8, 0, 0, 0, 0, 0x8B, 0x43, 0x08, 0x48, 0x83, 0xC4, 0x20, 0x5B, 0xC3];
        BitConverter.GetBytes(lea).CopyTo(b, 12);
        BitConverter.GetBytes(call).CopyTo(b, 17);
        return b;
    }

    /// <summary>An x64 executable: main at 0x1000 calls the routine at 0x1010, whose relocated fields the linker filled.</summary>
    private static byte[] Linked()
    {
        // sub rsp,28h; call 0x1010; add rsp,28h; ret; int3 padding to 0x1010.
        byte[] main = [0x48, 0x83, 0xEC, 0x28, 0xE8, 0x07, 0, 0, 0, 0x48, 0x83, 0xC4, 0x28, 0xC3, 0xCC, 0xCC];
        // The routine's call (next instruction at 0x1025) goes back to main.
        var pe = new PeBuilder { EntryPoint = 0x1000, Characteristics = 0x0022 };
        pe.Sections.Add(new PeBuilder.Section { Name = ".text", Rva = 0x1000, Data = [.. main, .. RoutineBytes(0x100, 0x1000 - 0x1025), 0xCC, 0xCC], Characteristics = 0x6000_0020 });
        return pe.Build();
    }

    [Fact]
    public async Task An_object_names_the_start_holding_its_function_and_a_dry_run_records_nothing()
    {
        using var dir = new TempDir();
        using var env = new Env();
        var code = new Corvus.Services.NativeCodeService(env.Workspace, env.Options, null, new AnnotationStore(dir.File("ann")));
        var tools = new Corvus.Tools.NativeDiffTools(env.Workspace, code);
        var image = dir.File("app.exe");
        File.WriteAllBytes(image, Linked());
        var native = env.Workspace.LoadAny(image).Native!;
        await code.Index(native, null, default);
        const uint Routine = 0x1010;
        var obj = dir.File("routines.obj");
        File.WriteAllBytes(obj, CoffFixtures.Object(0x8664, [new(".text$mn", CoffFixtures.Code, RoutineBytes(0, 0), [(12, 1, 4), (17, 2, 4)])],
            [new("library_routine", 0, 1, 0x20, 2), new("table", 0, 0, 0, 2), new("callback", 0, 0, 0x20, 2)]));

        var (dry, dryText) = await BuildToolCalls.Collected<Corvus.Tools.NativeDiffTools.MigrationReport>(() => tools.MigrateNativeNames(obj, image));
        var item = Assert.Single(dry.Items);
        Assert.Equal(("would_set", "library", "library_function", "library_routine"), (item.Action, item.Source, item.Reason, item.Value));
        Assert.Equal(Corvus.Native.NativeAddress.Va(native.Image, Routine), item.NewAddress);
        Assert.StartsWith("Dry run: 1 of 1 item(s) would carry from routines.obj", dryText);
        Assert.Contains("1 function(s) read from 1 member(s) of routines.obj", dryText);
        Assert.Null(code.Annotations(native).NameAt(Routine));

        var (done, _) = await BuildToolCalls.Collected<Corvus.Tools.NativeDiffTools.MigrationReport>(() => tools.MigrateNativeNames(obj, image, dryRun: false));
        Assert.Equal((1, true), (done.Set, done.Applied));
        Assert.Equal("library_routine", code.Annotations(native).NameAt(Routine));
    }

    [Fact]
    public async Task An_object_of_another_architecture_is_refused_with_both_named()
    {
        using var dir = new TempDir();
        using var env = new Env();
        var tools = new Corvus.Tools.NativeDiffTools(env.Workspace, new Corvus.Services.NativeCodeService(env.Workspace, env.Options, null, new AnnotationStore(dir.File("ann"))));
        var image = dir.File("app.dll");
        File.WriteAllBytes(image, NativePeTests.KitchenSink(is64: true));
        var obj = dir.File("routines32.obj");
        File.WriteAllBytes(obj, CoffFixtures.Object(0x014C, [new(".text$mn", CoffFixtures.Code, new byte[32], [])], [new("_routine", 0, 1, 0x20, 2)]));
        var e = await Assert.ThrowsAsync<ToolError>(() => tools.CarryLibraryNames(obj, image, true, default, default));
        Assert.Equal(ErrorCode.InvalidArgument, e.Code);
        Assert.Contains("routines32.obj holds X86 code; app.dll is X64", e.Message);
    }

    [Fact]
    public void A_library_object_or_relocatable_file_takes_the_library_route_and_an_image_does_not()
    {
        using var dir = new TempDir();
        var image = dir.File("app.dll");
        File.WriteAllBytes(image, NativePeTests.KitchenSink(is64: true));
        var obj = dir.File("a.obj");
        File.WriteAllBytes(obj, CoffFixtures.Object(0x8664, [], []));
        var lib = dir.File("a.lib");
        File.WriteAllBytes(lib, CoffFixtures.Library(("a.obj", File.ReadAllBytes(obj))));
        Assert.Null(Corvus.Tools.NativeDiffTools.LibraryFile(image));
        Assert.Null(Corvus.Tools.NativeDiffTools.LibraryFile("app.dll#2"));
        Assert.Equal(Path.GetFullPath(obj), Corvus.Tools.NativeDiffTools.LibraryFile(obj));
        Assert.Equal(Path.GetFullPath(lib), Corvus.Tools.NativeDiffTools.LibraryFile(lib));
        var elf = dir.File("a.o");
        File.WriteAllBytes(elf, ElfObjectFixtures.Write(62, [0xC3], [], []));
        Assert.Equal(Path.GetFullPath(elf), Corvus.Tools.NativeDiffTools.LibraryFile(elf));
    }
}
