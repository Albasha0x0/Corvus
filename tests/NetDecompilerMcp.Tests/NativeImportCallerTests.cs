using System.Text.RegularExpressions;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native.Annotations;
using NetDecompilerMcp.Services;
using NetDecompilerMcp.Tests.NativeFormats;
using NetDecompilerMcp.Tools;

namespace NetDecompilerMcp.Tests;

/// <summary>Call paths and caller trees to an import whose library is not loaded: PE module!name, ELF lib.so.N!name, Mach-O lib.dylib!_name.</summary>
public sealed class NativeImportCallerTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private (AssemblyWorkspace Workspace, CallGraphTools Paths, NativeCodeTools Code) Rig(params string[] files)
    {
        var options = new ServerOptions { BackgroundIndexing = false };
        var ws = new AssemblyWorkspace(options);
        foreach (var f in files) ws.LoadAny(f);
        var code = new NativeCodeService(ws, options, null, new AnnotationStore(_dir.File("ann")));
        var link = new NativeLinkService(ws, code);
        var pager = new OutputPager(options);
        return (ws, new CallGraphTools(ws, new CallGraphService(ws), pager, link, code), new NativeCodeTools(ws, code, pager, link));
    }

    /// <summary>app.exe: Main (entry point) calls Helper, which calls through provider_2c9d.dll!OpenThing; the provider exists nowhere.</summary>
    private string App()
    {
        var path = _dir.File("app.exe");
        File.WriteAllBytes(path, LinkedImages.Build("app.exe", [("Main", 0)], [("provider_2c9d.dll", ["OpenThing"])], slots =>
        {
            var c = new LinkedImages.Code(slots);
            c.Raw(0xE8, 11, 0, 0, 0).Ret().Pad(16); // call Helper (at 16)
            return c.CallImport("provider_2c9d.dll!OpenThing").Ret().ToArray();
        }));
        return path;
    }

    [Fact]
    public async Task Paths_reach_an_import_of_a_library_that_is_not_loaded()
    {
        var (ws, paths, _) = Rig(App());
        using var _ = ws;
        var text = await paths.FindCallPaths("provider_2c9d.dll!OpenThing");
        Assert.Contains("native provider_2c9d.dll!OpenThing (imported by app.exe; its library is not loaded)", text);
        Assert.Contains("(2 native calls; root: entry point)", text);
        Assert.Contains("[app.exe] Main at", text);
        Assert.Contains("(import at 0x", text);
        Assert.Contains("provider_2c9d!OpenThing", text);
    }

    [Fact]
    public async Task Each_importer_ends_its_chains_at_its_own_slot_and_a_slot_address_names_the_import()
    {
        var app = App();
        var copy = _dir.File("app2.exe");
        File.Copy(app, copy);
        var (ws, paths, _) = Rig(app, copy);
        using var _ = ws;
        var text = await paths.FindCallPaths("provider_2c9d.dll!OpenThing");
        Assert.Contains("imported by app.exe, app2.exe", text);
        foreach (var id in new[] { "app.exe", "app2.exe" })
            Assert.Matches($@"-> \[{Regex.Escape(id)}\] provider_2c9d!OpenThing at 0x[0-9A-F]+  \(import at", text);
        // the import slot by address, as native:<image>!<va>
        var native = ws.FindNative("app.exe")!;
        var slot = native.Image.Imports.Single(i => i.Name == "OpenThing").SlotRva;
        var bySlot = await paths.FindCallPaths($"native:app.exe!0x{native.Image.ImageBase + slot:X}");
        Assert.Contains("[app.exe] Main at", bySlot);
        Assert.DoesNotContain("no P/Invoke declaration", bySlot);
    }

    [Fact]
    public async Task Caller_tree_of_an_import_lists_its_callers_and_theirs()
    {
        var (ws, _, code) = Rig(App());
        using var _ = ws;
        var tree = await code.NativeCallTree("app.exe", "provider_2c9d.dll!OpenThing", direction: "callers");
        Assert.Contains("provider_2c9d!OpenThing  (import slot at 0x", tree);
        var lines = tree.Split('\n').Select(l => l.TrimEnd('\r')).ToList();
        int helper = lines.FindIndex(l => l.StartsWith("  sub_", StringComparison.Ordinal));
        Assert.True(helper > 0, tree);
        Assert.StartsWith("    Main", lines[helper + 1]);
    }

    [Fact]
    public async Task Elf_and_MachO_library_forms_name_their_imports()
    {
        // arm64 ELF: the entry calls free through its PLT stub (bl plt0 + 32; ret); libc.so.6 is needed, not loaded
        var elf = new ElfWriter
        {
            Machine = ElfWriter.EmAarch64, Type = 2, Base = 0x400000, Entry = ElfWriter.TextRva, Needed = ["libc.so.6"], PltImports = ["free"],
            Text = [0x0C, 0x00, 0x00, 0x94, 0xC0, 0x03, 0x5F, 0xD6],
        };
        var elfPath = _dir.File("tool");
        File.WriteAllBytes(elfPath, elf.Build());
        var (ws, paths, code) = Rig(elfPath);
        using var _ = ws;
        Assert.Equal(new NativeSymbol("libc.so.6", "free"), SymbolResolver.ParseNative("libc.so.6!free"));
        Assert.Equal(new NativeSymbol("libSystem.B.dylib", "_malloc"), SymbolResolver.ParseNative("libSystem.B.dylib!_malloc"));
        var text = await paths.FindCallPaths("libc.so.6!free");
        Assert.Contains("imported by tool; its library is not loaded", text);
        Assert.Contains("root: entry point", text);
        Assert.Contains("(import at 0x40", text);
        var tree = await code.NativeCallTree("tool", "libc.so.6!free", direction: "callers");
        Assert.Contains("(import slot at 0x", tree);
        Assert.DoesNotContain("nothing calls through it", tree);
    }

    [Fact]
    public async Task A_loaded_shared_object_provides_the_imports_naming_it()
    {
        var elf = new ElfWriter
        {
            Machine = ElfWriter.EmAarch64, Type = 2, Base = 0x400000, Entry = ElfWriter.TextRva, Needed = ["libc.so.6"], PltImports = ["free"],
            Text = [0x0C, 0x00, 0x00, 0x94, 0xC0, 0x03, 0x5F, 0xD6],
        };
        var toolPath = _dir.File("tool");
        File.WriteAllBytes(toolPath, elf.Build());
        // libc.so.6 elsewhere, loaded: free is ret
        var lib = new ElfWriter { Machine = ElfWriter.EmAarch64, SoName = "libc.so.6", Text = [0xC0, 0x03, 0x5F, 0xD6] };
        lib.Symbols.Add(new ElfWriter.Symbol("free", ElfWriter.TextRva, 4));
        Directory.CreateDirectory(_dir.File("lib"));
        var libPath = _dir.File(Path.Combine("lib", "libc.so.6"));
        File.WriteAllBytes(libPath, lib.Build());
        var (ws, paths, code) = Rig(toolPath, libPath);
        using var _ = ws;
        var text = await paths.FindCallPaths("libc.so.6!free");
        Assert.DoesNotContain("its library is not loaded", text);
        Assert.Contains("[libc.so.6] free at", text);
        var tree = await code.NativeCallTree("tool", $"0x{0x400000 + ElfWriter.TextRva:X}", direction: "callees");
        Assert.DoesNotContain("dll_not_found", tree);
    }
}
