using System.Net;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Code;
using Corvus.Native.Dwarf;
using Corvus.Native.Pdb;
using Corvus.Services;
using Corvus.Tests.NativeFormats;

namespace Corvus.Tests;

/// <summary>DWARF as debug symbols of ELF and Mach-O images (load_pdb): located, read into the PDB model, named, typed, with source lines.</summary>
public class DwarfTests
{
    private const string Library = "libSystem.Native.so";
    // facts of the linux-x64 build, checked against llvm-dwarfdump and llvm-symbolizer
    private const uint FStat = 0xD7A0;

    private static string Elf(string file = Library) => NativeFixtures.NativeAotLib("linux-x64", file);

    private sealed class Rig : IDisposable
    {
        public readonly TempDir Dir = new();
        public readonly ServerOptions Options = new() { TimeoutSeconds = 120, BackgroundIndexing = false };
        public readonly AssemblyWorkspace Workspace;
        public readonly NativeCodeService Code;
        public readonly PdbService Pdbs;

        public Rig(string? annotations = null)
        {
            Workspace = new AssemblyWorkspace(Options);
            Code = new NativeCodeService(Workspace, Options, null, new Corvus.Native.Annotations.AnnotationStore(annotations ?? Dir.File("ann")));
            Pdbs = new PdbService(Code);
        }

        /// <summary>Copies files into a folder of the rig (relative target names), returns the first copy's path.</summary>
        public string Copy(params (string From, string To)[] files)
        {
            foreach (var (from, to) in files)
            {
                var target = Dir.File(to);
                Directory.CreateDirectory(Path.GetDirectoryName(target)!);
                File.Copy(from, target, overwrite: true);
            }
            return Dir.File(files[0].To);
        }

        public Corvus.Tools.PdbTools Tools => new(Workspace, Pdbs);

        public void Dispose()
        {
            Workspace.Dispose();
            Dir.Dispose();
        }
    }

    [Fact]
    public async Task The_debug_file_beside_an_elf_image_is_read_with_the_code_index()
    {
        using var rig = new Rig();
        var image = rig.Copy((Elf(), Library), (Elf(Library + ".dbg"), Library + ".dbg"));
        var native = rig.Workspace.LoadAny(image).Native!;
        var index = await rig.Code.Index(native, null, default);
        var state = PdbService.StateOf(native);
        Assert.NotNull(state);
        Assert.True(state!.Automatic && state.Verified);
        Assert.Equal(DebugInfoFormat.Dwarf, state.Pdb.Format);
        Assert.Equal(image + ".dbg", state.Path);
        Assert.Equal(273, state.Pdb.Symbols.Count(s => s.IsFunction));
        Assert.Equal(("SystemNative_FStat", NativeNameSource.Pdb), index.Sourced.NameAt(FStat));
        Assert.StartsWith("DWARF loaded", Corvus.Tools.PdbTools.Status(native));
    }

    [Fact]
    public async Task Load_pdb_takes_a_folder_with_a_build_id_tree()
    {
        using var rig = new Rig();
        var image = rig.Copy((Elf(), Path.Combine("bin", Library)));
        var native = rig.Workspace.LoadAny(image).Native!;
        var id = native.Image.BuildId!;
        rig.Copy((Elf(Library + ".dbg"), Path.Combine("symbols", ".build-id", id[..2], id[2..] + ".debug")));
        var collector = Corvus.Mcp.ToolOutput.Collect();
        var text = await rig.Tools.LoadPdb(native.Id, path: rig.Dir.File("symbols"));
        Assert.Contains($"DWARF in a separate debug file, build-id {id}: matches the image", text);
        Assert.Contains("273 functions", text);
        var loaded = Assert.IsType<Corvus.Tools.EditResult>(collector.Value);
        Assert.True(loaded.Applied);
        Assert.Contains(PdbService.StateOf(native)!.Pdb.Symbols, s => s.Name == "SystemNative_Poll" && s.Kind == PdbSymbolKind.GlobalProc);
    }

    [Fact]
    public async Task A_debug_file_of_another_build_is_refused_unless_allowed()
    {
        using var rig = new Rig();
        var image = rig.Copy((Elf(), Library), (Elf("libSystem.Net.Security.Native.so.dbg"), "other.dbg"));
        var native = rig.Workspace.LoadAny(image).Native!;
        var refused = await rig.Pdbs.Load(native, rig.Dir.File("other.dbg"), false, null, false, TimeSpan.FromSeconds(5), 1 << 20, default);
        Assert.Null(refused.State);
        Assert.Contains(refused.Location.Probes, p => p.Location == rig.Dir.File("other.dbg") && p.Outcome.StartsWith("different build (build-id"));
        var forced = await rig.Pdbs.Load(native, rig.Dir.File("other.dbg"), false, null, true, TimeSpan.FromSeconds(5), 1 << 20, default);
        Assert.False(forced.State!.Verified);
    }

    [Fact]
    public async Task A_folder_in_the_debug_dirs_variable_is_searched()
    {
        using var rig = new Rig();
        var image = rig.Copy((Elf(), Path.Combine("bin", Library)));
        var native = rig.Workspace.LoadAny(image).Native!;
        var id = native.Image.BuildId!;
        rig.Copy((Elf(Library + ".dbg"), Path.Combine("debug", ".build-id", id[..2], id[2..] + ".debug")));
        var saved = Environment.GetEnvironmentVariable(DwarfLocator.DirsVariable);
        Environment.SetEnvironmentVariable(DwarfLocator.DirsVariable, rig.Dir.File("nowhere") + Path.PathSeparator + rig.Dir.File("debug"));
        try { Assert.Equal(rig.Dir.File(Path.Combine("debug", ".build-id", id[..2], id[2..] + ".debug")), DwarfLocator.Locate(native.Image, image).Path); }
        finally { Environment.SetEnvironmentVariable(DwarfLocator.DirsVariable, saved); }
    }

    [Fact]
    public void Without_a_build_id_the_debuglink_crc_picks_the_debug_file()
    {
        using var rig = new Rig();
        // the image's GNU build-id note renamed, so only its .gnu_debuglink (name and CRC-32) identifies the debug file
        var bytes = File.ReadAllBytes(Elf());
        int note = bytes.AsSpan().IndexOf((ReadOnlySpan<byte>)[4, 0, 0, 0, 20, 0, 0, 0, 3, 0, 0, 0, (byte)'G', (byte)'N', (byte)'U', 0]);
        Assert.True(note >= 0, "no build-id note");
        bytes[note + 12] = (byte)'X';
        var image = rig.Dir.File(Library);
        File.WriteAllBytes(image, bytes);
        var native = rig.Workspace.LoadAny(image).Native!;
        Assert.Null(native.Image.BuildId);
        rig.Copy((Elf(Library + ".dbg"), Library + ".dbg"));
        Assert.Equal(image + ".dbg", DwarfLocator.Locate(native.Image, image).Path);
        rig.Copy((Elf("libSystem.Net.Security.Native.so.dbg"), Library + ".dbg"));
        var other = DwarfLocator.Locate(native.Image, image);
        Assert.Null(other.Path);
        Assert.Contains(other.Probes, p => p.Outcome.StartsWith("different build (CRC-32", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Resolve_address_shows_source_lines_and_inlined_functions()
    {
        using var rig = new Rig();
        var image = rig.Copy((Elf(), Library), (Elf(Library + ".dbg"), Library + ".dbg"));
        var native = rig.Workspace.LoadAny(image).Native!;
        await rig.Code.Index(native, null, default);
        uint strErrorR = PdbService.StateOf(native)!.Pdb.Symbols.Single(s => s.Name == "SystemNative_StrErrorR").Rva!.Value;
        var tools = new Corvus.Tools.NativeTools(rig.Workspace, new OutputPager(rig.Options), rig.Code);
        var collector = Corvus.Mcp.ToolOutput.Collect();
        var text = await tools.ResolveAddress(native.Id, $"rva:0x{strErrorR + 4:X}");
        var info = Assert.IsType<Corvus.Tools.AddressInfo>(collector.Value);
        Assert.EndsWith("System.Native/pal_errno.c:17", info.Source);
        Assert.Equal(2, info.Inlined!.Count);
        Assert.StartsWith("StrErrorR at ", info.Inlined[0]);
        Assert.Matches("^SystemNative_StrErrorR at .*pal_errno.c:18$", info.Inlined[1]);
        Assert.Contains("  source ", text);
    }

    [Fact]
    public async Task A_dsym_bundle_beside_a_mach_o_image_is_found_by_uuid()
    {
        using var rig = new Rig();
        const string dylib = "libSystem.Native.dylib";
        var image = rig.Copy((NativeFixtures.NativeAotLib("osx-arm64", dylib), dylib),
            (NativeFixtures.NativeAotLib("osx-arm64", dylib + ".dwarf"), Path.Combine(dylib + ".dSYM", "Contents", "Resources", "DWARF", dylib)));
        var native = rig.Workspace.LoadAny(image).Native!;
        var index = await rig.Code.Index(native, null, default);
        var state = PdbService.StateOf(native)!;
        Assert.True(state.Verified);
        Assert.Contains(".dSYM", state.Path);
        Assert.Equal(native.Image.BuildId, state.Pdb.BuildId);
        var fstat = state.Pdb.Symbols.Single(s => s.Name == "SystemNative_FStat");
        Assert.Equal(("SystemNative_FStat", NativeNameSource.Pdb), index.Sourced.NameAt(fstat.Rva!.Value));
    }

    [Fact]
    public async Task An_image_with_its_own_dwarf_sections_needs_no_debug_file()
    {
        using var rig = new Rig();
        // a debug file is itself an ELF image that keeps the DWARF sections
        var image = rig.Copy((Elf(Library + ".dbg"), "unstripped.so"));
        var native = rig.Workspace.LoadAny(image).Native!;
        await rig.Code.Index(native, null, default);
        var state = PdbService.StateOf(native)!;
        Assert.Equal(image, state.Path);
        Assert.Contains(state.Probes, p => p.Outcome == DwarfLocator.Embedded);
        Assert.Equal(273, state.Pdb.Symbols.Count(s => s.IsFunction));
    }

    [Fact]
    public async Task Load_pdb_names_are_restored_when_the_image_loads_again()
    {
        var annotations = Path.Combine(Path.GetTempPath(), "corvus-test-" + Guid.NewGuid().ToString("N"));
        try
        {
            string image;
            using (var first = new Rig(annotations))
            {
                image = first.Copy((Elf(), Library), (Elf(Library + ".dbg"), Path.Combine("elsewhere", "x.debug")));
                var native = first.Workspace.LoadAny(image).Native!;
                await first.Code.Index(native, null, default);
                Assert.Null(PdbService.StateOf(native));
                var r = await first.Pdbs.Load(native, first.Dir.File(Path.Combine("elsewhere", "x.debug")), false, null, false, TimeSpan.FromSeconds(5), 1 << 20, default);
                Assert.Null(r.SaveProblem);
                // the same file in a new session: the saved layer reopens the debug file
                using var second = new Rig(annotations);
                var again = second.Workspace.LoadAny(image).Native!;
                var index = await second.Code.Index(again, null, default);
                Assert.Equal(("SystemNative_FStat", NativeNameSource.Pdb), index.Sourced.NameAt(FStat));
                Assert.True(PdbService.StateOf(again)!.Verified);
            }
        }
        finally { try { Directory.Delete(annotations, true); } catch (IOException) { } }
    }

    private sealed class FakeDebuginfod(byte[] file, string id) : HttpMessageHandler
    {
        public readonly List<string> Asked = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Asked.Add(request.RequestUri!.AbsolutePath);
            return Task.FromResult(request.RequestUri.AbsolutePath == $"/buildid/{id}/debuginfo"
                ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(file) }
                : new HttpResponseMessage(HttpStatusCode.NotFound));
        }
    }

    [Fact]
    public async Task Debuginfod_downloads_the_debug_file_by_build_id()
    {
        using var dir = new TempDir();
        var image = NativeImageLoader.Open(Elf());
        var server = new FakeDebuginfod(File.ReadAllBytes(Elf(Library + ".dbg")), image.BuildId!);
        var path = await DwarfLocator.DownloadAsync(image, "https://debuginfod.example/", TimeSpan.FromSeconds(10), 1 << 24, server, dir.File("cache"));
        Assert.Equal(Path.Combine(dir.File("cache"), image.BuildId!, "debuginfo"), path);
        Assert.Null(DwarfLocator.Check(path, image));
        Assert.Equal([$"/buildid/{image.BuildId}/debuginfo"], server.Asked);
        // a server answering with another build's file: refused and not kept
        var wrong = new FakeDebuginfod(File.ReadAllBytes(Elf("libSystem.Net.Security.Native.so.dbg")), image.BuildId!);
        var error = await Assert.ThrowsAsync<ToolError>(() => DwarfLocator.DownloadAsync(image, "https://other.example", TimeSpan.FromSeconds(10), 1 << 24, wrong, dir.File("cache2")));
        Assert.Equal(ErrorCode.MalformedInput, error.Code);
        Assert.Empty(Directory.GetFiles(dir.File("cache2"), "*", SearchOption.AllDirectories));
    }
}
