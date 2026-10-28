using System.Text;
using Corvus.Core;
using Corvus.Native.Dump;
using Corvus.Native.Dwarf;
using Corvus.Native.Elf;
using Corvus.Native.Linking;
using Corvus.Native.Pdb;
using Corvus.Native.Pe;
using Corvus.Services;
using Corvus.Services.Web;
using Corvus.Tests.NativeFormats;

namespace Corvus.Tests;

/// <summary>Paths found inside an analyzed file are checked before any probe; remote and device paths are reported as not opened.</summary>
public class NamedPathTests
{
    private const string Share = @"\\corvus-remote.invalid\share";

    [Fact]
    public void A_network_codeview_path_is_not_opened_and_an_own_pdb_matches()
    {
        using var dir = new TempDir();
        var guid = Guid.NewGuid();
        var own = dir.File(Path.Combine("build", "own.pdb"));
        Directory.CreateDirectory(Path.GetDirectoryName(own)!);
        File.WriteAllBytes(own, PdbBuilder.Sample(guid: guid).Build());
        Directory.CreateDirectory(dir.File("bin"));
        var local = dir.File(Path.Combine("bin", "local.dll"));
        File.WriteAllBytes(local, PdbTests.TinyImage(guid, 3, pdbPath: own));
        Assert.Equal(own, PdbLocator.Locate(PeFile.Open(local), symbolPath: "").Path);

        if (!OperatingSystem.IsWindows()) return;
        var remote = dir.File(Path.Combine("bin", "remote.dll"));
        File.WriteAllBytes(remote, PdbTests.TinyImage(guid, 3, pdbPath: Share + @"\remote.pdb"));
        var location = PdbLocator.Locate(PeFile.Open(remote), symbolPath: "");
        Assert.Null(location.Path);
        Assert.Equal(InputFiles.NotOpenedNetwork, Assert.Single(location.Probes, p => p.Location.StartsWith(Share, StringComparison.Ordinal)).Outcome);
    }

    public static TheoryData<string, string> DebugLinks() => OperatingSystem.IsWindows()
        ? new() { { Share + @"\app.debug", InputFiles.NotOpenedNetwork }, { @"\\.\NUL", InputFiles.NotOpenedDevice } }
        : new() { { "/dev/zero", InputFiles.NotOpenedDevice } };

    [Theory]
    [MemberData(nameof(DebugLinks))]
    public void A_debug_link_to_a_network_or_device_path_is_not_opened(string link, string outcome)
    {
        using var dir = new TempDir();
        var data = new byte[0x100];
        Encoding.UTF8.GetBytes(link).CopyTo(data, 0);
        var path = dir.File("app.so");
        File.WriteAllBytes(path, new ElfWriter { DataSectionName = ".gnu_debuglink", Data = data }.Build());
        var image = ElfFile.Open(path);
        var location = DwarfLocator.Locate(image, path);
        Assert.Null(location.Path);
        var probe = Assert.Single(location.Probes, p => p.Location == link);
        Assert.Equal(outcome, probe.Outcome);
    }

    [Fact]
    public void A_source_map_url_on_a_network_path_is_not_opened()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var dir = new TempDir();
        var path = dir.File("app.js");
        File.WriteAllText(path, "console.log(1);\n//# sourceMappingURL=//corvus-remote.invalid/share/app.js.map\n");
        var summary = JsAnalysis.Summary(path);
        Assert.Null(summary.SourceMap);
        Assert.Contains($"source map: the map {Share}\\app.js.map is {InputFiles.NotOpenedNetwork}.", summary.Notes);
        Assert.DoesNotContain(summary.Notes, n => n.StartsWith("No source map", StringComparison.Ordinal));
        Assert.Equal(ErrorCode.AccessDenied, Assert.Throws<ToolError>(() => JsAnalysis.Map(path)).Code);
    }

    [Fact]
    public void A_dump_module_on_a_network_path_is_not_opened_and_a_local_image_matches()
    {
        using var dir = new TempDir();
        var path = dir.File("app.dll");
        var bytes = PdbTests.TinyImage(Guid.NewGuid(), 1);
        File.WriteAllBytes(path, bytes);
        Assert.True(DumpImages.TryHeader(bytes, out uint stamp, out uint size, out _));
        var local = DumpImages.Find(new DumpModule(0x10000, size, 0, stamp, path, null, null, null), []);
        Assert.True(local.Matches);
        Assert.Equal(path, local.Path);

        if (!OperatingSystem.IsWindows()) return;
        var remote = DumpImages.Find(new DumpModule(0x10000, size, 0, stamp + 1, Share + @"\remote.dll", null, null, null), [dir.Path]);
        Assert.False(remote.Matches);
        Assert.Equal(InputFiles.NotOpenedNetwork, remote.Detail);
    }

    [Fact]
    public void An_import_named_by_a_network_or_device_path_is_not_opened()
    {
        using var dir = new TempDir();
        var named = OperatingSystem.IsWindows() ? Share + @"\lib.so" : "/dev/zero";
        var expected = OperatingSystem.IsWindows() ? InputFiles.NotOpenedNetwork : InputFiles.NotOpenedDevice;
        var (file, searched, _) = UnixProbing.Locate(named, dir.Path, new TargetPlatform("linux", "linux-x64", "test"));
        Assert.Null(file);
        Assert.Contains($"{named} ({expected})", searched);

        if (!OperatingSystem.IsWindows()) return;
        var opened = new List<string>();
        var linker = new NativeLinker(p => { opened.Add(p); return null; });
        var result = linker.Bind(Share + @"\lib.dll", dir.File("app.exe"), false, "Run", null, "import");
        Assert.Equal(NativeLinker.NotOpened, result.Status);
        Assert.Contains(InputFiles.NotOpenedNetwork, result.Detail);
        Assert.Empty(opened);
    }

    [Fact]
    public void A_reference_name_holding_a_path_is_never_looked_up_as_a_file()
    {
        using var workspace = new AssemblyWorkspace(new ServerOptions());
        Assert.Null(workspace.LocateReference(Share + @"\Lib", null, null, Env.FixturePath, false));
        Assert.Null(workspace.LocateReference("../Lib", null, null, Env.FixturePath, false));
        Assert.Null(InputFiles.NamedNameProblem("System.Runtime"));
        Assert.Equal("not opened: not a file name", InputFiles.NamedNameProblem("../Lib"));
        if (OperatingSystem.IsWindows()) Assert.Equal(InputFiles.NotOpenedNetwork, InputFiles.NamedNameProblem(Share + @"\Lib"));
    }

    [Fact]
    public async Task An_unlisted_symbol_server_is_refused_before_any_connection()
    {
        using var dir = new TempDir();
        using var env = new Env();
        var pdbs = new PdbService(new NativeCodeService(env.Workspace, env.Options, null, new Corvus.Native.Annotations.AnnotationStore(dir.File("ann"))));
        var path = dir.File("tiny.dll");
        File.WriteAllBytes(path, PdbTests.TinyImage(Guid.NewGuid(), 1));
        var native = env.Workspace.LoadAny(path).Native!;
        var error = await Assert.ThrowsAsync<ToolError>(() =>
            pdbs.Load(native, null, true, "https://corvus-remote.invalid/symbols", false, TimeSpan.FromSeconds(5), 1 << 20, default));
        Assert.Equal(ErrorCode.InvalidArgument, error.Code);
        Assert.StartsWith("server 'https://corvus-remote.invalid/symbols' is not a configured symbol server", error.Message);
        PdbLocator.RequireConfigured("https://sym.example/store/", ["https://sym.example/store"], "_NT_SYMBOL_PATH");
        Assert.Contains(PdbLocator.DefaultServer, PdbLocator.ConfiguredServers());
    }
}
