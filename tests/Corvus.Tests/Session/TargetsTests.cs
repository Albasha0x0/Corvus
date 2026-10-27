using System.Text.Json;
using Corvus.Core;

namespace Corvus.Tests;

/// <summary>The one target resolver: loaded names, unloaded paths, missing paths, the other kind, nothing loaded.</summary>
public class TargetsTests
{
    private static (TempDir Dir, string Managed, string Native) Files()
    {
        var dir = new TempDir();
        var managed = dir.File("TestFixture.dll");
        File.Copy(Env.FixturePath, managed);
        var native = dir.File("native.dll");
        File.WriteAllBytes(native, NativePeTests.KitchenSink(is64: true));
        return (dir, managed, native);
    }

    [Fact]
    public void An_unloaded_path_loads_with_a_notice()
    {
        var (dir, managed, native) = Files();
        using var _ = dir;
        using var ws = new AssemblyWorkspace();
        var target = Targets.Resolve(ws, managed, TargetKind.Assembly);
        Assert.Equal("TestFixture", target.Assembly!.Id);
        Assert.Equal($"loaded TestFixture from {managed}", target.Notice);
        // Loaded now: by path, file name or id, no second notice.
        Assert.Null(Targets.Resolve(ws, managed, TargetKind.Assembly).Notice);
        Assert.Same(target.Assembly, Targets.Resolve(ws, "TestFixture.dll", TargetKind.Any).Assembly);

        var image = Targets.Native(ws, native);
        Assert.Equal("native.dll", image.Id);
        Assert.Contains($"loaded native.dll from {native}", ws.DrainNotices());
    }

    [Fact]
    public void A_relative_path_resolves_against_the_server_directory()
    {
        var (dir, managed, _) = Files();
        using var _d = dir;
        var relative = Path.GetRelativePath(Environment.CurrentDirectory, managed);
        if (Path.IsPathRooted(relative)) return; // another drive: no relative form
        using var ws = new AssemblyWorkspace();
        Assert.Equal(managed, Targets.Assembly(ws, relative).FilePath);
    }

    [Fact]
    public void A_missing_path_is_the_same_not_found_for_every_kind()
    {
        using var dir = new TempDir();
        using var ws = new AssemblyWorkspace();
        var missing = dir.File("nope.dll");
        foreach (var call in new Action[]
                 {
                     () => Targets.Resolve(ws, missing, TargetKind.Assembly), () => Targets.Resolve(ws, missing, TargetKind.Native),
                     () => Targets.Prepare(ws, missing), () => ws.Read(() => ws.Get(missing)), () => ws.Read(() => ws.GetNative(missing)),
                     () => ws.Load(missing),
                 })
        {
            var e = Assert.Throws<ToolError>(call);
            Assert.Equal(ErrorCode.NotFound, e.Code);
            Assert.Equal($"File not found: '{missing}'", e.Message);
            Assert.Equal(Targets.FileNotFoundNext, e.Remediation);
        }
    }

    [Fact]
    public void The_other_kind_is_unsupported_naming_the_family()
    {
        var (dir, managed, native) = Files();
        using var _ = dir;
        using var ws = new AssemblyWorkspace();
        var e = Assert.Throws<ToolError>(() => Targets.Native(ws, managed));
        Assert.Equal(ErrorCode.Unsupported, e.Code);
        Assert.Contains(".NET tools", e.Remediation);
        e = Assert.Throws<ToolError>(() => Targets.Assembly(ws, native));
        Assert.Equal(ErrorCode.Unsupported, e.Code);
        Assert.Contains("native tools", e.Remediation);
    }

    [Fact]
    public void A_name_with_nothing_loaded_is_not_loaded_with_a_load_next()
    {
        using var ws = new AssemblyWorkspace();
        var e = Assert.Throws<ToolError>(() => Targets.Assembly(ws, "Contoso.Core"));
        Assert.Equal(ErrorCode.NotLoaded, e.Code);
        Assert.Equal("load_assembly path=Contoso.Core", e.Remediation);
        e = Assert.Throws<ToolError>(() => Targets.Native(ws, "app.dll"));
        Assert.Equal(ErrorCode.NotLoaded, e.Code);
        Assert.Equal("load_assembly path=app.dll", e.Remediation);
    }

    [Fact]
    public void Pre_resolution_loads_target_parameters_only()
    {
        var (dir, managed, native) = Files();
        using var _ = dir;
        using var ws = new AssemblyWorkspace();
        static Dictionary<string, JsonElement> Args(params (string Name, object Value)[] args) =>
            args.ToDictionary(a => a.Name, a => JsonSerializer.SerializeToElement(a.Value));
        Targets.PreResolve(ws, "patch_asm", Args(("image", "x"), ("assembly", managed)));
        Targets.PreResolve(ws, "unload_assembly", Args(("assembly", managed)));
        Targets.PreResolve(ws, "list_types", Args(("path", managed), ("filter", managed)));
        Assert.Equal(0, ws.LoadedCount);
        Targets.PreResolve(ws, "compare_native_images", Args(("oldImage", native), ("newImage", "native.dll")));
        Targets.PreResolve(ws, "list_types", Args(("images", new[] { managed })));
        Assert.Equal(2, ws.Read(() => ws.Assemblies.Count + ws.Natives.Count(n => n.ManagedView == null)));
        Assert.Throws<ToolError>(() => Targets.PreResolve(ws, "list_types", Args(("assembly", dir.File("gone/x.dll")))));
        // A package path is left to the tool (export_project writes a Gradle project from an .apk).
        var apk = dir.File("app.apk");
        File.WriteAllBytes(apk, [0x50, 0x4B, 0x05, 0x06, .. new byte[18]]);
        Targets.PreResolve(ws, "export_project", Args(("assembly", apk)));
        // Images as a list in one string, ';' or ',' separated.
        var second = dir.File("second.dll");
        File.WriteAllBytes(second, NativePeTests.KitchenSink(is64: false));
        Targets.PreResolve(ws, "symbolize_stack_text", Args(("images", $"native.dll; {second}")));
        Assert.NotNull(ws.Read(() => ws.FindNative(second)));
    }

    [Fact]
    public void A_file_of_the_other_kind_names_the_tools_that_read_it()
    {
        var (dir, _, native) = Files();
        using var _d = dir;
        using var ws = new AssemblyWorkspace();
        var inspection = new Corvus.Services.Analysis.InspectionService(ws);
        var e = Assert.Throws<ToolError>(() => inspection.ExtractStrings(null, native, null, default));
        Assert.Equal(ErrorCode.Unsupported, e.Code);
        Assert.StartsWith($"this tool reads .NET metadata; for a native image: search_native_strings image={native}", e.Remediation);
        var zip = dir.File("app.apk");
        File.WriteAllBytes(zip, [0x50, 0x4B, 0x05, 0x06, .. new byte[18]]); // an empty zip
        e = Assert.Throws<ToolError>(() => inspection.ExtractEmbedded(null, zip, false, null, false, default));
        Assert.Equal(ErrorCode.Unsupported, e.Code);
        Assert.StartsWith($"unpack_container path={zip}", e.Remediation);
    }

    [Fact]
    public void An_assembly_over_the_cap_is_refused_before_it_is_read()
    {
        var e = Assert.Throws<ToolError>(() => AssemblyWorkspace.CheckSize("big.dll", AssemblyWorkspace.MaxAssemblyBytes + 1));
        Assert.Equal(ErrorCode.LimitExceeded, e.Code);
        Assert.Contains($"{AssemblyWorkspace.MaxAssemblyBytes:N0} bytes", e.Message);
        AssemblyWorkspace.CheckSize("ok.dll", AssemblyWorkspace.MaxAssemblyBytes);

        using var dir = new TempDir();
        var big = dir.File("big.dll");
        using (var f = File.Create(big)) f.SetLength(AssemblyWorkspace.MaxAssemblyBytes + 1); // a length only, never written
        using var ws = new AssemblyWorkspace();
        Assert.Equal(ErrorCode.LimitExceeded, Assert.Throws<ToolError>(() => ws.Load(big)).Code);
    }
}
