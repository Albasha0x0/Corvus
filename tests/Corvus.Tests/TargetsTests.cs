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
    public void AnUnloadedPathLoadsWithANotice()
    {
        var (dir, managed, native) = Files();
        using var _ = dir;
        using var ws = new AssemblyWorkspace();
        var target = Targets.Resolve(ws, managed, TargetKind.Assembly);
        Assert.Equal("TestFixture", target.Assembly!.Id);
        Assert.Equal($"loaded TestFixture from {managed}", target.Notice);
        // loaded now: by path, file name or id, no second notice
        Assert.Null(Targets.Resolve(ws, managed, TargetKind.Assembly).Notice);
        Assert.Same(target.Assembly, Targets.Resolve(ws, "TestFixture.dll", TargetKind.Any).Assembly);

        var image = Targets.Native(ws, native);
        Assert.Equal("native.dll", image.Id);
        Assert.Contains($"loaded native.dll from {native}", ws.DrainNotices());
    }

    [Fact]
    public void ARelativePathResolvesAgainstTheServerDirectory()
    {
        var (dir, managed, _) = Files();
        using var _d = dir;
        var relative = Path.GetRelativePath(Environment.CurrentDirectory, managed);
        if (Path.IsPathRooted(relative)) return; // another drive: no relative form
        using var ws = new AssemblyWorkspace();
        Assert.Equal(managed, Targets.Assembly(ws, relative).FilePath);
    }

    [Fact]
    public void AMissingPathIsTheSameNotFoundForEveryKind()
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
    public void TheOtherKindIsUnsupportedNamingTheFamily()
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
    public void ANameWithNothingLoadedIsNotLoadedWithALoadNext()
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
    public void PreResolveLoadsTargetParametersOnly()
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
    }
}
