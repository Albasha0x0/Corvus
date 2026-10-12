using Corvus.Core;
using Corvus.Native.Annotations;
using Corvus.Native.Code;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests.NativeFormats;

/// <summary>The objc and swift layers are built with the code index, rank below the user's names and are what engines receive.</summary>
public sealed class AppleNameLayerTests
{
    private static async Task<(LoadedNative Native, NativeCodeIndex Index, NativeCodeService Code, AssemblyWorkspace Ws)> Load(TempDir dir, byte[] bytes)
    {
        var path = dir.File("image.dylib");
        File.WriteAllBytes(path, bytes);
        var ws = new AssemblyWorkspace();
        var native = ws.LoadAny(path).Native!;
        var code = new NativeCodeService(ws, new ServerOptions { BackgroundIndexing = false }, annotations: new AnnotationStore(dir.File("ann")));
        return (native, await code.Index(native, null, default), code, ws);
    }

    [Fact]
    public async Task ObjcLayer_NamesMethodsClassesAndReferences()
    {
        using var dir = new TempDir();
        var (bytes, layout) = AppleObjcTests.Sample();
        var (native, index, code, ws) = await Load(dir, bytes);
        using var _ = ws;
        Assert.Equal("-[Animal speak]", index.NameAt(0x1010));
        Assert.Equal("+[Animal create]", index.NameAt(0x1030));
        Assert.Equal("-[NSString(Fancy) fancyString]", index.NameAt(0x1050));
        Assert.Equal(NativeNameSource.ObjC, index.Sourced.NameAt(0x1010)!.Value.Source);
        Assert.Equal("ObjC instance method of Animal; types v16@0:8", index.CommentFor(0x1010));
        Assert.NotNull(index.FunctionByStart(0x1040));
        Assert.Equal("_OBJC_CLASS_$_Animal", index.NameAt(layout["Animal"]));
        Assert.Equal("_OBJC_METACLASS_$_Dog", index.NameAt(layout["Dog.meta"]));
        Assert.Equal("_OBJC_IVAR_$_Animal._age", index.NameAt(layout["ivar:_age"]));
        Assert.Equal("selRef_create", index.NameAt(layout["selref:create"]));
        Assert.Equal("_OBJC_PROTOCOL_$_Pet", index.NameAt(layout["Pet"]));

        // engines receive the layer; a user name wins at its address
        code.Annotations(native).SetName(0x1010, "my_speak");
        index.SetUserName(0x1010, "my_speak");
        Assert.Equal("my_speak", index.NameAt(0x1010));
        var effective = NativeNamePush.Effective(code.Annotations(native), NativeNameLayers.Of(native).Layers, native.Image);
        Assert.Equal("my_speak", effective[0x1010].Name);
        Assert.Equal(("-[Dog bark]", true), (effective[0x1040].Name, effective[0x1040].Function));
    }

    [Fact]
    public async Task SwiftLayer_MangledNamesShownDemangled()
    {
        using var dir = new TempDir();
        var (bytes, layout) = AppleSwiftTests.Sample();
        var (native, index, _, ws) = await Load(dir, bytes);
        using var _ = ws;
        Assert.Equal("_$s3Zoo6KeeperC4feedyyF", index.NameAt(0x1080));
        Assert.Equal(NativeNameSource.Swift, index.Sourced.NameAt(0x1080)!.Value.Source);
        Assert.Equal("Zoo.Keeper.feed() -> ()", NativeTools.DisplayName(index.NameAt(0x1080)!, native.Image.Format));
        Assert.Equal("type metadata accessor for Zoo.Animal", NativeTools.DisplayName(index.NameAt(0x1060)!, native.Image.Format));
        Assert.Equal("_$s3Zoo6AnimalVMn", index.NameAt(layout["Animal"]));
        Assert.StartsWith("Swift struct Zoo.Animal; fields:", index.CommentFor(layout["Animal"]));
    }

    [Fact]
    public async Task AutoApply_CanBeTurnedOff()
    {
        using var dir = new TempDir();
        Environment.SetEnvironmentVariable(AppleNames.AutoVariable, "0");
        try
        {
            var (_, index, _, ws) = await Load(dir, AppleObjcTests.Sample().Bytes);
            using var _ = ws;
            Assert.Null(index.Sourced.NameAt(0x1010));
        }
        finally { Environment.SetEnvironmentVariable(AppleNames.AutoVariable, null); }
    }
}
