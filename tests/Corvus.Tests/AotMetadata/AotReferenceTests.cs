using Corvus.Core;
using Corvus.Native.Annotations;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>find_references and find_callees on dummy methods whose native code is a loaded binary.</summary>
public sealed class AotReferenceTests : IDisposable
{
    private readonly TempDir _dir = new();
    private NativeLinkService? _link;

    public void Dispose() => _dir.Dispose();

    /// <summary>First (RVA 0x1000) calls Second (RVA 0x1100); the binary is optionally loaded.</summary>
    private async Task<(Env Env, ReferenceTools Tools)> Rig(bool loadBinary, bool warm = true, bool skipEntry = false)
    {
        var dump = Path.Combine(_dir.Path, "dump");
        var dummies = Path.Combine(dump, "DummyDll");
        Directory.CreateDirectory(dummies);
        var dll = Path.Combine(dummies, Path.GetFileName(Env.FixturePath));
        File.Copy(Env.FixturePath, dll);
        File.WriteAllText(Path.Combine(dump, "script.json"), """{ "Addresses": [ 4096, 4352 ] }""");
        var text = new byte[0x400];
        // First: call Second; ret. Second: ret.
        byte[] first = [0xE8, 0xFB, 0x00, 0x00, 0x00, 0xC3];
        first.CopyTo(text, 0);
        text[0x100] = 0xC3;
        // The reader matches this file name literally.
        var binary = Path.Combine(dump, "GameAssembly.dll");
        var image = AotStringTests.Pe64([(".text", 0x1000, text, 0x60000020), (".data", 0x5000, new byte[0x100], 0xC0000040)]);
        // The entry point seeds function discovery at First.
        if (!skipEntry) System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(0x68), 0x1000);
        File.WriteAllBytes(binary, image);
        var env = new Env(dll);
        if (loadBinary) env.Workspace.LoadAny(binary);
        var code = new NativeCodeService(env.Workspace, new ServerOptions { BackgroundIndexing = false }, null, new AnnotationStore(_dir.File("ann")));
        var link = new NativeLinkService(env.Workspace, code, env.AotNavigator);
        _link = link;
        if (loadBinary && warm) await link.WarmUp(null, default);
        return (env, new ReferenceTools(env.Workspace, env.References, link));
    }

    private async Task<(Env Env, ReferenceTools Tools, NativeLinkService Link)> Rig3(bool warm)
    {
        var (env, tools) = await Rig(loadBinary: true, warm: warm);
        return (env, tools, _link!);
    }

    private const string FirstVa = "180001000", SecondVa = "180001100";

    [Fact]
    public async Task A_placeholder_method_lists_its_native_caller_and_callee()
    {
        var (env, tools) = await Rig(loadBinary: true);
        using var _ = env;
        var refs = await tools.FindReferences("Fixture.Native.NativeThing::Second");
        Assert.Contains("native call", refs);
        Assert.Contains(FirstVa, refs);
        Assert.DoesNotContain("load the assemblies", refs);
        var callees = await tools.FindCallees("Fixture.Native.NativeThing::First");
        Assert.Contains("generated placeholder", callees);
        Assert.Contains(SecondVa, callees);
    }

    [Fact]
    public async Task A_placeholder_method_without_its_binary_names_the_missing_binary()
    {
        var (env, tools) = await Rig(loadBinary: false);
        using var _ = env;
        var refs = await tools.FindReferences("Fixture.Native.NativeThing::Second");
        Assert.Contains("native binary is not loaded", refs);
        Assert.DoesNotContain("load the assemblies", refs);
    }

    [Fact]
    public async Task A_placeholder_method_names_the_code_index_still_building()
    {
        var (env, _, link) = await Rig3(warm: false);
        using var _ = env;
        var method = env.Workspace.Assemblies[0].Module.GetTypes()
            .First(t => t.FullName == "Fixture.Native.NativeThing")
            .Methods.First(m => m.Name == "Second");
        Assert.Contains("still building", link.PlaceholderGap(method));
    }

    [Fact]
    public async Task Callees_of_a_placeholder_method_without_its_binary_are_marked_unknown()
    {
        var (env, tools) = await Rig(loadBinary: false);
        using var _ = env;
        var callees = await tools.FindCallees("Fixture.Native.NativeThing::First");
        Assert.Contains("native callees unknown", callees);
    }

    [Fact]
    public async Task A_placeholder_method_without_a_function_at_its_address_is_named()
    {
        var (env, tools) = await Rig(loadBinary: true, skipEntry: true);
        using var _ = env;
        var callees = await tools.FindCallees("Fixture.Native.NativeThing::Second");
        Assert.Contains("no function starts at", callees);
        Assert.Contains(SecondVa, callees);
    }

    [Fact]
    public async Task A_placeholder_method_without_callers_says_none_in_the_native_code()
    {
        var (env, tools) = await Rig(loadBinary: true);
        using var _ = env;
        var refs = await tools.FindReferences("Fixture.Native.NativeThing::First");
        Assert.Contains("or in the native code", refs);
    }

    [Fact]
    public async Task A_method_without_an_address_keeps_the_load_assemblies_hint()
    {
        var (env, tools) = await Rig(loadBinary: true);
        using var _ = env;
        var refs = await tools.FindReferences("Fixture.Native.NativeThing::.ctor");
        Assert.Contains("none found", refs);
        Assert.DoesNotContain("native", refs);
    }
}
