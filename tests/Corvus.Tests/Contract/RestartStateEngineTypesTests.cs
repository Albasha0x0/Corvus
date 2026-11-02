using Corvus.Core;
using Corvus.Native.Annotations;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>The engine type tools restore the saved user types after a restart.</summary>
public sealed class RestartStateEngineTypesTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly List<IDisposable> _owned = [];

    public void Dispose()
    {
        foreach (var d in _owned) d.Dispose();
        _dir.Dispose();
    }

    /// <summary>One server process on a shared annotation folder.</summary>
    private async Task<(NativeTypeTools Tools, NativeTypeEditTests.ScriptedProvider Engine, NativeCodeService Code, LoadedNative Native, string Function)> Start()
    {
        var options = new ServerOptions { BackgroundIndexing = false };
        var workspace = new AssemblyWorkspace(options);
        var code = new NativeCodeService(workspace, options, null, new AnnotationStore(_dir.File("annotations")));
        var engine = new NativeTypeEditTests.ScriptedProvider();
        var engines = new NativeEngineService([engine], _dir.File("cache"), code, workspace, options);
        _owned.Add(engines);
        _owned.Add(workspace);
        var native = workspace.LoadAny(McpProtocolTests.NativeSample(_dir)).Native!;
        await code.Index(native, null, default);
        return (new NativeTypeTools(workspace, engines, new NativeUserTypePush(code), code), engine, code, native, $"rva:0x{code.Ready(native)!.Functions[0].Start:X}");
    }

    // The second process never repeats the edits.
    [Fact]
    public async Task Engine_type_tools_restore_the_saved_user_types_into_a_new_session()
    {
        var (tools, _, code, native, function) = await Start();
        await tools.DeclareNativeTypes(native.Id, "struct Packet { int length; };");
        await tools.SetNativeType(native.Id, function, "int __fastcall Parse(Packet *p, int len)");
        await tools.SetNativeLocal(native.Id, function, "v1", newName: "sample_local");
        await tools.SetNativeStackVar(native.Id, function, "var_10", newName: "buffer", type: "char[4]");
        await tools.DefineNative(native.Id, function, "function");
        await tools.SetNativeOperand(native.Id, function, 0, "hex");
        var firstLayer = code.Annotations(native).UserTypes;
        Assert.False(firstLayer.IsEmpty);
        var first = await tools.ListNativeTypes(native.Id, name: "Packet");
        var firstFrame = await tools.GetNativeFrame(native.Id, function);

        var (again, restarted, restoredCode, restoredNative, _) = await Start();
        Assert.Equal(firstLayer.Stamp, restoredCode.Annotations(restoredNative).UserTypes.Stamp);
        var second = await again.ListNativeTypes(restoredNative.Id, name: "Packet");
        Assert.Equal(first, second);
        Assert.Equal(firstFrame, await again.GetNativeFrame(restoredNative.Id, function));
        // The new session received the saved layer once, without a repeated edit.
        var batch = Assert.Single(restarted.Batches);
        Assert.Equal(firstLayer.ToBatch().Declarations, batch.Declarations);
        Assert.Equal(firstLayer.ToBatch().Types.Count, batch.Types.Count);
        Assert.Single(batch.Types);
        Assert.Single(batch.Locals);
        Assert.Single(batch.StackVars);
        Assert.Single(batch.Analysis);
        Assert.Single(batch.Operands);
    }
}
