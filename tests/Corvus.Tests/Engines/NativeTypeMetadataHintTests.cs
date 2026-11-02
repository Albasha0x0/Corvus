using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Annotations;
using Corvus.Native.Providers;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>list_native_types names where a type's layout is when the engine lists none and the filter matches a metadata type.</summary>
public sealed class NativeTypeMetadataHintTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly List<IDisposable> _owned = [];

    public void Dispose()
    {
        foreach (var d in _owned) d.Dispose();
        _dir.Dispose();
    }

    private async Task<(NativeTypeTools Tools, string Id)> Setup(bool applyMetadata)
    {
        var (dll, binary) = AotNativeNamesTests.CreateDump(_dir);
        var env = new Env(dll);
        _owned.Add(env);
        var engine = new ScriptedEngine();
        engine.Types.Add(new NativeTypeEntry("Header", "struct", 8, 2));
        var engines = new NativeEngineService([engine], _dir.File("cache"), null, env.Workspace, env.Options);
        _owned.Add(engines);
        var code = new NativeCodeService(env.Workspace, env.Options, null, new AnnotationStore(_dir.File("ann")));
        var native = env.Workspace.LoadAny(binary).Native!;
        if (applyMetadata)
        {
            var index = await code.Index(native, null, default);
            new AotNativeNames(env.AotMetadata, env.AotNavigator, code).Apply(native, index, env.Workspace.Assemblies, default);
        }
        return (new NativeTypeTools(env.Workspace, engines, new NativeUserTypePush(code), code), native.Id);
    }

    // Metadata applied; the engine database holds only Header.
    [Fact]
    public async Task An_empty_engine_list_for_a_metadata_type_names_the_metadata_and_the_declare_call()
    {
        var (tools, id) = await Setup(applyMetadata: true);

        var text = await tools.ListNativeTypes(id, "*NativeThing*", engine: "ida");

        Assert.Contains("0 types", text);
        Assert.Contains("Fixture.Native.NativeThing is a metadata type", text);
        Assert.Contains("get_native_type", text);
        Assert.Contains("declare_native_types", text);
    }

    [Fact]
    public async Task An_empty_engine_list_of_one_kind_still_names_the_metadata_and_the_declare_call()
    {
        var (tools, id) = await Setup(applyMetadata: true);

        var text = await tools.ListNativeTypes(id, "*NativeThing*", kind: "struct", engine: "ida");

        Assert.Contains("No struct type in the ida database matches", text);
        Assert.Contains("Fixture.Native.NativeThing is a metadata type", text);
        Assert.Contains("declare_native_types", text);
    }

    [Fact]
    public async Task An_empty_engine_list_for_an_unrelated_filter_names_the_filter_and_engine()
    {
        var (tools, id) = await Setup(applyMetadata: true);

        var text = await tools.ListNativeTypes(id, "*NoSuchType*", engine: "ida");

        Assert.Contains("No type in the ida database matches '*NoSuchType*'", text);
        Assert.DoesNotContain("declare_native_types", text);
    }

    [Fact]
    public async Task An_empty_engine_list_without_applied_metadata_carries_no_metadata_hint()
    {
        var (tools, id) = await Setup(applyMetadata: false);

        var text = await tools.ListNativeTypes(id, "*NativeThing*", engine: "ida");

        Assert.DoesNotContain("metadata type", text);
        Assert.Contains("No type in the ida database matches '*NativeThing*'", text);
    }

    [Fact]
    public async Task A_kind_that_excludes_a_matching_type_is_named_in_the_empty_result()
    {
        var (tools, id) = await Setup(applyMetadata: true);

        var text = await tools.ListNativeTypes(id, "Header", kind: "enum", engine: "ida");

        Assert.Contains("No enum type in the ida database matches 'Header'", text);
        Assert.DoesNotContain("No type in the", text);
    }

    [Fact]
    public async Task A_nonempty_list_paged_past_its_end_carries_no_no_match_text()
    {
        var (tools, id) = await Setup(applyMetadata: false);

        var text = await tools.ListNativeTypes(id, "Header", offset: 5, engine: "ida");

        Assert.DoesNotContain("matches 'Header'", text);
    }
}
