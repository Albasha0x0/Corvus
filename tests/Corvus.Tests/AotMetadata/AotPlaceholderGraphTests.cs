using Corvus.Core;
using Corvus.Native.Annotations;
using Corvus.Services;
using Corvus.Services.Analysis;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>Call trees, call paths and surveys of dummy-assembly methods, joined to the native binary at their addresses.</summary>
public sealed class AotPlaceholderGraphTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly Env _env;
    private readonly NativeCodeService _code;
    private readonly string _binary;

    public AotPlaceholderGraphTests()
    {
        (var dll, _binary) = AotNativeNamesTests.CreateDump(_dir);
        _env = new Env(dll);
        _code = new NativeCodeService(_env.Workspace, _env.Options, null, new AnnotationStore(_dir.File("ann")));
    }

    public void Dispose()
    {
        _env.Dispose();
        _dir.Dispose();
    }

    private CallGraphTools Tools() =>
        new(_env.Workspace, new CallGraphService(_env.Workspace), new NativeLinkService(_env.Workspace, _code), _code, null, _env.AotMetadata, _env.AotNavigator);

    private async Task LoadBinary()
    {
        var native = _env.Workspace.LoadAny(_binary).Native!;
        await _code.Index(native, null, default);
    }

    // First (0x1000) calls Second (0x1100), which calls the function at 0x1200.
    [Fact]
    public async Task A_placeholder_method_lists_the_native_callees_at_its_address()
    {
        await LoadBinary();
        var tree = await Tools().GetCallTree("Fixture.Native.NativeThing::First()", "callees");
        Assert.Contains("placeholder: native callees of", tree);
        Assert.Contains("0x180001100", tree);
        Assert.Contains("0x180001200", tree);
        Assert.DoesNotContain("load the assemblies that might call it", tree);
    }

    [Fact]
    public async Task A_placeholder_method_lists_the_native_callers_at_its_address()
    {
        await LoadBinary();
        var tree = await Tools().GetCallTree("Fixture.Native.NativeThing::Second()", "callers");
        Assert.Contains("0x180001000", tree);
        Assert.DoesNotContain("load the assemblies that might call it", tree);
    }

    [Fact]
    public async Task A_placeholder_method_without_its_binary_is_named_as_partial()
    {
        var tree = await Tools().GetCallTree("Fixture.Native.NativeThing::Second()", "callers");
        Assert.Contains("placeholder with its code at RVA 0x1100, in a binary that is not loaded", tree);
        Assert.DoesNotContain("load the assemblies that might call it", tree);
    }

    [Fact]
    public async Task Call_paths_to_a_placeholder_method_follow_native_callers()
    {
        await LoadBinary();
        var paths = await Tools().FindCallPaths("Fixture.Native.NativeThing::Second()");
        Assert.Contains("0x180001000", paths);
        Assert.DoesNotContain("nothing in the loaded assemblies reaches it", paths);
    }

    [Fact]
    public void A_survey_of_a_placeholder_assembly_points_to_the_native_binary()
    {
        var report = new InspectionService(_env.Workspace, _code, aot: _env.AotNavigator, literals: _env.MetadataStrings)
            .SurveyFeatures(_env.Fixture.Id, null, null, default);
        Assert.Contains(report.Notes, n => n.Contains("dummy assembly") && n.Contains("survey_features image="));
    }

    [Fact]
    public async Task Native_callee_rows_are_named_at_their_depths()
    {
        await LoadBinary();
        var tree = await Tools().GetCallTree("Fixture.Native.NativeThing::First()", "callees");
        var rows = tree.ReplaceLineEndings("\n").Split("\n");
        Assert.Contains(rows, l => l.StartsWith("  sub_180001100 at 0x180001100"));
        Assert.Contains(rows, l => l.StartsWith("    sub_180001200 at 0x180001200"));
    }

    [Fact]
    public async Task A_placeholder_path_with_a_managed_start_and_no_binary_names_the_missing_binary()
    {
        var paths = await Tools().FindCallPaths("Fixture.Native.NativeThing::Second()", "Fixture.Native.NativeThing::First()");
        Assert.Contains("binary that is not loaded", paths);
    }

    [Fact]
    public async Task A_placeholder_without_a_dump_matched_to_one_binary_is_labelled_as_matched_by_address()
    {
        using var env = new Env();
        var code = new NativeCodeService(env.Workspace, env.Options, null, new AnnotationStore(_dir.File("ann2")));
        var native = env.Workspace.LoadAny(_binary).Native!;
        await code.Index(native, null, default);
        var tools = new CallGraphTools(env.Workspace, new CallGraphService(env.Workspace), new NativeLinkService(env.Workspace, code), code, null, env.AotMetadata, env.AotNavigator);
        var tree = await tools.GetCallTree("Fixture.Native.NativeThing::First()", "callees");
        Assert.Contains("binary matched by RVA only", tree);
    }

    [Fact]
    public async Task A_placeholder_without_a_dump_and_two_matching_binaries_is_named_ambiguous()
    {
        using var env = new Env();
        var copy = _dir.File("copy.dll");
        File.Copy(_binary, copy);
        var code = new NativeCodeService(env.Workspace, env.Options, null, new AnnotationStore(_dir.File("ann3")));
        env.Workspace.LoadAny(_binary);
        env.Workspace.LoadAny(copy);
        var tools = new CallGraphTools(env.Workspace, new CallGraphService(env.Workspace), new NativeLinkService(env.Workspace, code), code, null, env.AotMetadata, env.AotNavigator);
        var tree = await tools.GetCallTree("Fixture.Native.NativeThing::First()", "callees");
        Assert.Contains("2 loaded binaries have code there", tree);
    }

    [Fact]
    public async Task A_method_without_an_address_gets_no_placeholder_lines()
    {
        var tree = await Tools().GetCallTree("Fixture.Model.Account::CheckPreview()", "callees");
        Assert.DoesNotContain("placeholder", tree);
    }

    [Fact]
    public void A_category_that_matches_nothing_keeps_the_dummy_assembly_note()
    {
        var report = new InspectionService(_env.Workspace, _code, aot: _env.AotNavigator, literals: _env.MetadataStrings)
            .SurveyFeatures(_env.Fixture.Id, null, "no-such-category", default);
        Assert.Contains(report.Notes, n => n.Contains("dummy assembly"));
    }
}
