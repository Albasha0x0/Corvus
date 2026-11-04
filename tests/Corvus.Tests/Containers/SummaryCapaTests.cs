using Corvus.Core;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Worker;
using Corvus.Services;
using Corvus.Services.Analysis;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>The capa labels kept for a file, in the summarize_file overview and view=indicators.</summary>
[Collection(ExternalToolEnvironmentCollection.Name)]
public sealed class SummaryCapaTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly FakeTool _capa = new();
    private readonly List<IDisposable> _owned = [];

    public SummaryCapaTests() => NativeCapa.RootOverride.Value = _dir.File("capa-cache");

    public void Dispose()
    {
        NativeCapa.RootOverride.Value = null;
        foreach (var o in _owned) o.Dispose();
        _capa.Dispose();
        _dir.Dispose();
    }

    private string Fixture()
    {
        var path = _dir.File("fixture.exe");
        File.WriteAllBytes(path, CapaFixture.Build());
        return path;
    }

    private void SetUp() =>
        _owned.Add(new EnvironmentScope().Set("CORVUS_CAPA", _capa.CopyAs("capa")).Set(FakeTool.ScriptVariable, _capa.ScriptPath));

    private static void Keep(string path, CapaReport report) => NativeCapa.Keep(NativeCapa.Key(path)!, report);

    private static CapaLabel Label(string name) => new(name, "host-interaction/process", "function", ["Execution::T1059 [T1059]"], ["Process::Create Process [C0017]"], []);

    private static FileSummaryRecord Summarize(string path, string view = "overview")
    {
        var summary = new InspectionService(new AssemblyWorkspace()).Summarize(null, path, default, new FileViewOptions(view));
        return ContainerText.Summary(summary, view);
    }

    [Fact]
    public void A_kept_capa_report_is_listed_in_the_file_summary()
    {
        var path = Fixture();
        Keep(path, new("matched", "capa 10.0.0", true, "pe", [Label("create process on Windows"), Label("terminate process")], []));
        var record = Summarize(path);
        var capa = Assert.IsType<CapaSummary>(record.Capa);
        Assert.Equal(("matched", 2, null), (capa.State, capa.Labels, capa.LabelTotal));
        Assert.Equal(["create process on Windows", "terminate process"], capa.Items.Select(i => i.Name));
        Assert.Contains("capa: 2 labels kept (survey_features category=capa refreshes)", ContainerText.Summary(record));
        Assert.Contains("capa: 2 labels kept", ContainerText.Summary(Summarize(path, "indicators")));
    }

    [Fact]
    public void A_file_with_no_kept_report_says_capa_has_not_run()
    {
        SetUp();
        var record = Summarize(Fixture());
        Assert.Equal("not run", record.Capa?.State);
        Assert.Contains("capa: not run on this file (survey_features category=capa runs it)", ContainerText.Summary(record));
    }

    [Fact]
    public void A_file_with_no_kept_report_and_no_capa_says_nothing()
    {
        using var none = new EnvironmentScope().Set("CORVUS_CAPA", Path.Combine(_dir.Path, "missing"));
        var record = Summarize(Fixture());
        Assert.Null(record.Capa);
        Assert.DoesNotContain("capa:", ContainerText.Summary(record));
    }

    [Fact]
    public void An_unknown_capa_state_is_reported_with_its_notes()
    {
        var path = Fixture();
        Keep(path, new("unknown", "capa 10.0.0", true, null, [], ["capa could not read the rules"]));
        var text = ContainerText.Summary(Summarize(path));
        Assert.Contains("capa: unknown, capa could not read the rules", text);
        Assert.DoesNotContain("labels kept", text);
    }

    [Fact]
    public void Labels_past_50_are_cut_and_the_cut_is_named()
    {
        var path = Fixture();
        Keep(path, new("matched", "capa 10.0.0", true, "pe", [.. Enumerable.Range(0, 60).Select(i => Label($"rule {i}"))], []));
        var record = Summarize(path);
        Assert.Equal((60, 60, 50), (record.Capa!.Labels, record.Capa.LabelTotal, record.Capa.Items.Count));
        Assert.Contains("the first 50 of 60 are listed", ContainerText.Summary(record));
    }

    [Fact]
    public void summarize_file_never_starts_capa()
    {
        SetUp();
        _capa.On(@"^-j .+$", stdout: "{}");
        Summarize(Fixture());
        Assert.Empty(_capa.ArgumentLists);
    }
}
