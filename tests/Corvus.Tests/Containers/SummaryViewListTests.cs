using System.Runtime.CompilerServices;
using Corvus.Core;
using Corvus.Services.Analysis;
using Corvus.Tools;
using Xunit;

namespace Corvus.Tests;

/// <summary>Proves the summary view list keeps one order, lists each view once and explains an unavailable view.</summary>
public sealed class SummaryViewListTests
{
    private static InspectionService.FileSummary Summary(bool assembly, string[] notes, params string[] views)
    {
        var facts = new InspectionService.FileFacts("a.bin", 0, "", "", "", "pe", 0, new CertificateInfo(false));
        var map = new Dictionary<string, FileView>();
        foreach (var v in views) map[v] = new FileView(new object(), []);
        InspectionService.AssemblySummary[] assemblies = assembly
            ? [(InspectionService.AssemblySummary)RuntimeHelpers.GetUninitializedObject(typeof(InspectionService.AssemblySummary))]
            : [];
        return new InspectionService.FileSummary(facts, "none", assemblies, [], notes) { Views = map };
    }

    private static InspectionService.FileSummary Summary(params string[] views) => Summary(false, [], views);

    [Fact]
    public void The_view_list_does_not_depend_on_detection_order()
    {
        var a = ContainerText.ViewsOf(Summary("sideload", "native", "dependencies"), true);
        var b = ContainerText.ViewsOf(Summary("dependencies", "sideload", "native"), true);
        Assert.Equal(a, b);
        Assert.Equal(["overview", "dependencies", "hunts", "native", "sideload", "all"], a);
    }

    [Fact]
    public void A_native_view_with_a_triage_is_listed_once()
    {
        var views = ContainerText.ViewsOf(Summary("native"), true);
        Assert.Single(views, v => v == "native");
    }

    [Fact]
    public void A_triage_adds_the_native_view_when_no_provider_supplies_it()
    {
        Assert.Equal(["overview", "hunts", "native", "all"], ContainerText.ViewsOf(Summary(), true));
    }

    [Fact]
    public void No_triage_and_no_native_view_lists_no_native_entry()
    {
        Assert.Equal(["overview", "hunts", "all"], ContainerText.ViewsOf(Summary(), false));
    }

    [Fact]
    public void A_loaded_assembly_lists_no_hunts_view()
    {
        var loaded = Summary() with { Container = "none (loaded assembly)" };
        Assert.Equal(["overview", "all"], ContainerText.ViewsOf(loaded, false));
    }

    [Fact]
    public void The_managed_view_follows_the_overview()
    {
        Assert.Equal(["overview", "managed", "dependencies", "hunts", "all"], ContainerText.ViewsOf(Summary(true, [], "dependencies"), false));
    }

    [Fact]
    public void A_provider_view_named_like_a_reserved_view_is_listed_once()
    {
        var views = ContainerText.ViewsOf(Summary(true, [], "all", "managed", "overview", "go"), false);
        Assert.Equal(["overview", "managed", "go", "hunts", "all"], views);
    }

    [Fact]
    public void The_record_and_the_invalid_view_error_list_the_same_views()
    {
        var s = Summary("sideload", "dependencies");
        var overview = ContainerText.Summary(s, "overview").Views;
        Assert.Equal(overview, ContainerText.Summary(s, "all").Views);
        var error = Assert.Throws<ToolError>(() => ContainerText.Summary(s, "missing"));
        Assert.Contains(string.Join(", ", overview!), error.Remediation);
    }

    [Fact]
    public void The_overview_carries_the_reason_a_view_was_unavailable()
    {
        var s = Summary(false, ["The dependencies view could not read the file."]);
        Assert.Contains("The dependencies view could not read the file.", ContainerText.Summary(s, "overview").Notes!);
    }
}
