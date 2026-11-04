using Corvus.Services.Web.Packages;

namespace Corvus.Tests;

/// <summary>Cursor CLI permissions read from a project configuration.</summary>
public sealed class CursorCliReviewTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private PackageReport Review(string json)
    {
        var root = _dir.File("r" + Guid.NewGuid().ToString("N")[..6]);
        Directory.CreateDirectory(Path.Combine(root, ".cursor"));
        File.WriteAllText(Path.Combine(root, ".cursor", "cli.json"), json);
        return PackageReview.Review(root, default) ?? throw new InvalidOperationException("not reviewed");
    }

    [Fact]
    public void A_shell_permission_for_a_code_runner_is_a_review_finding()
    {
        var r = Review("""{ "permissions": { "allow": ["Shell(curl)", "Shell(git)"], "deny": ["Shell(rm)"] } }""");
        var found = Assert.Single(r.Findings, f => f.Rule == "package/agent-permission-widening");
        Assert.Equal("review", found.Level);
        Assert.Equal(1, found.Line);
        Assert.Contains("Shell(curl)", found.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void A_write_permission_over_every_path_is_a_review_finding()
    {
        var r = Review("{ \"permissions\": { \"allow\": [\n\"Write(**)\", \"Write(../other/**)\", \"Mcp(*:*)\"] } }");
        Assert.Equal([2, 2, 2], r.Findings.Where(f => f.Rule == "package/agent-permission-widening").Select(f => f.Line!.Value).ToArray());
    }

    [Fact]
    public void A_read_only_permission_raises_nothing()
    {
        var r = Review("""{ "permissions": { "allow": ["Read(src/**)", "Write(docs/**)", "Shell(git)"] } }""");
        Assert.DoesNotContain(r.Findings, f => f.Rule == "package/agent-permission-widening");
    }

    [Fact]
    public void A_file_that_is_not_json_reports_unknown()
    {
        var r = Review("permissions: allow");
        Assert.Contains(r.Notes ?? [], n => n.Contains("unknown", StringComparison.Ordinal));
    }
}
