using ModelContextProtocol.Protocol;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>verify_native_imports on a native PE image binds each import to the export of the module found beside it.</summary>
public sealed class PeLinkCheckTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private async Task<string> Verify(string app, string? status = null, int limit = 100)
    {
        await using var server = await InProcessServer.StartAsync();
        await server.Client.CallToolAsync("load_assembly", new Dictionary<string, object?> { ["path"] = app });
        var r = await server.Client.CallToolAsync("verify_native_imports",
            new Dictionary<string, object?> { ["assembly"] = Path.GetFileName(app), ["status"] = status, ["limit"] = limit });
        var text = string.Concat(r.Content.OfType<TextContentBlock>().Select(b => b.Text));
        output.WriteLine(text);
        return text;
    }

    // LinkedImages.Trio: app.dll imports 5 provlib.dll entries and nosuch_8f3a.dll!X.
    [Fact]
    public async Task Present_exports_are_verified_by_name_ordinal_and_forwarder()
    {
        var (app, _, _) = LinkedImages.Trio(_dir);
        var text = await Verify(app, "verified");
        Assert.Contains("verified (exact)  provlib.dll!Work", text);
        Assert.Contains("verified (forwarded)  provlib.dll!Fwd", text);
        Assert.Contains("verified (ordinal)  provlib.dll!#2  ->", text);
    }

    [Fact]
    public async Task A_missing_export_and_a_missing_module_are_named()
    {
        var (app, _, _) = LinkedImages.Trio(_dir);
        var text = await Verify(app);
        Assert.Contains("contradicted (missing_export)  provlib.dll!Missing", text);
        Assert.Contains("unresolved (dll_not_found)  nosuch_8f3a.dll!X: searched", text);
    }

    [Fact]
    public async Task The_head_line_counts_imports_per_verdict()
    {
        var (app, _, _) = LinkedImages.Trio(_dir);
        var text = await Verify(app);
        Assert.Contains("6 imports: 2 verified (exact), 1 verified (forwarded), 1 verified (ordinal), 1 contradicted (missing_export), 1 unresolved (dll_not_found)", text);
    }

    [Fact]
    public async Task Paging_limits_rows_and_keeps_the_total()
    {
        var (app, _, _) = LinkedImages.Trio(_dir);
        var text = await Verify(app, limit: 2);
        Assert.Contains("contradicted (missing_export)  provlib.dll!Missing", text);
        Assert.DoesNotContain("provlib.dll!Work", text);
        Assert.Contains("unresolved (dll_not_found)  nosuch_8f3a.dll!X", text);
    }

    [Fact]
    public async Task An_image_without_imports_reports_zero_imports()
    {
        var (_, _, deep) = LinkedImages.Trio(_dir);
        var text = await Verify(deep);
        Assert.Contains("0 imports", text);
    }

    // Imports an ordinal provlib.dll does not export, a forwarder whose target is absent, and an unmapped api set name.
    [Fact]
    public async Task Missing_ordinals_broken_forwarders_and_unmapped_api_sets_are_named()
    {
        var (_, _, _) = LinkedImages.Trio(_dir);
        File.WriteAllBytes(_dir.File("fwdlib.dll"), LinkedImages.Build("fwdlib.dll", [("Bad", "deeplib.Gone")], [], _ => new LinkedImages.Code([]).Ret().ToArray()));
        var app = _dir.File("app2.dll");
        File.WriteAllBytes(app, LinkedImages.Build("app2.dll", [("Main", 0)],
            [("provlib.dll", ["#9"]), ("fwdlib.dll", ["Bad"]), ("api-ms-win-nosuch-l1-1-0.dll", ["X"])],
            slots => new LinkedImages.Code(slots).CallImport("provlib.dll!#9").CallImport("fwdlib.dll!Bad").CallImport("api-ms-win-nosuch-l1-1-0.dll!X").Ret().ToArray()));
        var text = await Verify(app);
        Assert.Contains("contradicted (missing_ordinal)  provlib.dll!#9", text);
        Assert.Contains("contradicted (forwarder_broken)  fwdlib.dll!Bad", text);
        Assert.Contains(OperatingSystem.IsWindows() ? "unresolved (api_set_unmapped)  api-ms-win-nosuch-l1-1-0.dll!X" : "unresolved (system_dll_not_on_host)  api-ms-win-nosuch-l1-1-0.dll!X", text);
    }
}
