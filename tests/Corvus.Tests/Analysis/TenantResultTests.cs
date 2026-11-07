using System.Security.Cryptography;
using System.Text;
using Corvus.Core;
using Corvus.Services;
using Corvus.Services.Analysis;
using Corvus.Services.Analysis.Hunts;

namespace Corvus.Tests;

/// <summary>The tenant query of a file by SHA-1 and the join of its saved result, over a program built from source.</summary>
public sealed class TenantResultTests : IDisposable
{
    private const string Sha1 = "0123456789abcdef0123456789abcdef01234567";
    private static readonly DateTimeOffset Saved = new(2026, 11, 7, 10, 0, 0, TimeSpan.Zero);

    private readonly TempDir _dir = new();
    private readonly AssemblyWorkspace _ws = new();
    public void Dispose() { _ws.Dispose(); _dir.Dispose(); }

    private static string Row(string source, string sha1, string fields) =>
        "{\"Source\":\"" + source + "\",\"Queried\":\"" + sha1 + "\"," + fields + "}";

    private static string Result(params string[] rows) => "{\"schema\":[],\"results\":[" + string.Join(',', rows) + "]}";

    private static byte[] Bytes(string text) => Encoding.UTF8.GetBytes(text);

    private static string Catalog(string sha1, string signer = "Microsoft Windows", string trusted = "true") =>
        Row("DeviceFileCertificateInfo", sha1,
            "\"SignatureType\":\"Catalog\",\"IsTrusted\":" + trusted + ",\"Signer\":\"" + signer + "\",\"Devices\":2,\"FirstSeen\":\"2026-10-20T08:00:00Z\",\"LastSeen\":\"2026-11-06T09:00:00Z\"");

    private string Program(out string sha1)
    {
        var path = _dir.File("Caller.dll");
        File.WriteAllBytes(path, InspectionTests.Compile("Caller", "public static class Caller { public static string Pipe() => @\"\\\\.\\pipe\\tenant-test-pipe\"; }"));
        sha1 = Convert.ToHexStringLower(SHA1.HashData(File.ReadAllBytes(path)));
        return path;
    }

    private HuntSet View(string path, string? result)
    {
        var summary = new InspectionService(_ws).Summarize(null, path, default, new FileViewOptions("hunts") { TenantResultPath = result });
        return (HuntSet)summary.Views["hunts"].Detail;
    }

    [Fact]
    public void The_query_parses_against_the_schema_and_names_each_table_and_the_SHA1()
    {
        var hunt = TenantResult.Query(Sha1);
        Assert.Empty(KqlCheck.Diagnostics(hunt.Kql));
        Assert.Empty(HuntsWriterTests.Parse(hunt.Kql).GetDiagnostics());
        Assert.All(new[] { "DeviceFileCertificateInfo", "DeviceFileEvents", "DeviceProcessEvents", "DeviceImageLoadEvents" }, t => Assert.Contains(t, hunt.Kql));
        Assert.Equal(8, hunt.Kql.Split(Sha1).Length - 1);
        Assert.True(hunt.HuntingOnly);
        Assert.Empty(HuntRules.Rules(new HuntSet([hunt], [])));
    }

    [Fact]
    public void A_union_branch_with_an_unknown_column_is_reported()
    {
        var problems = KqlCheck.Diagnostics("union\n(DeviceFileEvents\n| where NoSuchColumn == 'x'),\n(DeviceProcessEvents\n| where SHA1 == 'x')");
        Assert.Contains(problems, p => p.Contains("NoSuchColumn", StringComparison.Ordinal));
    }

    [Fact]
    public void A_dangling_comma_in_a_union_is_reported()
    {
        var problems = KqlCheck.Diagnostics("union\n(DeviceFileEvents\n| where SHA1 == 'x'),");
        Assert.Contains(problems, p => p.Contains("comma", StringComparison.Ordinal));
    }

    [Fact]
    public void Aggregates_are_refused_outside_a_union_branch()
    {
        Assert.NotEmpty(KqlCheck.Diagnostics("DeviceFileEvents\n| summarize Devices = dcount(DeviceId)"));
        Assert.Empty(KqlCheck.Diagnostics("union\n(DeviceFileEvents\n| summarize Devices = dcount(DeviceId))"));
    }

    [Fact]
    public void A_catalog_signature_and_device_counts_are_joined_with_the_save_time()
    {
        var result = Result(Catalog(Sha1),
            Row("DeviceFileEvents", Sha1, "\"Devices\":1,\"FirstSeen\":\"2026-11-05T01:00:00Z\",\"LastSeen\":\"2026-11-05T01:00:00Z\""),
            Row("DeviceProcessEvents", Sha1, "\"Devices\":0"),
            Row("DeviceImageLoadEvents", Sha1, "\"Devices\":2"));
        var read = TenantResult.Read(Bytes(result), Sha1, Saved);
        var facts = Assert.IsType<TenantFacts>(read.Facts);
        var sig = Assert.Single(facts.Signatures);
        Assert.Equal(("Catalog", "Microsoft Windows", true, 2), (sig.Type, sig.Signer, sig.Trusted, sig.Devices));
        Assert.Equal("2026-11-07T10:00:00Z", facts.ResultSaved);
        Assert.Equal("not seen in process events in 30 days on onboarded devices", Assert.Single(facts.Reach, r => r.Table == "DeviceProcessEvents").Status);
        Assert.Equal(1, Assert.Single(facts.Reach, r => r.Table == "DeviceFileEvents").Devices);
        Assert.Equal(2, Assert.Single(facts.Reach, r => r.Table == "DeviceImageLoadEvents").Devices);
        Assert.Contains(TenantResult.Lines(facts), l => l.Contains("catalog signature by Microsoft Windows, trusted", StringComparison.Ordinal));
    }

    [Fact]
    public void Zero_in_every_event_table_reads_as_not_seen_in_file_process_or_image_load_events()
    {
        var result = Result(Row("DeviceFileEvents", Sha1, "\"Devices\":0"), Row("DeviceProcessEvents", Sha1, "\"Devices\":0"), Row("DeviceImageLoadEvents", Sha1, "\"Devices\":0"));
        var lines = TenantResult.Lines(TenantResult.Read(Bytes(result), Sha1, Saved).Facts!);
        Assert.Equal("Tenant (result saved 2026-11-07T10:00:00Z): not seen in file, process or image load events in 30 days on onboarded devices.", Assert.Single(lines));
    }

    [Theory]
    [InlineData("\"Devices\":0", 0, "not seen")]
    [InlineData("\"Devices\":\"0\"", 0, "not seen")]
    [InlineData("\"Other\":1", null, "unknown")]
    [InlineData("\"Devices\":1.5", null, "unknown")]
    [InlineData("\"Devices\":\"many\"", null, "unknown")]
    [InlineData("\"Devices\":-1", null, "unknown")]
    [InlineData("\"Devices\":null", null, "unknown")]
    [InlineData("\"Devices\":1e0", null, "unknown")]
    public void Only_a_whole_number_of_zero_or_more_is_a_count(string fields, int? devices, string status)
    {
        var read = TenantResult.Read(Bytes(Result(Row("DeviceFileEvents", Sha1, fields))), Sha1, Saved);
        var reach = Assert.Single(read.Facts!.Reach);
        Assert.Equal(devices, reach.Devices);
        Assert.StartsWith(status, reach.Status, StringComparison.Ordinal);
        if (devices == null) Assert.Contains(read.Facts.Notes, n => n.Contains("not a whole number", StringComparison.Ordinal));
    }

    [Fact]
    public void A_later_zero_does_not_hide_a_larger_count()
    {
        var result = Result(Row("DeviceFileEvents", Sha1, "\"Devices\":3"), Row("DeviceFileEvents", Sha1, "\"Devices\":0"));
        var facts = TenantResult.Read(Bytes(result), Sha1, Saved).Facts!;
        Assert.Equal(3, Assert.Single(facts.Reach).Devices);
        Assert.Contains(facts.Notes, n => n.Contains("larger count", StringComparison.Ordinal));
    }

    [Fact]
    public void A_result_over_the_row_limit_is_refused_whatever_its_late_rows_name()
    {
        var rows = Enumerable.Repeat(Row("DeviceFileEvents", Sha1, "\"Devices\":1"), TenantResult.MaxRows).Append(Row("DeviceFileEvents", new string('b', 40), "\"Devices\":1"));
        var read = TenantResult.Read(Bytes(Result([.. rows])), Sha1, Saved);
        Assert.Null(read.Facts);
        Assert.Contains("rows, over", read.Refused, StringComparison.Ordinal);
    }

    [Fact]
    public void A_result_for_another_SHA1_in_a_late_row_is_not_joined()
    {
        var other = new string('a', 40);
        var read = TenantResult.Read(Bytes(Result(Row("DeviceFileEvents", Sha1, "\"Devices\":3"), Row("DeviceProcessEvents", other, "\"Devices\":3"))), Sha1, Saved);
        Assert.Null(read.Facts);
        Assert.Contains(read.Notes, n => n.Contains(other, StringComparison.Ordinal) && n.Contains("not joined", StringComparison.Ordinal));
    }

    [Fact]
    public void A_result_for_another_SHA1_is_named_and_not_joined()
    {
        var other = new string('a', 40);
        var read = TenantResult.Read(Bytes(Result(Row("DeviceFileEvents", other, "\"Devices\":3"))), Sha1, Saved);
        Assert.Null(read.Facts);
        Assert.Null(read.Refused);
        Assert.Contains(read.Notes, n => n.Contains(other, StringComparison.Ordinal) && n.Contains("not joined", StringComparison.Ordinal));
    }

    [Fact]
    public void A_table_with_no_row_stays_unknown()
    {
        var read = TenantResult.Read(Bytes(Result(Row("DeviceFileEvents", Sha1, "\"Devices\":0"))), Sha1, Saved);
        var facts = read.Facts!;
        Assert.Empty(facts.Signatures);
        Assert.Contains(facts.Notes, n => n.StartsWith("DeviceProcessEvents: no row", StringComparison.Ordinal));
        Assert.Contains(facts.Notes, n => n.StartsWith("DeviceImageLoadEvents: no row", StringComparison.Ordinal));
        Assert.Contains(facts.Notes, n => n.Contains("signature is unknown", StringComparison.Ordinal));
        Assert.Single(facts.Reach);
    }

    [Theory]
    [InlineData("not json")]
    [InlineData("{\"results\":1}")]
    [InlineData("\"text\"")]
    public void Bytes_that_are_not_a_result_are_refused(string text)
    {
        var read = TenantResult.Read(Bytes(text), Sha1, Saved);
        Assert.Null(read.Facts);
        Assert.NotNull(read.Refused);
    }

    [Fact]
    public void A_signer_is_taken_only_from_a_trusted_row()
    {
        var rows = new[] { Row("DeviceFileEvents", Sha1, "\"Devices\":1") };
        foreach (var trusted in new[] { "false", "null" })
        {
            var facts = TenantResult.Read(Bytes(Result([Catalog(Sha1, "Untrusted Signer", trusted), .. rows])), Sha1, Saved).Facts!;
            Assert.Null(TenantResult.Signer(facts));
            Assert.Equal("Untrusted Signer", Assert.Single(facts.Signatures).Signer);
            Assert.Contains(facts.Notes, n => n.Contains("not marked trusted", StringComparison.Ordinal));
        }
        Assert.Equal("Microsoft Windows", TenantResult.Signer(TenantResult.Read(Bytes(Result([Catalog(Sha1), .. rows])), Sha1, Saved).Facts!));
    }

    [Fact]
    public void A_signer_cut_on_reading_is_not_taken()
    {
        var facts = TenantResult.Read(Bytes(Result(Catalog(Sha1, new string('x', 400)), Row("DeviceFileEvents", Sha1, "\"Devices\":1"))), Sha1, Saved).Facts!;
        Assert.Null(TenantResult.Signer(facts));
        Assert.Contains(facts.Notes, n => n.Contains("no signer query is written", StringComparison.Ordinal));
    }

    [Fact]
    public void Format_characters_are_removed_and_Markdown_is_escaped()
    {
        // The JSON holds a bidi override, a zero-width space and Markdown marks.
        var signer = "A\\u202eB\\u200bC *e* _f_ [g](h) <i> \\\\| `j`";
        var facts = TenantResult.Read(Bytes(Result(Catalog(Sha1, signer), Row("DeviceFileEvents", Sha1, "\"Devices\":1"))), Sha1, Saved).Facts!;
        var read = Assert.Single(facts.Signatures);
        Assert.True(read.SignerChanged);
        Assert.DoesNotContain(read.Signer!, c => c == (char)0x202e || c == (char)0x200b);
        var line = Assert.Single(TenantResult.Lines(facts), l => l.Contains("signature", StringComparison.Ordinal));
        Assert.Contains(@"\*e\*", line, StringComparison.Ordinal);
        Assert.Contains(@"\[g\]\(h\)", line, StringComparison.Ordinal);
        Assert.Contains(@"\<i\>", line, StringComparison.Ordinal);
        Assert.Contains(@"\`j\`", line, StringComparison.Ordinal);
    }

    [Fact]
    public void The_view_writes_the_tenant_query_without_a_rule()
    {
        var set = View(Program(out var sha1), null);
        var hunt = Assert.Single(set.Hunts, h => h.Id.StartsWith("tenant-", StringComparison.Ordinal));
        Assert.Contains(sha1, hunt.Kql, StringComparison.Ordinal);
        Assert.DoesNotContain(HuntRules.Rules(set), h => h.Id == hunt.Id);
        Assert.Null(set.Tenant);
    }

    [Fact]
    public void A_trusted_signer_the_tenant_names_makes_an_unknown_signer_known_and_is_labelled_from_the_tenant()
    {
        var file = Program(out var sha1);
        var before = View(file, null);
        Assert.Contains(HuntKind.Signer, before.UnknownKinds);
        var saved = _dir.File("result.json");
        File.WriteAllText(saved, Result(Catalog(sha1, "Example Signer"), Row("DeviceFileEvents", sha1, "\"Devices\":1")));
        var after = View(file, saved);
        Assert.DoesNotContain(HuntKind.Signer, after.UnknownKinds);
        Assert.Contains(after.Facts, f => f is { Kind: HuntKind.Signer, Value: "Example Signer", Evidence: IndicatorEvidence.Tenant });
        var query = Assert.Single(after.Hunts, h => h.Table == "DeviceFileCertificateInfo" && h.Facts.Contains("signer:Example Signer"));
        Assert.Equal(IndicatorEvidence.Tenant, query.Evidence);
        Assert.DoesNotContain(after.Notes, n => n.StartsWith("The signer is unknown", StringComparison.Ordinal));
        Assert.Equal(sha1, after.Tenant!.Sha1);
    }

    [Fact]
    public void An_untrusted_signer_leaves_the_signer_unknown_and_is_reported()
    {
        var file = Program(out var sha1);
        var saved = _dir.File("untrusted.json");
        File.WriteAllText(saved, Result(Catalog(sha1, "Untrusted Signer", "false"), Row("DeviceFileEvents", sha1, "\"Devices\":1")));
        var set = View(file, saved);
        Assert.Contains(HuntKind.Signer, set.UnknownKinds);
        Assert.DoesNotContain(set.Hunts, h => h.Facts.Contains("signer:Untrusted Signer"));
        Assert.Contains(set.Tenant!.Notes, n => n.Contains("not marked trusted", StringComparison.Ordinal));
    }

    [Fact]
    public void A_signer_with_a_quote_and_a_backslash_stays_inside_its_query_literal()
    {
        var file = Program(out var sha1);
        var saved = _dir.File("hostile.json");
        // As JSON text, the signer decodes to a quote and a backslash.
        var signer = @"Evil' or 1 == 1 \\ x";
        File.WriteAllText(saved, Result(Catalog(sha1, signer), Row("DeviceFileEvents", sha1, "\"Devices\":1")));
        var set = View(file, saved);
        var hunt = Assert.Single(set.Hunts, h => h.Table == "DeviceFileCertificateInfo" && h.Facts[0].StartsWith("signer:", StringComparison.Ordinal));
        Assert.Empty(KqlCheck.Diagnostics(hunt.Kql));
        Assert.Empty(HuntsWriterTests.Parse(hunt.Kql).GetDiagnostics());
        Assert.Contains(@"Evil\' or 1 == 1 \\ x", hunt.Kql, StringComparison.Ordinal);
        Assert.Single(hunt.Kql.Split((char)10), l => l.StartsWith("| where Signer has ", StringComparison.Ordinal));
    }

    [Fact]
    public void A_signer_with_a_newline_is_not_written_into_a_query()
    {
        var file = Program(out var sha1);
        var saved = _dir.File("newline.json");
        File.WriteAllText(saved, Result(Catalog(sha1, @"Evil\nSigner"), Row("DeviceFileEvents", sha1, "\"Devices\":1")));
        var set = View(file, saved);
        Assert.DoesNotContain(set.Hunts, h => h.Table == "DeviceFileCertificateInfo" && h.Facts[0].StartsWith("signer:", StringComparison.Ordinal));
        Assert.Contains(HuntKind.Signer, set.UnknownKinds);
    }

    [Fact]
    public void A_saved_hunts_file_is_labelled_and_its_signer_is_not_promoted()
    {
        var file = Program(out var sha1);
        var hunts = _dir.File("hunts.json");
        File.WriteAllBytes(hunts, HuntRules.Write(View(file, null)));
        var saved = _dir.File("result.json");
        File.WriteAllText(saved, Result(Catalog(sha1, "Example Signer"), Row("DeviceFileEvents", sha1, "\"Devices\":1")));
        var set = View(hunts, saved);
        Assert.Equal(sha1, set.Tenant!.Sha1);
        Assert.DoesNotContain(set.Hunts, h => h.Facts.Contains("signer:Example Signer"));
        Assert.Single(set.Hunts, h => h.Id.StartsWith("tenant-", StringComparison.Ordinal) && h.HuntingOnly);
    }

    [Fact]
    public async Task A_view_other_than_hunts_refuses_the_result_and_says_what_to_pass()
    {
        var tools = new Corvus.Tools.InspectionTools(new InspectionService(_ws), _ws);
        var error = await Assert.ThrowsAsync<ToolError>(() => tools.SummarizeFile(path: Program(out _), view: "overview", tenantResultPath: _dir.File("any.json")));
        Assert.Equal(ErrorCode.InvalidArgument, error.Code);
        Assert.Contains("view=hunts", error.Remediation, StringComparison.Ordinal);
    }

    [Fact]
    public void A_result_file_that_is_not_JSON_is_refused_with_its_path()
    {
        var file = Program(out _);
        var saved = _dir.File("bad.json");
        File.WriteAllText(saved, "<html>");
        var error = Assert.Throws<ToolError>(() => View(file, saved));
        Assert.Equal(ErrorCode.MalformedInput, error.Code);
        Assert.Contains("bad.json", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    [FuzzEntry(typeof(TenantResult))]
    public void Fuzzed_tenant_results_never_throw_unexpectedly()
    {
        var seed = Bytes(Result(Catalog(Sha1), Row("DeviceFileEvents", Sha1, "\"Devices\":1,\"FirstSeen\":\"2026-11-05T01:00:00Z\"")));
        var failures = FormatFuzz.Run(seed, b => TenantResult.Read(b, Sha1, Saved), 300);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }
}
