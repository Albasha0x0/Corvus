using System.Buffers.Binary;
using Corvus.Native;
using Corvus.Services.Analysis;
using Corvus.Services.Analysis.Hunts;
using Corvus.Tools;
using Kusto.Language;
using Kusto.Language.Symbols;

namespace Corvus.Tests;

/// <summary>compare_native_images view=hunts over two self-built builds: queries for what the new build adds and for the functions it changes.</summary>
public sealed class UpdateHuntsTests
{
    private const uint Name = 0x1000, Other = 0x1040, OldStamp = 0x5F8A1B2C;
    private const string SharedPipe = @"\\.\pipe\shared-pipe", AddedPipe = @"\\.\pipe\added-pipe";

    // The second build adds a library, a pipe and a URL string, and grows the first function.
    private static byte[] Image(bool newer, uint stamp)
    {
        (string, string[])[] imports = newer
            ? [("kernel32.dll", ["ExitProcess"]), ("shared-lib.dll", ["Run"]), ("added-lib.dll", ["Go"])]
            : [("kernel32.dll", ["ExitProcess"]), ("shared-lib.dll", ["Run"])];
        var image = LinkedImages.Build("host.dll", [], imports, _ =>
        {
            var code = Enumerable.Repeat((byte)0xCC, 0x80).ToArray();
            byte[] first = newer
                ? [0x31, 0xC0, 0x85, 0xC9, 0x74, 0x03, 0x83, 0xC0, 0x05, 0xC3]
                : [0x31, 0xC0, 0x83, 0xC0, 0x05, 0xC3];
            first.CopyTo(code, 0);
            new byte[] { 0xB8, 0x01, 0, 0, 0, 0x83, 0xC0, 0x22, 0xC3 }.CopyTo(code, 0x40);
            return code;
        }, (blob, _) =>
        {
            blob.Ascii(SharedPipe);
            if (newer)
            {
                blob.Ascii(AddedPipe);
                blob.Ascii("http://added.example.net/update");
            }
            return [];
        });
        BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(PeBuilder.PeOffset + 8), stamp);
        return image;
    }

    private static async Task<(NativeDiffTools.NativeComparison Record, string Text, string NewSha1)> Compare(byte[] before, byte[] after)
    {
        using var h = new NativeBuildUpdateTests.Harness();
        var (o, oi) = await h.Load(before, "old.dll", [Name, Other]);
        var (n, ni) = await h.Load(after, "new.dll", [Name, Other]);
        foreach (var (native, index) in new[] { (o, oi), (n, ni) })
        {
            h.Code.Annotations(native).SetMany([(Name, "Grown"), (Other, "Steady")], []);
            index.SetUserName(Name, "Grown");
            index.SetUserName(Other, "Steady");
        }
        var tools = new NativeDiffTools(h.Env.Workspace, h.Code, inspection: new InspectionService(h.Env.Workspace));
        var (record, text) = await BuildToolCalls.Collected<NativeDiffTools.NativeComparison>(() => tools.CompareNativeImages(o.Id, n.Id, view: "hunts"));
        return (record, text, Convert.ToHexStringLower(System.Security.Cryptography.SHA1.HashData(after)));
    }

    private static KustoCode Parse(string kql)
    {
        static TypeSymbol Scalar(string type) => type switch
        {
            "string" => ScalarTypes.String, "long" => ScalarTypes.Long, "int" => ScalarTypes.Int,
            "bool" => ScalarTypes.Bool, "datetime" => ScalarTypes.DateTime, _ => throw new ArgumentException(type),
        };
        var tables = HuntSchema.Tables.Select(t => new TableSymbol(t, HuntSchema.Columns(t).Select(c => new ColumnSymbol(c.Name, Scalar(c.Type))))).ToArray();
        var db = new DatabaseSymbol("hunts", tables);
        return KustoCode.ParseAndAnalyze(kql, GlobalState.Default.WithCluster(new ClusterSymbol("cluster", db)).WithDatabase(db));
    }

    [Fact]
    public async Task Only_the_added_library_pipe_and_URL_give_queries_scoped_to_the_new_SHA1()
    {
        var (record, text, sha1) = await Compare(Image(false, OldStamp), Image(true, OldStamp + 1));
        var facts = record.Hunts!.Where(h => h.Table != "Event").ToList();
        Assert.Contains(facts, h => h.Facts[0] == "dll_name:added-lib.dll");
        Assert.Contains(facts, h => h.Facts[0].StartsWith("named_pipe:", StringComparison.Ordinal) && h.Kql.Contains("added-pipe", StringComparison.Ordinal));
        Assert.Contains(facts, h => h.Facts[0] == "url:http://added.example.net/update");
        Assert.Contains(facts, h => h.Facts[0] == "domain:added.example.net");
        Assert.Equal(4, facts.Count);
        Assert.All(facts, h => Assert.Contains($"InitiatingProcessSHA1 == '{sha1}'", h.Kql, StringComparison.Ordinal));
        Assert.DoesNotContain(record.Hunts!, h => h.Kql.Contains("shared-pipe", StringComparison.Ordinal) || h.Kql.Contains("shared-lib", StringComparison.Ordinal));
        Assert.Contains("5 hunting queries.", text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_added_URL_found_only_as_a_string_gets_a_query_scoped_to_the_new_build()
    {
        var (record, _, _) = await Compare(Image(false, OldStamp), Image(true, OldStamp + 1));
        var network = record.Hunts!.Where(h => h.Kql.Contains("added.example.net", StringComparison.Ordinal)).ToList();
        Assert.Equal(2, network.Count);
        Assert.All(network, h => Assert.Contains("InitiatingProcessSHA1 ==", h.Kql, StringComparison.Ordinal));
        Assert.DoesNotContain(record.Notes, n => n.Contains("found only as strings", StringComparison.Ordinal));
    }

    [Fact]
    public async Task An_added_imported_function_is_listed_in_a_note()
    {
        var (record, _, _) = await Compare(Image(false, OldStamp), Image(true, OldStamp + 1));
        Assert.Contains(record.Notes, n => n.Contains("added-lib.dll!go", StringComparison.Ordinal) && !n.Contains("shared-lib", StringComparison.Ordinal));
    }

    [Fact]
    public async Task The_crash_query_names_the_old_time_stamp_and_the_changed_range_and_parses_clean()
    {
        var (record, _, _) = await Compare(Image(false, OldStamp), Image(true, OldStamp + 1));
        var crash = Assert.Single(record.Hunts!, h => h.Table == "Event");
        Assert.Contains("'5f8a1b2c'", crash.Kql, StringComparison.Ordinal);
        Assert.Contains("'0000000000001000'", crash.Kql, StringComparison.Ordinal);
        Assert.Contains("'0000000000001006'", crash.Kql, StringComparison.Ordinal);
        Assert.DoesNotContain("'0000000000001040'", crash.Kql, StringComparison.Ordinal);
        Assert.Empty(Parse(crash.Kql).GetDiagnostics().Select(d => d.Message));
        Assert.Empty(KqlCheck.Diagnostics(crash.Kql));
    }

    [Fact]
    public async Task Two_identical_builds_give_no_queries_and_a_note_saying_so()
    {
        var (record, _, _) = await Compare(Image(true, OldStamp), Image(true, OldStamp));
        Assert.Empty(record.Hunts!);
        Assert.Contains(record.Notes, n => n.Contains("was added in the new build, so no query was written", StringComparison.Ordinal));
        Assert.Contains(record.Notes, n => n.Contains("No function changed", StringComparison.Ordinal));
    }

    [Fact]
    public void A_URL_with_reference_evidence_in_the_new_build_only_gives_a_scoped_network_query()
    {
        const string sha1 = "0123456789abcdef0123456789abcdef01234567";
        var kept = new HuntFact(HuntKind.Url, "https://kept.example.net/a", "reference");
        var set = UpdateHunts.Added([kept], [kept, new(HuntKind.Url, "https://added.example.net/b", "reference")], sha1);
        var hunt = Assert.Single(set.Hunts);
        Assert.Equal("DeviceNetworkEvents", hunt.Table);
        Assert.Contains("added.example.net", hunt.Kql, StringComparison.Ordinal);
        Assert.Contains($"| where InitiatingProcessSHA1 == '{sha1}'", hunt.Kql, StringComparison.Ordinal);
        Assert.Empty(Parse(hunt.Kql).GetDiagnostics().Select(d => d.Message));
    }

    [Fact]
    public async Task The_crash_module_name_is_named_as_the_old_build_file_name()
    {
        var (record, _, _) = await Compare(Image(false, OldStamp), Image(true, OldStamp + 1));
        Assert.Contains(record.Notes, n => n.Contains("old build's file name", StringComparison.Ordinal) && n.Contains("old.dll", StringComparison.Ordinal));
    }

    [Fact]
    public void A_fact_in_both_builds_with_different_case_is_not_added()
    {
        const string sha1 = "0123456789abcdef0123456789abcdef01234567";
        var set = UpdateHunts.Added([new(HuntKind.Url, "https://Kept.Example.net/A", "reference")], [new(HuntKind.Url, "https://kept.example.net/A", "reference")], sha1);
        Assert.Empty(set.Hunts);
    }

    [Fact]
    public void A_malformed_scope_SHA1_is_refused()
    {
        Assert.Throws<ArgumentException>(() => UpdateHunts.Added([], [new(HuntKind.Url, "https://a.example.net/", "reference")], "not-a-sha1'; drop"));
    }

    [Fact]
    public void A_partial_read_of_either_build_is_named()
    {
        Assert.Empty(UpdateHunts.PartialReads(false, false));
        Assert.Contains("old build's facts are partial", Assert.Single(UpdateHunts.PartialReads(true, false)), StringComparison.Ordinal);
        Assert.Contains("new build's facts are partial", Assert.Single(UpdateHunts.PartialReads(false, true)), StringComparison.Ordinal);
    }

    [Fact]
    public void The_crash_query_skips_events_with_no_faulting_offset()
    {
        var set = KqlHunts.WriteCrash("host.dll", OldStamp, [(0u, 0x10u)]);
        Assert.Contains("isnotempty(FaultingOffset)", Assert.Single(set.Hunts).Kql, StringComparison.Ordinal);
        Assert.Empty(Parse(set.Hunts[0].Kql).GetDiagnostics().Select(d => d.Message));
    }

    [Fact]
    public void More_ranges_than_the_cap_are_counted_in_a_note()
    {
        var ranges = Enumerable.Range(0, KqlHunts.MaxCrashRanges + 5).Select(i => ((uint)(i * 0x20), (uint)(i * 0x20 + 0x10)));
        var set = KqlHunts.WriteCrash("host.dll", OldStamp, ranges);
        Assert.Single(set.Hunts);
        Assert.Contains(set.Notes, n => n.StartsWith("5 changed range(s)", StringComparison.Ordinal));
        Assert.Empty(Parse(set.Hunts[0].Kql).GetDiagnostics().Select(d => d.Message));
    }
}
