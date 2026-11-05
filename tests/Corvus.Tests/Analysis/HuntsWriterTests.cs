using System.Text.Json.Nodes;
using Corvus.Services.Analysis;
using Corvus.Services.Analysis.Hunts;
using Kusto.Language;
using Kusto.Language.Symbols;
using Kusto.Language.Syntax;

namespace Corvus.Tests;

/// <summary>The advanced hunting queries written from a fact list, parsed against the bundled table schema.</summary>
public sealed class HuntsWriterTests
{
    private const string Sha1 = "0123456789abcdef0123456789abcdef01234567";

    private static GlobalState Globals()
    {
        static TypeSymbol Scalar(string type) => type switch
        {
            "string" => ScalarTypes.String, "long" => ScalarTypes.Long, "int" => ScalarTypes.Int,
            "bool" => ScalarTypes.Bool, "datetime" => ScalarTypes.DateTime, _ => throw new ArgumentException(type),
        };
        var tables = HuntSchema.Tables.Select(t => new TableSymbol(t, HuntSchema.Columns(t).Select(c => new ColumnSymbol(c.Name, Scalar(c.Type))))).ToArray();
        var db = new DatabaseSymbol("hunts", tables);
        return GlobalState.Default.WithCluster(new ClusterSymbol("cluster", db)).WithDatabase(db);
    }

    private static KustoCode Parse(string kql) => KustoCode.ParseAndAnalyze(kql, Globals());

    private static HuntFact[] OneOfEach() =>
    [
        new(HuntKind.Sha1, Sha1, "decoded"),
        new(HuntKind.Signer, "CN=Example Publisher, O=Example", "decoded"),
        new(HuntKind.OriginalFileName, "tool.exe", "decoded"),
        new(HuntKind.DllName, "helper.dll", "reference"),
        new(HuntKind.Domain, "c2.example.net", "decoded"),
        new(HuntKind.Url, "https://c2.example.net/a?b=1", "reference"),
        new(HuntKind.Ipv4, "192.0.2.7", "decoded"),
        new(HuntKind.Ipv6, "2001:db8::7", "decoded"),
        new(HuntKind.NamedPipe, @"\\.\pipe\svc-pipe", "string"),
        new(HuntKind.FilePath, @"C:\Users\Public\drop.bin", "string"),
    ];

    [Theory]
    [InlineData(HuntKind.Sha1, "DeviceFileEvents", "DeviceProcessEvents", "DeviceImageLoadEvents")]
    [InlineData(HuntKind.Signer, "DeviceFileCertificateInfo")]
    [InlineData(HuntKind.OriginalFileName, "DeviceProcessEvents")]
    [InlineData(HuntKind.DllName, "DeviceImageLoadEvents")]
    [InlineData(HuntKind.Domain, "DeviceNetworkEvents")]
    [InlineData(HuntKind.Url, "DeviceNetworkEvents")]
    [InlineData(HuntKind.Ipv4, "DeviceNetworkEvents")]
    [InlineData(HuntKind.Ipv6, "DeviceNetworkEvents")]
    [InlineData(HuntKind.NamedPipe, "DeviceEvents")]
    [InlineData(HuntKind.FilePath, "DeviceFileEvents")]
    public void Each_fact_kind_gives_queries_on_the_expected_tables(string kind, params string[] tables)
    {
        var set = KqlHunts.Write(OneOfEach());
        var hunts = set.Hunts.Where(h => h.Facts[0].StartsWith(kind + ":", StringComparison.Ordinal)).ToList();
        Assert.Equal(tables.Order(StringComparer.Ordinal), hunts.Select(h => h.Table).Order(StringComparer.Ordinal));
        Assert.All(hunts, h => Assert.StartsWith(h.Table + "\n", h.Kql, StringComparison.Ordinal));
    }

    [Fact]
    public void Every_query_parses_with_zero_diagnostics()
    {
        var set = KqlHunts.Write(OneOfEach());
        Assert.Equal(12, set.Hunts.Count);
        Assert.All(set.Hunts, h => Assert.Empty(Parse(h.Kql).GetDiagnostics().Select(d => d.Message)));
        Assert.Equal(set.Hunts.Count, set.Hunts.Select(h => h.Id).Distinct().Count());
    }

    [Fact]
    public void A_value_with_a_quote_and_a_backslash_is_escaped()
    {
        const string value = @"it's a\path.exe";
        var set = KqlHunts.Write([new(HuntKind.OriginalFileName, value, "decoded")]);
        var hunt = Assert.Single(set.Hunts);
        Assert.Contains(@"'it\'s a\\path.exe'", hunt.Kql);
        var code = Parse(hunt.Kql);
        Assert.Empty(code.GetDiagnostics());
        Assert.Contains(code.Syntax.GetDescendants<LiteralExpression>(), l => (l.LiteralValue as string) == value);
    }

    [Fact]
    public void A_value_that_closes_the_literal_stays_inside_it()
    {
        const string value = "x' or 1 == 1 | take 1 //";
        var set = KqlHunts.Write([new(HuntKind.Domain, value, "decoded")]);
        var code = Parse(Assert.Single(set.Hunts).Kql);
        Assert.Empty(code.GetDiagnostics());
        Assert.Single(code.Syntax.GetDescendants<FilterOperator>());
        Assert.Contains(code.Syntax.GetDescendants<LiteralExpression>(), l => (l.LiteralValue as string) == value);
    }

    [Fact]
    public void A_control_character_is_written_as_an_escape()
    {
        var set = KqlHunts.Write([new(HuntKind.Domain, "a\nb\u0001.example.com", "decoded")]);
        var hunt = Assert.Single(set.Hunts);
        Assert.DoesNotContain("'a\nb", hunt.Kql);
        Assert.Contains(@"'a\nb\u0001.example.com'", hunt.Kql);
        Assert.Empty(Parse(hunt.Kql).GetDiagnostics());
    }

    [Fact]
    public void A_host_found_only_as_a_string_gives_no_network_query()
    {
        var set = KqlHunts.Write([new(HuntKind.Domain, "text.example.net", "string"), new(HuntKind.Url, "http://text.example.net/a", "string")]);
        Assert.Empty(set.Hunts);
        Assert.Contains(set.Notes, n => n.Contains("found only as strings", StringComparison.Ordinal));
    }

    [Fact]
    public void A_mutex_name_gives_a_note_and_no_query()
    {
        var set = KqlHunts.Write([new(HuntKind.Mutex, "Global\\one", "reference")]);
        Assert.Empty(set.Hunts);
        Assert.Contains(set.Notes, n => n.Contains("no mutex action type", StringComparison.Ordinal));
    }

    [Fact]
    public void A_library_name_without_the_file_hash_gives_a_note()
    {
        var set = KqlHunts.Write([new(HuntKind.DllName, "helper.dll", "reference")]);
        Assert.Empty(set.Hunts);
        Assert.Contains(set.Notes, n => n.Contains("SHA-1 of the loading file", StringComparison.Ordinal));
    }

    [Fact]
    public void A_hash_that_is_not_forty_hex_digits_gives_a_note()
    {
        var set = KqlHunts.Write([new(HuntKind.Sha1, "abc", "decoded")]);
        Assert.Empty(set.Hunts);
        Assert.Contains(set.Notes, n => n.Contains("not 40 hex digits", StringComparison.Ordinal));
    }

    [Fact]
    public void The_same_fact_twice_keeps_the_stronger_evidence_and_one_query_set()
    {
        var set = KqlHunts.Write([new(HuntKind.Domain, "c2.example.net", "reference"), new(HuntKind.Domain, "c2.example.net", "decoded")]);
        Assert.Equal("decoded", Assert.Single(set.Hunts).Evidence);
    }

    [Fact]
    public void The_checker_names_an_unknown_column_and_an_open_literal()
    {
        Assert.Contains("'Nope'", Assert.Single(KqlCheck.Diagnostics("DeviceFileEvents\n| where Nope == 'x'")));
        Assert.Contains("not terminated", Assert.Single(KqlCheck.Diagnostics("DeviceFileEvents\n| where SHA1 == 'x")));
        Assert.Contains("not in the schema", Assert.Single(KqlCheck.Diagnostics("Nothing\n| take 1")));
    }

    [Fact]
    public void A_rule_body_carries_the_required_fields_and_is_disabled()
    {
        var hunt = KqlHunts.Write([new(HuntKind.Sha1, Sha1, "decoded")]).Hunts[0];
        var rule = HuntRules.Rule(hunt);
        Assert.Equal(hunt.Id, (string?)rule["id"]);
        Assert.Equal(hunt.Title, (string?)rule["displayName"]);
        Assert.Equal(hunt.Kql, (string?)rule["queryCondition"]!["queryText"]);
        Assert.Equal("P1D", (string?)rule["schedule"]!["frequency"]);
        Assert.Equal("disabled", (string?)rule["status"]);
        var alert = rule["detectionAction"]!["alertTemplate"]!;
        Assert.Equal(hunt.Title, (string?)alert["title"]);
        Assert.Equal("medium", (string?)alert["severity"]);
        Assert.Equal("SHA1", (string?)alert["entityMappings"]!["files"]![0]!["sha1Column"]);
    }

    [Fact]
    public void Every_query_projects_the_columns_a_detection_rule_needs()
    {
        var set = KqlHunts.Write(OneOfEach());
        Assert.All(set.Hunts, h =>
        {
            var columns = Parse(h.Kql).ResultType is TableSymbol t ? t.Columns.Select(c => c.Name).ToList() : [];
            Assert.Contains("Timestamp", columns);
            Assert.Contains("DeviceId", columns);
            Assert.Contains("ReportId", columns);
            Assert.Contains("SHA1", columns);
        });
    }

    [Fact]
    public void The_hunt_file_holds_hunts_rules_and_notes()
    {
        var set = KqlHunts.Write([.. OneOfEach(), new(HuntKind.Mutex, "m", "reference")]);
        var root = JsonNode.Parse(HuntRules.Write(set))!;
        Assert.Equal(set.Hunts.Count, root["hunts"]!.AsArray().Count);
        Assert.Equal(set.Hunts.Count, root["detectionRules"]!.AsArray().Count);
        Assert.Contains(root["notes"]!.AsArray(), n => ((string?)n)!.Contains("mutex", StringComparison.Ordinal));
    }

    [Fact]
    public void The_library_query_compares_the_folder_of_the_library_with_the_folder_of_the_loader()
    {
        var hunt = KqlHunts.Write([new(HuntKind.Sha1, Sha1, "decoded"), new(HuntKind.DllName, "helper.dll", "reference")])
            .Hunts.Single(h => h.Table == "DeviceImageLoadEvents" && h.Facts[0].StartsWith("dll_name:", StringComparison.Ordinal));
        Assert.Contains("| where DllDir == LoaderDir", hunt.Kql, StringComparison.Ordinal);
        Assert.Contains("isnotempty(InitiatingProcessFolderPath)", hunt.Kql, StringComparison.Ordinal);
        Assert.Empty(Parse(hunt.Kql).GetDiagnostics());
    }

    [Fact]
    public void A_path_seen_only_as_a_string_reads_writes_by_this_file_alone()
    {
        var set = KqlHunts.Write([new(HuntKind.Sha1, Sha1, "decoded"), new(HuntKind.FilePath, @"C:\Windows\System32\cmd.exe", "string"),
            new(HuntKind.FilePath, @"C:\Users\Public\drop.bin", "decoded")]);
        var str = set.Hunts.Single(h => h.Facts[0].EndsWith("cmd.exe", StringComparison.Ordinal));
        var dec = set.Hunts.Single(h => h.Facts[0].EndsWith("drop.bin", StringComparison.Ordinal));
        Assert.Contains($"InitiatingProcessSHA1 == '{Sha1}'", str.Kql, StringComparison.Ordinal);
        Assert.DoesNotContain("InitiatingProcessSHA1", dec.Kql, StringComparison.Ordinal);
        Assert.Empty(Parse(str.Kql).GetDiagnostics());
        Assert.Empty(KqlHunts.Write([new(HuntKind.FilePath, @"C:\Windows\System32\cmd.exe", "string")]).Hunts);
    }

    [Fact]
    public void The_library_query_takes_a_folder_or_a_full_path_in_any_case()
    {
        var hunt = KqlHunts.Write([new(HuntKind.Sha1, Sha1, "decoded"), new(HuntKind.DllName, "helper.dll", "reference")])
            .Hunts.Single(h => h.Facts[0].StartsWith("dll_name:", StringComparison.Ordinal));
        // replace_string is case-sensitive and misses a folder-only path.
        Assert.DoesNotContain("replace_string", hunt.Kql, StringComparison.Ordinal);
        Assert.Contains(@"FolderPath endswith strcat('\\', FileName)", hunt.Kql, StringComparison.Ordinal);
        Assert.Contains(@"trim_end(@'\\', InitiatingProcessFolderPath)", hunt.Kql, StringComparison.Ordinal);
        Assert.Empty(Parse(hunt.Kql).GetDiagnostics());
    }

    [Fact]
    public void A_file_path_query_matches_the_folder_and_the_file_name_separately()
    {
        var hunt = KqlHunts.Write([new(HuntKind.FilePath, @"C:\Users\Public\drop.bin", "decoded")]).Hunts.Single();
        Assert.Contains(@"FolderPath =~ 'C:\\Users\\Public'", hunt.Kql, StringComparison.Ordinal);
        Assert.Contains(@"FolderPath =~ 'C:\\Users\\Public\\drop.bin'", hunt.Kql, StringComparison.Ordinal);
        Assert.Contains("FileName =~ 'drop.bin'", hunt.Kql, StringComparison.Ordinal);
        Assert.Empty(Parse(hunt.Kql).GetDiagnostics());
    }

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("0.0.0.0")]
    [InlineData("10.1.2.3")]
    [InlineData("192.168.0.9")]
    [InlineData("169.254.1.1")]
    [InlineData("::1")]
    public void A_local_address_gives_a_note_and_no_network_query(string address)
    {
        var set = KqlHunts.Write([new(address.Contains(':') ? HuntKind.Ipv6 : HuntKind.Ipv4, address, "reference")]);
        Assert.Empty(set.Hunts);
        Assert.Contains(set.Notes, n => n.Contains("loopback", StringComparison.Ordinal));
    }

    [Fact]
    public void A_URL_with_a_public_address_host_also_queries_the_remote_address()
    {
        var hunt = KqlHunts.Write([new(HuntKind.Url, "http://192.0.2.9/x", "reference")]).Hunts.Single();
        Assert.Contains("RemoteIP == '192.0.2.9'", hunt.Kql, StringComparison.Ordinal);
        Assert.Empty(Parse(hunt.Kql).GetDiagnostics());
    }

    [Fact]
    public void A_URL_with_a_private_address_host_adds_no_remote_address_clause()
    {
        var hunt = KqlHunts.Write([new(HuntKind.Url, "http://10.1.2.3/x", "reference")]).Hunts.Single();
        Assert.DoesNotContain("RemoteIP", hunt.Kql.Split('\n')[1], StringComparison.Ordinal);
    }

    [Fact]
    public void A_pipe_query_carries_a_note_that_its_names_are_unconfirmed()
    {
        var set = KqlHunts.Write([new(HuntKind.NamedPipe, @"\.\pipe\svc", "string")]);
        Assert.Contains(set.Notes, n => n.Contains("does not show the pipe is absent", StringComparison.Ordinal));
    }

    [Fact]
    public void An_unpaired_surrogate_is_replaced_and_the_hunt_file_still_writes()
    {
        var set = KqlHunts.Write([new(HuntKind.FilePath, @"C:\a\x" + "\ud800y.bin", "decoded"), new(HuntKind.NamedPipe, "p\udc00q", "string")]);
        Assert.NotEmpty(set.Hunts);
        Assert.NotEmpty(HuntRules.Write(set));
        Assert.All(set.Hunts, h => Assert.DoesNotContain(h.Kql, c => char.IsSurrogate(c)));
    }

    [Fact]
    public void Many_bad_hashes_give_one_note()
    {
        var set = KqlHunts.Write([.. Enumerable.Range(0, 30).Select(i => new HuntFact(HuntKind.Sha1, "bad" + i, "decoded"))]);
        Assert.Single(set.Notes);
        Assert.Contains("30 sha1 fact(s)", set.Notes[0], StringComparison.Ordinal);
    }

    [Fact]
    public void A_query_with_an_unbalanced_parenthesis_fails_the_check()
    {
        Assert.NotEmpty(KqlCheck.Diagnostics("DeviceFileEvents\n| where (SHA1 == 'a'"));
    }
}
