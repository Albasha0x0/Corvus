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
    [InlineData(HuntKind.Domain, "DeviceNetworkEvents", "DeviceNetworkEvents")]
    [InlineData(HuntKind.Url, "DeviceNetworkEvents", "DeviceNetworkEvents")]
    [InlineData(HuntKind.Ipv4, "DeviceNetworkEvents")]
    [InlineData(HuntKind.Ipv6, "DeviceNetworkEvents")]
    [InlineData(HuntKind.NamedPipe, "DeviceEvents")]
    [InlineData(HuntKind.FilePath, "DeviceFileEvents")]
    public void Each_fact_kind_gives_queries_on_the_expected_tables(string kind, params string[] tables)
    {
        var set = KqlHunts.Write(OneOfEach());
        var hunts = set.Hunts.Where(h => h.Facts.Any(f => f.StartsWith(kind + ":", StringComparison.Ordinal))).ToList();
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
        var code = Parse(Assert.Single(set.Hunts, h => !h.HuntingOnly).Kql);
        Assert.Empty(code.GetDiagnostics());
        Assert.Single(code.Syntax.GetDescendants<FilterOperator>());
        Assert.Contains(code.Syntax.GetDescendants<LiteralExpression>(), l => (l.LiteralValue as string) == value);
    }

    [Fact]
    public void A_control_character_is_written_as_an_escape()
    {
        var set = KqlHunts.Write([new(HuntKind.Domain, "a\nb\u0001.example.com", "decoded")]);
        var hunt = Assert.Single(set.Hunts, h => !h.HuntingOnly);
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
        Assert.Equal("decoded", Assert.Single(set.Hunts, h => !h.HuntingOnly).Evidence);
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
        Assert.All(set.Hunts.Where(h => !h.HuntingOnly), h =>
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
        Assert.Equal(set.Hunts.Count(h => !h.HuntingOnly) - 1, root["detectionRules"]!.AsArray().Count);
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
    public void The_library_query_leaves_out_loads_from_the_system_folders()
    {
        var hunt = KqlHunts.Write([new(HuntKind.Sha1, Sha1, "decoded"), new(HuntKind.DllName, "CRYPT32.dll", "reference")])
            .Hunts.Single(h => h.Table == "DeviceImageLoadEvents" && h.Facts[0].StartsWith("dll_name:", StringComparison.Ordinal));
        Assert.Contains(@"DllDir endswith @'\windows\system32'", hunt.Kql, StringComparison.Ordinal);
        Assert.Contains(@"DllDir endswith @'\windows\syswow64'", hunt.Kql, StringComparison.Ordinal);
        Assert.Empty(Parse(hunt.Kql).GetDiagnostics());
        Assert.Empty(KqlCheck.Diagnostics(hunt.Kql));
    }

    // Regression: ids hashed only kind and value, so two files' library
    // queries shared an id while filtering on different SHA-1 values.
    [Fact]
    public void Queries_filtered_on_a_file_get_an_id_per_file()
    {
        static Hunt Dll(HuntSet set) => set.Hunts.Single(h => h.Facts[0].StartsWith("dll_name:", StringComparison.Ordinal));
        static Hunt Signer(HuntSet set) => set.Hunts.Single(h => h.Table == "DeviceFileCertificateInfo");
        var other = new string('b', 40);
        var a = KqlHunts.Write([new(HuntKind.Sha1, Sha1, "decoded"), new(HuntKind.DllName, "version.dll", "reference"), new(HuntKind.Signer, "CN=Example", "decoded")]);
        var b = KqlHunts.Write([new(HuntKind.Sha1, other, "decoded"), new(HuntKind.DllName, "version.dll", "reference"), new(HuntKind.Signer, "CN=Example", "decoded")]);
        Assert.NotEqual(Dll(a).Id, Dll(b).Id);
        Assert.Equal(Signer(a).Id, Signer(b).Id);
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
        var set = KqlHunts.Write([new(HuntKind.NamedPipe, @"\.\pipe\svc", "reference")]);
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

    // Field test 11a: a signer query matches much of any fleet.
    [Fact]
    public void A_signer_query_stays_a_hunting_query_and_gets_no_detection_rule()
    {
        var set = KqlHunts.Write([new(HuntKind.Sha1, Sha1, "computed"), new(HuntKind.Signer, "CN=Example Publisher", "computed")]);
        var root = JsonNode.Parse(HuntRules.Write(set))!;
        Assert.Contains(root["hunts"]!.AsArray(), h => (string?)h!["table"] == "DeviceFileCertificateInfo");
        Assert.DoesNotContain(root["detectionRules"]!.AsArray(), r => ((string?)r!["queryCondition"]!["queryText"])!.StartsWith("DeviceFileCertificateInfo", StringComparison.Ordinal));
        Assert.Single(root["notes"]!.AsArray(), n => ((string?)n)!.Contains("Signer and DNS or TLS name queries", StringComparison.Ordinal));
    }

    // Field test 15g: the hunts array had no severity.
    [Fact]
    public void Each_hunt_of_the_file_carries_its_severity()
    {
        var root = JsonNode.Parse(HuntRules.Write(KqlHunts.Write(OneOfEach())))!;
        Assert.All(root["hunts"]!.AsArray(), h => Assert.Contains((string?)h!["severity"], new[] { "informational", "low", "medium", "high" }));
    }

    // Field test 11b: a pipe seen only as a string was not limited to the file.
    [Fact]
    public void A_pipe_seen_only_as_a_string_reads_opens_by_this_file_alone()
    {
        var pipe = new HuntFact(HuntKind.NamedPipe, @"\\.\pipe\svc-pipe", "string");
        var hunt = KqlHunts.Write([new(HuntKind.Sha1, Sha1, "computed"), pipe]).Hunts.Single(h => h.Table == "DeviceEvents");
        Assert.Contains($"InitiatingProcessSHA1 == '{Sha1}'", hunt.Kql, StringComparison.Ordinal);
        Assert.Empty(Parse(hunt.Kql).GetDiagnostics());
        var open = KqlHunts.Write([new(HuntKind.NamedPipe, @"\\.\pipe\svc-pipe", "reference")]).Hunts.Single();
        Assert.DoesNotContain("InitiatingProcessSHA1 ==", open.Kql, StringComparison.Ordinal);
        var none = KqlHunts.Write([pipe]);
        Assert.Empty(none.Hunts);
        Assert.Contains(none.Notes, n => n.Contains("file SHA-1 is unknown", StringComparison.Ordinal));
    }

    // Field test 12b: VERSION.dll and version.dll made two hunts.
    [Fact]
    public void Facts_that_differ_only_in_case_merge_and_keep_the_first_spelling()
    {
        var set = KqlHunts.Write([new(HuntKind.Domain, "C2.Example.NET", "reference"), new(HuntKind.Domain, "c2.example.net", "decoded"),
            new(HuntKind.OriginalFileName, "Tool.EXE", "decoded"), new(HuntKind.OriginalFileName, "tool.exe", "decoded")]);
        Assert.Equal(3, set.Hunts.Count);
        Assert.Equal("domain:C2.Example.NET", set.Hunts.Single(h => h.Table == "DeviceNetworkEvents" && !h.HuntingOnly).Facts[0]);
        Assert.Equal("decoded", set.Hunts.Single(h => h.Table == "DeviceNetworkEvents" && !h.HuntingOnly).Evidence);
    }

    // Field test 12c: one query per library name.
    [Fact]
    public void Library_names_share_one_query_with_a_case_insensitive_list()
    {
        var set = KqlHunts.Write([new(HuntKind.Sha1, Sha1, "computed"), new(HuntKind.DllName, "VERSION.dll", "reference"), new(HuntKind.DllName, "version.dll", "reference"),
            new(HuntKind.DllName, "helper.dll", "reference")]);
        var hunt = set.Hunts.Single(h => h.Facts[0].StartsWith("dll_name:", StringComparison.Ordinal));
        Assert.Equal(["dll_name:helper.dll", "dll_name:VERSION.dll"], hunt.Facts);
        Assert.Contains("| where FileName in~ ('helper.dll', 'VERSION.dll')", hunt.Kql, StringComparison.Ordinal);
        Assert.Empty(Parse(hunt.Kql).GetDiagnostics());
        Assert.Empty(KqlCheck.Diagnostics(hunt.Kql));
    }

    [Fact]
    public void A_library_list_past_the_character_cap_splits_into_queries()
    {
        var names = Enumerable.Range(0, 400).Select(i => new HuntFact(HuntKind.DllName, $"library-{i:D4}-{new string('x', 40)}.dll", "reference"));
        var set = KqlHunts.Write([new(HuntKind.Sha1, Sha1, "computed"), .. names]);
        var libraries = set.Hunts.Where(h => h.Facts[0].StartsWith("dll_name:", StringComparison.Ordinal)).ToList();
        Assert.True(libraries.Count > 1);
        Assert.Equal(400, libraries.Sum(h => h.Facts.Count));
        Assert.All(libraries, h => Assert.Empty(KqlCheck.Diagnostics(h.Kql)));
        Assert.Equal(libraries.Count, libraries.Select(h => h.Id).Distinct().Count());
    }

    [Fact]
    public void The_library_query_id_hashes_the_sorted_names_and_the_file()
    {
        static string Id(string sha1, params string[] names) =>
            KqlHunts.Write([new(HuntKind.Sha1, sha1, "computed"), .. names.Select(n => new HuntFact(HuntKind.DllName, n, "reference"))]).Hunts.Single(h => h.Facts[0].StartsWith("dll_name:", StringComparison.Ordinal)).Id;
        Assert.Equal(Id(Sha1, "a.dll", "B.dll"), Id(Sha1, "b.dll", "A.DLL"));
        Assert.NotEqual(Id(Sha1, "a.dll", "b.dll"), Id(Sha1, "a.dll"));
        Assert.NotEqual(Id(Sha1, "a.dll"), Id(new string('b', 40), "a.dll"));
    }

    // Field test 14: an archive has no process or image-load events.
    [Theory]
    [InlineData(HuntKind.Ipv4, "2.5.29.19")]
    [InlineData(HuntKind.Ipv4, "255.255.255.255")]
    [InlineData(HuntKind.Ipv6, "b::")]
    [InlineData(HuntKind.Ipv6, "::add")]
    [InlineData(HuntKind.Domain, "www")]
    [InlineData(HuntKind.Url, "http://t/")]
    public void A_string_that_only_has_the_form_of_an_address_gets_no_query(string kind, string value)
    {
        var set = KqlHunts.Write([new(kind, value, "string")], Sha1, true);
        Assert.Empty(set.Hunts);
        Assert.Contains(set.Notes, n => n.Contains("no network query", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(HuntKind.Ipv4, "2.5.29.19")]
    [InlineData(HuntKind.Domain, "intranet")]
    public void A_value_the_code_refers_to_keeps_its_query(string kind, string value)
    {
        Assert.NotEmpty(KqlHunts.Write([new(kind, value, "reference")], Sha1, true).Hunts);
    }

    [Theory]
    [InlineData(HuntKind.Ipv4, "1.1.1.1")]
    [InlineData(HuntKind.Ipv6, "2606:4700:4700::1111")]
    [InlineData(HuntKind.Domain, "www.example.org")]
    [InlineData(HuntKind.Url, "http://example.com/a")]
    public void A_plausible_string_keeps_its_query(string kind, string value)
    {
        Assert.NotEmpty(KqlHunts.Write([new(kind, value, "string")], Sha1, true).Hunts);
    }

    [Fact]
    public void The_written_note_counts_queries_and_rules_apart()
    {
        var set = KqlHunts.Write([new(HuntKind.Sha1, Sha1, "computed"), new(HuntKind.Domain, "app.example.net", "string")]);
        var rules = HuntRules.Rules(set).Count;
        Assert.True(rules < set.Hunts.Count);
        Assert.Equal($"{set.Hunts.Count} hunting queries and {rules} detection rules (disabled) written to a.json.", HuntRules.Written(set, "a.json"));
    }

    [Fact]
    public void A_host_query_also_reads_the_DNS_and_TLS_names_and_gets_no_rule()
    {
        var set = KqlHunts.Write([new(HuntKind.Sha1, Sha1, "computed"), new(HuntKind.Domain, "app.example.net", "string")]);
        var hunt = Assert.Single(set.Hunts, h => h.HuntingOnly);
        Assert.Contains("'DnsConnectionInspected', 'SslConnectionInspected'", hunt.Kql, StringComparison.Ordinal);
        Assert.DoesNotContain("InitiatingProcessSHA1", hunt.Kql, StringComparison.Ordinal);
        Assert.Empty(Parse(hunt.Kql).GetDiagnostics());
        Assert.DoesNotContain(hunt, HuntRules.Rules(set));
        Assert.Contains(set.Notes, n => n.Contains("RemoteUrl is empty on some connections", StringComparison.Ordinal));
    }

    [Fact]
    public void A_host_found_only_as_a_string_reads_the_connections_of_its_file()
    {
        var hunt = Assert.Single(KqlHunts.Write([new(HuntKind.Sha1, Sha1, "computed"), new(HuntKind.Ipv4, "1.1.1.1", "string")]).Hunts, h => h.Table == "DeviceNetworkEvents");
        Assert.Contains($"InitiatingProcessSHA1 == '{Sha1}'", hunt.Kql, StringComparison.Ordinal);
        Assert.EndsWith("by this file", hunt.Title, StringComparison.Ordinal);
        Assert.Empty(Parse(hunt.Kql).GetDiagnostics());
    }

    [Fact]
    public void A_host_string_in_a_file_that_is_not_executable_gives_no_network_query()
    {
        var set = KqlHunts.Write([new(HuntKind.Sha1, Sha1, "computed"), new(HuntKind.Domain, "text.example.net", "string")], null, false);
        Assert.DoesNotContain(set.Hunts, h => h.Table == "DeviceNetworkEvents");
        Assert.Contains(set.Notes, n => n.Contains("found only as strings", StringComparison.Ordinal));
    }

    [Fact]
    public void A_url_query_matches_the_host_because_RemoteUrl_can_omit_the_path()
    {
        var set = KqlHunts.Write([new(HuntKind.Url, "https://app.example.net/a/b", "reference")]);
        Assert.Contains("RemoteUrl has 'app.example.net'", Assert.Single(set.Hunts, h => !h.HuntingOnly).Kql, StringComparison.Ordinal);
        Assert.Contains(set.Notes, n => n.Contains("match the host", StringComparison.Ordinal));
    }

    [Fact]
    public void A_url_and_its_host_share_one_query_that_names_both_facts()
    {
        var hunt = Assert.Single(KqlHunts.Write([new(HuntKind.Domain, "app.example.net", "reference"), new(HuntKind.Url, "https://app.example.net/a", "reference")]).Hunts, h => !h.HuntingOnly);
        Assert.Equal(["domain:app.example.net", "url:https://app.example.net/a"], hunt.Facts);
    }

    [Theory]
    [InlineData(@"HKCU\Software\Vendor\App", @"Software\Vendor\App")]
    [InlineData(@"HKEY_LOCAL_MACHINE\SOFTWARE\Vendor", @"SOFTWARE\Vendor")]
    [InlineData(@"Software\Vendor\App", @"Software\Vendor\App")]
    public void A_registry_query_reads_the_path_below_the_hive(string value, string path)
    {
        var hunt = Assert.Single(KqlHunts.Write([new(HuntKind.Sha1, Sha1, "computed"), new(HuntKind.RegistryKey, value, "string")]).Hunts, h => h.Table == "DeviceRegistryEvents");
        // A delete leaves RegistryKey empty and keeps the key in the previous column.
        Assert.Contains($"PreviousRegistryKey endswith {KqlHunts.Literal("\\" + path)}", hunt.Kql, StringComparison.Ordinal);
        Assert.Contains($"InitiatingProcessSHA1 == '{Sha1}'", hunt.Kql, StringComparison.Ordinal);
        Assert.Empty(Parse(hunt.Kql).GetDiagnostics());
    }

    [Fact]
    public void A_hive_alone_gives_no_registry_query()
    {
        var set = KqlHunts.Write([new(HuntKind.Sha1, Sha1, "computed"), new(HuntKind.RegistryKey, "HKLM", "string")]);
        Assert.DoesNotContain(set.Hunts, h => h.Table == "DeviceRegistryEvents");
    }

    [Fact]
    public void A_file_query_notes_that_no_result_does_not_show_no_write()
    {
        var set = KqlHunts.Write([new(HuntKind.FilePath, @"C:\ProgramData\a.txt", "reference")]);
        Assert.Contains(set.Notes, n => n.Contains("does not record every write", StringComparison.Ordinal));
    }

    [Fact]
    public void A_rule_maps_the_device_and_file_columns_its_query_returns()
    {
        var hunt = KqlHunts.Write([new(HuntKind.Sha1, Sha1, "computed")]).Hunts[0];
        var map = HuntRules.Rule(hunt)["detectionAction"]!["alertTemplate"]!["entityMappings"]!;
        Assert.Equal("DeviceId", (string?)map["hosts"]![0]!["deviceIdColumn"]);
        Assert.Equal("DeviceName", (string?)map["hosts"]![0]!["nameColumn"]);
        Assert.Equal("SHA1", (string?)map["files"]![0]!["sha1Column"]);
    }

    [Fact]
    public void A_crash_rule_maps_the_computer_and_no_file()
    {
        var hunt = Assert.Single(KqlHunts.WriteCrash("host.dll", 0x12345678, [(0x10u, 0x20u)]).Hunts);
        var map = HuntRules.Rule(hunt)["detectionAction"]!["alertTemplate"]!["entityMappings"]!;
        Assert.Equal("Computer", (string?)map["hosts"]![0]!["nameColumn"]);
        Assert.Null(map["files"]);
    }

    [Fact]
    public void A_signer_note_does_not_mark_the_facts_partial()
    {
        Assert.False(HuntFacts.LimitsFacts("The signer is unknown: the file has no embedded signature, and catalog signatures are not read."));
        Assert.True(HuntFacts.LimitsFacts("The version resource and imports are unknown, the image did not parse: bad."));
    }

    [Theory]
    [InlineData("1.1.1.1", "ipv4", "1.1.1.1")]
    [InlineData("2606:4700:4700::1111", "ipv6", "2606:4700:4700::1111")]
    public void A_short_address_in_a_native_string_is_read(string text, string type, string value)
    {
        byte[] image = [0, .. System.Text.Encoding.ASCII.GetBytes(text), 0];
        Assert.Contains(IndicatorList.FromImageStrings("native", image, default), h => h.Type == type && h.Value == value);
    }

    [Theory]
    [InlineData(@"pipe \\.\pipe\demo-pipe: ready", "named_pipe", @"\\.\pipe\demo-pipe")]
    [InlineData(@"C:\ProgramData\demo.txt: ok", "file_path", @"C:\ProgramData\demo.txt")]
    [InlineData("fetch https://example.net/demo:", "url", "https://example.net/demo")]
    [InlineData(@"Cannot open HKLM\\Software\\Vendor\\App: access denied", "registry_key", @"HKLM\\Software\\Vendor\\App")]
    [InlineData(@"Software\\Vendor\\App: ok", "registry_key", @"Software\\Vendor\\App")]
    public void A_value_in_a_message_keeps_none_of_the_message(string text, string type, string value)
    {
        var found = Values.FromFields([(text, "field")], out _, default);
        Assert.Equal(value, Assert.Single(found, v => v.Type == type).Value);
    }

    [Fact]
    public void A_file_that_is_not_executable_gets_the_file_event_query_only()
    {
        var set = KqlHunts.Write([new(HuntKind.Sha1, Sha1, "computed")], null, executable: false);
        Assert.Equal("DeviceFileEvents", Assert.Single(set.Hunts).Table);
    }
}
