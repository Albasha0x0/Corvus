using System.Security.Cryptography;
using System.Text.Json;
using System.Xml;
using System.Xml.Schema;
using Corvus.Core;
using Corvus.Services;
using Corvus.Services.Analysis;
using Corvus.Services.Analysis.Hunts;

namespace Corvus.Tests;

/// <summary>Defender indicator bodies and an App Control audit policy written from the facts a proof kept; programs are built from source.</summary>
public sealed class AuditFilesTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly AssemblyWorkspace _ws = new();
    public void Dispose() { _ws.Dispose(); _dir.Dispose(); }

    private string Folder(string name) => Directory.CreateDirectory(_dir.File(name)).FullName;

    private static string Build(string folder, string name, string body)
    {
        var path = Path.Combine(folder, name + ".dll");
        File.WriteAllBytes(path, InspectionTests.Compile(name, "public static class " + name + " { " + body + " }"));
        return path;
    }

    private const string Contacts = """
        public static object A() => new System.Uri("https://shared.example.com/a");
        public static object B() => new System.Uri("https://own.example.com/b");
        public static object C() => new System.Uri("https://schemas.microsoft.com/x");
        public static string D() => "https://string-only.example.com/d";
        """;

    // Three clean files carry shared.example.com, so its fact is dropped.
    private (HuntSet Set, string File) Prove()
    {
        var clean = Folder("clean");
        for (int i = 0; i < 3; i++) Build(clean, "Clean" + i, "public static object A() => new System.Uri(\"https://shared.example.com/a\");");
        var file = Build(Folder("input"), "Subject", Contacts);
        var options = new FileViewOptions("hunts") { Hunts = true, AuditFiles = true, Proof = new ProofOptions(clean, MinFiles: 1) };
        var summary = new InspectionService(_ws).Summarize(null, file, default, options);
        return ((HuntSet)summary.Views["hunts"].Detail, file);
    }

    // Every document is checked for Audit with an alert, and for no blocking word outside the one warning note.
    private static JsonDocument Parse(HuntSet set)
    {
        var doc = JsonDocument.Parse(AuditIndicators.Write(set).Json);
        foreach (var b in doc.RootElement.GetProperty("indicators").EnumerateArray())
        {
            Assert.Equal("Audit", b.GetProperty("action").GetString());
            Assert.True(b.GetProperty("generateAlert").GetBoolean());
        }
        var notes = doc.RootElement.GetProperty("notes").EnumerateArray().Select(n => n.GetString()!).ToList();
        Assert.Contains(AuditIndicators.LeavingAudit, notes);
        Assert.DoesNotContain(notes.Where(n => n != AuditIndicators.LeavingAudit), n => n.Contains("block", StringComparison.OrdinalIgnoreCase));
        return doc;
    }

    private static JsonElement[] Bodies(JsonDocument doc) => [.. doc.RootElement.GetProperty("indicators").EnumerateArray()];

    private static string Reason(JsonDocument doc, string fact)
    {
        var rows = doc.RootElement.GetProperty("withheld").EnumerateArray().ToList();
        var row = rows.Where(w => w.GetProperty("fact").GetString() == fact).ToList();
        Assert.True(row.Count == 1, $"{fact} not among {string.Join(" | ", rows.Select(r => r.GetProperty("fact").GetString()))}");
        return row[0].GetProperty("reason").GetString()!;
    }

    [Fact]
    public void Every_indicator_body_is_audit_with_an_alert_and_none_blocks()
    {
        var (set, _) = Prove();
        using var doc = Parse(set);
        var bodies = Bodies(doc);
        Assert.NotEmpty(bodies);
        foreach (var b in bodies)
        {
            Assert.Equal("Audit", b.GetProperty("action").GetString());
            Assert.True(b.GetProperty("generateAlert").GetBoolean());
            Assert.Contains(b.GetProperty("indicatorType").GetString(), new[] { "FileSha1", "FileSha256", "DomainName", "Url", "IpAddress" });
        }
        var text = string.Concat(bodies.Select(b => b.GetRawText()));
        foreach (var word in new[] { "Block", "BlockAndRemediate", "AlertAndBlock", "Warn", "Allowed", "\"Alert\"" })
            Assert.DoesNotContain(word, text, StringComparison.Ordinal);
    }

    [Fact]
    public void A_kept_file_gives_a_SHA_1_body_and_a_SHA_256_body_of_its_digests()
    {
        var (set, file) = Prove();
        using var doc = Parse(set);
        var bytes = File.ReadAllBytes(file);
        var values = Bodies(doc).ToDictionary(b => b.GetProperty("indicatorType").GetString()!, b => b.GetProperty("indicatorValue").GetString()!);
        Assert.Equal(Convert.ToHexStringLower(SHA1.HashData(bytes)), values["FileSha1"]);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(bytes)), values["FileSha256"]);
    }

    [Fact]
    public void A_dropped_fact_a_string_only_URL_and_a_benign_host_are_withheld_with_their_reason()
    {
        var (set, _) = Prove();
        using var doc = Parse(set);
        var values = Bodies(doc).Select(b => b.GetProperty("indicatorValue").GetString()).ToList();
        Assert.Contains("https://own.example.com/b", values);
        Assert.DoesNotContain("https://shared.example.com/a", values);
        Assert.DoesNotContain("https://schemas.microsoft.com/x", values);
        Assert.DoesNotContain("https://string-only.example.com/d", values);
        Assert.StartsWith("drop:", Reason(doc, "url:https://shared.example.com/a"), StringComparison.Ordinal);
        Assert.Contains("only as a string", Reason(doc, "url:https://string-only.example.com/d"), StringComparison.Ordinal);
    }

    [Fact]
    public void A_set_with_no_proof_is_refused()
    {
        var summary = new InspectionService(_ws).Summarize(null, Build(Folder("input"), "Subject", Contacts), default, new FileViewOptions("hunts") { AuditFiles = true });
        var set = (HuntSet)summary.Views["hunts"].Detail;
        var error = Assert.Throws<ToolError>(() => AuditIndicators.Write(set));
        Assert.Equal(ErrorCode.InvalidArgument, error.Code);
        Assert.Throws<ToolError>(() => AuditPolicy.Write(set));
    }

    [Fact]
    public void The_policy_denies_the_authenticode_hashes_and_allows_every_other_file_in_audit_mode()
    {
        var (set, file) = Prove();
        var (xml, note) = AuditPolicy.Write(set);
        Assert.NotNull(xml);
        Assert.Equal("", note);
        var doc = new XmlDocument();
        doc.LoadXml(System.Text.Encoding.UTF8.GetString(xml!));
        var ns = new XmlNamespaceManager(doc.NameTable);
        ns.AddNamespace("p", "urn:schemas-microsoft-com:sipolicy");
        var options = doc.SelectNodes("//p:Rules/p:Rule/p:Option", ns)!.Cast<XmlNode>().Select(n => n.InnerText).ToList();
        Assert.Contains("Enabled:Audit Mode", options);
        Assert.Contains("Disabled:Script Enforcement", options);
        Assert.Contains("Enabled:UMCI", options);
        Assert.DoesNotContain(options, o => o.Contains("Enforce", StringComparison.Ordinal) && o.StartsWith("Enabled", StringComparison.Ordinal));
        var bytes = File.ReadAllBytes(file);
        var denied = doc.SelectNodes("//p:FileRules/p:Deny", ns)!.Cast<XmlElement>().Select(e => e.GetAttribute("Hash")).ToList();
        Assert.Equal([Convert.ToHexString(Certificates.AuthenticodeDigest(bytes, HashAlgorithmName.SHA1)!), Convert.ToHexString(Certificates.AuthenticodeDigest(bytes, HashAlgorithmName.SHA256)!)], denied);
        // Without an allow rule for every file in both scenarios, an audit
        // policy would log every other file.
        var allow = doc.SelectNodes("//p:FileRules/p:Allow[@FileName='*']", ns)!.Cast<XmlElement>().Select(e => e.GetAttribute("ID")).ToList();
        Assert.Equal(2, allow.Count);
        foreach (var scenario in doc.SelectNodes("//p:SigningScenario", ns)!.Cast<XmlElement>())
        {
            var refs = scenario.SelectNodes(".//p:FileRuleRef", ns)!.Cast<XmlElement>().Select(e => e.GetAttribute("RuleID")).ToList();
            Assert.Contains(allow, id => refs.Contains(id));
            Assert.Contains("ID_DENY_D_1", refs);
            Assert.Contains("ID_DENY_D_2", refs);
        }
        Assert.Empty(doc.SelectNodes("//p:Deny[@FileName]", ns)!.Cast<XmlNode>());
    }

    [Fact]
    public void The_policy_of_the_same_file_is_the_same_bytes()
    {
        var (set, _) = Prove();
        Assert.Equal(AuditPolicy.Write(set).Xml, AuditPolicy.Write(set).Xml);
    }

    [WindowsFact("The code integrity schema ships with Windows.")]
    public void The_policy_validates_against_the_code_integrity_schema()
    {
        var schemaFile = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "schemas", "CodeIntegrity", "cipolicy.xsd");
        if (!File.Exists(schemaFile)) return;
        var schemas = new XmlSchemaSet();
        schemas.Add("urn:schemas-microsoft-com:sipolicy", schemaFile);
        var (set, _) = Prove();
        var problems = new List<string>();
        var settings = new XmlReaderSettings { ValidationType = ValidationType.Schema, Schemas = schemas };
        settings.ValidationEventHandler += (_, e) => problems.Add(e.Message);
        using var reader = XmlReader.Create(new MemoryStream(AuditPolicy.Write(set).Xml!), settings);
        while (reader.Read()) { }
        Assert.Empty(problems);
    }

    private static ProofScan Scan(int notRead = 0)
    {
        var folder = new ProofFolder("clean", 25, 25 - notRead, notRead, 0, 0, [], 0, [], new Dictionary<string, int>());
        return new ProofScan(3, 5, 1, 0, 0, folder, null);
    }

    private static string TableOf(string fact) =>
        fact.StartsWith("sha1:", StringComparison.Ordinal) ? "DeviceFileEvents"
        : fact.StartsWith("signer:", StringComparison.Ordinal) ? "DeviceFileCertificateInfo" : "DeviceNetworkEvents";

    private static Hunt Query(string id, string fact, string evidence, string verdict = "keep", string? table = null) =>
        new(id, "title", table ?? TableOf(fact), "kql", [fact], evidence)
        { Severity = "low", Proof = verdict == "none" ? null : new HuntProof(verdict, "reason", 0, [], []) };

    private static HuntSet Of(IEnumerable<Hunt> hunts, ImageDigests? image = null, int notRead = 0) =>
        new(hunts.ToList(), []) { Proof = Scan(notRead), Image = image };

    private static HuntSet Handmade(string fact, string evidence, ImageDigests? image = null, string? table = null, string verdict = "keep") =>
        Of([Query("h", fact, evidence, verdict, table)], image);

    private static HuntSet Facts(params string[] facts) =>
        Of(facts.Select((f, i) => Query("h" + i, f, f.StartsWith("sha1:", StringComparison.Ordinal) ? IndicatorEvidence.Computed : IndicatorEvidence.Reference)),
            new ImageDigests("a.exe", new string('a', 40), new string('b', 64), new string('c', 40), new string('d', 64), null));

    private static List<(string Type, string Value)> Written(JsonDocument doc) =>
        [.. Bodies(doc).Select(b => (b.GetProperty("indicatorType").GetString()!, b.GetProperty("indicatorValue").GetString()!))];

    [Fact]
    public void Every_body_kind_is_audit_with_an_alert_and_an_IPv6_address_has_eight_segments()
    {
        using var doc = Parse(Facts("sha1:" + new string('a', 40), "domain:c2.example.test", "ipv4:8.8.8.8", "ipv6:2001:4860:4860::8888", "url:https://c2.example.test/a"));
        Assert.Equal(
            [("FileSha1", new string('a', 40)), ("FileSha256", new string('b', 64)), ("DomainName", "c2.example.test"), ("Url", "https://c2.example.test/a"),
             ("IpAddress", "8.8.8.8"), ("IpAddress", "2001:4860:4860:0:0:0:0:8888")], Written(doc));
    }

    [Theory]
    [InlineData("ipv4:10.0.0.5")]
    [InlineData("ipv4:127.0.0.1")]
    [InlineData("ipv4:169.254.1.1")]
    [InlineData("ipv6:::1")]
    [InlineData("ipv6:fe80::1")]
    [InlineData("ipv6:fc00::1")]
    [InlineData("url:http://10.0.0.5/a")]
    [InlineData("url:http://127.0.0.1:8080/a")]
    [InlineData("url:http://[::1]/a")]
    [InlineData("url:http://[::1]:8080/a")]
    [InlineData("url:http://169.254.169.254/latest")]
    public void A_private_loopback_or_link_local_address_is_withheld_alone_or_as_a_URL_host(string fact)
    {
        using var doc = Parse(Facts(fact));
        Assert.Empty(Bodies(doc));
        Assert.Contains("external address", Reason(doc, fact), StringComparison.Ordinal);
    }

    [Fact]
    public void A_fact_in_several_queries_is_kept_only_when_every_query_kept_it()
    {
        var set = Of([Query("a", "domain:mixed.example.test", IndicatorEvidence.Reference), Query("b", "domain:mixed.example.test", IndicatorEvidence.Reference, "review")]);
        using var doc = Parse(set);
        Assert.Empty(Bodies(doc));
        Assert.StartsWith("review:", Reason(doc, "domain:mixed.example.test"), StringComparison.Ordinal);
    }

    [Fact]
    public void A_query_with_no_verdict_is_not_a_kept_query()
    {
        using var doc = Parse(Of([Query("a", "domain:none.example.test", IndicatorEvidence.Reference, "none")]));
        Assert.Empty(Bodies(doc));
        Assert.Equal("no proof verdict", Reason(doc, "domain:none.example.test"));
    }

    [Fact]
    public void A_hunting_only_query_does_not_keep_a_fact()
    {
        var hunt = Query("a", "domain:only.example.test", IndicatorEvidence.Reference, "none") with { HuntingOnly = true };
        using var doc = Parse(Of([hunt]));
        Assert.Empty(Bodies(doc));
        Assert.Equal("no detection query reads it", Reason(doc, "domain:only.example.test"));
    }

    [Fact]
    public void A_partial_clean_scan_is_stated_in_the_indicator_notes_and_the_policy()
    {
        var sha1 = new string('a', 40);
        var image = new ImageDigests("a.exe", sha1, new string('b', 64), new string('c', 40), new string('d', 64), null);
        var set = Of([Query("h", "sha1:" + sha1, IndicatorEvidence.Computed)], image, notRead: 2);
        using var doc = Parse(set);
        var proof = doc.RootElement.GetProperty("notes").EnumerateArray().Select(n => n.GetString()!).Single(n => n.StartsWith("Proof:", StringComparison.Ordinal));
        Assert.Contains("23 of 25 clean files read, 2 not read", proof, StringComparison.Ordinal);
        Assert.Contains("minFiles 1", proof, StringComparison.Ordinal);
        Assert.Contains("partial", proof, StringComparison.Ordinal);
        Assert.Contains(proof, System.Text.Encoding.UTF8.GetString(AuditPolicy.Write(set).Xml!), StringComparison.Ordinal);
    }

    [Fact]
    public void A_repeated_value_is_written_once_after_it_is_normalized()
    {
        using var doc = Parse(Facts("domain:Example.TEST", "domain:example.test.", "url:https://h.example.test/a#top", "url:https://h.example.test/a#other", "url:https://h.example.test/a"));
        Assert.Equal([("DomainName", "example.test"), ("Url", "https://h.example.test/a")], Written(doc));
    }

    [Theory]
    [InlineData("domain:bücher.example.test")]
    [InlineData("url:https://bücher.example.test/a")]
    public void A_name_that_is_not_ASCII_is_withheld_not_guessed(string fact)
    {
        using var doc = Parse(Facts(fact));
        Assert.Empty(Bodies(doc));
        Assert.Contains("not ASCII", Reason(doc, fact), StringComparison.Ordinal);
    }

    [Fact]
    public void A_punycode_name_is_written_as_it_is()
    {
        using var doc = Parse(Facts("domain:xn--bcher-kva.example.test"));
        Assert.Equal([("DomainName", "xn--bcher-kva.example.test")], Written(doc));
    }

    [Theory]
    [InlineData("domain:www.w3.org.")]
    [InlineData("domain:WWW.W3.ORG")]
    [InlineData("domain:a.b.schemas.microsoft.com")]
    [InlineData("url:https://A.Schemas.Microsoft.com./x")]
    public void A_benign_host_is_matched_with_its_subdomains_and_ignoring_case_and_a_trailing_dot(string fact)
    {
        using var doc = Parse(Facts(fact));
        Assert.Empty(Bodies(doc));
        Assert.Contains("benign host", Reason(doc, fact), StringComparison.Ordinal);
    }

    [Fact]
    public void A_host_that_only_ends_like_a_benign_host_is_kept()
    {
        using var doc = Parse(Facts("domain:notw3.org"));
        Assert.Equal([("DomainName", "notw3.org")], Written(doc));
    }

    [Fact]
    public void A_URL_with_user_information_is_withheld_and_its_password_is_written_nowhere()
    {
        var set = Facts("url:https://user:s3cret-pw@host.example.test/a");
        using var doc = Parse(set);
        Assert.Empty(Bodies(doc));
        Assert.DoesNotContain("s3cret-pw", System.Text.Encoding.UTF8.GetString(AuditIndicators.Write(set).Json), StringComparison.Ordinal);
        Assert.Contains("user information", Reason(doc, "url:https://[user information removed]@host.example.test/a"), StringComparison.Ordinal);
    }

    [Fact]
    public void The_notes_name_network_protection_the_expiry_and_the_domain_scope()
    {
        using var doc = Parse(Facts("domain:c2.example.test"));
        var notes = string.Join('\n', doc.RootElement.GetProperty("notes").EnumerateArray().Select(n => n.GetString()));
        Assert.Contains("Network Protection", notes, StringComparison.Ordinal);
        Assert.Contains("No expirationTime is set", notes, StringComparison.Ordinal);
        Assert.Contains("every subdomain on every device", notes, StringComparison.Ordinal);
    }

    [Fact]
    public void A_saved_hunts_file_gives_indicators_of_its_hash_and_no_policy()
    {
        var (set, _) = Prove();
        var saved = _dir.File("hunts.json");
        File.WriteAllBytes(saved, HuntRules.Write(set));
        var clean = Folder("clean2");
        for (int i = 0; i < 3; i++) Build(clean, "Other" + i, "public static int N() => " + i + ";");
        var options = new FileViewOptions("hunts") { Hunts = true, AuditFiles = true, Proof = new ProofOptions(clean, MinFiles: 1) };
        var again = (HuntSet)new InspectionService(_ws).Summarize(null, saved, default, options).Views["hunts"].Detail;
        using var doc = Parse(again);
        Assert.Contains(Written(doc), w => w.Type == "FileSha1");
        Assert.DoesNotContain(Written(doc), w => w.Type == "FileSha256");
        Assert.Contains(doc.RootElement.GetProperty("withheld").EnumerateArray(), w => w.GetProperty("fact").GetString()!.StartsWith("sha256 of", StringComparison.Ordinal));
        var (xml, note) = AuditPolicy.Write(again);
        Assert.Null(xml);
        Assert.Contains("saved set", note, StringComparison.Ordinal);
    }

    [Fact]
    public void The_policy_states_the_effect_of_leaving_audit_in_its_comments_and_its_Info_setting()
    {
        var (set, _) = Prove();
        var text = System.Text.Encoding.UTF8.GetString(AuditPolicy.Write(set).Xml!);
        var doc = new XmlDocument();
        doc.LoadXml(text);
        var ns = new XmlNamespaceManager(doc.NameTable);
        ns.AddNamespace("p", "urn:schemas-microsoft-com:sipolicy");
        Assert.Equal(AuditPolicy.LeavingAudit, doc.SelectSingleNode("//p:Setting[@ValueName='Info']/p:Value/p:String", ns)!.InnerText);
        Assert.Contains(doc.SelectNodes("//comment()")!.Cast<XmlComment>(), c => c.Value!.Contains(AuditPolicy.LeavingAudit, StringComparison.Ordinal));
        // Outside that warning no blocking word is written.
        Assert.DoesNotContain("Block", text.Replace(AuditPolicy.LeavingAudit, ""), StringComparison.Ordinal);
    }

    [Fact]
    public void A_URL_with_quotes_and_angle_brackets_is_written_as_the_same_value()
    {
        var url = "https://host.example.test/a?q=\"1\"&r=<2>&s='3'";
        using var doc = Parse(Handmade("url:" + url, IndicatorEvidence.Reference));
        var body = Assert.Single(Bodies(doc));
        Assert.Equal(url, body.GetProperty("indicatorValue").GetString());
        Assert.Equal("Url", body.GetProperty("indicatorType").GetString());
    }

    [Theory]
    [InlineData("domain:evil\u0001.example.test")]
    [InlineData("domain:bad host.example.test")]
    [InlineData("url:https://host.example.test/a\u0007b")]
    [InlineData("url:ftp://host.example.test/a")]
    public void A_value_with_control_characters_or_spaces_or_no_web_scheme_is_withheld(string fact)
    {
        using var doc = Parse(Handmade(fact, IndicatorEvidence.Reference));
        Assert.Empty(Bodies(doc));
        Assert.Single(doc.RootElement.GetProperty("withheld").EnumerateArray());
    }

    [Fact]
    public void A_file_name_with_quotes_angle_brackets_and_control_characters_is_escaped_in_the_policy()
    {
        var sha1 = new string('a', 40);
        var image = new ImageDigests("a\"<b>&'\u0001\u0002.exe", sha1, new string('b', 64), new string('c', 40), new string('d', 64), null);
        var (xml, _) = AuditPolicy.Write(Handmade("sha1:" + sha1, IndicatorEvidence.Computed, image, "DeviceFileEvents"));
        var doc = new XmlDocument();
        doc.LoadXml(System.Text.Encoding.UTF8.GetString(xml!));
        var ns = new XmlNamespaceManager(doc.NameTable);
        ns.AddNamespace("p", "urn:schemas-microsoft-com:sipolicy");
        var name = ((XmlElement)doc.SelectSingleNode("//p:Deny[@ID='ID_DENY_D_1']", ns)!).GetAttribute("FriendlyName");
        Assert.StartsWith("a\"<b>&'��.exe", name, StringComparison.Ordinal);
    }

    [Fact]
    public void A_file_whose_hash_fact_the_proof_did_not_keep_gets_no_policy_and_names_why()
    {
        var sha1 = new string('a', 40);
        var image = new ImageDigests("a.exe", sha1, new string('b', 64), new string('c', 40), new string('d', 64), null);
        var (xml, note) = AuditPolicy.Write(Handmade("sha1:" + sha1, IndicatorEvidence.Computed, image, "DeviceFileEvents", "drop"));
        Assert.Null(xml);
        Assert.Contains("not kept (drop: reason)", note, StringComparison.Ordinal);
    }

    [Fact]
    public void A_file_with_no_authenticode_hashes_gets_no_policy_and_names_why()
    {
        var sha1 = new string('a', 40);
        var image = new ImageDigests("a.bin", sha1, new string('b', 64), null, null, "the file is not a PE image");
        var (xml, note) = AuditPolicy.Write(Handmade("sha1:" + sha1, IndicatorEvidence.Computed, image, "DeviceFileEvents"));
        Assert.Null(xml);
        Assert.Contains("not a PE image", note, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("domain:www.w3.org")]
    [InlineData("url:https://schemas.xmlsoap.org/ws/2005/02/trust")]
    public void A_host_of_the_benign_table_is_withheld(string fact)
    {
        using var doc = Parse(Handmade(fact, IndicatorEvidence.Reference));
        Assert.Empty(Bodies(doc));
        Assert.Contains("benign host", Reason(doc, fact), StringComparison.Ordinal);
    }

    [Fact]
    public void A_signer_fact_is_withheld_since_it_covers_every_file_the_publisher_signs()
    {
        using var doc = Parse(Handmade("signer:CN=Example", IndicatorEvidence.Computed, null, "DeviceFileCertificateInfo"));
        Assert.Empty(Bodies(doc));
        Assert.Contains("every file the publisher signs", Reason(doc, "signer"), StringComparison.Ordinal);
    }
}
