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
        using var doc = JsonDocument.Parse(AuditIndicators.Write(set).Json);
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
        using var doc = JsonDocument.Parse(AuditIndicators.Write(set).Json);
        var bytes = File.ReadAllBytes(file);
        var values = Bodies(doc).ToDictionary(b => b.GetProperty("indicatorType").GetString()!, b => b.GetProperty("indicatorValue").GetString()!);
        Assert.Equal(Convert.ToHexStringLower(SHA1.HashData(bytes)), values["FileSha1"]);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(bytes)), values["FileSha256"]);
    }

    [Fact]
    public void A_dropped_fact_a_string_only_URL_and_a_benign_host_are_withheld_with_their_reason()
    {
        var (set, _) = Prove();
        using var doc = JsonDocument.Parse(AuditIndicators.Write(set).Json);
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

    private static HuntSet Handmade(string fact, string evidence, ImageDigests? image = null, string table = "DeviceNetworkEvents", string verdict = "keep")
    {
        var hunt = new Hunt("h", "title", table, "kql", [fact], evidence) { Severity = "low", Proof = new HuntProof(verdict, "reason", 0, [], []) };
        var folder = new ProofFolder("clean", 1, 1, 0, 0, 0, [], 0, [], new Dictionary<string, int>());
        return new HuntSet([hunt], []) { Proof = new ProofScan(3, 5, 1, 0, 0, folder, null), Image = image };
    }

    [Fact]
    public void A_URL_with_quotes_and_angle_brackets_is_written_as_the_same_value()
    {
        var url = "https://host.example.test/a?q=\"1\"&r=<2>&s='3'";
        using var doc = JsonDocument.Parse(AuditIndicators.Write(Handmade("url:" + url, IndicatorEvidence.Reference)).Json);
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
        using var doc = JsonDocument.Parse(AuditIndicators.Write(Handmade(fact, IndicatorEvidence.Reference)).Json);
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
        using var doc = JsonDocument.Parse(AuditIndicators.Write(Handmade(fact, IndicatorEvidence.Reference)).Json);
        Assert.Empty(Bodies(doc));
        Assert.Contains("benign host", Reason(doc, fact), StringComparison.Ordinal);
    }

    [Fact]
    public void A_signer_fact_is_withheld_since_it_covers_every_file_the_publisher_signs()
    {
        using var doc = JsonDocument.Parse(AuditIndicators.Write(Handmade("signer:CN=Example", IndicatorEvidence.Computed, null, "DeviceFileCertificateInfo")).Json);
        Assert.Empty(Bodies(doc));
        Assert.Contains("every file the publisher signs", Reason(doc, "signer"), StringComparison.Ordinal);
    }
}
