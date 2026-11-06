using Corvus.Services.Analysis;
using Corvus.Services.Analysis.Hunts;

namespace Corvus.Tests;

/// <summary>A clean fact is a hit when the query written for a fact would return a row for it.</summary>
public sealed class RuleProofMatchTests : IDisposable
{
    private readonly TempDir _dir = new();
    public void Dispose() => _dir.Dispose();

    private int Hits(string kind, string value, params HuntFact[] clean)
    {
        File.WriteAllText(_dir.File("clean.bin"), "x");
        var set = new HuntSet([new Hunt("h", "title", "DeviceEvents", "DeviceEvents", [kind + ":" + value], IndicatorEvidence.String)], []);
        var proved = RuleProof.Apply(set, new ProofOptions(_dir.Path, MinFiles: 1), (_, _) => new RuleProof.FileRead(false, clean, new HashSet<string>()), default);
        return proved.Hunts[0].Proof!.CleanHits;
    }

    private static HuntFact Fact(string kind, string value) => new(kind, value, IndicatorEvidence.String);

    [Theory]
    [InlineData("domain", "example.com", "domain", "www.example.com", 1)]
    [InlineData("domain", "example.com", "domain", "notexample.com", 0)]
    [InlineData("domain", "example.com", "url", "https://github.com/z?next=example.com", 1)]
    [InlineData("domain", "github.com", "url", "https://github.com/z", 1)]
    [InlineData("url", "https://github.com/a", "domain", "GITHUB.com", 1)]
    [InlineData("url", "https://github.com/a", "domain", "gist.github.io", 0)]
    public void Hosts_match_by_term_as_the_has_operator_does(string queryKind, string query, string cleanKind, string clean, int hits) =>
        Assert.Equal(hits, Hits(queryKind, query, Fact(cleanKind, clean)));

    [Fact]
    public void An_IPv6_address_matches_in_any_spelling() =>
        Assert.Equal(1, Hits("ipv6", "2001:DB8::1", Fact("ipv6", "2001:db8:0:0:0:0:0:1")));

    [Theory]
    [InlineData("svc-pipe", "svc-pipe", 1)]
    [InlineData("svc-pipe", "SVC-pipe", 1)]
    [InlineData("svc-pipe", "other-pipe", 0)]
    public void A_pipe_matches_by_its_name_with_or_without_the_pipe_prefix(string query, string clean, int hits)
    {
        Assert.Equal(hits, Hits("named_pipe", @"\.\pipe\" + query, Fact("named_pipe", clean)));
        Assert.Equal(hits, Hits("named_pipe", query, Fact("named_pipe", @"\.\pipe\" + clean)));
    }

    [Fact]
    public void A_registry_key_matches_below_the_hive_and_without_case() =>
        Assert.Equal(1, Hits("registry_key", @"HKEY_LOCAL_MACHINE\SOFTWARE\Vendor\App", Fact("registry_key", @"HKLM\software\vendor\app")));

    [Fact]
    public void A_registry_key_matches_as_the_tail_of_a_longer_path() =>
        Assert.Equal(1, Hits("registry_key", @"Vendor\App", Fact("registry_key", @"HKLM\Software\Vendor\App")));

    [Fact]
    public void An_unrooted_path_matches_by_its_file_name_and_slashes_fold()
    {
        Assert.Equal(1, Hits("file_path", "run.ps1", Fact("file_path", @"C:\Data\RUN.ps1")));
        Assert.Equal(1, Hits("file_path", @"C:\Data\run.ps1", Fact("file_path", "C:/data/run.ps1")));
        Assert.Equal(0, Hits("file_path", @"C:\Data\run.ps1", Fact("file_path", @"C:\Other\run.ps1")));
    }

    [Fact]
    public void A_signer_matches_by_its_name_inside_a_distinguished_name() =>
        Assert.Equal(1, Hits("signer", "CN=Example Publisher, O=Example", Fact("signer", "CN=Example Publisher, O=Example Corp, C=US")));
}
