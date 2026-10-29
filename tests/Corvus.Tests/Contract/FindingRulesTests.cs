using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>The rule table: levels, noteworthy combinations, renames, vocabulary maps and recall of earlier noteworthy rules.</summary>
public sealed class FindingRulesTests
{
    // Rules that reported noteworthy in 2.7, by their 2.8.0 ids.
    private static readonly string[] NoteworthyIn27 =
    [
        "package/exec-decoded", "package/exec-download", "package/eval-response", "package/file-host-program", "package/download-and-run",
        "package/download-and-start", "package/decoded-command", "package/account-listing", "package/credential-files", "package/collection-url",
        "package/chat-webhook", "package/raw-address-url", "package/raw-address-socket", "package/reverse-shell", "package/download-to-shell",
        "package/hidden-powershell", "package/logon-start", "package/string-array", "package/escaped-call", "package/eval-decoded", "package/hidden-url",
        "package/exec-char-codes", "package/pyobfuscate", "package/space-run", "package/peeled-layers", "package/install-bundled-program",
        "package/install-compiled-eval", "package/collector-host", "package/install-network-collect", "package/install-network-launch",
        "package/socket-shell", "package/install-detached", "package/install-xor", "package/stdin-remote-code", "package/webhook-secrets",
        "package/load-beacon", "package/self-publish", "package/provenance-failed", "package/install-network-tool", "package/close-name",
        "package/credential-collection-dependencies", "package/record-differs", "package/csp-remote-code", "package/fetched-eval", "package/cookie-send",
        "package/crx-proof-failed", "package/invisible-name", "package/tag-characters", "package/bidi-controls", "package/zero-width",
        "package/agent-hook", "package/folder-open-task", "package/git-config-command", "package/git-hook", "package/devcontainer-command",
        "package/msbuild-exec", "package/msbuild-inline-task", "package/gradle-wrapper-url", "guarddog/threat-runtime-exec",
    ];

    [Fact]
    public void Every_row_has_a_unique_id_and_a_level_from_the_set()
    {
        Assert.Equal(FindingRules.All.Count, FindingRules.All.Select(r => r.Id).Distinct(StringComparer.Ordinal).Count());
        Assert.All(FindingRules.All, r => Assert.InRange(FindingLevel.Rank(r.Level), 1, 3));
        Assert.All(FindingRules.All, r => Assert.False(string.IsNullOrWhiteSpace(r.Reason), r.Id));
    }

    [Fact]
    public void A_noteworthy_row_names_the_list_or_combination_and_no_other_row_does()
    {
        Assert.All(FindingRules.All, r => Assert.Equal(r.Level == FindingLevel.Noteworthy, r.Noteworthy != null));
    }

    [Fact]
    public void A_level_above_its_row_or_an_unknown_id_is_refused()
    {
        Assert.Equal("review", FindingRules.Check("package/network", "review"));
        Assert.Equal("info", FindingRules.Check("package/network", "info"));
        Assert.Throws<InvalidOperationException>(() => FindingRules.Check("package/network", "noteworthy"));
        Assert.Throws<InvalidOperationException>(() => FindingRules.Check("package/network", "high"));
        Assert.Throws<InvalidOperationException>(() => FindingRules.Check("package/no-such-rule", "info"));
    }

    [Fact]
    public void A_rule_pack_id_resolves_to_its_family_row()
    {
        Assert.Equal("malcontent/*", FindingRules.Find("malcontent/net/http/request")?.Id);
        Assert.Equal("guarddog/*", FindingRules.Find("guarddog/threat-runtime-exec")?.Id);
        Assert.Null(FindingRules.Find("unknown/rule"));
    }

    [Fact]
    public void Renamed_ids_point_at_rows_and_are_never_reused()
    {
        foreach (var (old, renamed) in FindingRules.Renamed)
        {
            Assert.DoesNotContain(FindingRules.All, r => r.Id == old);
            Assert.NotNull(FindingRules.Find(renamed));
        }
    }

    [Fact]
    public void Each_rule_noteworthy_in_27_keeps_its_level_or_the_table_names_the_change()
    {
        foreach (var id in NoteworthyIn27)
        {
            var rule = FindingRules.Find(id);
            Assert.NotNull(rule);
            Assert.True(rule.Level == FindingLevel.Noteworthy || FindingRules.Relevelled.ContainsKey(id), $"{id} is {rule.Level} with no entry in Relevelled");
        }
    }

    [Fact]
    public void No_rule_changes_level_in_2_8_and_the_five_package_heuristics_stay_noteworthy()
    {
        Assert.Empty(FindingRules.Relevelled);
        foreach (var id in new[] { "package/hidden-url", "package/invisible-name", "package/raw-address-socket", "package/space-run", "package/string-array" })
            Assert.Equal(FindingLevel.Noteworthy, FindingRules.Find(id)!.Level);
    }

    [Theory]
    [InlineData("critical", "noteworthy")]
    [InlineData("high", "review")]
    [InlineData("medium", "review")]
    [InlineData("low", "info")]
    [InlineData(null, "info")]
    public void A_malcontent_risk_maps_to_a_level(string? risk, string level) => Assert.Equal(level, FindingRules.FromMalcontent(risk));

    [Fact]
    public void Masvs_severity_and_packer_kind_map_to_levels()
    {
        Assert.Equal("review", FindingRules.FromMasvs("high"));
        Assert.Equal("review", FindingRules.FromMasvs("medium"));
        Assert.Equal("info", FindingRules.FromMasvs("low"));
        Assert.Equal("review", FindingRules.FromPacker("suspicious"));
        Assert.Equal("info", FindingRules.FromPacker("packing tool"));
        Assert.Contains(FindingRules.All, r => r.Id == "android-trust-all" && r.Level == "review");
    }

    [Fact]
    public void The_table_digest_is_16_hex_digits_and_stable_within_a_build()
    {
        Assert.Matches("^[0-9a-f]{16}$", FindingRules.Digest);
        Assert.Equal(FindingRules.Digest, FindingRules.Digest);
    }

    [Fact]
    public void The_strongest_level_is_none_without_findings()
    {
        Assert.Equal("none", FindingLevel.Strongest([]));
        Assert.Equal("noteworthy", FindingLevel.Strongest(["info", "noteworthy", "review"]));
    }
}
