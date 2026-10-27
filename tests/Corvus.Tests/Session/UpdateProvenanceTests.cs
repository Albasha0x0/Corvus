using Corvus.Setup;
using static Corvus.Setup.Installation;

namespace Corvus.Tests;

/// <summary>How <c>corvus update</c> acts on gh's provenance check of a downloaded archive; gh is faked.</summary>
public class UpdateProvenanceTests
{
    private const string Repo = "owner/name";
    private const string Asset = "corvus-linux-x64.tar.gz";

    private static Provenance Check(GhRunner gh, string? require = null, string? tag = "v2.0.0") =>
        CheckProvenance("/tmp/" + Asset, Asset, Repo, tag, require, gh);

    private static GhRunner Answers(int code, string output) => _ => (code, output);

    [Fact]
    public void A_pass_binds_the_repository_the_release_workflow_and_the_tag()
    {
        IReadOnlyList<string>? seen = null;
        var result = Check(args => { seen = args; return (0, ""); });
        Assert.Equal(ProvenanceState.Verified, result.State);
        Assert.Contains("Provenance verified", result.Message);
        Assert.Equal(["attestation", "verify", "/tmp/" + Asset, "--repo", Repo, "--signer-workflow", $"{Repo}/.github/workflows/release.yml",
            "--source-ref", "refs/tags/v2.0.0"], seen);
    }

    [Fact]
    public void Without_gh_the_build_installs_unchecked()
    {
        var result = Check(_ => null);
        Assert.Equal(ProvenanceState.NotChecked, result.State);
        Assert.Equal("Provenance not checked (gh is not on PATH).", result.Message);
    }

    [Fact]
    public void Strict_mode_refuses_an_unchecked_build()
    {
        var result = Check(_ => null, require: "1");
        Assert.Equal(ProvenanceState.Refused, result.State);
        Assert.Contains("CORVUS_REQUIRE_ATTESTATION=1", result.Message);
    }

    [Fact]
    public void A_file_gh_finds_no_attestation_for_is_refused()
    {
        var result = Check(Answers(1, "\nError: HTTP 404: Not Found (https://api.github.com/repos/owner/name/attestations/sha256:00)\n"));
        Assert.Equal(ProvenanceState.Refused, result.State);
        Assert.Contains("HTTP 404", result.Message);
        Assert.Equal(ProvenanceState.Refused, Check(Answers(1, "Error: verifying with issuer \"sigstore.dev\"")).State);
        Assert.Equal(ProvenanceState.Refused, Check(Answers(1, "Error: expected SourceRepositoryRef to be refs/tags/v2.0.0, got refs/tags/v1.0.0")).State);
    }

    // Gh 2.83.1's output when signed out (exit 4), offline, and too old for --signer-workflow.
    [Fact]
    public void Gh_signed_out_offline_or_too_old_leaves_the_build_unchecked()
    {
        Assert.Contains("not signed in", Check(Answers(4, "To get started with GitHub CLI, please run:  gh auth login")).Message);
        Assert.Equal(ProvenanceState.NotChecked, Check(Answers(1, "error creating Sigstore verifier: no valid Sigstore verifiers could be initialized")).State);
        Assert.Equal(ProvenanceState.NotChecked, Check(Answers(1, "unknown flag: --signer-workflow\n\nUsage: ...")).State);
    }

    [Fact]
    public void Opting_out_skips_gh()
    {
        var result = Check(_ => throw new InvalidOperationException("gh was run"), require: "0");
        Assert.Equal(ProvenanceState.NotChecked, result.State);
        Assert.Contains("CORVUS_REQUIRE_ATTESTATION=0", result.Message);
    }
}
