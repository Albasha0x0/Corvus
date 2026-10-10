using System.Security.Cryptography;
using NetDecompilerMcp.Services;

namespace NetDecompilerMcp.Tests;

/// <summary>get_assembly_info facts: build identity, metadata inventory and structural problems.</summary>
public class AssemblyInfoTests
{
    [Fact]
    public void Provenance_FileSha256AndMvid_InTextAndStructured()
    {
        using var env = new Env();
        var sha = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(Env.FixturePath)));
        AssemblyReport.Summary summary = null!;
        var text = env.Workspace.Read(() => env.Report.Build(env.Fixture, out summary));
        Assert.Contains($"SHA-256: {sha}\n", text.ReplaceLineEndings("\n"));
        Assert.Contains($"MVID {env.Fixture.Module.Mvid}", text);
        Assert.Equal(sha, summary.Sha256);
        Assert.Equal(env.Fixture.Module.Mvid.ToString(), summary.Mvid);

        env.Edit(() => env.Edits.StubMethod(env.One("Fixture.Model.Account::Score"), "5"));
        Assert.Contains($"SHA-256: {sha} (file as loaded; unsaved edits not included)", env.Workspace.Read(() => env.Report.Build(env.Fixture)));
    }
}
