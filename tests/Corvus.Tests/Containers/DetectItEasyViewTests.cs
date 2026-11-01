using Corvus.Core;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>The native view adds the packers Detect It Easy names when CORVUS_DIE is set.</summary>
[Collection(ExternalToolEnvironmentCollection.Name)]
public sealed class DetectItEasyViewTests
{
    private static byte[] Image()
    {
        var b = new PeBuilder();
        b.Add(".text", new byte[0x40], 0x60000020);
        return b.Build();
    }

    private static FileView? View(byte[] file) =>
        new NativeFileView().Inspect(new FileInput("app.exe", file, Blob.Identify(file)) { Options = new FileViewOptions("native") }, default);

    [Fact]
    public void A_packer_named_by_diec_is_listed_with_its_source()
    {
        using var fake = new FakeTool();
        fake.On("-j", stdout: """{"detects":[{"values":[{"type":"Protector","string":"ExampleGuard(1.0)"},{"type":"Packer","string":"ExamplePack(2.0)"},{"type":"Obfuscator","string":"ExampleMangler"},{"type":"Linker","string":"Example Linker"}]}]}""");
        using var scope = new EnvironmentScope().Set(FakeTool.ScriptVariable, fake.ScriptPath).Set("CORVUS_DIE", fake.CopyAs("diec"));
        var view = View(Image());
        var finding = Assert.Single(view!.Findings!, f => f.Rule == "packer/hardening-tool");
        Assert.Contains("ExampleGuard(1.0)", finding.Evidence);
        Assert.Contains("Detect It Easy", finding.Evidence);
        Assert.Contains(view.Findings, f => f.Rule == "packer/packing-tool" && f.Evidence.Contains("ExamplePack(2.0)"));
        Assert.DoesNotContain(view.Findings, f => f.Evidence.Contains("ExampleMangler") || f.Evidence.Contains("Example Linker"));
    }

    [Fact]
    public void A_packer_both_detectors_name_is_listed_once()
    {
        var b = new PeBuilder();
        b.Add("UPX0", new byte[0x40], 0x60000020);
        b.Add("UPX1", new byte[0x40], 0x60000020);
        var file = b.Build();
        using var fake = new FakeTool();
        fake.On("-j", stdout: """{"detects":[{"values":[{"type":"Packer","string":"UPX(3.96)"}]}]}""");
        using var scope = new EnvironmentScope().Set(FakeTool.ScriptVariable, fake.ScriptPath).Set("CORVUS_DIE", fake.CopyAs("diec"));
        var view = View(file);
        Assert.Single(view!.Findings!, f => f.Rule.StartsWith("packer/") && f.Evidence.Contains("UPX", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void A_stalled_diec_names_the_window_and_the_bytes_reached()
    {
        using var fake = new FakeTool();
        fake.On("-j", hangMs: 30_000);
        using var scope = new EnvironmentScope().Set(FakeTool.ScriptVariable, fake.ScriptPath).Set("CORVUS_DIE", fake.CopyAs("diec"));
        var result = DetectItEasy.Scan(DetectItEasy.Find()!, "app.exe", default, TimeSpan.FromMilliseconds(600));
        Assert.Empty(result.Detections);
        Assert.Contains("no output for 0.6 s", result.Problem);
        Assert.Contains("bytes", result.Problem);
        Assert.Contains("repeat the call or raise", result.Problem);
    }

    [Fact]
    public void A_failing_diec_reports_its_exit_code()
    {
        using var fake = new FakeTool();
        fake.On("-j", stderr: "bad", exit: 3);
        using var scope = new EnvironmentScope().Set(FakeTool.ScriptVariable, fake.ScriptPath).Set("CORVUS_DIE", fake.CopyAs("diec"));
        var view = View(Image());
        Assert.Contains(view!.Highlights, h => h.Contains("exit 3"));
    }

    [Fact]
    public void A_missing_diec_is_named_with_the_variable_to_set()
    {
        using var scope = new EnvironmentScope().Set("CORVUS_DIE", Path.Combine(Path.GetTempPath(), "no-such-diec"));
        var view = View(Image());
        Assert.Contains(view!.Highlights, h => h.Contains("CORVUS_DIE") && h.Contains("set it"));
    }
}
