using System.Text;
using Corvus.Services.Web.Scripts;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>Script readers: transformation layers peeled to plain text by a bounded evaluator, nothing executed.</summary>
public sealed class ScriptReaderTests(ITestOutputHelper output)
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
        Assert.Contains("$wc = New-Object Net.WebClient", r.Plain, StringComparison.OrdinalIgnoreCase);
        Assert.True(r.Complete);
    }

    public static TheoryData<string> LauncherSamples() =>
        [.. Directory.GetFiles(Path.Combine(AppContext.BaseDirectory, "Web", "ScriptFixtures", "launchers"), "*.cmd").Select(f => Path.GetFileName(f)).Order()];

    [Theory]
    [MemberData(nameof(LauncherSamples))]
    public void Invoke_obfuscation_launchers_reach_the_powershell_they_start(string name)
    {
        var r = ScriptReader.Read(File.ReadAllText(Fixture("launchers", name)), "cmd");
        Assert.Contains(r.Layers, l => l.Language == "powershell" && l.Text.Trim().StartsWith("Write-Host 'corvus marker';", StringComparison.Ordinal));
        Assert.True(r.Complete);
    }

    /// <summary>Layered samples from the generators: each hides "corvus marker" behind its layers.</summary>
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
        var notes = $"complete={r.Complete}; recovered: {string.Join(", ", r.Recovered)}; notes: {string.Join(" | ", r.Notes)}";
        Assert.True(r.Plain.Contains("corvus marker", StringComparison.OrdinalIgnoreCase), notes);
        Assert.True(r.Complete, notes);
    }

    [Fact]
    public void A_vba_auto_run_macro_is_followed_into_its_shell_command()
    {
        var r = ScriptReader.Read(File.ReadAllText(Fixture("vbscript", "macro-autoopen.bas")), "vbscript");
        Assert.Contains(r.Calls, c => c.StartsWith("Shell \"cmd /c echo corvus marker", StringComparison.Ordinal));
        Assert.Contains("c = \"cmd /c echo corvus marker > %TEMP%\\c.txt\"", r.Plain);
    }

    [Fact]
    public void Layers_cross_languages_from_batch_through_vbscript_to_a_command_line()
    {
        var r = ScriptReader.Read(File.ReadAllText(Fixture("batch", "mshta-vbscript.cmd")), "batch");
        Assert.Equal(["vbscript", "vbscript", "cmd", "cmd"], r.Layers.Select(l => l.Language));
        Assert.Equal("WScript.Shell.Run", r.Layers[2].Via);
        Assert.Contains("WScript.Shell.Run \"cmd /c echo corvus marker\"", r.Calls);
    }

    [Fact]
    public void An_obfuscator_io_string_array_is_decoded_and_its_machinery_removed()
    {
        var r = ScriptReader.Read(File.ReadAllText(Fixture("javascript", "obfuscator-preset-high.js")), "javascript");
        Assert.Contains("='corvus marker';", r.Plain);
        // Decoder, rotation, wrappers and aliases gone.
        Assert.DoesNotContain("function _0x", r.Plain);
        Assert.Contains(r.Notes, n => n.StartsWith("obfuscator.io string array of ", StringComparison.Ordinal) && n.Contains(" strings decoded (rc4)", StringComparison.Ordinal));
    }

    [Fact]
    public void A_javascript_reading_out_of_steps_is_partial_and_says_so()
    {
        var text = File.ReadAllText(Fixture("javascript", "obfuscator-preset-high.js"));
        var r = ScriptReader.Read(text, "javascript", steps: 1_000);
        Assert.False(r.Complete);
        Assert.Contains("The evaluation budget ran out: later passes are not shown.", r.Notes);
        Assert.DoesNotContain(r.Notes, n => n.Contains("time limit", StringComparison.Ordinal));
        Assert.Contains("='corvus marker';", ScriptReader.Read(text, "javascript", steps: 100_000).Plain);
    }

    [Fact]
    public void A_reading_stopped_by_the_time_cap_is_partial_and_names_it()
    {
        // Steps far above what the loop reaches in 250 ms, so only the cap can stop it.
        var r = ScriptReader.Read("$i = 0; while ($true) { $i++ }", "powershell", steps: 1L << 40, milliseconds: 250);
        Assert.False(r.Complete);
        Assert.Contains("The 0.25 s time limit ran out: the reading is partial.", r.Notes);
    }

    [Fact]
    public void A_flattened_switch_loop_is_put_back_in_order()
    {
        const string script = "function f(){var s='2|0|1'.split('|'),i=0;while(!![]){switch(s[i++]){case'0':second();continue;case'1':third();continue;case'2':first();continue;}break;}}";
        var r = ScriptReader.Read(script, "javascript");
        int a = r.Plain.IndexOf("first();", StringComparison.Ordinal), b = r.Plain.IndexOf("second();", StringComparison.Ordinal), c = r.Plain.IndexOf("third();", StringComparison.Ordinal);
        Assert.True(a >= 0 && a < b && b < c, r.Plain);
        Assert.DoesNotContain("switch", r.Plain);
    }

    [Fact]
    public void A_packed_script_is_unpacked_as_a_layer()
    {
        var r = ScriptReader.Read(File.ReadAllText(Fixture("javascript", "packer.js")), "javascript");
        Assert.Equal("eval of a packer", Assert.Single(r.Layers).Via);
        Assert.StartsWith("var u = 'https://api.example.com/v1/notes';", r.Plain);
    }

    [Fact]
    public void The_script_view_pages_the_plain_text_and_names_the_layers()
    {
        var path = Fixture("powershell", "compress-1.ps1");
        var bytes = File.ReadAllBytes(path);
        var view = new Corvus.Services.Analysis.ScriptFileView().Inspect(new Corvus.Services.Analysis.FileInput(path, bytes, Corvus.Core.Blob.Identify(bytes))
            { Options = new Corvus.Services.Analysis.FileViewOptions("script", Offset: 5) }, default)!;
        var facts = (Corvus.Services.Analysis.ScriptFileView.Facts)view.Detail;
        Assert.Equal("powershell", facts.Language);
        Assert.Equal("Invoke-Expression of deflate", Assert.Single(facts.Layers).Via);
        Assert.Equal(5, facts.Offset);
        Assert.StartsWith("'http://example.com/corvus/stage.txt';", facts.Plain);
        Assert.StartsWith("PowerShell script: 1 transformation layer(s) peeled (powershell via Invoke-Expression of deflate)", view.Highlights[0]);
    }

    [Fact]
    public void A_plain_javascript_file_has_no_script_view_in_the_overview()
    {
        var bytes = Encoding.UTF8.GetBytes("export function add(a, b) { return a + b; }\n");
        Assert.Null(new Corvus.Services.Analysis.ScriptFileView().Inspect(new Corvus.Services.Analysis.FileInput("add.js", bytes, Corvus.Core.Blob.Identify(bytes)), default));
    }

    private static Corvus.Services.Analysis.FileView? Page(string script)
    {
        var bytes = Encoding.UTF8.GetBytes($"<!doctype html><html><body><button id=\"b\">Copy</button><script>{script}</script></body></html>");
        return new Corvus.Services.Analysis.ScriptFileView().Inspect(new Corvus.Services.Analysis.FileInput("page.html", bytes, Corvus.Core.Blob.Identify(bytes)), default);
    }

    [Fact]
    public void A_page_that_copies_an_encoded_command_shows_it_decoded()
    {
        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes("Write-Output hello"));
        var view = Page($"const c = 'powershell -nop -enc ' + '{encoded}'; document.getElementById('b').onclick = () => navigator.clipboard.writeText(c);")!;
        var copied = Assert.Single(((Corvus.Services.Analysis.ScriptFileView.Facts)view.Detail).Copied!);
        Assert.Equal(("navigator.clipboard.writeText", $"powershell -nop -enc {encoded}", "Write-Output hello"), (copied.Via, copied.Text, copied.Plain));
        Assert.Contains(view.Highlights, h => h.StartsWith("Copies a command to the clipboard (navigator.clipboard.writeText)", StringComparison.Ordinal)
            && h.EndsWith("it reads as: Write-Output hello.", StringComparison.Ordinal));
    }

    [Fact]
    public void A_command_copied_through_a_text_field_and_exec_command_is_reported()
    {
        var r = ScriptReader.Read("""
            const cmd = 'cmd /c echo hello';
            function copy() { const t = document.createElement('textarea'); t.value = cmd; document.body.appendChild(t); t.select(); document.execCommand('copy'); }
            """, "javascript");
        var copied = Assert.Single(r.Copied);
        Assert.Equal(("document.execCommand('copy')", "cmd /c echo hello"), (copied.Via, copied.Text));
    }

    [Fact]
    public void A_copy_button_for_ordinary_text_reports_nothing()
    {
        Assert.Null(Page("document.getElementById('b').onclick = () => navigator.clipboard.writeText('Order 1234 shipped');"));
        Assert.Empty(ScriptReader.Read("e.clipboardData.setData('text/plain', 'hello world');", "javascript").Copied);
    }

    [Fact]
    public void An_html_application_reads_its_script_blocks()
    {
        var hta = "<html><head><script language=\"VBScript\">Execute Chr(77) & \"sgBox \"\"corvus marker\"\"\"</script></head></html>";
        var bytes = Encoding.UTF8.GetBytes(hta);
        var view = new Corvus.Services.Analysis.ScriptFileView().Inspect(new Corvus.Services.Analysis.FileInput("a.hta", bytes, Corvus.Core.Blob.Identify(bytes)), default)!;
        var facts = (Corvus.Services.Analysis.ScriptFileView.Facts)view.Detail;
        Assert.Contains("MsgBox \"corvus marker\"", facts.Plain);
        Assert.Equal("vbscript", facts.Language);
    }

    [Fact]
    public void An_encoded_command_is_a_layer_with_its_decoding_chain()
    {
        var inner = Convert.ToBase64String(Encoding.Unicode.GetBytes("Write-Host 'second layer'"));
        var r = ScriptReader.Read($"powershell.exe -NoP -W Hidden -Enc {inner}", "powershell");
        var layer = Assert.Single(r.Layers);
        Assert.Equal("powershell -EncodedCommand of base64 > utf-16le", layer.Via);
        Assert.Equal("Write-Host 'second layer'", r.Plain.Trim());
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
        var r = ScriptReader.Read("$w = New-Object Net.WebClient; $w.DownloadFile('http://example.com/readme.txt', \"$env:TEMP\\readme.txt\"); Start-Process notepad.exe", "powershell");
        Assert.Contains("New-Object Net.WebClient", r.Calls);
        Assert.Contains(r.Calls, c => c.StartsWith("Net.WebClient.DownloadFile('http://example.com/readme.txt'", StringComparison.Ordinal));
        Assert.Contains("Start-Process", r.Calls);
    }

    [Fact]
    [Trait(PerfBudget.Trait, PerfBudget.Timing)]
    public void An_endless_loop_ends_at_the_budget()
    {
        var watch = System.Diagnostics.Stopwatch.StartNew();
        var r = ScriptReader.Read("$i = 0; while ($true) { $i++ }", "powershell", steps: 300_000);
        Assert.False(r.Complete);
        PerfBudget.Time("web/script-reader-loop-budget", watch.Elapsed, TimeSpan.FromSeconds(5), output);
    }

    [Fact]
    public void Damaged_scripts_read_without_failing()
    {
        (string Language, string Name)[] scripts =
        [
            ("powershell", "string-reverse-1.ps1"), ("powershell", "encoding-bxor-1.ps1"), ("powershell", "compress-1.ps1"),
            ("powershell", "token-all-1.ps1"), ("vbscript", "hex-function.vbs"), ("vbscript", "msxml-base64.vbs"),
            ("batch", "for-loop.bat"), ("batch", "mshta-vbscript.cmd"), ("javascript", "obfuscator-strings-rc4.js"),
            ("javascript", "obfuscator-control-flow.js"), ("javascript", "packer.js"),
        ];
        // Each read may run to its 30,000 steps, so the scripts are fuzzed side by side.
        var failures = new List<string>[scripts.Length];
        Parallel.For(0, scripts.Length, i => failures[i] = FormatFuzz.Run(File.ReadAllBytes(Fixture(scripts[i].Language, scripts[i].Name)), b =>
        {
            var r = ScriptReader.Read(Encoding.UTF8.GetString(b), scripts[i].Language, steps: 30_000);
            Assert.NotNull(r.Plain);
        }, 25));
        var all = failures.SelectMany(f => f).ToList();
        Assert.True(all.Count == 0, string.Join("\n", all.Take(10)));
    }
}
