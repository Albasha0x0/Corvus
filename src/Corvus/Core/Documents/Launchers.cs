using System.Text.RegularExpressions;

namespace Corvus.Core.Documents;

/// <summary>Programs that start other code and the argument shapes that make a command line worth reviewing; shortcut, script, installer and process views share it.</summary>
internal static class Launchers
{
    /// <summary>One program use: the program, the argument shape and what the shape does.</summary>
    internal sealed record Use(string Program, string Shape, string What);

    private sealed record Row(string Program, string Shape, string What, Regex Match);

    /// <summary>Command interpreters, script hosts and system tools a shortcut target is checked against.</summary>
    internal static IReadOnlyList<string> Programs { get; } =
        ["cmd.exe", "powershell.exe", "pwsh.exe", "mshta.exe", "wscript.exe", "cscript.exe", "rundll32.exe", "regsvr32.exe", "msiexec.exe", "certutil.exe",
         "bitsadmin.exe", "curl.exe", "conhost.exe", "forfiles.exe", "schtasks.exe", "wmic.exe", "msbuild.exe", "installutil.exe", "regasm.exe", "odbcconf.exe"];

    // Options and their wording follow the Windows commands reference, about_PowerShell_exe
    // and about_Pwsh on Microsoft Learn. Arguments end at & or |; NonBacktracking keeps
    // matching linear.
    private static Row Make(string program, string shape, string what, string arguments) =>
        new(program, shape, what, new Regex($@"(?i)\b{program}(?:\.exe)?\b[^&|]*{arguments}",
            RegexOptions.CultureInvariant | RegexOptions.NonBacktracking));

    private static readonly Row[] Rows =
    [
        Make("certutil", "-urlcache URL", "names a URL for the URL cache", @"\s[-/]urlcache\b[^&|]*https?://"),
        Make("certutil", "-decode", "decodes a file", @"\s[-/](?:decode|decodehex)\b"),
        Make("bitsadmin", "/transfer", "starts a file transfer", @"\s[-/](?:transfer|addfile)\b"),
        Make("mshta", "URL", "runs an application from a URL", @"https?://"),
        Make("regsvr32", "/i:URL", "passes a URL to DllInstall", @"\s[-/]i:\s*""?https?://"),
        Make("msiexec", "/i URL", "installs a package named by a URL", @"\s[-/]i\s+""?https?://"),
        Make("wmic", "process call create", "starts a process", @"\sprocess\s+call\s+create\b"),
        Make("powershell", "-EncodedCommand", "runs a base64 command", @"\s[-/]e(?:c|nc(?:odedcommand)?)?\s+[A-Za-z0-9+/=]{20,}"),
        Make("powershell", "-WindowStyle Hidden", "runs with a hidden window", @"\s[-/]w(?:indowstyle)?\s+hidden\b"),
        Make("pwsh", "-EncodedCommand", "runs a base64 command", @"\s[-/]e(?:c|nc(?:odedcommand)?)?\s+[A-Za-z0-9+/=]{20,}"),
        Make("pwsh", "-WindowStyle Hidden", "runs with a hidden window", @"\s[-/]w(?:indowstyle)?\s+hidden\b"),
    ];

    /// <summary>Every row of <paramref name="commandLine"/> that matches, one per program and shape; empty for a command line no row matches.</summary>
    internal static IReadOnlyList<Use> Match(string? commandLine)
    {
        if (string.IsNullOrEmpty(commandLine)) return [];
        var found = new List<Use>();
        foreach (var row in Rows)
            if (row.Match.IsMatch(commandLine)) found.Add(new Use(row.Program, row.Shape, row.What));
        return found;
    }

    /// <summary>The distinct matches of every command line, in order.</summary>
    internal static IReadOnlyList<Use> MatchAll(IEnumerable<string?> commandLines) =>
        [.. commandLines.SelectMany(Match).Distinct()];
}
