using System.Text.RegularExpressions;
using Corvus.Core.Archives;

namespace Corvus.Core.Documents;

/// <summary>A shortcut as a container: the data appended after its last extra data block, as overlay.bin.</summary>
internal sealed class ShellLinkReader : IContainerReader
{
    public string Kind => "lnk";

    public bool Accepts(ReadOnlySpan<byte> data, string name) => ShellLink.Looks(data);

    public ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        var link = ShellLink.Read(data, name);
        var items = new List<ExtractedItem>();
        var entries = new List<ContainerEntry>();
        long total = 0;
        if (link.Overlay.Length > 0) ArchiveItems.Take(items, entries, "appended data", "overlay.bin", link.Overlay, true, limits, ref total);
        var notes = new List<string>(link.Notes);
        notes.Add($"Shortcut to {link.Target ?? "(no target)"}{(link.Arguments is { Length: > 0 } a ? " " + ShellLinkRules.Clip(a) : "")}; summarize_file view=lnk lists its fields.");
        return new ContainerContents("Windows shortcut", items, notes) { Entries = entries };
    }
}

/// <summary>What is worth reviewing in a shortcut: the program it starts, hidden or encoded arguments, a disguising icon, appended data.</summary>
internal static class ShellLinkRules
{
    private static readonly string[] Launchers =
        ["cmd.exe", "powershell.exe", "pwsh.exe", "mshta.exe", "wscript.exe", "cscript.exe", "rundll32.exe", "regsvr32.exe", "msiexec.exe", "certutil.exe",
         "bitsadmin.exe", "curl.exe", "conhost.exe", "forfiles.exe", "schtasks.exe", "wmic.exe", "msbuild.exe", "installutil.exe", "regasm.exe", "odbcconf.exe"];

    private static readonly string[] DocumentIcons = [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".jpg", ".png", ".rtf", ".html", "msedge", "chrome", "acrord", "acrobat", "winword", "excel"];

    // Arguments run to 65,535 characters: NonBacktracking matches in linear
    // time, so no match timeout.
    private static readonly Regex EncodedCommand = new(@"(?i)(-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/=]{20,}|FromBase64String|\biex\b|Invoke-Expression|DownloadString|DownloadFile)",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
    private static readonly Regex Url = new(@"(?i)\b(?:https?|ftp)://[^\s'""\)]+", RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);

    public static string Clip(string s) => s.Length <= 200 ? s : s[..197] + "...";

    public static List<MacroFinding> Scan(ShellLink link)
    {
        var f = new List<MacroFinding>();
        var target = link.Target ?? "";
        var program = Path.GetFileName(target.Replace('\\', '/')).ToLowerInvariant();
        var args = link.Arguments ?? "";
        if (Launchers.Contains(program)) f.Add(new MacroFinding("Suspicious", program, "the shortcut starts a command interpreter, script host or system tool"));
        if (args.Length > 250) f.Add(new MacroFinding("Suspicious", "long arguments", $"{args.Length} characters of arguments; the properties dialog shows only the first 259 of target and arguments"));
        int leading = args.TakeWhile(char.IsWhiteSpace).Count();
        if (leading >= 50) f.Add(new MacroFinding("Suspicious", "padded arguments", $"the arguments start with {leading} blanks, which pushes them out of view"));
        var encoded = EncodedCommand.Match(args);
        if (encoded.Success) f.Add(new MacroFinding("Suspicious", encoded.Value.Length > 40 ? encoded.Value[..40] + "..." : encoded.Value, "encoded or downloaded commands in the arguments"));
        foreach (Match m in Url.Matches(args))
            f.Add(new MacroFinding("IOC", m.Value, "URL"));
        if (link.ShowCommand.StartsWith("minimized", StringComparison.Ordinal) && Launchers.Contains(program))
            f.Add(new MacroFinding("Suspicious", "minimized window", "the program starts minimized, out of sight"));
        var icon = (link.IconLocation ?? link.IconEnvironment ?? "").ToLowerInvariant();
        if (icon.Length > 0 && Launchers.Contains(program) && DocumentIcons.Any(d => icon.Contains(d, StringComparison.Ordinal)))
            f.Add(new MacroFinding("Suspicious", "document icon", $"the icon ({link.IconLocation ?? link.IconEnvironment}) suggests a document while the target is {program}"));
        if (link.Overlay.Length > 0)
            f.Add(new MacroFinding("Suspicious", "appended data", $"{link.Overlay.Length:N0} bytes ({Blob.Identify(link.Overlay)}) after the shortcut's last block") { Location = $"0x{link.OverlayOffset:X}" });
        return f;
    }
}
