using System.Text;
using System.Text.RegularExpressions;

namespace Corvus.Core.Documents;

/// <summary>A finding in macro text: AutoExec, Suspicious, IOC, Hex String or Base64 String, with what it means.</summary>
internal sealed record MacroFinding(string Type, string Keyword, string Description)
{
    /// <summary>The encoding a keyword was found under (Hex, Base64), null for the plain text.</summary>
    public string? Decoded { get; init; }
    /// <summary>Module and line of the first occurrence in the plain text.</summary>
    public string? Location { get; init; }
}

/// <summary>olevba's keyword rules over VBA and XLM macro text; hex and base64 strings are decoded and scanned again.</summary>
internal static class MacroScan
{
    // NonBacktracking matches in linear time, so the rules take no match timeout.
    private const RegexOptions Linear = RegexOptions.CultureInvariant | RegexOptions.NonBacktracking;

    // Keyword rules and IOC locators are BoundedRegex: NonBacktracking
    // construction costs about 1.3 MB per rule, and there are about 200.
    private const RegexOptions Bounded = RegexOptions.CultureInvariant;

    private static readonly (string Description, string[] Keywords)[] AutoExec =
    [
        ("runs when the Word document is opened", ["AutoExec", "AutoOpen", "DocumentOpen"]),
        ("runs when the Word document is closed", ["AutoExit", "AutoClose", "Document_Close", "DocumentBeforeClose"]),
        ("runs when the Word document is modified", ["DocumentChange"]),
        ("runs when a new Word document is created", ["AutoNew", "Document_New", "NewDocument"]),
        ("runs when the Word or Publisher document is opened", ["Document_Open"]),
        ("runs when the Publisher document is closed", ["Document_BeforeClose"]),
        ("runs when the Excel workbook is opened", ["Auto_Open", "Workbook_Open", "Workbook_Activate", "Auto_Ope"]),
        ("runs when the Excel workbook is closed", ["Auto_Close", "Workbook_Close", "Workbook_BeforeClose"]),
        ("may run when an Excel worksheet is opened", ["Worksheet_Calculate"]),
    ];

    private static readonly (string Description, string[] Patterns)[] AutoExecPatterns =
    [
        ("runs when the file is opened (InkPicture ActiveX object)", [@"\w+_Painted", @"\w+_Painting"]),
        ("runs when the file is opened and ActiveX objects trigger events", [@"\w+_GotFocus", @"\w+_LostFocus", @"\w+_MouseHover", @"\w+_Click", @"\w+_Change",
            @"\w+_Resize", @"\w+_BeforeNavigate2", @"\w+_BeforeScriptExecute", @"\w+_DocumentComplete", @"\w+_DownloadBegin", @"\w+_DownloadComplete",
            @"\w+_FileDownload", @"\w+_NavigateComplete2", @"\w+_NavigateError", @"\w+_ProgressChange", @"\w+_PropertyChange", @"\w+_SetSecureLockIcon",
            @"\w+_StatusTextChange", @"\w+_TitleChange", @"\w+_MouseMove", @"\w+_MouseEnter", @"\w+_MouseLeave", @"\w+_Layout", @"\w+_OnConnecting",
            @"\w+_FollowHyperlink", @"\w+_ContentControlOnEnter"]),
    ];

    private static readonly (string Description, string[] Keywords)[] Suspicious =
    [
        ("may read environment variables", ["Environ", "Win32_Environment", "Environment", "ExpandEnvironmentStrings", @"HKCU\Environment", @"HKEY_CURRENT_USER\Environment"]),
        ("may open a file", ["Open"]),
        ("may write to a file (with Open)", ["Write", "Put", "Output", "Print #"]),
        ("may read or write a binary file (with Open)", ["Binary"]),
        ("may copy a file", ["FileCopy", "CopyFile", "CopyHere", "CopyFolder"]),
        ("may move a file", ["MoveHere", "MoveFile", "MoveFolder"]),
        ("may delete a file", ["Kill"]),
        ("may create a text file", ["CreateTextFile", "ADODB.Stream", "WriteText", "SaveToFile"]),
        ("may run a program or a system command", ["Shell", "vbNormal", "vbNormalFocus", "vbHide", "vbMinimizedFocus", "vbMaximizedFocus", "vbNormalNoFocus",
            "vbMinimizedNoFocus", "WScript.Shell", "Run", "ShellExecute", "ShellExecuteA", "shell32", "InvokeVerb", "InvokeVerbEx", "DoIt"]),
        ("may run a DLL", ["ControlPanelItem"]),
        ("may run a program or command through WMI", ["Create"]),
        ("may run a program or command on a Mac", ["MacScript", "AppleScript"]),
        ("may run PowerShell commands", ["PowerShell", "noexit", "ExecutionPolicy", "noprofile", "command", "EncodedCommand", "invoke-command", "scriptblock",
            "Invoke-Expression", "AuthorizationManager"]),
        ("may run a program or command through PowerShell", ["Start-Process"]),
        ("may call a DLL through Excel 4.0 macros", ["CALL"]),
        ("may hide the application", ["Application.Visible", "ShowWindow", "SW_HIDE"]),
        ("may create a directory", ["MkDir"]),
        ("may save the current workbook", ["ActiveWorkbook.SaveAs"]),
        ("may change the startup folder", ["Application.AltStartupPath"]),
        ("may create an OLE object", ["CreateObject"]),
        ("may get a running OLE object", ["GetObject"]),
        ("may create an OLE object through PowerShell", ["New-Object"]),
        ("may run an application (with CreateObject)", ["Shell.Application"]),
        ("may run an Excel 4.0 macro from VBA", ["ExecuteExcel4Macro"]),
        ("may enumerate application windows", ["Windows", "FindWindow"]),
        ("may run code from a DLL", ["Lib"]),
        ("may run code from a library on a Mac", ["libc.dylib", "dylib"]),
        ("may inject code into another process", ["CreateThread", "CreateUserThread", "VirtualAlloc", "VirtualAllocEx", "RtlMoveMemory", "WriteProcessMemory",
            "SetContextThread", "QueueApcThread", "WriteVirtualMemory", "VirtualProtect"]),
        ("may run shellcode in memory", ["SetTimer"]),
        ("may download files", ["URLDownloadToFileA", "Msxml2.XMLHTTP", "Microsoft.XMLHTTP", "MSXML2.ServerXMLHTTP", "User-Agent"]),
        ("may download files through PowerShell", ["Net.WebClient", "DownloadFile", "DownloadString"]),
        ("may send keystrokes to another application", ["SendKeys", "AppActivate"]),
        ("may hide calls behind names", ["CallByName"]),
        ("may hide strings", ["Chr", "ChrB", "ChrW", "StrReverse", "Xor"]),
        ("may read or write registry keys", ["RegOpenKeyExA", "RegOpenKeyEx", "RegCloseKey"]),
        ("may read registry keys", ["RegQueryValueExA", "RegQueryValueEx", "RegRead"]),
        ("may detect virtualization", [@"SYSTEM\ControlSet001\Services\Disk\Enum", "VIRTUAL", "VMWARE", "VBOX"]),
        ("may detect an analysis sandbox", ["GetVolumeInformationA", "GetVolumeInformation", "1824245000", @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductId",
            "76487-337-8429955-22614", "andy", @"C:\exec\exec.exe", "popupkiller", "SbieDll.dll", "SandboxieControlWndClass", @"C:\file.exe", "currentuser", "Schmidti", "Afx:400000:0"]),
        ("may disable macro security or Protected View", ["AccessVBOM", "VBAWarnings", "ProtectedView", "DisableAttachementsInPV", "DisableInternetFilesInPV",
            "DisableUnsafeLocationsInPV", "blockcontentexecutionfrominternet"]),
        ("may modify its own VBA code", ["VBProject", "VBComponents", "CodeModule", "AddFromString"]),
        ("may modify Excel 4.0 formulas at run time", ["FORMULA.FILL"]),
    ];

    private static readonly (string Description, string[] Patterns)[] SuspiciousPatterns =
    [
        ("may hide data in Word document variables", [@"\.\s*Variables"]),
        ("may run shellcode in memory", ["EnumSystemLanguageGroupsW?", "EnumDateFormats(?:W|(?:Ex){1,2})?"]),
        ("may run a program on a Mac (with libc.dylib)", ["system", "popen", "exec[lv][ep]?"]),
        ("may run a program or command through Excel 4.0 macros", ["EXEC"]),
        ("may call a DLL through Excel 4.0 macros", ["REGISTER"]),
    ];

    private const string Ipv4 = @"(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])";
    private const string Server = "(?:" + Ipv4 + @"|(?:[a-zA-Z0-9\-\.]+\.(?:xn--[a-zA-Z0-9]{4,20}|[a-zA-Z]{2,20})))";

    private static readonly (string Type, Regex Pattern)[] Iocs =
    [
        ("URL", new Regex(@"\b(?:http|ftp)s?\://" + Server + @"(?:\:[0-9]{1,5})?(?:/[a-zA-Z0-9\-\._\?\,\'/\\\+&%\$#\=~]*)?", Linear)),
        ("IPv4 address", new Regex(Ipv4, Linear)),
        ("E-mail address", new Regex(@"(?i)\b[A-Z0-9._%+-]+@" + Server + @"\b", Linear)),
        ("Executable file name", new Regex(@"(?i)\b\w+\.(EXE|PIF|GADGET|MSI|MSP|MSC|VBS|VBE|VB|JSE|JS|WSF|WSC|WSH|WS|BAT|CMD|DLL|SCR|HTA|CPL|CLASS|JAR|PS1XML|PS1|PS2XML|PS2|PSC1|PSC2|SCF|LNK|INF|REG)\b",
            Linear)),
    ];

    private static readonly string[] ExcludedUrls = ["http://schemas.openxmlformats.org/", "http://schemas.microsoft.com/"];
    private static readonly Regex HexString = new("(?:[0-9A-Fa-f]{2}){4,}", Linear);
    private static readonly Regex Base64String = new("\"(?:[A-Za-z0-9+/]{4}){1,}(?:[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=|[A-Za-z0-9+/][AQgw]==)?\"", Linear);
    private static readonly Regex NotHex = new("[G-Zg-z]", Linear);
    private static readonly HashSet<string> Base64Allowed = ["thisdocument", "thisworkbook", "test", "temp", "http", "open", "exit", "kernel32", "virtualalloc", "createthread"];

    private static readonly Dictionary<string, BoundedRegex> Cache = [];

    /// <summary>Every keyword and pattern rule as Scan builds it.</summary>
    internal static IEnumerable<Regex> KeywordRules() =>
        AutoExec.Concat(Suspicious).SelectMany(r => r.Keywords).Select(k => Word(Regex.Escape(k)))
            .Concat(AutoExecPatterns.Concat(SuspiciousPatterns).SelectMany(r => r.Patterns).Select(Word));

    private static BoundedRegex Word(string pattern)
    {
        lock (Cache)
        {
            if (!Cache.TryGetValue(pattern, out var r))
                Cache[pattern] = r = new BoundedRegex(@"\b" + pattern + @"\b", RegexOptions.IgnoreCase | Bounded);
            return r;
        }
    }

    /// <summary>One finding per type and keyword; a plain-text finding names its first module and line.</summary>
    public static List<MacroFinding> Scan(IReadOnlyList<(string Module, string Text)> modules)
    {
        var code = string.Join("\n", modules.Select(m => m.Text));
        var rows = new List<MacroFinding>();
        var seen = new HashSet<(string, string)>();
        void Add(MacroFinding f, Regex? where)
        {
            if (!seen.Add((f.Type, f.Keyword))) return;
            rows.Add(where != null && f.Decoded == null ? f with { Location = Locate(modules, where) } : f);
        }

        var hex = new List<(string Encoded, string Decoded)>();
        var b64 = new List<(string Encoded, string Decoded)>();
        foreach (Match m in HexString.Matches(code))
            if (!hex.Any(h => h.Encoded == m.Value)) hex.Add((m.Value, Latin1(Convert.FromHexString(m.Value))));
        foreach (Match m in Base64String.Matches(code))
        {
            var value = m.Value.Trim('"');
            if (!NotHex.IsMatch(value) || Base64Allowed.Contains(value.ToLowerInvariant()) || b64.Any(b => b.Encoded == value)) continue;
            try { b64.Add((value, Latin1(Convert.FromBase64String(value)))); }
            catch (FormatException) { }
        }

        foreach (var (text, decoded) in new[] { (code, (string?)null), (string.Concat(hex.Select(h => "\n" + h.Decoded)), "Hex"), (string.Concat(b64.Select(b => "\n" + b.Decoded)), "Base64") })
        {
            if (text.Length == 0) continue;
            foreach (var (description, keywords) in AutoExec)
                foreach (var k in keywords)
                    if (Word(Regex.Escape(k)) is var r && r.IsMatch(text)) Add(new MacroFinding("AutoExec", k, description) { Decoded = decoded }, r);
            foreach (var (description, patterns) in AutoExecPatterns)
                foreach (var p in patterns)
                    if (Word(p) is var r && r.Match(text) is { Success: true } m) Add(new MacroFinding("AutoExec", m.Value, description) { Decoded = decoded }, r);
            foreach (var (description, keywords) in Suspicious)
                foreach (var k in keywords)
                    if (Word(Regex.Escape(k)) is var r && r.IsMatch(text)) Add(new MacroFinding("Suspicious", k, description) { Decoded = decoded }, r);
            foreach (var (description, patterns) in SuspiciousPatterns)
                foreach (var p in patterns)
                    if (Word(p) is var r && r.Match(text) is { Success: true } m) Add(new MacroFinding("Suspicious", m.Value, description) { Decoded = decoded }, r);
            if (decoded == null && text.Contains('\b')) Add(new MacroFinding("Suspicious", "\\b", "backspace characters can hide code when printed"), null);
            foreach (var (type, pattern) in Iocs)
                foreach (Match m in pattern.Matches(text))
                    if (!ExcludedUrls.Any(u => m.Value.StartsWith(u, StringComparison.Ordinal)))
                        Add(new MacroFinding("IOC", m.Value, type) { Decoded = decoded }, new BoundedRegex(Regex.Escape(m.Value), Bounded));
        }
        if (hex.Count > 0) Add(new MacroFinding("Suspicious", "Hex Strings", "hex-encoded strings, may hide strings"), null);
        if (b64.Count > 0) Add(new MacroFinding("Suspicious", "Base64 Strings", "base64-encoded strings, may hide strings"), null);
        foreach (var (encoded, value) in hex) Add(new MacroFinding("Hex String", Clip(value), Clip(encoded)), null);
        foreach (var (encoded, value) in b64) Add(new MacroFinding("Base64 String", Clip(value), Clip(encoded)), null);
        return rows;
    }

    /// <summary>"Module:line" of the first match.</summary>
    private static string? Locate(IReadOnlyList<(string Module, string Text)> modules, Regex where)
    {
        foreach (var (module, text) in modules)
        {
            var m = where.Match(text);
            if (!m.Success) continue;
            int line = 1;
            for (int i = 0; i < m.Index; i++) if (text[i] == '\n') line++;
            return $"{module}:{line}";
        }
        return null;
    }

    private static string Latin1(byte[] b) => Encoding.Latin1.GetString(b);

    /// <summary>At most 120 characters, control characters as \xNN.</summary>
    private static string Clip(string s)
    {
        s = string.Concat(s.Take(121).Select(c => c < 32 || c == 127 ? $"\\x{(int)c:X2}" : c.ToString()));
        return s.Length <= 120 ? s : s[..117] + "...";
    }
}
