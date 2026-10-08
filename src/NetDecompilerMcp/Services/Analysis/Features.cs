using System.Text.RegularExpressions;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Services.Analysis;

/// <summary>A matched rule with its optional MITRE ATT&amp;CK technique and evidence.</summary>
public sealed record Feature(string Name, string Category, string? Attack, string? AttackName, IReadOnlyList<Evidence> Evidence);

/// <summary>A matched feature pattern, its match count and up to 5 locations.</summary>
public sealed record Evidence(string Feature, int Count, IReadOnlyList<string> Locations);

/// <summary>
/// Capability rules over a module's code. Feature kinds: "api:Ns.Type::Name" (wildcards; a parameter list matches the
/// signature), "native:module!Entry" (P/Invoke; extension ignored, A / W suffix accepted) and "str:" (regex over
/// strings). A rule matches when every group has a matching feature. ATT&amp;CK ids are set only when the operation
/// itself is the technique.
/// </summary>
public static class Features
{
    /// <summary>All groups must match; within a group, any feature.</summary>
    public sealed record Rule(string Name, string Category, string? Attack, string? AttackName, string[][] Groups);

    private static Rule Any(string name, string category, string? attack, string? attackName, params string[] features) =>
        new(name, category, attack, attackName, [features]);

    private static Rule All(string name, string category, string? attack, string? attackName, params string[][] groups) =>
        new(name, category, attack, attackName, groups);

    private static readonly string[] CreateProcess =
    [
        "api:System.Diagnostics.Process::Start", "native:kernel32!CreateProcess*", "native:shell32!ShellExecute*", "native:kernel32!WinExec",
    ];

    private static readonly string[] RegistryWrite =
    [
        "api:Microsoft.Win32.RegistryKey::SetValue", "api:Microsoft.Win32.RegistryKey::CreateSubKey", "api:Microsoft.Win32.Registry::SetValue",
        "native:advapi32!RegSetValue*", "native:advapi32!RegCreateKey*",
    ];

    public static readonly IReadOnlyList<Rule> Rules =
    [
        Any("send HTTP requests", "network", "T1071.001", "Application Layer Protocol: Web Protocols",
            "api:System.Net.Http.HttpClient::*Async", "api:System.Net.Http.HttpMessageInvoker::SendAsync", "api:System.Net.WebClient::Download*",
            "api:System.Net.WebClient::Upload*", "api:System.Net.WebClient::OpenRead*", "api:System.Net.WebRequest::Create*",
            "api:System.Net.WebRequest::GetResponse*", "api:System.Net.HttpWebRequest::GetResponse*", "native:wininet!InternetOpenUrl*",
            "native:wininet!HttpSendRequest*", "native:winhttp!WinHttpSendRequest"),
        Any("download files", "network", "T1105", "Ingress Tool Transfer",
            "api:System.Net.WebClient::DownloadFile*", "api:System.Net.WebClient::DownloadData*", "api:System.Net.Http.HttpClient::GetByteArrayAsync",
            "api:System.Net.Http.HttpClient::GetStreamAsync", "native:urlmon!URLDownloadToFile*"),
        Any("use raw TCP / UDP sockets", "network", "T1095", "Non-Application Layer Protocol",
            "api:System.Net.Sockets.Socket::Connect*", "api:System.Net.Sockets.TcpClient::Connect*", "api:System.Net.Sockets.TcpClient::.ctor(System.String,System.Int32)",
            "api:System.Net.Sockets.UdpClient::Send*", "native:ws2_32!connect", "native:ws2_32!WSAConnect"),
        Any("use WebSockets", "network", "T1071.001", "Application Layer Protocol: Web Protocols",
            "api:System.Net.WebSockets.ClientWebSocket::ConnectAsync"),
        Any("send email", "network", "T1071.003", "Application Layer Protocol: Mail Protocols",
            "api:System.Net.Mail.SmtpClient::Send*"),
        Any("communicate through a web service (Telegram, Discord, Pastebin...)", "network", "T1102", "Web Service",
            @"str:api\.telegram\.org|discord(?:app)?\.com/api/webhooks|pastebin\.com/raw|hastebin\.com|transfer\.sh|anonfiles\.com"),
        Any("resolve DNS names", "network", null, null,
            "api:System.Net.Dns::GetHost*", "api:System.Net.Dns::Resolve", "native:dnsapi!DnsQuery*"),
        Any("listen for incoming connections", "network", null, null,
            "api:System.Net.Sockets.TcpListener::Start", "api:System.Net.HttpListener::Start", "api:System.Net.Sockets.Socket::Listen"),

        Any("create processes", "execution", null, null, CreateProcess),
        All("run the Windows command shell", "execution", "T1059.003", "Command and Scripting Interpreter: Windows Command Shell",
            CreateProcess, [@"str:(?i)(?:^|[\\\s""])cmd(?:\.exe)?(?:$|[\s""])|\bcmd(?:\.exe)?\s+/[ck]\b"]),
        All("run PowerShell", "execution", "T1059.001", "Command and Scripting Interpreter: PowerShell",
            [.. CreateProcess, "api:System.Management.Automation.PowerShell::Invoke*"],
            [@"str:(?i)\b(?:powershell|pwsh)(?:\.exe)?\b", "api:System.Management.Automation.PowerShell::*"]),
        Any("use WMI", "execution", "T1047", "Windows Management Instrumentation",
            "api:System.Management.ManagementObjectSearcher::*", "api:System.Management.ManagementClass::*", "api:System.Management.ManagementScope::*"),
        Any("hide the window of created processes", "defense evasion", "T1564.003", "Hide Artifacts: Hidden Window",
            "api:System.Diagnostics.ProcessStartInfo::set_CreateNoWindow", "api:System.Diagnostics.ProcessStartInfo::set_WindowStyle"),
        Any("terminate processes", "execution", null, null,
            "api:System.Diagnostics.Process::Kill", "native:kernel32!TerminateProcess"),
        Any("stop services", "impact", "T1489", "Service Stop",
            "api:System.ServiceProcess.ServiceController::Stop", "native:advapi32!ControlService"),
        Any("shut down or restart the system", "impact", "T1529", "System Shutdown/Reboot",
            @"str:(?i)\bshutdown(?:\.exe)?\s+[/-][srt]\b", "native:user32!ExitWindowsEx", "native:advapi32!InitiateSystemShutdown*"),

        Any("query the registry", "registry", "T1012", "Query Registry",
            "api:Microsoft.Win32.RegistryKey::GetValue*", "api:Microsoft.Win32.RegistryKey::OpenSubKey", "api:Microsoft.Win32.RegistryKey::GetSubKeyNames",
            "api:Microsoft.Win32.Registry::GetValue", "native:advapi32!RegQueryValue*", "native:advapi32!RegOpenKey*"),
        Any("modify the registry", "registry", "T1112", "Modify Registry",
            [.. RegistryWrite, "api:Microsoft.Win32.RegistryKey::DeleteValue", "api:Microsoft.Win32.RegistryKey::DeleteSubKey*", "native:advapi32!RegDeleteKey*"]),
        All("persist through a Run registry key", "persistence", "T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
            [@"str:(?i)\\CurrentVersion\\Run(?:Once)?(?:\\|$)"], RegistryWrite),
        Any("persist through the Startup folder", "persistence", "T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
            @"str:(?i)\\Start Menu\\Programs\\Startup"),
        Any("persist through a scheduled task", "persistence", "T1053.005", "Scheduled Task/Job: Scheduled Task",
            @"str:(?i)\bschtasks(?:\.exe)?\b|Schedule\.Service", "api:Microsoft.Win32.TaskScheduler.TaskService::*"),
        Any("install a Windows service", "persistence", "T1543.003", "Create or Modify System Process: Windows Service",
            "native:advapi32!CreateService*", @"str:(?i)\bsc(?:\.exe)?\s+create\b", "api:System.Configuration.Install.ManagedInstallerClass::InstallHelper"),

        Any("log keystrokes", "collection", "T1056.001", "Input Capture: Keylogging",
            "native:user32!SetWindowsHookEx*", "native:user32!GetAsyncKeyState", "native:user32!GetKeyboardState"),
        All("capture the screen", "collection", "T1113", "Screen Capture",
            ["api:System.Drawing.Graphics::CopyFromScreen", "native:gdi32!BitBlt"],
            ["api:System.Drawing.Graphics::CopyFromScreen", "native:user32!GetDesktopWindow", "native:user32!GetWindowDC", "native:user32!GetDC"]),
        Any("read the clipboard", "collection", "T1115", "Clipboard Data",
            "api:System.Windows.Forms.Clipboard::Get*", "api:System.Windows.Clipboard::Get*", "native:user32!GetClipboardData"),
        Any("access browser credential stores", "credential access", "T1555.003", "Credentials from Password Stores: Credentials from Web Browsers",
            @"str:(?i)\\(?:Google\\Chrome|Microsoft\\Edge|BraveSoftware\\Brave-Browser|Opera Software|Yandex\\YandexBrowser)\\User Data|\bLogin Data\b|\blogins\.json\b|\bkey4\.db\b|\bsignons\.sqlite\b"),
        Any("access cryptocurrency wallets", "collection", "T1005", "Data from Local System",
            @"str:(?i)\\(?:Exodus|Electrum|Ethereum\\keystore|Atomic\\Local Storage|Coinomi)\b|\bwallet\.dat\b"),
        Any("decrypt data with DPAPI", "credential access", null, null,
            "api:System.Security.Cryptography.ProtectedData::Unprotect", "native:crypt32!CryptUnprotectData"),

        Any("check for a debugger", "anti-analysis", "T1622", "Debugger Evasion",
            "api:System.Diagnostics.Debugger::get_IsAttached", "api:System.Diagnostics.Debugger::IsLogging", "native:kernel32!IsDebuggerPresent",
            "native:kernel32!CheckRemoteDebuggerPresent", "native:ntdll!NtQueryInformationProcess"),
        Any("detect virtual machines and sandboxes", "anti-analysis", "T1497.001", "Virtualization/Sandbox Evasion: System Checks",
            @"str:(?i)\b(?:vbox\w*|virtualbox|vmware|qemu|parallels)\b|\bsbiedll\.dll\b|\bwine_get_unix_file_name\b"),
        Any("disable or bypass Windows Defender", "defense evasion", "T1562.001", "Impair Defenses: Disable or Modify Tools",
            @"str:(?i)Add-MpPreference|Set-MpPreference|DisableRealtimeMonitoring|\\Windows Defender\\Exclusions"),
        Any("bypass User Account Control", "privilege escalation", "T1548.002", "Abuse Elevation Control Mechanism: Bypass User Account Control",
            @"str:(?i)\b(?:fodhelper|eventvwr|computerdefaults|sdclt)(?:\.exe)?\b|ms-settings\\shell\\open\\command|mscfile\\shell\\open\\command"),
        Any("delete itself after running", "defense evasion", "T1070.004", "Indicator Removal: File Deletion",
            @"str:(?i)\bping\b[^""]*&[^""]*\b(?:del|erase)\b|\bchoice\s+/c\s+y\s+/n\s+/d\s+y\s+/t\b"),
        Any("change file timestamps", "defense evasion", "T1070.006", "Indicator Removal: Timestomp",
            "api:System.IO.File::SetCreationTime*", "api:System.IO.File::SetLastWriteTime*", "api:System.IO.File::SetLastAccessTime*",
            "api:System.IO.FileSystemInfo::set_CreationTime*", "api:System.IO.FileSystemInfo::set_LastWriteTime*"),
        Any("adjust token privileges", "privilege escalation", "T1134", "Access Token Manipulation",
            "native:advapi32!AdjustTokenPrivileges", "native:advapi32!DuplicateToken*", "native:advapi32!ImpersonateLoggedOnUser"),

        Any("load .NET assemblies from memory", "code loading", "T1620", "Reflective Code Loading",
            "api:System.Reflection.Assembly::Load(System.Byte[]*", "api:System.AppDomain::Load(System.Byte[]*",
            "api:System.Runtime.Loader.AssemblyLoadContext::LoadFromStream"),
        Any("compile code at run time", "code loading", "T1027.004", "Obfuscated Files or Information: Compile After Delivery",
            "api:Microsoft.CSharp.CSharpCodeProvider::*", "api:System.CodeDom.Compiler.CodeDomProvider::CompileAssembly*",
            "api:Microsoft.CodeAnalysis.CSharp.CSharpCompilation::Create"),
        Any("invoke code through reflection", "code loading", null, null,
            "api:System.Reflection.MethodBase::Invoke", "api:System.Reflection.MethodInfo::Invoke", "api:System.Type::InvokeMember",
            "api:System.Delegate::DynamicInvoke", "api:System.Activator::CreateInstance"),
        Any("generate IL at run time", "code loading", null, null,
            "api:System.Reflection.Emit.ILGenerator::Emit*", "api:System.Reflection.Emit.DynamicMethod::.ctor"),
        Any("resolve native functions at run time", "code loading", "T1106", "Native API",
            "native:kernel32!GetProcAddress", "native:kernel32!LoadLibrary*", "api:System.Runtime.InteropServices.NativeLibrary::GetExport",
            "api:System.Runtime.InteropServices.Marshal::GetDelegateForFunctionPointer*"),
        All("inject code into another process", "injection", "T1055", "Process Injection",
            ["native:kernel32!VirtualAllocEx", "native:ntdll!NtAllocateVirtualMemory"],
            ["native:kernel32!WriteProcessMemory", "native:ntdll!NtWriteVirtualMemory"],
            ["native:kernel32!CreateRemoteThread*", "native:ntdll!NtCreateThreadEx", "native:ntdll!RtlCreateUserThread", "native:kernel32!QueueUserAPC"]),
        All("hollow a process", "injection", "T1055.012", "Process Injection: Process Hollowing",
            ["native:ntdll!NtUnmapViewOfSection", "native:ntdll!ZwUnmapViewOfSection"],
            ["native:kernel32!SetThreadContext", "native:kernel32!Wow64SetThreadContext"],
            ["native:kernel32!ResumeThread"]),
        All("run shellcode in its own process", "injection", null, null,
            ["native:kernel32!VirtualAlloc", "native:kernel32!VirtualProtect"],
            ["native:kernel32!CreateThread", "api:System.Runtime.InteropServices.Marshal::GetDelegateForFunctionPointer*"]),

        Any("get system information", "discovery", "T1082", "System Information Discovery",
            "api:System.Environment::get_OSVersion", "api:System.Environment::get_MachineName", "api:System.Runtime.InteropServices.RuntimeInformation::get_OSDescription"),
        Any("get the user name", "discovery", "T1033", "System Owner/User Discovery",
            "api:System.Environment::get_UserName", "api:System.Security.Principal.WindowsIdentity::GetCurrent"),
        Any("enumerate processes", "discovery", "T1057", "Process Discovery",
            "api:System.Diagnostics.Process::GetProcesses*", "native:kernel32!CreateToolhelp32Snapshot", "native:kernel32!Process32First*"),
        Any("enumerate network configuration", "discovery", "T1016", "System Network Configuration Discovery",
            "api:System.Net.NetworkInformation.NetworkInterface::GetAllNetworkInterfaces", "api:System.Net.NetworkInformation.IPGlobalProperties::*"),
        Any("enumerate files and directories", "discovery", "T1083", "File and Directory Discovery",
            "api:System.IO.Directory::GetFiles", "api:System.IO.Directory::EnumerateFiles", "api:System.IO.Directory::GetDirectories",
            "api:System.IO.Directory::EnumerateDirectories", "api:System.IO.DirectoryInfo::GetFiles", "api:System.IO.DriveInfo::GetDrives"),
        Any("check for administrator rights", "discovery", null, null,
            "api:System.Security.Principal.WindowsPrincipal::IsInRole"),

        Any("encrypt or decrypt data", "crypto", null, null,
            "api:*::CreateDecryptor", "api:*::CreateEncryptor", "api:System.Security.Cryptography.Aes::Create", "api:*::DecryptCbc", "api:*::EncryptCbc",
            "api:System.Security.Cryptography.AesGcm::Decrypt", "api:System.Security.Cryptography.RSA::Decrypt", "native:advapi32!CryptDecrypt"),
        Any("hash data", "crypto", null, null,
            "api:System.Security.Cryptography.HashAlgorithm::ComputeHash", "api:System.Security.Cryptography.SHA256::HashData", "api:System.Security.Cryptography.MD5::HashData",
            "api:System.Security.Cryptography.SHA1::HashData"),
        Any("decode base64", "encoding", null, null, "api:System.Convert::FromBase64String"),
        Any("compress or decompress data", "data", null, null,
            "api:System.IO.Compression.GZipStream::.ctor", "api:System.IO.Compression.DeflateStream::.ctor", "api:System.IO.Compression.ZipArchive::.ctor",
            "api:System.IO.Compression.ZipFile::*"),
        Any("create a mutex", "synchronization", null, null,
            "api:System.Threading.Mutex::.ctor", "api:System.Threading.Mutex::OpenExisting", "api:System.Threading.Mutex::TryOpenExisting", "native:kernel32!CreateMutex*"),
    ];

    private const int MaxLocations = 5;

    public static List<Feature> Detect(ModuleScan scan, CancellationToken ct)
    {
        var cache = new Dictionary<string, Evidence?>(StringComparer.Ordinal);
        Evidence? Match(string feature) => cache.TryGetValue(feature, out var e) ? e : cache[feature] = Evaluate(scan, feature);

        var found = new List<Feature>();
        foreach (var rule in Rules)
        {
            ct.ThrowIfCancellationRequested();
            var evidence = new List<Evidence>();
            bool all = true;
            foreach (var group in rule.Groups)
            {
                var hits = group.Select(Match).OfType<Evidence>().ToList();
                if (hits.Count == 0) { all = false; break; }
                evidence.AddRange(hits.Where(h => !evidence.Any(x => x.Feature == h.Feature)));
            }
            if (all) found.Add(new Feature(rule.Name, rule.Category, rule.Attack, rule.AttackName, evidence));
        }
        return found;
    }

    private static Evidence? Evaluate(ModuleScan scan, string feature)
    {
        var colon = feature.IndexOf(':');
        var kind = feature[..colon];
        var pattern = feature[(colon + 1)..];
        var locations = new List<string>();
        int count = 0;
        void Hit(string where)
        {
            count++;
            if (locations.Count < MaxLocations && !locations.Contains(where)) locations.Add(where);
        }

        switch (kind)
        {
            case "api":
            {
                bool withSignature = pattern.Contains('(');
                var regex = Wildcard(pattern);
                foreach (var call in scan.Calls)
                    if (regex.IsMatch(withSignature ? call.Signature : call.Api))
                        Hit($"{Format.MemberLabel(call.Caller)} @IL_{call.Offset:X4}");
                break;
            }
            case "native":
            {
                var bang = pattern.IndexOf('!');
                var module = pattern[..bang];
                var entry = Wildcard(pattern[(bang + 1)..], allowCharsetSuffix: true);
                foreach (var import in scan.Imports)
                    if (SameModule(import.Module, module) && entry.IsMatch(import.Entry))
                        Hit($"P/Invoke {Format.MemberLabel(import.Method)} -> {import.Module}!{import.Entry}");
                break;
            }
            case "str":
            {
                var regex = new Regex(pattern, RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
                foreach (var s in scan.Strings)
                {
                    try { if (s.Value.Length <= 64 * 1024 && regex.IsMatch(s.Value)) Hit($"{s.Location.Where}: \"{Clip(s.Value)}\""); }
                    catch (RegexMatchTimeoutException) { }
                }
                break;
            }
            default:
                throw new InvalidOperationException($"Unknown feature kind in rule: {feature}");
        }
        return count == 0 ? null : new Evidence(feature, count, locations);
    }

    private static string Clip(string s) => s.Length <= 80 ? s : s[..80] + "…";

    private static bool SameModule(string actual, string expected)
    {
        var a = Path.GetFileNameWithoutExtension(actual.Trim());
        return a.Equals(expected, StringComparison.OrdinalIgnoreCase);
    }

    private static readonly Dictionary<string, Regex> WildcardCache = [];

    /// <summary>'*' matches anything; <paramref name="allowCharsetSuffix"/> accepts a trailing A / W entry-point suffix.</summary>
    private static Regex Wildcard(string pattern, bool allowCharsetSuffix = false)
    {
        var key = pattern + (allowCharsetSuffix ? "|aw" : "");
        lock (WildcardCache)
        {
            if (WildcardCache.TryGetValue(key, out var cached)) return cached;
            var body = Regex.Escape(pattern).Replace(@"\*", ".*");
            var regex = new Regex("^" + body + (allowCharsetSuffix ? "[AW]?" : "") + "$", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
            WildcardCache[key] = regex;
            return regex;
        }
    }
}
