using System.Text.RegularExpressions;
using Corvus.Core;

namespace Corvus.Services.Analysis;

/// <summary>A matched rule with its evidence.</summary>
public sealed record Feature(string Name, string Category, IReadOnlyList<Evidence> Evidence)
{
    /// <summary>The mobile rule that matched (one with a MASVS id), else null.</summary>
    public Features.Rule? Rule { get; init; }
}

/// <summary>A matched feature pattern, its match count and up to 5 locations.</summary>
public sealed record Evidence(string Feature, int Count, IReadOnlyList<string> Locations)
{
    /// <summary>"derived" when a string or argument constant suggests the operation; null when an import or call site shows it.</summary>
    public string? Basis { get; init; }

    /// <summary>Mobile rules: matches in library code, not counted in <see cref="Count"/>.</summary>
    public int? Library { get; init; }
}

/// <summary>
/// Capability rules over a module's code, shared by managed assemblies and native images. Feature kinds:
/// "api:Ns.Type::Name" (managed calls; wildcards; a parameter list matches the signature), "native:module!Entry"
/// (P/Invoke, or a native image's static and late-bound imports; extension ignored, A / W suffix accepted), "str:"
/// (regex over strings), and for native images "arg:module!Api#i=ENTRY" (a call whose argument i is a constant with that
/// flag or enumeration value), "section:entropy>x" / "section:name=regex" / "section:wx" and "rtti:regex" (MSVC RTTI class
/// names). A rule matches when every group has a matching feature.
/// </summary>
public static class Features
{
    /// <summary>All groups must match; within a group, any feature.</summary>
    public sealed record Rule(string Name, string Category, string[][] Groups)
    {
        /// <summary>Mobile rules: a stable id, the MASVS control, a severity (high, medium, low, info) and what to check.</summary>
        public string? Id { get; init; }
        public string? Masvs { get; init; }
        public string? Severity { get; init; }
        public string? Review { get; init; }

        /// <summary>"android" (DEX subjects only) or "apple" (Mach-O images); null: .NET assemblies and native images.</summary>
        public string? Platform { get; init; }
    }

    private static Rule Any(string name, string category, params string[] features) =>
        new(name, category, [features]);

    private static Rule All(string name, string category, params string[][] groups) =>
        new(name, category, groups);

    /// <summary>Section names left by known executable packing tools.</summary>
    public const string PackerSectionNames = @"^(?:UPX\d|\.aspack|\.adata|\.petite|\.nsp\d|\.MPRESS\d|\.themida|\.vmp\d|\.enigma\d|\.yP|PEC2\w*|\.packed|\.boom)$";

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
        Any("send HTTP requests", "network",
            "api:System.Net.Http.HttpClient::*Async", "api:System.Net.Http.HttpMessageInvoker::SendAsync", "api:System.Net.WebClient::Download*",
            "api:System.Net.WebClient::Upload*", "api:System.Net.WebClient::OpenRead*", "api:System.Net.WebRequest::Create*",
            "api:System.Net.WebRequest::GetResponse*", "api:System.Net.HttpWebRequest::GetResponse*", "native:wininet!InternetOpenUrl*",
            "native:wininet!HttpSendRequest*", "native:winhttp!WinHttpSendRequest", @"rtti:^(?:web::http::|cpr::|httplib::)"),
        Any("download files", "network",
            "api:System.Net.WebClient::DownloadFile*", "api:System.Net.WebClient::DownloadData*", "api:System.Net.Http.HttpClient::GetByteArrayAsync",
            "api:System.Net.Http.HttpClient::GetStreamAsync", "native:urlmon!URLDownloadToFile*"),
        Any("use raw TCP / UDP sockets", "network",
            "api:System.Net.Sockets.Socket::Connect*", "api:System.Net.Sockets.TcpClient::Connect*", "api:System.Net.Sockets.TcpClient::.ctor(System.String,System.Int32)",
            "api:System.Net.Sockets.UdpClient::Send*", "native:ws2_32!connect", "native:ws2_32!WSAConnect", "native:ws2_32!sendto",
            @"rtti:^boost::asio::ip::(?:tcp|udp)\b"),
        Any("use WebSockets", "network",
            "api:System.Net.WebSockets.ClientWebSocket::ConnectAsync", "native:winhttp!WinHttpWebSocketCompleteUpgrade", "rtti:^websocketpp::"),
        Any("send email", "network",
            "api:System.Net.Mail.SmtpClient::Send*"),
        Any("communicate through a web service (Telegram, Discord, Pastebin...)", "network",
            @"str:api\.telegram\.org|discord(?:app)?\.com/api/webhooks|pastebin\.com/raw|hastebin\.com|transfer\.sh|anonfiles\.com"),
        Any("resolve DNS names", "network",
            "api:System.Net.Dns::GetHost*", "api:System.Net.Dns::Resolve", "native:dnsapi!DnsQuery*"),
        Any("listen for incoming connections", "network",
            "api:System.Net.Sockets.TcpListener::Start", "api:System.Net.HttpListener::Start", "api:System.Net.Sockets.Socket::Listen"),

        Any("create processes", "execution", CreateProcess),
        All("run the Windows command shell", "execution",
            CreateProcess, [@"str:(?i)(?:^|[\\\s""])cmd(?:\.exe)?(?:$|[\s""])|\bcmd(?:\.exe)?\s+/[ck]\b"]),
        All("run PowerShell", "execution",
            [.. CreateProcess, "api:System.Management.Automation.PowerShell::Invoke*"],
            [@"str:(?i)\b(?:powershell|pwsh)(?:\.exe)?\b", "api:System.Management.Automation.PowerShell::*"]),
        Any("use WMI", "execution",
            "api:System.Management.ManagementObjectSearcher::*", "api:System.Management.ManagementClass::*", "api:System.Management.ManagementScope::*"),
        Any("start processes without a window", "system changes",
            "api:System.Diagnostics.ProcessStartInfo::set_CreateNoWindow", "api:System.Diagnostics.ProcessStartInfo::set_WindowStyle"),
        Any("terminate processes", "execution",
            "api:System.Diagnostics.Process::Kill", "native:kernel32!TerminateProcess"),
        Any("stop services", "system control",
            "api:System.ServiceProcess.ServiceController::Stop", "native:advapi32!ControlService"),
        Any("shut down or restart the system", "system control",
            @"str:(?i)\bshutdown(?:\.exe)?\s+[/-][srt]\b", "native:user32!ExitWindowsEx", "native:advapi32!InitiateSystemShutdown*"),

        Any("query the registry", "registry",
            "api:Microsoft.Win32.RegistryKey::GetValue*", "api:Microsoft.Win32.RegistryKey::OpenSubKey", "api:Microsoft.Win32.RegistryKey::GetSubKeyNames",
            "api:Microsoft.Win32.Registry::GetValue", "native:advapi32!RegQueryValue*", "native:advapi32!RegOpenKey*"),
        Any("modify the registry", "registry",
            [.. RegistryWrite, "api:Microsoft.Win32.RegistryKey::DeleteValue", "api:Microsoft.Win32.RegistryKey::DeleteSubKey*", "native:advapi32!RegDeleteKey*"]),
        All("auto-start through a Run registry key", "autostart",
            [@"str:(?i)\\CurrentVersion\\Run(?:Once)?(?:\\|$)"], RegistryWrite),
        Any("auto-start through the Startup folder", "autostart",
            @"str:(?i)\\Start Menu\\Programs\\Startup"),
        Any("run on a schedule through Task Scheduler", "autostart",
            @"str:(?i)\bschtasks(?:\.exe)?\b|Schedule\.Service", "api:Microsoft.Win32.TaskScheduler.TaskService::*"),
        Any("install a Windows service", "autostart",
            "native:advapi32!CreateService*", @"str:(?i)\bsc(?:\.exe)?\s+create\b", "api:System.Configuration.Install.ManagedInstallerClass::InstallHelper"),

        Any("read keyboard input", "local data",
            "native:user32!SetWindowsHookEx*", "native:user32!GetAsyncKeyState", "native:user32!GetKeyboardState"),
        Any("register a system-wide keyboard callback", "local data",
            "arg:user32!SetWindowsHookEx*#0=WH_KEYBOARD_LL", "arg:user32!SetWindowsHookEx*#0=WH_KEYBOARD"),
        All("capture the screen", "local data",
            ["api:System.Drawing.Graphics::CopyFromScreen", "native:gdi32!BitBlt"],
            ["api:System.Drawing.Graphics::CopyFromScreen", "native:user32!GetDesktopWindow", "native:user32!GetWindowDC", "native:user32!GetDC"]),
        Any("read the clipboard", "local data",
            "api:System.Windows.Forms.Clipboard::Get*", "api:System.Windows.Clipboard::Get*", "native:user32!GetClipboardData"),
        Any("read browser login data files", "protected storage",
            @"str:(?i)\\(?:Google\\Chrome|Microsoft\\Edge|BraveSoftware\\Brave-Browser|Opera Software|Yandex\\YandexBrowser)\\User Data|\bLogin Data\b|\blogins\.json\b|\bkey4\.db\b|\bsignons\.sqlite\b"),
        Any("reference cryptocurrency wallet files", "local data",
            @"str:(?i)\\(?:Exodus|Electrum|Ethereum\\keystore|Atomic\\Local Storage|Coinomi)\b|\bwallet\.dat\b"),
        Any("unprotect data with DPAPI", "protected storage",
            "api:System.Security.Cryptography.ProtectedData::Unprotect", "native:crypt32!CryptUnprotectData"),

        Any("check for a debugger", "environment checks",
            "api:System.Diagnostics.Debugger::get_IsAttached", "api:System.Diagnostics.Debugger::IsLogging", "native:kernel32!IsDebuggerPresent",
            "native:kernel32!CheckRemoteDebuggerPresent", "native:ntdll!NtQueryInformationProcess",
            "arg:ntdll!NtQueryInformationProcess#1=ProcessDebugPort", "arg:ntdll!NtQueryInformationProcess#1=ProcessDebugObjectHandle",
            "arg:ntdll!NtQueryInformationProcess#1=ProcessDebugFlags"),
        Any("exclude threads from debugger notification", "environment checks",
            "arg:ntdll!NtSetInformationThread#1=ThreadHideFromDebugger"),
        Any("contain high-entropy sections", "environment checks",
            "section:entropy>7.2"),
        Any("use a known executable packing tool", "environment checks",
            "section:name=" + PackerSectionNames),
        Any("have a writable and executable section", "system changes", "section:wx"),
        Any("detect virtual machines and instrumented environments", "environment checks",
            @"str:(?i)\b(?:vbox\w*|virtualbox|vmware|qemu|parallels)\b|\bsbiedll\.dll\b|\bwine_get_unix_file_name\b",
            // CPUID hypervisor vendor ids
            @"str:VMwareVMware|KVMKVMKVM|Microsoft Hv|XenVMMXenVMM|prl hyperv|VBoxVBoxVBox|TCGTCGTCGTCG"),
        Any("reference diagnostic tool names", "environment checks",
            @"str:(?i)\b(?:ollydbg|x64dbg|x32dbg|windbg|immunitydebugger|idaq64|ida64|procmon\d*|processhacker|wireshark|fiddler|dnspy|ghidra)(?:\.exe)?\b"),
        Any("change Windows Defender settings", "system changes",
            @"str:(?i)Add-MpPreference|Set-MpPreference|DisableRealtimeMonitoring|\\Windows Defender\\Exclusions"),
        Any("reference auto-elevated system components", "privileges",
            @"str:(?i)\b(?:fodhelper|eventvwr|computerdefaults|sdclt)(?:\.exe)?\b|ms-settings\\shell\\open\\command|mscfile\\shell\\open\\command"),
        Any("schedule its own deletion", "system changes",
            @"str:(?i)\bping\b[^""]*&[^""]*\b(?:del|erase)\b|\bchoice\s+/c\s+y\s+/n\s+/d\s+y\s+/t\b"),
        Any("change file timestamps", "system changes",
            "api:System.IO.File::SetCreationTime*", "api:System.IO.File::SetLastWriteTime*", "api:System.IO.File::SetLastAccessTime*",
            "api:System.IO.FileSystemInfo::set_CreationTime*", "api:System.IO.FileSystemInfo::set_LastWriteTime*"),
        Any("adjust token privileges", "privileges",
            "native:advapi32!AdjustTokenPrivileges", "native:advapi32!DuplicateToken*", "native:advapi32!ImpersonateLoggedOnUser"),

        Any("load .NET assemblies from memory", "code loading",
            "api:System.Reflection.Assembly::Load(System.Byte[]*", "api:System.AppDomain::Load(System.Byte[]*",
            "api:System.Runtime.Loader.AssemblyLoadContext::LoadFromStream"),
        Any("compile code at run time", "code loading",
            "api:Microsoft.CSharp.CSharpCodeProvider::*", "api:System.CodeDom.Compiler.CodeDomProvider::CompileAssembly*",
            "api:Microsoft.CodeAnalysis.CSharp.CSharpCompilation::Create"),
        Any("invoke code through reflection", "code loading",
            "api:System.Reflection.MethodBase::Invoke", "api:System.Reflection.MethodInfo::Invoke", "api:System.Type::InvokeMember",
            "api:System.Delegate::DynamicInvoke", "api:System.Activator::CreateInstance"),
        Any("generate IL at run time", "code loading",
            "api:System.Reflection.Emit.ILGenerator::Emit*", "api:System.Reflection.Emit.DynamicMethod::.ctor"),
        Any("resolve native functions at run time", "code loading",
            "native:kernel32!GetProcAddress", "native:kernel32!LoadLibrary*", "native:ntdll!LdrGetProcedureAddress*", "api:System.Runtime.InteropServices.NativeLibrary::GetExport",
            "api:System.Runtime.InteropServices.Marshal::GetDelegateForFunctionPointer*"),
        All("write code into another process and run it", "cross-process",
            ["native:kernel32!VirtualAllocEx", "native:ntdll!NtAllocateVirtualMemory"],
            ["native:kernel32!WriteProcessMemory", "native:ntdll!NtWriteVirtualMemory"],
            ["native:kernel32!CreateRemoteThread*", "native:ntdll!NtCreateThreadEx", "native:ntdll!RtlCreateUserThread", "native:kernel32!QueueUserAPC"]),
        All("replace a suspended process's image", "cross-process",
            ["native:ntdll!NtUnmapViewOfSection", "native:ntdll!ZwUnmapViewOfSection"],
            ["native:kernel32!SetThreadContext", "native:kernel32!Wow64SetThreadContext"],
            ["native:kernel32!ResumeThread"]),
        All("run generated machine code in its own process", "cross-process",
            ["native:kernel32!VirtualAlloc", "native:kernel32!VirtualProtect"],
            ["native:kernel32!CreateThread", "api:System.Runtime.InteropServices.Marshal::GetDelegateForFunctionPointer*"]),
        Any("allocate or make memory writable and executable", "code loading",
            "arg:kernel32!VirtualAlloc#3=PAGE_EXECUTE_READWRITE", "arg:kernel32!VirtualAllocEx#4=PAGE_EXECUTE_READWRITE",
            "arg:kernel32!VirtualProtect#2=PAGE_EXECUTE_READWRITE", "arg:kernel32!VirtualProtectEx#3=PAGE_EXECUTE_READWRITE",
            "arg:ntdll!NtAllocateVirtualMemory#5=PAGE_EXECUTE_READWRITE", "arg:ntdll!NtProtectVirtualMemory#3=PAGE_EXECUTE_READWRITE",
            "arg:kernel32!VirtualAlloc#3=PAGE_EXECUTE_WRITECOPY", "arg:kernel32!VirtualProtect#2=PAGE_EXECUTE_WRITECOPY"),
        Any("create a suspended process", "cross-process",
            "arg:kernel32!CreateProcess*#5=CREATE_SUSPENDED", "arg:advapi32!CreateProcessAsUser*#6=CREATE_SUSPENDED"),

        Any("get system information", "discovery",
            "api:System.Environment::get_OSVersion", "api:System.Environment::get_MachineName", "api:System.Runtime.InteropServices.RuntimeInformation::get_OSDescription",
            "native:kernel32!GetSystemInfo", "native:kernel32!GetNativeSystemInfo", "native:kernel32!GetVersionEx*", "native:kernel32!GetComputerName*"),
        Any("get the user name", "discovery",
            "api:System.Environment::get_UserName", "api:System.Security.Principal.WindowsIdentity::GetCurrent", "native:advapi32!GetUserName*"),
        Any("enumerate processes", "discovery",
            "api:System.Diagnostics.Process::GetProcesses*", "native:kernel32!CreateToolhelp32Snapshot", "native:kernel32!Process32First*", "native:psapi!EnumProcesses", "native:kernel32!K32EnumProcesses"),
        Any("enumerate network configuration", "discovery",
            "api:System.Net.NetworkInformation.NetworkInterface::GetAllNetworkInterfaces", "api:System.Net.NetworkInformation.IPGlobalProperties::*",
            "native:iphlpapi!GetAdaptersInfo", "native:iphlpapi!GetAdaptersAddresses"),
        Any("enumerate files and directories", "discovery",
            "api:System.IO.Directory::GetFiles", "api:System.IO.Directory::EnumerateFiles", "api:System.IO.Directory::GetDirectories",
            "api:System.IO.Directory::EnumerateDirectories", "api:System.IO.DirectoryInfo::GetFiles", "api:System.IO.DriveInfo::GetDrives", "native:kernel32!FindFirstFile*"),
        Any("check for administrator rights", "discovery",
            "api:System.Security.Principal.WindowsPrincipal::IsInRole", "native:shell32!IsUserAnAdmin", "native:advapi32!CheckTokenMembership"),

        Any("encrypt or decrypt data", "crypto",
            "api:*::CreateDecryptor", "api:*::CreateEncryptor", "api:System.Security.Cryptography.Aes::Create", "api:*::DecryptCbc", "api:*::EncryptCbc",
            "api:System.Security.Cryptography.AesGcm::Decrypt", "api:System.Security.Cryptography.RSA::Decrypt", "native:advapi32!CryptDecrypt",
            "native:advapi32!CryptEncrypt", "native:bcrypt!BCryptEncrypt", "native:bcrypt!BCryptDecrypt", "rtti:^CryptoPP::"),
        Any("hash data", "crypto",
            "api:System.Security.Cryptography.HashAlgorithm::ComputeHash", "api:System.Security.Cryptography.SHA256::HashData", "api:System.Security.Cryptography.MD5::HashData",
            "api:System.Security.Cryptography.SHA1::HashData",
            "native:advapi32!CryptCreateHash", "native:bcrypt!BCryptCreateHash", "native:bcrypt!BCryptHash"),
        Any("decode base64", "encoding", "api:System.Convert::FromBase64String", "native:crypt32!CryptStringToBinary*"),
        Any("compress or decompress data", "data",
            "api:System.IO.Compression.GZipStream::.ctor", "api:System.IO.Compression.DeflateStream::.ctor", "api:System.IO.Compression.ZipArchive::.ctor",
            "api:System.IO.Compression.ZipFile::*",
            "native:ntdll!RtlDecompressBuffer*", "native:cabinet!Decompress", "native:cabinet!Compress", @"rtti:^boost::iostreams::(?:zlib|gzip)"),
        Any("create a mutex", "synchronization",
            "api:System.Threading.Mutex::.ctor", "api:System.Threading.Mutex::OpenExisting", "api:System.Threading.Mutex::TryOpenExisting", "native:kernel32!CreateMutex*"),
    ];

    private const int MaxLocations = 5;

    /// <summary>Feature kinds; managed modules evaluate api / native / str, native images native / str / arg / section / rtti.</summary>
    private static readonly HashSet<string> Kinds = ["api", "native", "str", "arg", "section", "rtti"];

    public static List<Feature> Detect(ModuleScan scan, CancellationToken ct) => Detect(feature => Evaluate(scan, feature), new SurveySubject(scan, null), ct);

    /// <summary>Rules over a native image (<see cref="NativeFeatureScan"/>).</summary>
    internal static List<Feature> Detect(NativeFeatureScan scan, CancellationToken ct, MobileSubject? mobile = null) =>
        Detect(scan.Evaluate, new SurveySubject(null, scan.Index) { Mobile = mobile }, ct);

    /// <summary>The android rules over an app's DEX code, manifest and network security config.</summary>
    internal static List<Feature> Detect(MobileSubject mobile, CancellationToken ct) => Detect(_ => null, new SurveySubject(null, null) { Mobile = mobile }, ct);

    /// <summary>The built-in rules, then each <see cref="ISurveyRuleProvider"/>'s.</summary>
    public static IEnumerable<Rule> AllRules => Rules.Concat(Providers.Of<ISurveyRuleProvider>().SelectMany(p => p.Rules));

    private static List<Feature> Detect(Func<string, Evidence?> evaluate, SurveySubject subject, CancellationToken ct)
    {
        var cache = new Dictionary<string, Evidence?>(StringComparer.Ordinal);
        var extra = Providers.Of<ISurveyRuleProvider>();
        Evidence? Match(string feature)
        {
            if (cache.TryGetValue(feature, out var e)) return e;
            int colon = feature.IndexOf(':');
            var kind = colon < 0 ? feature : feature[..colon];
            // A string or an argument constant suggests the operation; an import, call site, section or class shows it.
            if (Kinds.Contains(kind))
            {
                var found = evaluate(feature);
                return cache[feature] = found != null && kind is "str" or "arg" ? found with { Basis = "derived" } : found;
            }
            var provider = extra.FirstOrDefault(p => p.Kinds.Contains(kind)) ?? throw new InvalidOperationException($"Unknown feature kind in rule: {feature}");
            return cache[feature] = provider.Evaluate(subject, feature, ct);
        }

        var found = new List<Feature>();
        var platform = subject.Mobile?.Platform;
        foreach (var rule in AllRules)
        {
            ct.ThrowIfCancellationRequested();
            if (rule.Platform != null ? rule.Platform != platform : platform == "android") continue;
            var evidence = new List<Evidence>();
            bool all = true;
            foreach (var group in rule.Groups)
            {
                var hits = group.Select(Match).OfType<Evidence>().ToList();
                if (hits.Count == 0) { all = false; break; }
                evidence.AddRange(hits.Where(h => !evidence.Any(x => x.Feature == h.Feature)));
            }
            if (all) found.Add(new Feature(rule.Name, rule.Category, evidence) { Rule = rule.Masvs != null ? rule : null });
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
                var isMatch = WildcardMatcher(pattern);
                var matched = new List<ModuleScan.ApiUse>();
                foreach (var (api, calls) in scan.CallsByApi)
                {
                    if (!withSignature) { if (isMatch(api)) matched.AddRange(calls); continue; }
                    foreach (var byTarget in calls.GroupBy(c => c.Target, ReferenceEqualityComparer.Instance))
                        if (isMatch(byTarget.First().Signature)) matched.AddRange(byTarget);
                }
                count = matched.Count;
                // Locations in scan order, as when every call was tested in turn.
                foreach (var call in matched.OrderBy(c => c.Index))
                {
                    if (locations.Count >= MaxLocations) break;
                    var where = $"{Format.MemberLabel(call.Caller)} @IL_{call.Offset:X4}";
                    if (!locations.Contains(where)) locations.Add(where);
                }
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
                var regex = RulePattern(pattern);
                foreach (var s in scan.Strings)
                    if (s.Value.Length <= 64 * 1024 && regex.IsMatch(s.Value)) Hit($"{s.Location.Where}: \"{Clip(s.Value)}\"");
                break;
            }
            default:
                // arg / section / rtti: native images only
                return null;
        }
        return count == 0 ? null : new Evidence(feature, count, locations);
    }

    private static string Clip(string s) => s.Length <= 80 ? s : s[..80] + "…";

    private static bool SameModule(string actual, string expected)
    {
        var a = Path.GetFileNameWithoutExtension(actual.Trim());
        return a.Equals(expected, StringComparison.OrdinalIgnoreCase);
    }

    private static readonly Dictionary<string, Regex> RulePatterns = [];

    private static readonly Lazy<int> Prepared = new(() =>
    {
        foreach (var feature in AllRules.SelectMany(r => r.Groups).SelectMany(g => g))
        {
            int colon = feature.IndexOf(':');
            var (kind, pattern) = colon < 0 ? (feature, "") : (feature[..colon], feature[(colon + 1)..]);
            if (kind is "str" or "rtti" or "sym") RulePattern(pattern);
            else if (kind == "section" && pattern.StartsWith("name=", StringComparison.Ordinal)) RulePattern(pattern[5..]);
        }
        return RulePatterns.Count;
    });

    /// <summary>
    /// Builds every rule's regular expression once per process and returns how many are kept; a timed survey calls it
    /// first, so its budget measures its own scan, not this one-time work.
    /// </summary>
    internal static int Prepare() => Prepared.Value;

    /// <summary>
    /// A rule's regular expression (str:, rtti:, sym:, section:name=, a dex string), parsed once. Throws
    /// NotSupportedException for a construct NonBacktracking does not take; a test keeps every rule clear of them.
    /// </summary>
    internal static Regex RulePattern(string pattern)
    {
        // Rules run over every string and name of a file: NonBacktracking
        // matches in linear time, so they take no match timeout.
        lock (RulePatterns)
        {
            if (!RulePatterns.TryGetValue(pattern, out var regex))
                RulePatterns[pattern] = regex = new Regex(pattern, RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
            return regex;
        }
    }

    /// <summary><see cref="Wildcard"/> as a test, without a regular expression for a plain name or a name with one trailing '*'.</summary>
    private static Func<string, bool> WildcardMatcher(string pattern)
    {
        int star = pattern.IndexOf('*');
        if (star < 0) return s => s.Equals(pattern, StringComparison.OrdinalIgnoreCase);
        if (star == pattern.Length - 1) { var prefix = pattern[..^1]; return s => s.StartsWith(prefix, StringComparison.OrdinalIgnoreCase); }
        var regex = Wildcard(pattern);
        return regex.IsMatch;
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
