namespace NetDecompilerMcp.Native.Calls;

/// <summary>A capability group an image's imports imply: the APIs that put it there (static and late-bound).</summary>
public sealed record ApiCapability(string Group, int Count, IReadOnlyList<string> Apis);

/// <summary>
/// Capability groups from imported API names (Windows and POSIX): files, registry, network, crypto, process and thread,
/// UI, services, COM, debugging and anti-debugging, dynamic loading. Names match without the A / W / Ex suffixes; a
/// group also takes whole modules (ws2_32, bcrypt) whose every import belongs to it.
/// </summary>
public static class ApiCapabilities
{
    private sealed record Group(string Name, string[] Modules, string[] Prefixes, string[] Exact);

    private static readonly Group[] Groups =
    [
        new("files", [],
            ["CreateFile", "ReadFile", "WriteFile", "DeleteFile", "CopyFile", "MoveFile", "FindFirstFile", "FindNextFile", "GetFileAttributes", "SetFileAttributes",
             "CreateDirectory", "RemoveDirectory", "GetTempPath", "GetTempFileName", "SetFilePointer", "GetFileSize", "FlushFileBuffers", "CreateFileMapping",
             "MapViewOfFile", "NtCreateFile", "NtReadFile", "NtWriteFile", "SHFileOperation", "PathFileExists", "fopen", "fread", "fwrite", "_wfopen"],
            ["open", "openat", "read", "write", "unlink", "rename", "mkdir", "rmdir", "stat", "fstat", "lstat", "opendir", "readdir", "mmap"]),
        new("registry", [], ["RegOpenKey", "RegCreateKey", "RegQueryValue", "RegSetValue", "RegDeleteKey", "RegDeleteValue", "RegEnumKey", "RegEnumValue",
            "RegGetValue", "RegCloseKey", "NtOpenKey", "NtQueryValueKey", "NtSetValueKey", "SHGetValue", "SHSetValue"], []),
        new("network", ["ws2_32", "wsock32", "wininet", "winhttp", "urlmon", "dnsapi", "iphlpapi", "mswsock", "libcurl"],
            ["WSA", "Internet", "HttpOpenRequest", "HttpSendRequest", "WinHttp", "URLDownloadTo", "DnsQuery", "curl_"],
            ["socket", "connect", "bind", "listen", "accept", "send", "recv", "sendto", "recvfrom", "getaddrinfo", "gethostbyname", "inet_addr", "select", "inet_pton"]),
        new("crypto", ["bcrypt", "ncrypt", "crypt32", "libcrypto", "libssl"],
            ["Crypt", "BCrypt", "NCrypt", "CertOpen", "CertFind", "CertGetCertificate", "EVP_", "SSL_", "RSA_", "AES_", "SHA256", "MD5_"], []),
        new("process_thread", [],
            ["CreateProcess", "OpenProcess", "TerminateProcess", "CreateThread", "CreateRemoteThread", "OpenThread", "SuspendThread", "ResumeThread",
             "ShellExecute", "WinExec", "VirtualAllocEx", "WriteProcessMemory", "ReadProcessMemory", "CreateToolhelp32Snapshot", "Process32First", "Process32Next",
             "NtCreateThread", "RtlCreateUserThread", "QueueUserAPC", "_beginthread", "pthread_create"],
            ["fork", "vfork", "execve", "execv", "execvp", "posix_spawn", "kill", "system", "popen", "clone"]),
        new("ui", ["user32", "gdi32", "comctl32", "comdlg32", "uxtheme", "dwmapi", "d2d1", "d3d11", "dxgi", "opengl32", "libX11", "libgtk-3"],
            ["CreateWindow", "MessageBox", "DialogBox", "ShowWindow", "GetMessage", "DispatchMessage", "RegisterClass", "SetWindowsHook"], []),
        new("services", [], ["OpenSCManager", "CreateService", "OpenService", "StartService", "ControlService", "DeleteService", "ChangeServiceConfig",
            "RegisterServiceCtrlHandler", "StartServiceCtrlDispatcher", "QueryServiceStatus"], []),
        new("com", ["ole32", "oleaut32", "combase"], ["CoCreateInstance", "CoInitialize", "CoGetClassObject", "OleInitialize", "SysAllocString", "VariantInit"], []),
        new("debug", ["dbghelp", "dbgeng"],
            ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "OutputDebugString", "DebugActiveProcess", "WaitForDebugEvent",
             "ContinueDebugEvent", "SetUnhandledExceptionFilter", "NtSetInformationThread", "MiniDumpWriteDump", "DebugBreak"],
            ["ptrace"]),
        new("dynamic_loading", [], ["LoadLibrary", "GetProcAddress", "GetModuleHandle", "LdrLoadDll", "LdrGetProcedureAddress", "FreeLibrary"], ["dlopen", "dlsym", "dlclose"]),
    ];

    /// <summary>The groups the APIs fall into, largest first; each with up to <paramref name="examples"/> distinct API names.</summary>
    public static IReadOnlyList<ApiCapability> Classify(IEnumerable<(string Module, string Name)> apis, int examples = 6)
    {
        var byGroup = new Dictionary<string, List<string>>();
        foreach (var (module, name) in apis.Distinct())
        {
            var mod = ModuleStem(module);
            var bare = Bare(name);
            foreach (var g in Groups)
            {
                if (!g.Modules.Contains(mod, StringComparer.OrdinalIgnoreCase)
                    && !g.Prefixes.Any(p => bare.StartsWith(p, StringComparison.Ordinal) || name.StartsWith(p, StringComparison.Ordinal))
                    && !g.Exact.Contains(bare, StringComparer.Ordinal))
                    continue;
                if (!byGroup.TryGetValue(g.Name, out var list)) byGroup[g.Name] = list = [];
                if (!list.Contains(bare, StringComparer.Ordinal)) list.Add(bare);
            }
        }
        return Groups.Where(g => byGroup.ContainsKey(g.Name))
            .Select(g => new ApiCapability(g.Name, byGroup[g.Name].Count, byGroup[g.Name].Take(examples).ToList()))
            .OrderByDescending(c => c.Count).ThenBy(c => c.Group, StringComparer.Ordinal).ToList();
    }

    private static string ModuleStem(string module)
    {
        var m = Path.GetFileName(module ?? "");
        int dot = m.IndexOf('.');
        return dot > 0 ? m[..dot] : m;
    }

    /// <summary>The name without a trailing Ex, A or W (CreateFileExW -> CreateFile), and without a leading underscore for POSIX names.</summary>
    internal static string Bare(string name)
    {
        var n = name;
        if (n.Length > 2 && (n[^1] == 'A' || n[^1] == 'W') && char.IsLower(n[^2])) n = n[..^1];
        if (n.EndsWith("Ex", StringComparison.Ordinal) && n.Length > 3) n = n[..^2];
        return n.Length > 1 && n[0] == '_' && char.IsLower(n[1]) && !n.StartsWith("_beginthread", StringComparison.Ordinal) ? n[1..] : n;
    }
}
