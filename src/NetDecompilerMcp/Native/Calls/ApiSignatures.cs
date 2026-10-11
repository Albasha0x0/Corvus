using System.Globalization;
using System.Text;

namespace NetDecompilerMcp.Native.Calls;

/// <summary>How a parameter's value is shown and read.</summary>
public enum ApiParamType : byte
{
    Int,
    UInt,
    /// <summary>A number shown in hex (codes, styles).</summary>
    Hex,
    Pointer,
    Handle,
    Module,
    Size,
    Bool,
    AnsiString,
    WideString,
    /// <summary>printf-style format (ANSI); with a variadic signature it decides the extra arguments.</summary>
    AnsiFormat,
    WideFormat,
    /// <summary>GetProcAddress name: an ANSI string or an ordinal below 0x10000.</summary>
    ProcName,
    /// <summary>Pointer to a GUID (CLSID, IID).</summary>
    Guid,
    Float,
    Double,
    /// <summary>64-bit integer (two stack slots on x86).</summary>
    Int64,
    /// <summary>A named enumeration or flag set (<see cref="ApiParam.Enum"/>).</summary>
    Enum,
}

public sealed record ApiParam(string Name, ApiParamType Type, ApiEnum? Enum = null)
{
    public bool IsString => Type is ApiParamType.AnsiString or ApiParamType.WideString or ApiParamType.AnsiFormat or ApiParamType.WideFormat;
    /// <summary>Stack slots on x86.</summary>
    public int Slots32 => Type is ApiParamType.Int64 or ApiParamType.Double ? 2 : 1;
    public bool IsFloat => Type is ApiParamType.Float or ApiParamType.Double;
    public string TypeName => Enum?.Name ?? Type.ToString().ToLowerInvariant();
}

/// <summary>What a known API returns: <see cref="Meaning"/> ("a Win32 error code") and the names of its values when they form an enumeration.</summary>
public sealed record ApiReturn(string Meaning, ApiEnum? Enum);

/// <summary>A known API: parameter names and types; <see cref="Variadic"/> takes extra arguments described by its format string.</summary>
public sealed record ApiSignature(string Name, IReadOnlyList<ApiParam> Params, bool Variadic, bool Cdecl);

/// <summary>Named values of a parameter: an enumeration (exact match) or flags (each entry claims value under its mask).</summary>
public sealed class ApiEnum(string name, bool flags, IReadOnlyList<(string Name, ulong Value, ulong Mask)> entries)
{
    public string Name { get; } = name;
    public bool IsFlags { get; } = flags;
    public IReadOnlyList<(string Name, ulong Value, ulong Mask)> Entries { get; } = entries;

    /// <summary>The value of a named entry, or null.</summary>
    public ulong? ValueOf(string entry)
    {
        foreach (var e in Entries)
            if (e.Name.Equals(entry, StringComparison.OrdinalIgnoreCase)) return e.Value;
        return null;
    }

    /// <summary>Whether <paramref name="value"/> has the entry: equal for an enumeration, all its bits under its mask for flags.</summary>
    public bool Has(ulong value, string entry)
    {
        value = Normalize(value);
        foreach (var e in Entries)
        {
            if (!e.Name.Equals(entry, StringComparison.OrdinalIgnoreCase)) continue;
            return IsFlags ? (value & e.Mask) == e.Value && (e.Value != 0 || e.Mask != 0) : value == e.Value;
        }
        return false;
    }

    /// <summary>Sign-extended 32-bit constants (HKEY_LOCAL_MACHINE as 0xFFFFFFFF80000002) compare by their low half.</summary>
    private static ulong Normalize(ulong v) => v >> 32 == 0xFFFFFFFF ? v & 0xFFFFFFFF : v;

    /// <summary>"OPEN_EXISTING", "GENERIC_READ|GENERIC_WRITE", or null when nothing matches.</summary>
    public string? Describe(ulong value)
    {
        value = Normalize(value);
        if (!IsFlags)
        {
            foreach (var e in Entries) if (e.Value == value) return e.Name;
            return null;
        }
        var parts = new List<string>();
        ulong covered = 0;
        foreach (var (name, v, mask) in Entries)
        {
            if (v == 0)
            {
                // a zero entry names an empty field (mask) or an all-zero value (no mask)
                if (mask == 0 ? value == 0 && parts.Count == 0 : (value & mask) == 0 && (covered & mask) == 0)
                {
                    parts.Add(name);
                    covered |= mask;
                }
                continue;
            }
            if ((value & mask) != v || (v & ~covered) == 0) continue;
            parts.Add(name);
            covered |= mask;
        }
        ulong rest = value & ~covered;
        if (parts.Count == 0) return null;
        if (rest != 0) parts.Add($"0x{rest:X}");
        return string.Join("|", parts);
    }
}

/// <summary>
/// Signatures of common Win32 / CRT APIs, parsed from a compact table: parameter names, types and the enumerations and
/// flags that decode constant arguments. Lookup by name ignores the module ("kernel32!CreateFileW", "__imp_CreateFileW"
/// and "j_CreateFileW" all find CreateFileW).
/// </summary>
public static class ApiSignatures
{
    // Table format:
    //   flags NAME: ENTRY=value[/mask] ...     entries decode in order; a zero entry with a mask names an empty field
    //   enum NAME: ENTRY=value ...
    //   [cdecl] Name(type name, ...[, ...])     a trailing % expands to the A and W forms (str / fmt become astr / wstr, afmt / wfmt)
    // Types: int uint hex ptr handle hmodule size bool str astr wstr fmt afmt wfmt procname guid float double i64, or an enum / flags name.
    private const string Table = """
        flags Access: FILE_ALL_ACCESS=0x1F01FF FILE_GENERIC_READ=0x120089 FILE_GENERIC_WRITE=0x120116 FILE_GENERIC_EXECUTE=0x1200A0 GENERIC_READ=0x80000000 GENERIC_WRITE=0x40000000 GENERIC_EXECUTE=0x20000000 GENERIC_ALL=0x10000000 MAXIMUM_ALLOWED=0x2000000 ACCESS_SYSTEM_SECURITY=0x1000000 SYNCHRONIZE=0x100000 WRITE_OWNER=0x80000 WRITE_DAC=0x40000 READ_CONTROL=0x20000 DELETE=0x10000 FILE_READ_DATA=0x1 FILE_WRITE_DATA=0x2 FILE_APPEND_DATA=0x4 FILE_READ_EA=0x8 FILE_WRITE_EA=0x10 FILE_EXECUTE=0x20 FILE_READ_ATTRIBUTES=0x80 FILE_WRITE_ATTRIBUTES=0x100
        flags FileShare: FILE_SHARE_READ=1 FILE_SHARE_WRITE=2 FILE_SHARE_DELETE=4
        enum CreationDisposition: CREATE_NEW=1 CREATE_ALWAYS=2 OPEN_EXISTING=3 OPEN_ALWAYS=4 TRUNCATE_EXISTING=5
        flags FileAttributes: FILE_ATTRIBUTE_READONLY=0x1 FILE_ATTRIBUTE_HIDDEN=0x2 FILE_ATTRIBUTE_SYSTEM=0x4 FILE_ATTRIBUTE_DIRECTORY=0x10 FILE_ATTRIBUTE_ARCHIVE=0x20 FILE_ATTRIBUTE_NORMAL=0x80 FILE_ATTRIBUTE_TEMPORARY=0x100 FILE_FLAG_WRITE_THROUGH=0x80000000 FILE_FLAG_OVERLAPPED=0x40000000 FILE_FLAG_NO_BUFFERING=0x20000000 FILE_FLAG_RANDOM_ACCESS=0x10000000 FILE_FLAG_SEQUENTIAL_SCAN=0x8000000 FILE_FLAG_DELETE_ON_CLOSE=0x4000000 FILE_FLAG_BACKUP_SEMANTICS=0x2000000 FILE_FLAG_POSIX_SEMANTICS=0x1000000 FILE_FLAG_OPEN_REPARSE_POINT=0x200000 FILE_FLAG_OPEN_NO_RECALL=0x100000
        flags PageProtect: PAGE_NOACCESS=0x1 PAGE_READONLY=0x2 PAGE_READWRITE=0x4 PAGE_WRITECOPY=0x8 PAGE_EXECUTE=0x10 PAGE_EXECUTE_READ=0x20 PAGE_EXECUTE_READWRITE=0x40 PAGE_EXECUTE_WRITECOPY=0x80 PAGE_GUARD=0x100 PAGE_NOCACHE=0x200 PAGE_WRITECOMBINE=0x400 PAGE_TARGETS_INVALID=0x40000000
        flags SectionProtect: PAGE_NOACCESS=0x1 PAGE_READONLY=0x2 PAGE_READWRITE=0x4 PAGE_WRITECOPY=0x8 PAGE_EXECUTE=0x10 PAGE_EXECUTE_READ=0x20 PAGE_EXECUTE_READWRITE=0x40 PAGE_EXECUTE_WRITECOPY=0x80 SEC_IMAGE=0x1000000 SEC_RESERVE=0x4000000 SEC_COMMIT=0x8000000 SEC_NOCACHE=0x10000000 SEC_LARGE_PAGES=0x80000000
        flags MemAlloc: MEM_COMMIT=0x1000 MEM_RESERVE=0x2000 MEM_REPLACE_PLACEHOLDER=0x4000 MEM_RESERVE_PLACEHOLDER=0x40000 MEM_RESET=0x80000 MEM_TOP_DOWN=0x100000 MEM_WRITE_WATCH=0x200000 MEM_PHYSICAL=0x400000 MEM_RESET_UNDO=0x1000000 MEM_LARGE_PAGES=0x20000000
        flags MemFree: MEM_COALESCE_PLACEHOLDERS=0x1 MEM_PRESERVE_PLACEHOLDER=0x2 MEM_DECOMMIT=0x4000 MEM_RELEASE=0x8000
        enum HKEY: HKEY_CLASSES_ROOT=0x80000000 HKEY_CURRENT_USER=0x80000001 HKEY_LOCAL_MACHINE=0x80000002 HKEY_USERS=0x80000003 HKEY_PERFORMANCE_DATA=0x80000004 HKEY_CURRENT_CONFIG=0x80000005 HKEY_DYN_DATA=0x80000006 HKEY_CURRENT_USER_LOCAL_SETTINGS=0x80000007
        flags RegSam: KEY_ALL_ACCESS=0xF003F KEY_READ=0x20019 KEY_WRITE=0x20006 KEY_QUERY_VALUE=0x1 KEY_SET_VALUE=0x2 KEY_CREATE_SUB_KEY=0x4 KEY_ENUMERATE_SUB_KEYS=0x8 KEY_NOTIFY=0x10 KEY_CREATE_LINK=0x20 KEY_WOW64_64KEY=0x100 KEY_WOW64_32KEY=0x200 DELETE=0x10000 READ_CONTROL=0x20000 WRITE_DAC=0x40000 WRITE_OWNER=0x80000 MAXIMUM_ALLOWED=0x2000000
        flags RegOptions: REG_OPTION_NON_VOLATILE=0 REG_OPTION_VOLATILE=0x1 REG_OPTION_CREATE_LINK=0x2 REG_OPTION_BACKUP_RESTORE=0x4 REG_OPTION_OPEN_LINK=0x8
        enum RegType: REG_NONE=0 REG_SZ=1 REG_EXPAND_SZ=2 REG_BINARY=3 REG_DWORD=4 REG_DWORD_BIG_ENDIAN=5 REG_LINK=6 REG_MULTI_SZ=7 REG_QWORD=11
        flags RegGetFlags: RRF_RT_ANY=0xFFFF RRF_RT_REG_NONE=0x1 RRF_RT_REG_SZ=0x2 RRF_RT_REG_EXPAND_SZ=0x4 RRF_RT_REG_BINARY=0x8 RRF_RT_REG_DWORD=0x10 RRF_RT_REG_MULTI_SZ=0x20 RRF_RT_REG_QWORD=0x40 RRF_SUBKEY_WOW6464KEY=0x10000 RRF_SUBKEY_WOW6432KEY=0x20000 RRF_NOEXPAND=0x10000000 RRF_ZEROONFAILURE=0x20000000
        flags LoadLibraryFlags: DONT_RESOLVE_DLL_REFERENCES=0x1 LOAD_LIBRARY_AS_DATAFILE=0x2 LOAD_WITH_ALTERED_SEARCH_PATH=0x8 LOAD_IGNORE_CODE_AUTHZ_LEVEL=0x10 LOAD_LIBRARY_AS_IMAGE_RESOURCE=0x20 LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE=0x40 LOAD_LIBRARY_REQUIRE_SIGNED_TARGET=0x80 LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR=0x100 LOAD_LIBRARY_SEARCH_APPLICATION_DIR=0x200 LOAD_LIBRARY_SEARCH_USER_DIRS=0x400 LOAD_LIBRARY_SEARCH_SYSTEM32=0x800 LOAD_LIBRARY_SEARCH_DEFAULT_DIRS=0x1000 LOAD_LIBRARY_SAFE_CURRENT_DIRS=0x2000
        flags ModuleHandleFlags: GET_MODULE_HANDLE_EX_FLAG_PIN=0x1 GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT=0x2 GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS=0x4
        flags MessageBoxType: MB_OK=0/0xF MB_OKCANCEL=1/0xF MB_ABORTRETRYIGNORE=2/0xF MB_YESNOCANCEL=3/0xF MB_YESNO=4/0xF MB_RETRYCANCEL=5/0xF MB_CANCELTRYCONTINUE=6/0xF MB_ICONERROR=0x10/0xF0 MB_ICONQUESTION=0x20/0xF0 MB_ICONWARNING=0x30/0xF0 MB_ICONINFORMATION=0x40/0xF0 MB_DEFBUTTON2=0x100/0xF00 MB_DEFBUTTON3=0x200/0xF00 MB_DEFBUTTON4=0x300/0xF00 MB_SYSTEMMODAL=0x1000/0x3000 MB_TASKMODAL=0x2000/0x3000 MB_HELP=0x4000 MB_NOFOCUS=0x8000 MB_SETFOREGROUND=0x10000 MB_DEFAULT_DESKTOP_ONLY=0x20000 MB_TOPMOST=0x40000 MB_RIGHT=0x80000 MB_RTLREADING=0x100000 MB_SERVICE_NOTIFICATION=0x200000
        flags ProcessCreation: DEBUG_PROCESS=0x1 DEBUG_ONLY_THIS_PROCESS=0x2 CREATE_SUSPENDED=0x4 DETACHED_PROCESS=0x8 CREATE_NEW_CONSOLE=0x10 NORMAL_PRIORITY_CLASS=0x20 IDLE_PRIORITY_CLASS=0x40 HIGH_PRIORITY_CLASS=0x80 REALTIME_PRIORITY_CLASS=0x100 CREATE_NEW_PROCESS_GROUP=0x200 CREATE_UNICODE_ENVIRONMENT=0x400 CREATE_SEPARATE_WOW_VDM=0x800 CREATE_SHARED_WOW_VDM=0x1000 BELOW_NORMAL_PRIORITY_CLASS=0x4000 ABOVE_NORMAL_PRIORITY_CLASS=0x8000 INHERIT_PARENT_AFFINITY=0x10000 CREATE_PROTECTED_PROCESS=0x40000 EXTENDED_STARTUPINFO_PRESENT=0x80000 PROCESS_MODE_BACKGROUND_BEGIN=0x100000 CREATE_SECURE_PROCESS=0x400000 CREATE_BREAKAWAY_FROM_JOB=0x1000000 CREATE_PRESERVE_CODE_AUTHZ_LEVEL=0x2000000 CREATE_DEFAULT_ERROR_MODE=0x4000000 CREATE_NO_WINDOW=0x8000000
        flags ThreadCreation: CREATE_SUSPENDED=0x4 STACK_SIZE_PARAM_IS_A_RESERVATION=0x10000
        flags ProcessAccess: PROCESS_ALL_ACCESS=0x1FFFFF PROCESS_TERMINATE=0x1 PROCESS_CREATE_THREAD=0x2 PROCESS_SET_SESSIONID=0x4 PROCESS_VM_OPERATION=0x8 PROCESS_VM_READ=0x10 PROCESS_VM_WRITE=0x20 PROCESS_DUP_HANDLE=0x40 PROCESS_CREATE_PROCESS=0x80 PROCESS_SET_QUOTA=0x100 PROCESS_SET_INFORMATION=0x200 PROCESS_QUERY_INFORMATION=0x400 PROCESS_SUSPEND_RESUME=0x800 PROCESS_QUERY_LIMITED_INFORMATION=0x1000 DELETE=0x10000 READ_CONTROL=0x20000 WRITE_DAC=0x40000 WRITE_OWNER=0x80000 SYNCHRONIZE=0x100000 MAXIMUM_ALLOWED=0x2000000
        enum ShowCmd: SW_HIDE=0 SW_SHOWNORMAL=1 SW_SHOWMINIMIZED=2 SW_SHOWMAXIMIZED=3 SW_SHOWNOACTIVATE=4 SW_SHOW=5 SW_MINIMIZE=6 SW_SHOWMINNOACTIVE=7 SW_SHOWNA=8 SW_RESTORE=9 SW_SHOWDEFAULT=10 SW_FORCEMINIMIZE=11
        enum Timeout: INFINITE=0xFFFFFFFF
        enum StdHandle: STD_INPUT_HANDLE=0xFFFFFFF6 STD_OUTPUT_HANDLE=0xFFFFFFF5 STD_ERROR_HANDLE=0xFFFFFFF4
        enum AddressFamily: AF_UNSPEC=0 AF_UNIX=1 AF_INET=2 AF_NETBIOS=17 AF_INET6=23 AF_IRDA=26 AF_BTH=32
        enum SocketType: SOCK_STREAM=1 SOCK_DGRAM=2 SOCK_RAW=3 SOCK_RDM=4 SOCK_SEQPACKET=5
        enum Protocol: IPPROTO_IP=0 IPPROTO_ICMP=1 IPPROTO_IGMP=2 IPPROTO_TCP=6 IPPROTO_UDP=17 IPPROTO_ICMPV6=58 IPPROTO_RAW=255
        flags ToolhelpFlags: TH32CS_SNAPALL=0xF TH32CS_SNAPHEAPLIST=0x1 TH32CS_SNAPPROCESS=0x2 TH32CS_SNAPTHREAD=0x4 TH32CS_SNAPMODULE=0x8 TH32CS_SNAPMODULE32=0x10 TH32CS_INHERIT=0x80000000
        enum HookType: WH_MSGFILTER=0xFFFFFFFF WH_JOURNALRECORD=0 WH_JOURNALPLAYBACK=1 WH_KEYBOARD=2 WH_GETMESSAGE=3 WH_CALLWNDPROC=4 WH_CBT=5 WH_SYSMSGFILTER=6 WH_MOUSE=7 WH_DEBUG=9 WH_SHELL=10 WH_FOREGROUNDIDLE=11 WH_CALLWNDPROCRET=12 WH_KEYBOARD_LL=13 WH_MOUSE_LL=14
        flags HeapFlags: HEAP_NO_SERIALIZE=0x1 HEAP_GROWABLE=0x2 HEAP_GENERATE_EXCEPTIONS=0x4 HEAP_ZERO_MEMORY=0x8 HEAP_REALLOC_IN_PLACE_ONLY=0x10 HEAP_CREATE_ENABLE_EXECUTE=0x40000
        flags LocalFlags: LMEM_FIXED=0 LMEM_MOVEABLE=0x2 LMEM_ZEROINIT=0x40
        flags MoveFileFlags: MOVEFILE_REPLACE_EXISTING=0x1 MOVEFILE_COPY_ALLOWED=0x2 MOVEFILE_DELAY_UNTIL_REBOOT=0x4 MOVEFILE_WRITE_THROUGH=0x8
        flags FileMapAccess: FILE_MAP_ALL_ACCESS=0xF001F FILE_MAP_COPY=0x1 FILE_MAP_WRITE=0x2 FILE_MAP_READ=0x4 FILE_MAP_EXECUTE=0x20
        enum SeekMethod: FILE_BEGIN=0 FILE_CURRENT=1 FILE_END=2
        enum InternetOpenType: INTERNET_OPEN_TYPE_PRECONFIG=0 INTERNET_OPEN_TYPE_DIRECT=1 INTERNET_OPEN_TYPE_PROXY=3
        enum InternetService: INTERNET_SERVICE_FTP=1 INTERNET_SERVICE_GOPHER=2 INTERNET_SERVICE_HTTP=3
        flags InternetFlags: INTERNET_FLAG_RELOAD=0x80000000 INTERNET_FLAG_NO_CACHE_WRITE=0x4000000 INTERNET_FLAG_SECURE=0x800000 INTERNET_FLAG_KEEP_CONNECTION=0x400000 INTERNET_FLAG_NO_AUTO_REDIRECT=0x200000 INTERNET_FLAG_NO_COOKIES=0x80000 INTERNET_FLAG_IGNORE_CERT_DATE_INVALID=0x2000 INTERNET_FLAG_IGNORE_CERT_CN_INVALID=0x1000 INTERNET_FLAG_NO_UI=0x200 INTERNET_FLAG_PRAGMA_NOCACHE=0x100
        enum WinHttpAccessType: WINHTTP_ACCESS_TYPE_DEFAULT_PROXY=0 WINHTTP_ACCESS_TYPE_NO_PROXY=1 WINHTTP_ACCESS_TYPE_NAMED_PROXY=3 WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY=4
        flags WinHttpFlags: WINHTTP_FLAG_SECURE=0x800000 WINHTTP_FLAG_BYPASS_PROXY_CACHE=0x100 WINHTTP_FLAG_ESCAPE_DISABLE=0x40 WINHTTP_FLAG_NULL_CODEPAGE=0x8 WINHTTP_FLAG_ESCAPE_PERCENT=0x4
        flags ScmAccess: SC_MANAGER_ALL_ACCESS=0xF003F SC_MANAGER_CONNECT=0x1 SC_MANAGER_CREATE_SERVICE=0x2 SC_MANAGER_ENUMERATE_SERVICE=0x4 SC_MANAGER_LOCK=0x8 SC_MANAGER_QUERY_LOCK_STATUS=0x10 SC_MANAGER_MODIFY_BOOT_CONFIG=0x20 GENERIC_READ=0x80000000 GENERIC_WRITE=0x40000000 GENERIC_EXECUTE=0x20000000
        flags ServiceAccess: SERVICE_ALL_ACCESS=0xF01FF SERVICE_QUERY_CONFIG=0x1 SERVICE_CHANGE_CONFIG=0x2 SERVICE_QUERY_STATUS=0x4 SERVICE_ENUMERATE_DEPENDENTS=0x8 SERVICE_START=0x10 SERVICE_STOP=0x20 SERVICE_PAUSE_CONTINUE=0x40 SERVICE_INTERROGATE=0x80 SERVICE_USER_DEFINED_CONTROL=0x100 DELETE=0x10000
        flags ServiceType: SERVICE_KERNEL_DRIVER=0x1 SERVICE_FILE_SYSTEM_DRIVER=0x2 SERVICE_WIN32_OWN_PROCESS=0x10 SERVICE_WIN32_SHARE_PROCESS=0x20 SERVICE_INTERACTIVE_PROCESS=0x100
        enum ServiceStart: SERVICE_BOOT_START=0 SERVICE_SYSTEM_START=1 SERVICE_AUTO_START=2 SERVICE_DEMAND_START=3 SERVICE_DISABLED=4
        enum ServiceControl: SERVICE_CONTROL_STOP=1 SERVICE_CONTROL_PAUSE=2 SERVICE_CONTROL_CONTINUE=3 SERVICE_CONTROL_INTERROGATE=4 SERVICE_CONTROL_SHUTDOWN=5 SERVICE_CONTROL_PARAMCHANGE=6
        flags ErrorMode: SEM_FAILCRITICALERRORS=0x1 SEM_NOGPFAULTERRORBOX=0x2 SEM_NOALIGNMENTFAULTEXCEPT=0x4 SEM_NOOPENFILEERRORBOX=0x8000
        enum CryptProvType: PROV_RSA_FULL=1 PROV_RSA_SIG=2 PROV_DSS=3 PROV_FORTEZZA=4 PROV_MS_EXCHANGE=5 PROV_SSL=6 PROV_RSA_SCHANNEL=12 PROV_DSS_DH=13 PROV_DH_SCHANNEL=18 PROV_RSA_AES=24
        flags CryptContextFlags: CRYPT_VERIFYCONTEXT=0xF0000000 CRYPT_NEWKEYSET=0x8 CRYPT_DELETEKEYSET=0x10 CRYPT_MACHINE_KEYSET=0x20 CRYPT_SILENT=0x40
        enum AlgId: CALG_MD2=0x8001 CALG_MD4=0x8002 CALG_MD5=0x8003 CALG_SHA1=0x8004 CALG_MAC=0x8005 CALG_HMAC=0x8009 CALG_SHA_256=0x800C CALG_SHA_384=0x800D CALG_SHA_512=0x800E CALG_DES=0x6601 CALG_3DES_112=0x6609 CALG_3DES=0x6603 CALG_RC2=0x6602 CALG_RC4=0x6801 CALG_AES_128=0x660E CALG_AES_192=0x660F CALG_AES_256=0x6610 CALG_AES=0x6611 CALG_RSA_SIGN=0x2400 CALG_RSA_KEYX=0xA400
        enum ProcessInfoClass: ProcessBasicInformation=0 ProcessQuotaLimits=1 ProcessIoCounters=2 ProcessTimes=4 ProcessDebugPort=7 ProcessWow64Information=26 ProcessImageFileName=27 ProcessBreakOnTermination=29 ProcessDebugObjectHandle=30 ProcessDebugFlags=31 ProcessImageInformation=37
        enum ThreadInfoClass: ThreadBasicInformation=0 ThreadTimes=1 ThreadPriority=2 ThreadQuerySetWin32StartAddress=9 ThreadHideFromDebugger=17
        flags ClsCtx: CLSCTX_ALL=0x17 CLSCTX_SERVER=0x15 CLSCTX_INPROC_SERVER=0x1 CLSCTX_INPROC_HANDLER=0x2 CLSCTX_LOCAL_SERVER=0x4 CLSCTX_REMOTE_SERVER=0x10 CLSCTX_NO_CODE_DOWNLOAD=0x400 CLSCTX_ENABLE_CLOAKING=0x100000 CLSCTX_ACTIVATE_32_BIT_SERVER=0x40000 CLSCTX_ACTIVATE_64_BIT_SERVER=0x80000
        flags CoInit: COINIT_MULTITHREADED=0 COINIT_APARTMENTTHREADED=0x2 COINIT_DISABLE_OLE1DDE=0x4 COINIT_SPEED_OVER_MEMORY=0x8
        flags PipeOpenMode: PIPE_ACCESS_INBOUND=1/0x3 PIPE_ACCESS_OUTBOUND=2/0x3 PIPE_ACCESS_DUPLEX=3/0x3 FILE_FLAG_FIRST_PIPE_INSTANCE=0x80000 FILE_FLAG_WRITE_THROUGH=0x80000000 FILE_FLAG_OVERLAPPED=0x40000000 WRITE_DAC=0x40000 WRITE_OWNER=0x80000 ACCESS_SYSTEM_SECURITY=0x1000000
        flags PipeMode: PIPE_WAIT=0 PIPE_NOWAIT=0x1 PIPE_READMODE_MESSAGE=0x2 PIPE_TYPE_MESSAGE=0x4 PIPE_REJECT_REMOTE_CLIENTS=0x8
        enum WindowMessage: WM_NULL=0 WM_CREATE=1 WM_DESTROY=2 WM_SETTEXT=0xC WM_GETTEXT=0xD WM_CLOSE=0x10 WM_QUIT=0x12 WM_COPYDATA=0x4A WM_SETICON=0x80 WM_KEYDOWN=0x100 WM_KEYUP=0x101 WM_CHAR=0x102 WM_COMMAND=0x111 WM_SYSCOMMAND=0x112 WM_TIMER=0x113 WM_USER=0x400
        flags FormatMessageFlags: FORMAT_MESSAGE_ALLOCATE_BUFFER=0x100 FORMAT_MESSAGE_IGNORE_INSERTS=0x200 FORMAT_MESSAGE_FROM_STRING=0x400 FORMAT_MESSAGE_FROM_HMODULE=0x800 FORMAT_MESSAGE_FROM_SYSTEM=0x1000 FORMAT_MESSAGE_ARGUMENT_ARRAY=0x2000
        enum Win32Error: ERROR_SUCCESS=0 ERROR_INVALID_FUNCTION=1 ERROR_FILE_NOT_FOUND=2 ERROR_PATH_NOT_FOUND=3 ERROR_TOO_MANY_OPEN_FILES=4 ERROR_ACCESS_DENIED=5 ERROR_INVALID_HANDLE=6 ERROR_NOT_ENOUGH_MEMORY=8 ERROR_INVALID_DATA=13 ERROR_OUTOFMEMORY=14 ERROR_NO_MORE_FILES=18 ERROR_SHARING_VIOLATION=32 ERROR_HANDLE_EOF=38 ERROR_NOT_SUPPORTED=50 ERROR_FILE_EXISTS=80 ERROR_INVALID_PARAMETER=87 ERROR_BROKEN_PIPE=109 ERROR_INSUFFICIENT_BUFFER=122 ERROR_INVALID_NAME=123 ERROR_MOD_NOT_FOUND=126 ERROR_PROC_NOT_FOUND=127 ERROR_ALREADY_EXISTS=183 ERROR_ENVVAR_NOT_FOUND=203 ERROR_MORE_DATA=234 ERROR_NO_MORE_ITEMS=259 ERROR_OPERATION_ABORTED=995 ERROR_IO_INCOMPLETE=996 ERROR_IO_PENDING=997 ERROR_NOACCESS=998 ERROR_NOT_FOUND=1168 ERROR_CANCELLED=1223 ERROR_TIMEOUT=1460
        enum WaitResult: WAIT_OBJECT_0=0 WAIT_ABANDONED=0x80 WAIT_IO_COMPLETION=0xC0 WAIT_TIMEOUT=0x102 WAIT_FAILED=0xFFFFFFFF
        enum HResult: S_OK=0 S_FALSE=1 E_NOTIMPL=0x80004001 E_NOINTERFACE=0x80004002 E_POINTER=0x80004003 E_ABORT=0x80004004 E_FAIL=0x80004005 E_UNEXPECTED=0x8000FFFF E_ACCESSDENIED=0x80070005 E_HANDLE=0x80070006 E_OUTOFMEMORY=0x8007000E E_INVALIDARG=0x80070057 RPC_E_CHANGED_MODE=0x80010106 CO_E_NOTINITIALIZED=0x800401F0 REGDB_E_CLASSNOTREG=0x80040154
        enum NtStatus: STATUS_SUCCESS=0 STATUS_BUFFER_OVERFLOW=0x80000005 STATUS_NO_MORE_ENTRIES=0x8000001A STATUS_UNSUCCESSFUL=0xC0000001 STATUS_NOT_IMPLEMENTED=0xC0000002 STATUS_INFO_LENGTH_MISMATCH=0xC0000004 STATUS_ACCESS_VIOLATION=0xC0000005 STATUS_INVALID_HANDLE=0xC0000008 STATUS_INVALID_PARAMETER=0xC000000D STATUS_NO_MEMORY=0xC0000017 STATUS_ACCESS_DENIED=0xC0000022 STATUS_BUFFER_TOO_SMALL=0xC0000023 STATUS_OBJECT_NAME_NOT_FOUND=0xC0000034 STATUS_OBJECT_NAME_COLLISION=0xC0000035 STATUS_NOT_SUPPORTED=0xC00000BB
        enum WinsockError: WSAEINTR=10004 WSAEACCES=10013 WSAEFAULT=10014 WSAEINVAL=10022 WSAEWOULDBLOCK=10035 WSAEINPROGRESS=10036 WSAENOTSOCK=10038 WSAEADDRINUSE=10048 WSAENETDOWN=10050 WSAENETUNREACH=10051 WSAECONNABORTED=10053 WSAECONNRESET=10054 WSAENOTCONN=10057 WSAETIMEDOUT=10060 WSAECONNREFUSED=10061 WSAHOST_NOT_FOUND=11001 WSANOTINITIALISED=10093

        CreateFile%(str lpFileName, Access dwDesiredAccess, FileShare dwShareMode, ptr lpSecurityAttributes, CreationDisposition dwCreationDisposition, FileAttributes dwFlagsAndAttributes, handle hTemplateFile)
        CreateFile2(wstr lpFileName, Access dwDesiredAccess, FileShare dwShareMode, CreationDisposition dwCreationDisposition, ptr pCreateExParams)
        ReadFile(handle hFile, ptr lpBuffer, uint nNumberOfBytesToRead, ptr lpNumberOfBytesRead, ptr lpOverlapped)
        WriteFile(handle hFile, ptr lpBuffer, uint nNumberOfBytesToWrite, ptr lpNumberOfBytesWritten, ptr lpOverlapped)
        CloseHandle(handle hObject)
        DeleteFile%(str lpFileName)
        CopyFile%(str lpExistingFileName, str lpNewFileName, bool bFailIfExists)
        MoveFile%(str lpExistingFileName, str lpNewFileName)
        MoveFileEx%(str lpExistingFileName, str lpNewFileName, MoveFileFlags dwFlags)
        CreateDirectory%(str lpPathName, ptr lpSecurityAttributes)
        RemoveDirectory%(str lpPathName)
        FindFirstFile%(str lpFileName, ptr lpFindFileData)
        GetFileAttributes%(str lpFileName)
        SetFileAttributes%(str lpFileName, FileAttributes dwFileAttributes)
        GetTempPath%(uint nBufferLength, ptr lpBuffer)
        GetTempFileName%(str lpPathName, str lpPrefixString, uint uUnique, ptr lpTempFileName)
        SetFilePointer(handle hFile, int lDistanceToMove, ptr lpDistanceToMoveHigh, SeekMethod dwMoveMethod)
        SetFilePointerEx(handle hFile, i64 liDistanceToMove, ptr lpNewFilePointer, SeekMethod dwMoveMethod)
        CreateFileMapping%(handle hFile, ptr lpFileMappingAttributes, SectionProtect flProtect, uint dwMaximumSizeHigh, uint dwMaximumSizeLow, str lpName)
        OpenFileMapping%(FileMapAccess dwDesiredAccess, bool bInheritHandle, str lpName)
        MapViewOfFile(handle hFileMappingObject, FileMapAccess dwDesiredAccess, uint dwFileOffsetHigh, uint dwFileOffsetLow, size dwNumberOfBytesToMap)
        UnmapViewOfFile(ptr lpBaseAddress)
        DeviceIoControl(handle hDevice, hex dwIoControlCode, ptr lpInBuffer, uint nInBufferSize, ptr lpOutBuffer, uint nOutBufferSize, ptr lpBytesReturned, ptr lpOverlapped)
        CreateNamedPipe%(str lpName, PipeOpenMode dwOpenMode, PipeMode dwPipeMode, uint nMaxInstances, uint nOutBufferSize, uint nInBufferSize, uint nDefaultTimeOut, ptr lpSecurityAttributes)
        GetStdHandle(StdHandle nStdHandle)

        VirtualAlloc(ptr lpAddress, size dwSize, MemAlloc flAllocationType, PageProtect flProtect)
        VirtualAllocEx(handle hProcess, ptr lpAddress, size dwSize, MemAlloc flAllocationType, PageProtect flProtect)
        VirtualProtect(ptr lpAddress, size dwSize, PageProtect flNewProtect, ptr lpflOldProtect)
        VirtualProtectEx(handle hProcess, ptr lpAddress, size dwSize, PageProtect flNewProtect, ptr lpflOldProtect)
        VirtualFree(ptr lpAddress, size dwSize, MemFree dwFreeType)
        VirtualFreeEx(handle hProcess, ptr lpAddress, size dwSize, MemFree dwFreeType)
        VirtualQuery(ptr lpAddress, ptr lpBuffer, size dwLength)
        NtAllocateVirtualMemory(handle ProcessHandle, ptr BaseAddress, size ZeroBits, ptr RegionSize, MemAlloc AllocationType, PageProtect Protect)
        NtProtectVirtualMemory(handle ProcessHandle, ptr BaseAddress, ptr RegionSize, PageProtect NewProtect, ptr OldProtect)
        WriteProcessMemory(handle hProcess, ptr lpBaseAddress, ptr lpBuffer, size nSize, ptr lpNumberOfBytesWritten)
        ReadProcessMemory(handle hProcess, ptr lpBaseAddress, ptr lpBuffer, size nSize, ptr lpNumberOfBytesRead)
        HeapAlloc(handle hHeap, HeapFlags dwFlags, size dwBytes)
        HeapReAlloc(handle hHeap, HeapFlags dwFlags, ptr lpMem, size dwBytes)
        HeapFree(handle hHeap, HeapFlags dwFlags, ptr lpMem)
        HeapCreate(HeapFlags flOptions, size dwInitialSize, size dwMaximumSize)
        LocalAlloc(LocalFlags uFlags, size uBytes)
        GlobalAlloc(LocalFlags uFlags, size dwBytes)

        LoadLibrary%(str lpLibFileName)
        LoadLibraryEx%(str lpLibFileName, handle hFile, LoadLibraryFlags dwFlags)
        GetModuleHandle%(str lpModuleName)
        GetModuleHandleEx%(ModuleHandleFlags dwFlags, str lpModuleName, ptr phModule)
        GetModuleFileName%(hmodule hModule, ptr lpFilename, uint nSize)
        GetProcAddress(hmodule hModule, procname lpProcName)
        FreeLibrary(hmodule hLibModule)
        LdrLoadDll(ptr DllPath, ptr DllCharacteristics, ptr DllName, ptr DllHandle)

        CreateProcess%(str lpApplicationName, str lpCommandLine, ptr lpProcessAttributes, ptr lpThreadAttributes, bool bInheritHandles, ProcessCreation dwCreationFlags, ptr lpEnvironment, str lpCurrentDirectory, ptr lpStartupInfo, ptr lpProcessInformation)
        CreateProcessAsUser%(handle hToken, str lpApplicationName, str lpCommandLine, ptr lpProcessAttributes, ptr lpThreadAttributes, bool bInheritHandles, ProcessCreation dwCreationFlags, ptr lpEnvironment, str lpCurrentDirectory, ptr lpStartupInfo, ptr lpProcessInformation)
        OpenProcess(ProcessAccess dwDesiredAccess, bool bInheritHandle, uint dwProcessId)
        TerminateProcess(handle hProcess, uint uExitCode)
        ExitProcess(uint uExitCode)
        CreateThread(ptr lpThreadAttributes, size dwStackSize, ptr lpStartAddress, ptr lpParameter, ThreadCreation dwCreationFlags, ptr lpThreadId)
        CreateRemoteThread(handle hProcess, ptr lpThreadAttributes, size dwStackSize, ptr lpStartAddress, ptr lpParameter, ThreadCreation dwCreationFlags, ptr lpThreadId)
        QueueUserAPC(ptr pfnAPC, handle hThread, ptr dwData)
        ResumeThread(handle hThread)
        SuspendThread(handle hThread)
        SetThreadContext(handle hThread, ptr lpContext)
        WinExec(astr lpCmdLine, ShowCmd uCmdShow)
        ShellExecute%(handle hwnd, str lpOperation, str lpFile, str lpParameters, str lpDirectory, ShowCmd nShowCmd)
        cdecl system(astr command)
        cdecl _wsystem(wstr command)
        CreateToolhelp32Snapshot(ToolhelpFlags dwFlags, uint th32ProcessID)

        CreateMutex%(ptr lpMutexAttributes, bool bInitialOwner, str lpName)
        CreateMutexEx%(ptr lpMutexAttributes, str lpName, uint dwFlags, hex dwDesiredAccess)
        OpenMutex%(hex dwDesiredAccess, bool bInheritHandle, str lpName)
        CreateEvent%(ptr lpEventAttributes, bool bManualReset, bool bInitialState, str lpName)
        OpenEvent%(hex dwDesiredAccess, bool bInheritHandle, str lpName)
        CreateSemaphore%(ptr lpSemaphoreAttributes, int lInitialCount, int lMaximumCount, str lpName)
        WaitForSingleObject(handle hHandle, Timeout dwMilliseconds)
        WaitForSingleObjectEx(handle hHandle, Timeout dwMilliseconds, bool bAlertable)
        WaitForMultipleObjects(uint nCount, ptr lpHandles, bool bWaitAll, Timeout dwMilliseconds)
        Sleep(Timeout dwMilliseconds)
        SleepEx(Timeout dwMilliseconds, bool bAlertable)
        InitializeCriticalSectionAndSpinCount(ptr lpCriticalSection, uint dwSpinCount)
        InitializeCriticalSectionEx(ptr lpCriticalSection, uint dwSpinCount, hex Flags)

        RegOpenKey%(HKEY hKey, str lpSubKey, ptr phkResult)
        RegOpenKeyEx%(HKEY hKey, str lpSubKey, RegOptions ulOptions, RegSam samDesired, ptr phkResult)
        RegCreateKey%(HKEY hKey, str lpSubKey, ptr phkResult)
        RegCreateKeyEx%(HKEY hKey, str lpSubKey, uint Reserved, str lpClass, RegOptions dwOptions, RegSam samDesired, ptr lpSecurityAttributes, ptr phkResult, ptr lpdwDisposition)
        RegQueryValueEx%(HKEY hKey, str lpValueName, ptr lpReserved, ptr lpType, ptr lpData, ptr lpcbData)
        RegSetValueEx%(HKEY hKey, str lpValueName, uint Reserved, RegType dwType, ptr lpData, uint cbData)
        RegGetValue%(HKEY hkey, str lpSubKey, str lpValue, RegGetFlags dwFlags, ptr pdwType, ptr pvData, ptr pcbData)
        RegSetKeyValue%(HKEY hKey, str lpSubKey, str lpValueName, RegType dwType, ptr lpData, uint cbData)
        RegDeleteKey%(HKEY hKey, str lpSubKey)
        RegDeleteKeyEx%(HKEY hKey, str lpSubKey, RegSam samDesired, uint Reserved)
        RegDeleteValue%(HKEY hKey, str lpValueName)
        RegDeleteTree%(HKEY hKey, str lpSubKey)
        RegCloseKey(HKEY hKey)

        OpenSCManager%(str lpMachineName, str lpDatabaseName, ScmAccess dwDesiredAccess)
        OpenService%(handle hSCManager, str lpServiceName, ServiceAccess dwDesiredAccess)
        CreateService%(handle hSCManager, str lpServiceName, str lpDisplayName, ServiceAccess dwDesiredAccess, ServiceType dwServiceType, ServiceStart dwStartType, uint dwErrorControl, str lpBinaryPathName, str lpLoadOrderGroup, ptr lpdwTagId, ptr lpDependencies, str lpServiceStartName, str lpPassword)
        StartService%(handle hService, uint dwNumServiceArgs, ptr lpServiceArgVectors)
        ControlService(handle hService, ServiceControl dwControl, ptr lpServiceStatus)

        MessageBox%(handle hWnd, str lpText, str lpCaption, MessageBoxType uType)
        MessageBoxEx%(handle hWnd, str lpText, str lpCaption, MessageBoxType uType, hex wLanguageId)
        FindWindow%(str lpClassName, str lpWindowName)
        FindWindowEx%(handle hWndParent, handle hWndChildAfter, str lpszClass, str lpszWindow)
        ShowWindow(handle hWnd, ShowCmd nCmdShow)
        SetWindowsHookEx%(HookType idHook, ptr lpfn, hmodule hmod, uint dwThreadId)
        GetAsyncKeyState(hex vKey)
        RegisterWindowMessage%(str lpString)
        CreateWindowEx%(hex dwExStyle, str lpClassName, str lpWindowName, hex dwStyle, int X, int Y, int nWidth, int nHeight, handle hWndParent, handle hMenu, hmodule hInstance, ptr lpParam)
        LoadString%(hmodule hInstance, uint uID, ptr lpBuffer, int cchBufferMax)
        SendMessage%(handle hWnd, WindowMessage Msg, ptr wParam, ptr lParam)
        PostMessage%(handle hWnd, WindowMessage Msg, ptr wParam, ptr lParam)

        socket(AddressFamily af, SocketType type, Protocol protocol)
        WSASocket%(AddressFamily af, SocketType type, Protocol protocol, ptr lpProtocolInfo, uint g, hex dwFlags)
        connect(handle s, ptr name, int namelen)
        bind(handle s, ptr name, int namelen)
        listen(handle s, int backlog)
        send(handle s, ptr buf, int len, hex flags)
        recv(handle s, ptr buf, int len, hex flags)
        sendto(handle s, ptr buf, int len, hex flags, ptr to, int tolen)
        htons(uint hostshort)
        inet_addr(astr cp)
        inet_pton(AddressFamily Family, astr pszAddrString, ptr pAddrBuf)
        getaddrinfo(astr pNodeName, astr pServiceName, ptr pHints, ptr ppResult)
        GetAddrInfoW(wstr pNodeName, wstr pServiceName, ptr pHints, ptr ppResult)
        gethostbyname(astr name)
        WSAStartup(hex wVersionRequested, ptr lpWSAData)
        InternetOpen%(str lpszAgent, InternetOpenType dwAccessType, str lpszProxy, str lpszProxyBypass, hex dwFlags)
        InternetOpenUrl%(handle hInternet, str lpszUrl, str lpszHeaders, uint dwHeadersLength, InternetFlags dwFlags, ptr dwContext)
        InternetConnect%(handle hInternet, str lpszServerName, uint nServerPort, str lpszUserName, str lpszPassword, InternetService dwService, hex dwFlags, ptr dwContext)
        HttpOpenRequest%(handle hConnect, str lpszVerb, str lpszObjectName, str lpszVersion, str lpszReferrer, ptr lplpszAcceptTypes, InternetFlags dwFlags, ptr dwContext)
        HttpSendRequest%(handle hRequest, str lpszHeaders, uint dwHeadersLength, ptr lpOptional, uint dwOptionalLength)
        InternetReadFile(handle hFile, ptr lpBuffer, uint dwNumberOfBytesToRead, ptr lpdwNumberOfBytesRead)
        URLDownloadToFile%(ptr pCaller, str szURL, str szFileName, uint dwReserved, ptr lpfnCB)
        WinHttpOpen(wstr pszAgentW, WinHttpAccessType dwAccessType, wstr pszProxyW, wstr pszProxyBypassW, hex dwFlags)
        WinHttpConnect(handle hSession, wstr pswzServerName, uint nServerPort, uint dwReserved)
        WinHttpOpenRequest(handle hConnect, wstr pwszVerb, wstr pwszObjectName, wstr pwszVersion, wstr pwszReferrer, ptr ppwszAcceptTypes, WinHttpFlags dwFlags)
        WinHttpSendRequest(handle hRequest, wstr lpszHeaders, uint dwHeadersLength, ptr lpOptional, uint dwOptionalLength, uint dwTotalLength, ptr dwContext)

        GetProcessHeap()
        GetLastError()
        GetCurrentProcess()
        GetCurrentThread()
        GetCurrentProcessId()
        GetCurrentThreadId()
        GetTickCount()
        GetTickCount64()
        GetCommandLine%()
        IsDebuggerPresent()
        CheckRemoteDebuggerPresent(handle hProcess, ptr pbDebuggerPresent)
        NtQueryInformationProcess(handle ProcessHandle, ProcessInfoClass ProcessInformationClass, ptr ProcessInformation, uint ProcessInformationLength, ptr ReturnLength)
        NtSetInformationThread(handle ThreadHandle, ThreadInfoClass ThreadInformationClass, ptr ThreadInformation, uint ThreadInformationLength)
        OutputDebugString%(str lpOutputString)
        SetErrorMode(ErrorMode uMode)
        SetUnhandledExceptionFilter(ptr lpTopLevelExceptionFilter)
        AddVectoredExceptionHandler(uint First, ptr Handler)
        RaiseException(hex dwExceptionCode, hex dwExceptionFlags, uint nNumberOfArguments, ptr lpArguments)
        SetLastError(uint dwErrCode)
        FormatMessage%(FormatMessageFlags dwFlags, ptr lpSource, hex dwMessageId, hex dwLanguageId, ptr lpBuffer, uint nSize, ptr Arguments)
        GetEnvironmentVariable%(str lpName, ptr lpBuffer, uint nSize)
        SetEnvironmentVariable%(str lpName, str lpValue)
        ExpandEnvironmentStrings%(str lpSrc, ptr lpDst, uint nSize)
        GetSystemDirectory%(ptr lpBuffer, uint uSize)
        GetWindowsDirectory%(ptr lpBuffer, uint uSize)
        CoInitializeEx(ptr pvReserved, CoInit dwCoInit)
        CoCreateInstance(guid rclsid, ptr pUnkOuter, ClsCtx dwClsContext, guid riid, ptr ppv)
        CryptAcquireContext%(ptr phProv, str szContainer, str szProvider, CryptProvType dwProvType, CryptContextFlags dwFlags)
        CryptCreateHash(handle hProv, AlgId Algid, handle hKey, hex dwFlags, ptr phHash)
        CryptDeriveKey(handle hProv, AlgId Algid, handle hBaseData, hex dwFlags, ptr phKey)
        BCryptOpenAlgorithmProvider(ptr phAlgorithm, wstr pszAlgId, wstr pszImplementation, hex dwFlags)
        RtlInitUnicodeString(ptr DestinationString, wstr SourceString)
        RtlInitAnsiString(ptr DestinationString, astr SourceString)

        lstrcpy%(ptr lpString1, str lpString2)
        lstrcat%(ptr lpString1, str lpString2)
        lstrcmp%(str lpString1, str lpString2)
        lstrcmpi%(str lpString1, str lpString2)
        lstrlen%(str lpString)
        cdecl memcpy(ptr dest, ptr src, size count)
        cdecl memmove(ptr dest, ptr src, size count)
        cdecl memset(ptr dest, int c, size count)
        cdecl memcmp(ptr buf1, ptr buf2, size count)
        cdecl memcpy_s(ptr dest, size destSize, ptr src, size count)
        cdecl memmove_s(ptr dest, size destSize, ptr src, size count)
        cdecl malloc(size size)
        cdecl calloc(size number, size size)
        cdecl realloc(ptr memblock, size size)
        cdecl free(ptr memblock)
        cdecl strlen(astr str)
        cdecl wcslen(wstr str)
        cdecl strcpy(ptr dest, astr src)
        cdecl wcscpy(ptr dest, wstr src)
        cdecl strcpy_s(ptr dest, size destSize, astr src)
        cdecl wcscpy_s(ptr dest, size destSize, wstr src)
        cdecl strcat(ptr dest, astr src)
        cdecl wcscat(ptr dest, wstr src)
        cdecl strcat_s(ptr dest, size destSize, astr src)
        cdecl wcscat_s(ptr dest, size destSize, wstr src)
        cdecl strncpy(ptr dest, astr src, size count)
        cdecl wcsncpy(ptr dest, wstr src, size count)
        cdecl strcmp(astr string1, astr string2)
        cdecl wcscmp(wstr string1, wstr string2)
        cdecl strncmp(astr string1, astr string2, size count)
        cdecl wcsncmp(wstr string1, wstr string2, size count)
        cdecl _stricmp(astr string1, astr string2)
        cdecl _wcsicmp(wstr string1, wstr string2)
        cdecl _strnicmp(astr string1, astr string2, size count)
        cdecl _wcsnicmp(wstr string1, wstr string2, size count)
        cdecl strstr(astr str, astr strSearch)
        cdecl wcsstr(wstr str, wstr strSearch)
        cdecl strchr(astr str, int c)
        cdecl wcschr(wstr str, int c)
        cdecl atoi(astr str)
        cdecl _wtoi(wstr str)
        cdecl strtoul(astr strSource, ptr endptr, int base)
        cdecl wcstoul(wstr strSource, ptr endptr, int base)
        cdecl getenv(astr varname)
        cdecl _wgetenv(wstr varname)
        cdecl fopen(astr filename, astr mode)
        cdecl _wfopen(wstr filename, wstr mode)
        cdecl fopen_s(ptr pFile, astr filename, astr mode)
        cdecl _wfopen_s(ptr pFile, wstr filename, wstr mode)
        cdecl fwrite(ptr buffer, size size, size count, ptr stream)
        cdecl fread(ptr buffer, size size, size count, ptr stream)
        cdecl puts(astr str)
        cdecl _putws(wstr str)
        cdecl printf(afmt format, ...)
        cdecl wprintf(wfmt format, ...)
        cdecl fprintf(ptr stream, afmt format, ...)
        cdecl fwprintf(ptr stream, wfmt format, ...)
        cdecl sprintf(ptr buffer, afmt format, ...)
        cdecl swprintf(ptr buffer, size count, wfmt format, ...)
        cdecl sprintf_s(ptr buffer, size sizeOfBuffer, afmt format, ...)
        cdecl swprintf_s(ptr buffer, size sizeOfBuffer, wfmt format, ...)
        cdecl _snprintf(ptr buffer, size count, afmt format, ...)
        cdecl _snwprintf(ptr buffer, size count, wfmt format, ...)
        cdecl snprintf(ptr buffer, size count, afmt format, ...)
        cdecl _snprintf_s(ptr buffer, size sizeOfBuffer, size count, afmt format, ...)
        cdecl _snwprintf_s(ptr buffer, size sizeOfBuffer, size count, wfmt format, ...)
        cdecl sscanf(astr buffer, afmt format, ...)
        cdecl swscanf(wstr buffer, wfmt format, ...)
        cdecl wsprintfA(ptr buffer, afmt format, ...)
        cdecl wsprintfW(ptr buffer, wfmt format, ...)
        cdecl DbgPrint(afmt Format, ...)
        cdecl DbgPrintEx(uint ComponentId, uint Level, afmt Format, ...)
        cdecl __stdio_common_vsprintf(i64 Options, ptr Buffer, size BufferCount, afmt Format, ptr Locale, ptr ArgList)
        cdecl __stdio_common_vswprintf(i64 Options, ptr Buffer, size BufferCount, wfmt Format, ptr Locale, ptr ArgList)
        cdecl __stdio_common_vfprintf(i64 Options, ptr Stream, afmt Format, ptr Locale, ptr ArgList)
        cdecl __stdio_common_vfwprintf(i64 Options, ptr Stream, wfmt Format, ptr Locale, ptr ArgList)
        cdecl sqrt(double x)
        cdecl pow(double x, double y)
        cdecl floor(double x)
        cdecl ceil(double x)
        cdecl sqrtf(float x)
        cdecl powf(float x, float y)
        """;

    // What APIs return: "returns ENUM|- "meaning": Name Name% ...".
    private const string ReturnTable = """
        returns Win32Error "a Win32 error code": GetLastError RegOpenKey% RegOpenKeyEx% RegCreateKey% RegCreateKeyEx% RegQueryValueEx% RegSetValueEx% RegGetValue% RegSetKeyValue% RegDeleteKey% RegDeleteKeyEx% RegDeleteValue% RegDeleteTree% RegCloseKey RegEnumKeyEx% RegEnumValue% RegQueryInfoKey%
        returns WinsockError "0 or a Winsock error code": WSAGetLastError WSAStartup
        returns WaitResult "a wait result": WaitForSingleObject WaitForSingleObjectEx WaitForMultipleObjects WaitForMultipleObjectsEx SignalObjectAndWait MsgWaitForMultipleObjects MsgWaitForMultipleObjectsEx
        returns HResult "an HRESULT": CoInitialize CoInitializeEx CoCreateInstance CoCreateInstanceEx CoGetClassObject OleInitialize URLDownloadToFile% SHGetFolderPath% SHGetKnownFolderPath DllRegisterServer DllGetClassObject
        returns NtStatus "an NTSTATUS": NtAllocateVirtualMemory NtProtectVirtualMemory NtQueryInformationProcess NtSetInformationThread NtQuerySystemInformation NtCreateFile NtOpenFile NtReadFile NtWriteFile NtClose LdrLoadDll LdrGetProcedureAddress BCryptOpenAlgorithmProvider BCryptGenRandom
        returns - "a handle; INVALID_HANDLE_VALUE (-1) on failure": CreateFile% CreateFile2 CreateNamedPipe% FindFirstFile% FindFirstFileEx% CreateToolhelp32Snapshot CreateMailslot%
        returns - "a handle; NULL on failure": OpenProcess OpenThread CreateThread CreateRemoteThread CreateEvent% CreateMutex% CreateMutexEx% CreateSemaphore% OpenEvent% OpenMutex% CreateFileMapping% OpenFileMapping% OpenSCManager% OpenService% CreateService% InternetOpen% InternetOpenUrl% InternetConnect% HttpOpenRequest% WinHttpOpen WinHttpConnect WinHttpOpenRequest HeapCreate
        returns - "a module handle; NULL on failure": LoadLibrary% LoadLibraryEx% GetModuleHandle%
        returns - "a function address; NULL on failure": GetProcAddress
        returns - "an address; NULL on failure": VirtualAlloc VirtualAllocEx HeapAlloc HeapReAlloc LocalAlloc GlobalAlloc MapViewOfFile malloc calloc realloc
        returns - "nonzero on success, zero on failure (GetLastError)": ReadFile WriteFile CloseHandle DeleteFile% CopyFile% MoveFile% MoveFileEx% CreateDirectory% RemoveDirectory% SetFileAttributes% VirtualProtect VirtualProtectEx VirtualFree VirtualFreeEx WriteProcessMemory ReadProcessMemory HeapFree FreeLibrary CreateProcess% CreateProcessAsUser% TerminateProcess SetThreadContext DeviceIoControl StartService% ControlService CryptAcquireContext% CryptCreateHash CryptDeriveKey InternetReadFile HttpSendRequest% WinHttpSendRequest CheckRemoteDebuggerPresent UnmapViewOfFile
        """;

    private static readonly Lazy<Dictionary<string, ApiReturn>> Returns = new(() =>
    {
        var result = new Dictionary<string, ApiReturn>(StringComparer.Ordinal);
        foreach (var raw in ReturnTable.Split('\n'))
        {
            var line = raw.Trim();
            if (!line.StartsWith("returns ", StringComparison.Ordinal)) continue;
            int open = line.IndexOf('"'), close = line.IndexOf('"', open + 1);
            var enumName = line[8..open].Trim();
            var meaning = new ApiReturn(line[(open + 1)..close], enumName == "-" ? null : Enums[enumName]);
            foreach (var name in line[(line.IndexOf(':', close) + 1)..].Split(' ', StringSplitOptions.RemoveEmptyEntries))
                foreach (var n in name.EndsWith('%') ? [name[..^1] + "A", name[..^1] + "W"] : new[] { name })
                    result[n] = meaning;
        }
        return result;
    });

    /// <summary>What an API returns (its meaning and the enumeration of its values), or null when not in the table.</summary>
    public static ApiReturn? FindReturn(string? name)
    {
        if (string.IsNullOrEmpty(name)) return null;
        var n = BareName(name);
        return Returns.Value.GetValueOrDefault(n) ?? (n.Length > 1 && n[0] == '_' ? Returns.Value.GetValueOrDefault(n[1..]) : null);
    }

    private static readonly Lazy<(Dictionary<string, ApiSignature> Signatures, Dictionary<string, ApiEnum> Enums)> Parsed = new(Parse);

    /// <summary>Every signature by name (A and W forms separate).</summary>
    public static IReadOnlyDictionary<string, ApiSignature> All => Parsed.Value.Signatures;

    /// <summary>The enumerations and flag sets by name.</summary>
    public static IReadOnlyDictionary<string, ApiEnum> Enums => Parsed.Value.Enums;

    /// <summary>
    /// The signature for a callee name: "CreateFileW", "kernel32!CreateFileW", "__imp_CreateFileW", "j_CreateFileW",
    /// "_CreateFileW@28" (x86 stdcall decoration); null when not in the table.
    /// </summary>
    public static ApiSignature? Find(string? name)
    {
        if (string.IsNullOrEmpty(name)) return null;
        var n = BareName(name);
        // x86 cdecl decoration: "_memcpy"
        return All.GetValueOrDefault(n) ?? (n.Length > 1 && n[0] == '_' ? All.GetValueOrDefault(n[1..]) : null);
    }

    /// <summary>The API name without module, import / thunk prefixes and x86 decoration.</summary>
    public static string BareName(string name)
    {
        var n = name;
        int bang = n.LastIndexOf('!');
        if (bang >= 0) n = n[(bang + 1)..];
        if (n.StartsWith("__imp_", StringComparison.Ordinal)) n = n[6..];
        if (n.StartsWith("j_", StringComparison.Ordinal)) n = n[2..];
        if (n.Length > 1 && n[0] == '_' && n.LastIndexOf('@') is var at and > 1 && n[(at + 1)..].All(char.IsAsciiDigit)) n = n[1..at];
        return n;
    }

    private static (Dictionary<string, ApiSignature>, Dictionary<string, ApiEnum>) Parse()
    {
        var enums = new Dictionary<string, ApiEnum>(StringComparer.Ordinal);
        var signatures = new Dictionary<string, ApiSignature>(StringComparer.Ordinal);
        foreach (var raw in Table.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#')) continue;
            if (line.StartsWith("flags ", StringComparison.Ordinal) || line.StartsWith("enum ", StringComparison.Ordinal))
            {
                bool flags = line[0] == 'f';
                int colon = line.IndexOf(':');
                var name = line[(flags ? 6 : 5)..colon].Trim();
                var entries = new List<(string, ulong, ulong)>();
                foreach (var item in line[(colon + 1)..].Split(' ', StringSplitOptions.RemoveEmptyEntries))
                {
                    int eq = item.IndexOf('=');
                    var valueText = item[(eq + 1)..];
                    int slash = valueText.IndexOf('/');
                    ulong value = Number(slash < 0 ? valueText : valueText[..slash]);
                    ulong mask = slash < 0 ? value : Number(valueText[(slash + 1)..]);
                    entries.Add((item[..eq], value, mask));
                }
                enums[name] = new ApiEnum(name, flags, entries);
                continue;
            }
            bool cdecl = line.StartsWith("cdecl ", StringComparison.Ordinal);
            if (cdecl) line = line[6..];
            int open = line.IndexOf('(');
            var fname = line[..open].Trim();
            var paramText = line[(open + 1)..line.LastIndexOf(')')];
            bool expand = fname.EndsWith('%');
            if (expand) fname = fname[..^1];
            foreach (var (suffix, wide) in expand ? new[] { ("A", false), ("W", true) } : [("", false)])
            {
                var ps = new List<ApiParam>();
                bool variadic = false;
                foreach (var p in paramText.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                {
                    if (p == "...") { variadic = true; continue; }
                    int space = p.IndexOf(' ');
                    var type = p[..space];
                    var pname = p[(space + 1)..];
                    ps.Add(TypeOf(type, pname, wide, enums));
                }
                signatures[fname + suffix] = new ApiSignature(fname + suffix, ps, variadic, cdecl);
            }
        }
        return (signatures, enums);
    }

    private static ApiParam TypeOf(string type, string name, bool wide, Dictionary<string, ApiEnum> enums) => type switch
    {
        "int" => new(name, ApiParamType.Int),
        "uint" => new(name, ApiParamType.UInt),
        "hex" => new(name, ApiParamType.Hex),
        "ptr" => new(name, ApiParamType.Pointer),
        "handle" => new(name, ApiParamType.Handle),
        "hmodule" => new(name, ApiParamType.Module),
        "size" => new(name, ApiParamType.Size),
        "bool" => new(name, ApiParamType.Bool),
        "str" => new(name, wide ? ApiParamType.WideString : ApiParamType.AnsiString),
        "fmt" => new(name, wide ? ApiParamType.WideFormat : ApiParamType.AnsiFormat),
        "astr" => new(name, ApiParamType.AnsiString),
        "wstr" => new(name, ApiParamType.WideString),
        "afmt" => new(name, ApiParamType.AnsiFormat),
        "wfmt" => new(name, ApiParamType.WideFormat),
        "procname" => new(name, ApiParamType.ProcName),
        "guid" => new(name, ApiParamType.Guid),
        "float" => new(name, ApiParamType.Float),
        "double" => new(name, ApiParamType.Double),
        "i64" => new(name, ApiParamType.Int64),
        _ => enums.TryGetValue(type, out var e) ? new(name, ApiParamType.Enum, e) : throw new InvalidOperationException($"Unknown type '{type}' in the API table"),
    };

    private static ulong Number(string text) =>
        text.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            ? ulong.Parse(text.AsSpan(2), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture)
            : ulong.Parse(text, CultureInfo.InvariantCulture);

    /// <summary>
    /// Types of the variadic arguments a printf / scanf format asks for (null for "%%" and unknown conversions are
    /// treated as integers); <paramref name="wide"/> picks the default string width of %s.
    /// </summary>
    public static List<ApiParamType> FormatArguments(string format, bool wide, int max = 32)
    {
        var result = new List<ApiParamType>();
        for (int i = 0; i < format.Length && result.Count < max; i++)
        {
            if (format[i] != '%') continue;
            if (++i >= format.Length) break;
            if (format[i] == '%') continue;
            // flags, width, precision ('*' takes an argument)
            while (i < format.Length && "-+ #0'".Contains(format[i])) i++;
            while (i < format.Length && (char.IsAsciiDigit(format[i]) || format[i] is '*' or '.'))
            {
                if (format[i] == '*') result.Add(ApiParamType.Int);
                i++;
            }
            // length modifiers
            var size = new StringBuilder();
            while (i < format.Length && "hlLwIzjt3264".Contains(format[i])) size.Append(format[i++]);
            if (i >= format.Length) break;
            char c = format[i];
            string s = size.ToString();
            result.Add(c switch
            {
                's' => s.Contains('h') ? ApiParamType.AnsiString : s.Contains('l') || s.Contains('w') ? ApiParamType.WideString : wide ? ApiParamType.WideString : ApiParamType.AnsiString,
                'S' => s.Contains('h') ? ApiParamType.AnsiString : s.Contains('l') || s.Contains('w') ? ApiParamType.WideString : wide ? ApiParamType.AnsiString : ApiParamType.WideString,
                'p' or 'n' => ApiParamType.Pointer,
                'f' or 'F' or 'e' or 'E' or 'g' or 'G' or 'a' or 'A' => ApiParamType.Double,
                'x' or 'X' => s.Contains("ll") || s.Contains("I64") ? ApiParamType.Int64 : ApiParamType.Hex,
                _ => s.Contains("ll") || s.Contains("I64") ? ApiParamType.Int64 : ApiParamType.Int,
            });
        }
        return result;
    }
}
