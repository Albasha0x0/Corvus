using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Corvus.Native.Providers;

/// <summary>Windows restrictions for a child that reads untrusted files: a restricted token at low integrity, process mitigation policies, low-labelled scratch folders.</summary>
internal static class WindowsSandbox
{
    /// <summary>Most processes the child's job holds: the worker plus the helper tools it runs side by side.</summary>
    internal const uint ActiveProcessLimit = 16;

    internal const uint JobActiveProcessLimit = 0x8;
    internal const int JobObjectBasicUiRestrictions = 4;

    // All eight JOB_OBJECT_UILIMIT_* flags: handles, clipboard, system parameters, display settings, atoms, desktops, exit.
    internal const uint JobUiLimitAll = 0xFF;

    internal static readonly IntPtr ProcThreadAttributeMitigationPolicy = 0x20007;

    private const ulong StrictHandleChecks = 1UL << 24;
    private const ulong ExtensionPointDisable = 1UL << 32;
    private const ulong ImageLoadNoRemote = 1UL << 52;
    private const ulong ImageLoadNoLowLabel = 1UL << 56;

    /// <summary>The PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY value: extension points off, strict handle checks, no remote or low-label images, all always on.</summary>
    internal const ulong MitigationPolicy = StrictHandleChecks | ExtensionPointDisable | ImageLoadNoRemote | ImageLoadNoLowLabel;

    private const uint DisableMaxPrivilege = 0x1;
    private const int TokenIntegrityLevel = 25;
    private const uint SeGroupIntegrity = 0x20;
    private const string LowIntegritySid = "S-1-16-4096";

    /// <summary>A primary token of this process with every privilege removed, at low integrity; the caller disposes it.</summary>
    internal static SafeFileHandle CreateLowToken()
    {
        if (!OpenProcessToken(GetCurrentProcess(), 0x1 | 0x2 | 0x8 | 0x80, out var own)) throw Failure("OpenProcessToken");
        using (own)
        {
            if (!CreateRestrictedToken(own, DisableMaxPrivilege, 0, IntPtr.Zero, 0, IntPtr.Zero, 0, IntPtr.Zero, out var token)) throw Failure("CreateRestrictedToken");
            var sid = IntPtr.Zero;
            var label = IntPtr.Zero;
            try
            {
                if (!ConvertStringSidToSidW(LowIntegritySid, out sid)) throw Failure("ConvertStringSidToSid");
                // TOKEN_MANDATORY_LABEL: the SID pointer and its attributes; the call also counts the SID's length.
                var size = IntPtr.Size * 2;
                label = Marshal.AllocHGlobal(size);
                Marshal.WriteIntPtr(label, 0, sid);
                Marshal.WriteInt32(label, IntPtr.Size, (int)SeGroupIntegrity);
                if (!SetTokenInformation(token, TokenIntegrityLevel, label, (uint)(size + GetLengthSid(sid)))) throw Failure("SetTokenInformation");
                return token;
            }
            catch
            {
                token.Dispose();
                throw;
            }
            finally
            {
                if (label != IntPtr.Zero) Marshal.FreeHGlobal(label);
                if (sid != IntPtr.Zero) LocalFree(sid);
            }
        }
    }

    /// <summary>Marks <paramref name="path"/> and what it will hold as low integrity, so a low-integrity process can write there; throws Win32Exception when the label cannot be set.</summary>
    internal static void LabelLow(string path)
    {
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW("S:(ML;OICI;NW;;;LW)", 1, out var descriptor, out _)) throw Failure("ConvertStringSecurityDescriptor");
        try
        {
            if (!GetSecurityDescriptorSacl(descriptor, out var present, out var sacl, out _) || !present) throw Failure("GetSecurityDescriptorSacl");
            var error = SetNamedSecurityInfoW(path, 1, 0x10, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, sacl);
            if (error != 0) throw new Win32Exception(error, $"Setting the low integrity label failed for {path}");
        }
        finally { LocalFree(descriptor); }
    }

    /// <summary>The folder a sandboxed child uses as TEMP: private to this account and labelled low; created when missing.</summary>
    internal static string Scratch()
    {
        var path = PrivateFolder.Create(PrivateFolder.Temp("sandbox"));
        if (Labelled.TryAdd(path, true)) LabelLow(path);
        return path;
    }

    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, bool> Labelled = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>The policies of this process that <see cref="MitigationPolicy"/> sets, read with GetProcessMitigationPolicy.</summary>
    internal static (bool StrictHandleChecks, bool ExtensionPointsDisabled, bool NoRemoteImages, bool NoLowLabelImages) ReadPolicies()
    {
        var strict = ReadPolicy(3);
        var extension = ReadPolicy(6);
        var image = ReadPolicy(10);
        return ((strict & 0x1) != 0, (extension & 0x1) != 0, (image & 0x1) != 0, (image & 0x2) != 0);
    }

    private static uint ReadPolicy(int policy)
    {
        var buffer = Marshal.AllocHGlobal(8);
        try
        {
            Marshal.WriteInt64(buffer, 0);
            if (!GetProcessMitigationPolicy(GetCurrentProcess(), policy, buffer, 4)) throw Failure("GetProcessMitigationPolicy");
            return (uint)Marshal.ReadInt32(buffer);
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    /// <summary>The integrity level of this process's token as a RID: 4096 low, 8192 medium.</summary>
    internal static int IntegrityRid()
    {
        if (!OpenProcessToken(GetCurrentProcess(), 0x8, out var token)) throw Failure("OpenProcessToken");
        using (token)
        {
            GetTokenInformation(token, TokenIntegrityLevel, IntPtr.Zero, 0, out var length);
            var buffer = Marshal.AllocHGlobal((int)length);
            try
            {
                if (!GetTokenInformation(token, TokenIntegrityLevel, buffer, length, out _)) throw Failure("GetTokenInformation");
                var sid = Marshal.ReadIntPtr(buffer);
                var count = Marshal.ReadByte(sid, 1);
                return Marshal.ReadInt32(sid, 8 + 4 * (count - 1));
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
    }

    private static Win32Exception Failure(string call) => new(Marshal.GetLastWin32Error(), $"{call} failed");

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetProcessMitigationPolicy(IntPtr process, int policy, IntPtr buffer, nuint length);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr process, uint access, out SafeFileHandle token);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CreateRestrictedToken(SafeFileHandle existing, uint flags, uint disableCount, IntPtr disable, uint deleteCount, IntPtr delete,
        uint restrictCount, IntPtr restrict, out SafeFileHandle token);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool SetTokenInformation(SafeFileHandle token, int infoClass, IntPtr info, uint length);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(SafeFileHandle token, int infoClass, IntPtr info, uint length, out uint returned);

    [DllImport("advapi32.dll")]
    private static extern uint GetLengthSid(IntPtr sid);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool ConvertStringSidToSidW(string sid, out IntPtr result);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string text, uint revision, out IntPtr descriptor, out uint size);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetSecurityDescriptorSacl(IntPtr descriptor, out bool present, out IntPtr sacl, out bool defaulted);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int SetNamedSecurityInfoW(string path, int objectType, uint information, IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern bool CreateProcessAsUserW(SafeFileHandle token, string application, char[] commandLine, IntPtr processAttributes, IntPtr threadAttributes,
        bool inheritHandles, uint flags, string environment, string? currentDirectory, ref WindowsJob.STARTUPINFOEX startupInfo, out WindowsJob.PROCESS_INFORMATION info);
}
