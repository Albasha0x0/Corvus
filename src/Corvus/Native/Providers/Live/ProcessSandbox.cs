using System.Runtime.InteropServices;
using Corvus.Core;
using Corvus.Native.Live;

namespace Corvus.Native.Providers.Live;

/// <summary>The sandbox a Windows process runs in, read from its token, as it keeps a session's agent out of the process.</summary>
internal static class ProcessSandbox
{
    private const uint TOKEN_QUERY = 0x0008;
    private const int TokenIntegrityLevel = 25, TokenIsAppContainer = 29;
    private const int SECURITY_MANDATORY_MEDIUM_RID = 0x2000;

    /// <summary>What sandboxes <paramref name="processId"/> ("a restricted token, low integrity"), or null when nothing does or it cannot be read.</summary>
    public static string? Describe(int processId)
    {
        if (!OperatingSystem.IsWindows()) return null;
        using var process = LiveNative.OpenProcess(LiveNative.PROCESS_QUERY_LIMITED_INFORMATION, false, processId);
        if (process.IsInvalid || !OpenProcessToken(process.DangerousGetHandle(), TOKEN_QUERY, out var token)) return null;
        try
        {
            var parts = new List<string>();
            if (IsTokenRestricted(token)) parts.Add("a restricted token");
            if (GetTokenInformation(token, TokenIsAppContainer, out int appContainer, sizeof(int), out _) && appContainer != 0) parts.Add("an AppContainer");
            var label = Marshal.AllocHGlobal(64);
            try
            {
                if (GetTokenInformation(token, TokenIntegrityLevel, label, 64, out _))
                {
                    // TOKEN_MANDATORY_LABEL: a SID pointer, then the SID; the integrity level is its last subauthority
                    var sid = Marshal.ReadIntPtr(label);
                    int rid = Marshal.ReadInt32(sid, 8 + 4 * (Marshal.ReadByte(sid, 1) - 1));
                    if (rid < SECURITY_MANDATORY_MEDIUM_RID) parts.Add(rid == 0 ? "untrusted integrity" : "low integrity");
                }
            }
            finally { Marshal.FreeHGlobal(label); }
            return parts.Count == 0 ? null : string.Join(", ", parts);
        }
        finally { LiveNative.CloseHandle(token); }
    }

    /// <summary>access_denied for an attach <paramref name="detail"/> says failed, naming the sandbox that refused it.</summary>
    public static ToolError Refusal(string sandbox, string detail) => new(ErrorCode.AccessDenied,
        $"{detail} (the process runs sandboxed: {sandbox}, which kept the session's agent out)",
        "start the program with its sandbox off: Chromium and Electron programs take --no-sandbox, or --disable-gpu-sandbox for the GPU process alone");

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(nint process, uint access, out nint token);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool IsTokenRestricted(nint token);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(nint token, int infoClass, out int info, int length, out int returned);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(nint token, int infoClass, nint info, int length, out int returned);
}
