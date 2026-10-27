using System.Globalization;
using Corvus.Core;

namespace Corvus.Native.Live;

/// <summary>The Yama <c>ptrace_scope</c> setting, as it limits which processes this server (and its workers) may trace on Linux.</summary>
internal static class PtraceScope
{
    public const string SettingPath = "/proc/sys/kernel/yama/ptrace_scope";

    /// <summary>The setting when it refuses tracing the process (started: from 2 without CAP_SYS_PTRACE, other: from 1, 3: all); null when nothing is refused or there is no Yama.</summary>
    public static int? Refusing(bool started)
    {
        if (!OperatingSystem.IsLinux()) return null;
        int scope;
        try { scope = int.Parse(File.ReadAllText(SettingPath).Trim(), CultureInfo.InvariantCulture); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or FormatException) { return null; }
        bool privileged = Environment.IsPrivilegedProcess;
        return scope >= 3 || (scope == 2 && !privileged) || (scope == 1 && !privileged && !started) ? scope : null;
    }

    /// <summary>access_denied for an operation <paramref name="detail"/> says failed, naming the setting that refused it.</summary>
    public static ToolError Refusal(int scope, string detail) => new(ErrorCode.AccessDenied,
        $"{detail} (ptrace_scope is {scope}: " + scope switch
        {
            1 => "a user may trace only the programs it starts",
            2 => "only a process with CAP_SYS_PTRACE may trace",
            _ => "no process may trace",
        } + ")",
        scope switch
        {
            1 => "run the server as root, or set kernel.yama.ptrace_scope to 0 (at 1, sessions on programs started with action=spawn work)",
            2 => "run the server as root, or set kernel.yama.ptrace_scope to 0 or 1",
            _ => "ptrace_scope 3 holds until the machine restarts",
        });
}
