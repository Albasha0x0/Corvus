using System.Runtime.InteropServices;

namespace Corvus.Core;

/// <summary>Unix file calls File.Move cannot stand in for: it follows a link to a directory, and without overwrite it checks, then renames.</summary>
internal static class Posix
{
    // Linux and macOS.
    private const int EEXIST = 17;

    /// <summary>Renames <paramref name="source"/> over <paramref name="target"/> atomically; a link is moved, not followed.</summary>
    public static void Rename(string source, string target)
    {
        if (rename(source, target) != 0) throw Error($"Could not rename {source} to {target}");
    }

    /// <summary>Hard-links <paramref name="target"/> to <paramref name="source"/>; an existing target throws IOException, false when unsupported.</summary>
    public static bool TryLink(string source, string target)
    {
        if (link(source, target) == 0) return true;
        return Marshal.GetLastPInvokeError() == EEXIST ? throw Error($"{target} exists") : false;
    }

    private static IOException Error(string what) => new($"{what}: {Marshal.GetPInvokeErrorMessage(Marshal.GetLastPInvokeError())}");

    [DllImport("libc", SetLastError = true)]
    private static extern int rename([MarshalAs(UnmanagedType.LPUTF8Str)] string oldPath, [MarshalAs(UnmanagedType.LPUTF8Str)] string newPath);

    [DllImport("libc", SetLastError = true)]
    private static extern int link([MarshalAs(UnmanagedType.LPUTF8Str)] string oldPath, [MarshalAs(UnmanagedType.LPUTF8Str)] string newPath);
}
