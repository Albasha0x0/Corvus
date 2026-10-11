using System.Runtime.InteropServices;

namespace Corvus.Core;

/// <summary>Unix file calls File.Move cannot stand in for: it follows a link to a directory.</summary>
internal static class Posix
{
    /// <summary>Renames <paramref name="source"/> over <paramref name="target"/> atomically; a link is moved, not followed.</summary>
    public static void Rename(string source, string target)
    {
        if (rename(source, target) != 0) throw Error($"Could not rename {source} to {target}");
    }

    private static IOException Error(string what) => new($"{what}: {Marshal.GetPInvokeErrorMessage(Marshal.GetLastPInvokeError())}");

    [DllImport("libc", SetLastError = true)]
    private static extern int rename([MarshalAs(UnmanagedType.LPUTF8Str)] string oldPath, [MarshalAs(UnmanagedType.LPUTF8Str)] string newPath);
}
