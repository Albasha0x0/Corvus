using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Corvus.Core;

/// <summary>Whether two paths name the same file through links and short names, by file id, else by resolved full path.</summary>
public static class FileIdentity
{
    private static readonly StringComparison PathComparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

    public static bool Same(string a, string b)
    {
        var ra = Resolve(a);
        var rb = Resolve(b);
        if (string.Equals(ra, rb, PathComparison)) return true;
        return Id(ra) is { } ia && Id(rb) is { } ib && ia == ib;
    }

    /// <summary>The full path with a link at the last segment followed to its final target.</summary>
    public static string Resolve(string path)
    {
        var full = Path.GetFullPath(path);
        try { return File.ResolveLinkTarget(full, returnFinalTarget: true)?.FullName ?? full; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return full; }
    }

    /// <summary>(device, file) identity of an existing file, or null when it cannot be read.</summary>
    public static (ulong Device, ulong File)? Id(string path)
    {
        try
        {
            if (OperatingSystem.IsWindows()) return WindowsId(path);
            if ((OperatingSystem.IsLinux() || OperatingSystem.IsMacOS()) && Environment.Is64BitProcess) return PosixId(path);
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException) { }
        return null;
    }

    private static (ulong, ulong)? WindowsId(string path)
    {
        // Attribute access only: works on files other processes hold open without sharing.
        using var handle = CreateFileW(path, 0x80 /* FILE_READ_ATTRIBUTES */, 7 /* share read, write, delete */, IntPtr.Zero, 3 /* OPEN_EXISTING */,
            0x02000000 /* FILE_FLAG_BACKUP_SEMANTICS */, IntPtr.Zero);
        if (handle.IsInvalid || !GetFileInformationByHandle(handle, out var info)) return null;
        return (info.VolumeSerialNumber, ((ulong)info.FileIndexHigh << 32) | info.FileIndexLow);
    }

    private static (ulong, ulong)? PosixId(string path)
    {
        // struct stat on 64-bit Linux and macOS: st_dev at 0 (8 bytes on Linux, 4 on macOS), st_ino at 8 (8 bytes).
        var buffer = new byte[512];
        int result = OperatingSystem.IsMacOS()
            ? RuntimeInformation.ProcessArchitecture == Architecture.X64 ? MacStat64(path, buffer) : Stat(path, buffer)
            : Stat(path, buffer);
        if (result != 0) return null;
        ulong device = OperatingSystem.IsMacOS() ? BitConverter.ToUInt32(buffer, 0) : BitConverter.ToUInt64(buffer, 0);
        return (device, BitConverter.ToUInt64(buffer, 8));
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        // FILETIMEs as 4-byte-aligned halves.
        public uint CreationLow, CreationHigh, AccessLow, AccessHigh, WriteLow, WriteHigh;
        public uint VolumeSerialNumber, FileSizeHigh, FileSizeLow, NumberOfLinks, FileIndexHigh, FileIndexLow;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle file, out ByHandleFileInformation info);

    [DllImport("libc", EntryPoint = "stat", SetLastError = true)]
    private static extern int Stat([MarshalAs(UnmanagedType.LPUTF8Str)] string path, byte[] buffer);

    [DllImport("libc", EntryPoint = "stat$INODE64", SetLastError = true)]
    private static extern int MacStat64([MarshalAs(UnmanagedType.LPUTF8Str)] string path, byte[] buffer);
}
