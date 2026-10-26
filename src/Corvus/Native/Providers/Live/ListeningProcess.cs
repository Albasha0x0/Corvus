using System.Buffers.Binary;
using System.Globalization;
using System.Runtime.InteropServices;

namespace Corvus.Native.Providers.Live;

/// <summary>The process that listens on a local TCP port, for endpoints whose protocol names no process (JDWP).</summary>
public static class ListeningProcess
{
    /// <summary>The id of the process listening on <paramref name="port"/> (IPv4 or IPv6); null when none is found or the OS table cannot be read (macOS).</summary>
    public static int? Of(int port)
    {
        try
        {
            if (OperatingSystem.IsWindows()) return Windows(port, 2) ?? Windows(port, 23);
            if (OperatingSystem.IsLinux()) return Linux(port);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or FormatException) { }
        return null;
    }

    // TCP_TABLE_OWNER_PID_LISTENER rows: MIB_TCPROW_OWNER_PID (24 bytes) or MIB_TCP6ROW_OWNER_PID (56 bytes).
    private static int? Windows(int port, int family)
    {
        int size = 0;
        _ = GetExtendedTcpTable(IntPtr.Zero, ref size, false, family, 3, 0);
        for (int attempt = 0; attempt < 3 && size > 0; attempt++)
        {
            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                var status = GetExtendedTcpTable(buffer, ref size, false, family, 3, 0);
                // ERROR_INSUFFICIENT_BUFFER: the table grew between the calls.
                if (status == 122) continue;
                if (status != 0) return null;
                int rows = Marshal.ReadInt32(buffer), rowSize = family == 2 ? 24 : 56, portAt = family == 2 ? 8 : 20, pidAt = family == 2 ? 20 : 52;
                for (int i = 0; i < rows; i++)
                {
                    var row = buffer + 4 + i * rowSize;
                    // The port is in network byte order in the low 16 bits.
                    if (BinaryPrimitives.ReverseEndianness((ushort)Marshal.ReadInt32(row, portAt)) == port) return Marshal.ReadInt32(row, pidAt);
                }
                return null;
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
        return null;
    }

    // A listening socket's inode in /proc/net/tcp{,6} (state 0A), then the process holding a descriptor to it.
    private static int? Linux(int port)
    {
        var inodes = new HashSet<string>(StringComparer.Ordinal);
        foreach (var table in new[] { "/proc/net/tcp", "/proc/net/tcp6" })
        {
            if (!File.Exists(table)) continue;
            foreach (var line in File.ReadLines(table).Skip(1))
            {
                var f = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (f.Length > 9 && f[3] == "0A" && int.Parse(f[1][(f[1].LastIndexOf(':') + 1)..], NumberStyles.HexNumber, CultureInfo.InvariantCulture) == port)
                    inodes.Add($"socket:[{f[9]}]");
            }
        }
        if (inodes.Count == 0) return null;
        foreach (var dir in Directory.EnumerateDirectories("/proc"))
        {
            if (!int.TryParse(Path.GetFileName(dir), NumberStyles.None, CultureInfo.InvariantCulture, out var pid)) continue;
            try
            {
                foreach (var fd in Directory.EnumerateFiles(Path.Combine(dir, "fd")))
                    if (new FileInfo(fd).LinkTarget is { } target && inodes.Contains(target)) return pid;
            }
            // Another user's process, or one that exited meanwhile.
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
        }
        return null;
    }

    [DllImport("iphlpapi.dll", SetLastError = false)]
    private static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool order, int family, int tableClass, uint reserved);
}
