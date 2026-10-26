using System.Buffers.Binary;
using System.Text;

namespace Corvus.Tests;

/// <summary>
/// Builds Process Monitor backing files (format 9, 64-bit): a header, events with stack frames and the detail structure
/// of their operation, the event offsets, a process table, a string table, an icon table, and host and port names.
/// </summary>
internal static class ProcmonSamples
{
    public static readonly DateTime Start = new(2026, 3, 4, 5, 6, 7, DateTimeKind.Utc);

    /// <summary>One process of the table; events name it by its position, written as an index from 1 (0 is no process).</summary>
    public sealed record Proc(int Pid, int ParentPid, string Name, string ImagePath, string CommandLine, string User = @"BUILD\builder");

    /// <summary>One event: class and operation numbers, the process index, thread, result status, and the detail bytes.</summary>
    public sealed record Ev(int Process, int Thread, int Class, int Operation, uint Result, byte[] Detail, int Frames = 2, long Duration = 1234);

    public static readonly IReadOnlyList<Proc> Processes =
    [
        new(4100, 900, "builder.exe", @"C:\work\builder.exe", @"builder.exe --all"),
        new(4200, 4100, "worker.exe", @"C:\work\worker.exe", @"worker.exe /job 7"),
    ];

    /// <summary>A host name for 192.168.1.10 and a port name for TCP 443.</summary>
    public static readonly byte[] NamedHost = [192, 168, 1, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    /// <summary>A detail string's info word followed later by its characters: UTF-16, or ASCII with bit 15 set.</summary>
    private static (ushort Info, byte[] Bytes) Str(string s, bool ascii = false) =>
        ascii ? ((ushort)(s.Length | 0x8000), Encoding.ASCII.GetBytes(s)) : ((ushort)s.Length, Encoding.Unicode.GetBytes(s));

    public static byte[] ProcessCreate(int pid, string path, string commandLine)
    {
        var (pi, pb) = Str(path);
        var (ci, cb) = Str(commandLine);
        var d = new Detail();
        d.U32(0); d.U32((uint)pid); d.Zero(0x24); d.U8(0); d.U8(0); d.U16(pi); d.U16(ci); d.Zero(2); d.Bytes(pb); d.Bytes(cb);
        return d.ToArray();
    }

    public static byte[] LoadImage(ulong imageBase, uint size, string path)
    {
        var (i, b) = Str(path);
        var d = new Detail();
        d.U64(imageBase); d.U32(size); d.U16(i); d.Zero(2); d.Bytes(b);
        return d.ToArray();
    }

    public static byte[] ThreadCreate(int tid)
    {
        var d = new Detail();
        d.U32((uint)tid);
        return d.ToArray();
    }

    public static byte[] RegOpenKey(string path, bool ascii = false)
    {
        var (i, b) = Str(path, ascii);
        var d = new Detail();
        d.U16(i); d.Zero(2); d.U32(0x20019); d.Bytes(b);
        return d.ToArray();
    }

    public static byte[] RegQueryValue(string path)
    {
        var (i, b) = Str(path);
        var d = new Detail();
        d.U16(i); d.Zero(2); d.U32(528); d.U32(2); d.Bytes(b);
        return d.ToArray();
    }

    /// <summary>A file system detail: sub-operation, the fixed block (five pointers and 0x14 bytes), the path, then <paramref name="after"/>.</summary>
    public static byte[] File(string path, int sub = 0, byte[]? fixedBlock = null, byte[]? after = null)
    {
        var (i, b) = Str(path);
        var d = new Detail();
        d.U8((byte)sub); d.Zero(3);
        var block = new byte[8 * 5 + 0x14];
        fixedBlock?.CopyTo(block, 0);
        d.Bytes(block);
        d.U16(i); d.Zero(2); d.Bytes(b);
        if (after != null) d.Bytes(after);
        return d.ToArray();
    }

    /// <summary>A QueryDirectory detail: the directory, then its filter.</summary>
    public static byte[] QueryDirectory(string directory, string filter)
    {
        var (i, b) = Str(filter);
        var after = new Detail();
        after.U16(i); after.Bytes(b);
        var block = new byte[8 * 5 + 0x14];
        // FileInformationClass sits after 0x10 bytes, two pointers' padding and four more bytes: FileBothDirectoryInformation.
        BinaryPrimitives.WriteUInt32LittleEndian(block.AsSpan(0x10 + 4 + 4 + 4), 3);
        return File(directory, 1, block, after.ToArray());
    }

    /// <summary>A network detail; the values follow as name/value pairs.</summary>
    public static byte[] Network(bool tcp, byte[] source, int sourcePort, byte[] target, int targetPort, bool v4, uint length, params string[] pairs)
    {
        var d = new Detail();
        d.U16((ushort)((v4 ? 3 : 0) | (tcp ? 4 : 0))); d.Zero(2); d.U32(length); d.Bytes(source); d.Bytes(target); d.U16((ushort)sourcePort); d.U16((ushort)targetPort);
        foreach (var p in pairs) { d.Bytes(Encoding.Unicode.GetBytes(p)); d.U16(0); }
        d.U16(0);
        return d.ToArray();
    }

    /// <summary>The backing file: events in order, the first at <see cref="Start"/> and each 10 ms after the one before.</summary>
    public static byte[] Log(IReadOnlyList<Ev> events, string computer = "BUILD-HOST")
    {
        var f = new Detail();
        f.Zero(0x3A8);
        long eventsAt = f.Length;
        var offsets = new List<long>();
        for (int n = 0; n < events.Count; n++)
        {
            var e = events[n];
            offsets.Add(f.Length);
            f.U32((uint)e.Process + 1); f.U32((uint)e.Thread); f.U32((uint)e.Class); f.U16((ushort)e.Operation); f.Zero(6);
            f.U64((ulong)e.Duration); f.U64((ulong)Start.AddMilliseconds(10 * n).ToFileTimeUtc()); f.U32(e.Result);
            f.U16((ushort)e.Frames); f.U16(0); f.U32((uint)e.Detail.Length); f.U32(0);
            for (int i = 0; i < e.Frames; i++) f.U64(0x7FF600001000UL + (ulong)i * 0x10);
            f.Bytes(e.Detail);
        }
        long offsetsAt = f.Length;
        foreach (var o in offsets) { f.U32((uint)o); f.U8(0); }

        var strings = new List<string> { "" };
        int S(string s) { int i = strings.IndexOf(s); if (i < 0) { strings.Add(s); i = strings.Count - 1; } return i; }
        var records = new List<byte[]>();
        for (int i = 0; i < Processes.Count; i++)
        {
            var p = Processes[i];
            var r = new Detail();
            int parent = Processes.ToList().FindIndex(q => q.Pid == p.ParentPid);
            r.U32((uint)i + 1); r.U32((uint)p.Pid); r.U32((uint)p.ParentPid); r.U32((uint)(parent + 1)); r.U64(0x3E7); r.U32(1); r.U32(0);
            r.U64((ulong)Start.AddSeconds(-30 + i).ToFileTimeUtc()); r.U64(0); r.U32(0); r.U32(1);
            foreach (var s in new[] { "High", p.User, p.Name, p.ImagePath, p.CommandLine, "Sample Company", "1.0.0.0", "Sample program" }) r.U32((uint)S(s));
            // Icon indexes, then a pointer-sized field Process Monitor requires to be 1, then one module.
            r.U32(1); r.U32(2); r.U64(1); r.U32(1);
            r.U64(0); r.U64(0x7FF600000000UL); r.U32(0x20000); r.U32((uint)S(p.ImagePath)); r.U32((uint)S("1.0.0.0")); r.U32((uint)S("Sample Company"));
            r.U32((uint)S("Sample program")); r.U32(0x60000000); r.Zero(0x18);
            records.Add(r.ToArray());
        }
        long processesAt = f.Length;
        int processHeader = 4 + records.Count * 8;
        f.U32((uint)records.Count);
        for (int i = 0; i < records.Count; i++) f.U32((uint)i + 1);
        int running = processHeader;
        foreach (var r in records) { f.U32((uint)running); running += r.Length; }
        foreach (var r in records) f.Bytes(r);

        long stringsAt = f.Length;
        f.U32((uint)strings.Count);
        running = 4 + strings.Count * 4;
        var encoded = strings.Select(s => Encoding.Unicode.GetBytes(s + "\0")).ToList();
        foreach (var e in encoded) { f.U32((uint)running); running += 4 + e.Length; }
        foreach (var e in encoded) { f.U32((uint)e.Length); f.Bytes(e); }

        // Icons: an empty entry, then blank 16 and 32 pixel images (a 32-bit DIB of double height and its AND mask).
        long iconsAt = f.Length;
        var icons = new List<byte[]> { new byte[8] };
        foreach (int px in new[] { 16, 32 })
        {
            var icon = new Detail();
            int size = 40 + px * px * 4 + px * (px / 8 + 3) / 4 * 4;
            icon.U32((uint)px); icon.U32((uint)size);
            icon.U32(40); icon.U32((uint)px); icon.U32((uint)(px * 2)); icon.U16(1); icon.U16(32); icon.Zero(size - 16);
            icons.Add(icon.ToArray());
        }
        f.U32((uint)icons.Count);
        running = 4 + icons.Count * 4;
        foreach (var icon in icons) { f.U32((uint)running); running += icon.Length; }
        foreach (var icon in icons) f.Bytes(icon);
        long hostsAt = f.Length;
        f.U32(1); f.Bytes(NamedHost); var host = Encoding.Unicode.GetBytes("files.build.example\0"); f.U32((uint)host.Length); f.Bytes(host);
        f.U32(1); f.U16(443); f.U16(1); var port = Encoding.Unicode.GetBytes("https\0"); f.U32((uint)port.Length); f.Bytes(port);

        var b = f.ToArray();
        "PML_"u8.CopyTo(b);
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(4), 9);
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(8), 1);
        Encoding.Unicode.GetBytes(computer).CopyTo(b, 0xC);
        Encoding.Unicode.GetBytes(@"C:\Windows").CopyTo(b, 0x2C);
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(0x234), (uint)events.Count);
        BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(0x238), (ulong)events.Count);
        BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(0x240), (ulong)eventsAt);
        BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(0x248), (ulong)offsetsAt);
        BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(0x250), (ulong)processesAt);
        BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(0x258), (ulong)stringsAt);
        BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(0x260), (ulong)iconsAt);
        BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(0x268), 0x7FFFFFFEFFFF);
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(0x270), 284);
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(0x274), 10);
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(0x27C), 26100);
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(0x280), 2);
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(0x38C), 8);
        BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(0x390), 16UL << 30);
        BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(0x398), 0x3A8);
        BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(0x3A0), (ulong)hostsAt);
        return b;
    }

    private sealed class Detail
    {
        private readonly MemoryStream _s = new();
        public long Length => _s.Length;
        public void U8(byte v) => _s.WriteByte(v);
        public void U16(ushort v) { Span<byte> b = stackalloc byte[2]; BinaryPrimitives.WriteUInt16LittleEndian(b, v); _s.Write(b); }
        public void U32(uint v) { Span<byte> b = stackalloc byte[4]; BinaryPrimitives.WriteUInt32LittleEndian(b, v); _s.Write(b); }
        public void U64(ulong v) { Span<byte> b = stackalloc byte[8]; BinaryPrimitives.WriteUInt64LittleEndian(b, v); _s.Write(b); }
        public void Zero(int n) => _s.Write(new byte[n]);
        public void Bytes(ReadOnlySpan<byte> b) => _s.Write(b);
        public byte[] ToArray() => _s.ToArray();
    }
}
