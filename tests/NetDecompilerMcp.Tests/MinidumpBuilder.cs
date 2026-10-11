using System.Buffers.Binary;
using System.Text;

namespace NetDecompilerMcp.Tests;

/// <summary>Writes synthetic Windows minidumps: system info, modules, threads with contexts, an exception, memory, regions, names.</summary>
internal sealed class MinidumpBuilder
{
    public sealed record Module(ulong Base, uint Size, uint TimeDateStamp, string Path, Guid? PdbGuid = null, uint PdbAge = 1, string PdbPath = "",
        uint VersionMs = 0x00010002, uint VersionLs = 0x00030004);
    public sealed record Thread(uint Id, ulong StackStart, byte[] Context, string? Name = null);
    public sealed record Region(ulong Base, ulong Size, uint Protect, uint State = 0x1000, uint Type = 0x20000);

    public ushort ProcessorArchitecture { get; set; } = 9;
    public List<Module> Modules { get; } = [];
    public List<Thread> Threads { get; } = [];
    public List<(ulong Start, byte[] Data)> Memory { get; } = [];
    public List<Region> Regions { get; } = [];
    public bool FullMemory { get; set; }
    public (uint ThreadId, uint Code, ulong Address, ulong[] Parameters, byte[] Context)? Exception { get; set; }
    public List<(uint Type, byte[] Data)> ExtraStreams { get; } = [];
    public uint? ProcessId { get; set; } = 4242;

    /// <summary>A CONTEXT (x64, 1232 bytes): general registers in unwind order (rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, r8-r15) and rip.</summary>
    public static byte[] ContextX64(ulong rip, ulong rsp, ulong rbp = 0, ulong rax = 0, ulong rcx = 0)
    {
        var c = new byte[0x4D0];
        BinaryPrimitives.WriteUInt32LittleEndian(c.AsSpan(0x30), 0x10001F); // CONTEXT_ALL
        BinaryPrimitives.WriteUInt64LittleEndian(c.AsSpan(0x78), rax);
        BinaryPrimitives.WriteUInt64LittleEndian(c.AsSpan(0x80), rcx);
        BinaryPrimitives.WriteUInt64LittleEndian(c.AsSpan(0x98), rsp);
        BinaryPrimitives.WriteUInt64LittleEndian(c.AsSpan(0xA0), rbp);
        BinaryPrimitives.WriteUInt64LittleEndian(c.AsSpan(0xF8), rip);
        return c;
    }

    /// <summary>An x86 CONTEXT (0xCC bytes) with the control and integer registers.</summary>
    public static byte[] ContextX86(uint eip, uint esp, uint ebp = 0, uint eax = 0, uint ecx = 0)
    {
        var c = new byte[0xCC];
        BinaryPrimitives.WriteUInt32LittleEndian(c, 0x10007); // CONTEXT_i386 | CONTROL | INTEGER | SEGMENTS
        BinaryPrimitives.WriteUInt32LittleEndian(c.AsSpan(0xAC), ecx);
        BinaryPrimitives.WriteUInt32LittleEndian(c.AsSpan(0xB0), eax);
        BinaryPrimitives.WriteUInt32LittleEndian(c.AsSpan(0xB4), ebp);
        BinaryPrimitives.WriteUInt32LittleEndian(c.AsSpan(0xB8), eip);
        BinaryPrimitives.WriteUInt32LittleEndian(c.AsSpan(0xC4), esp);
        return c;
    }

    public byte[] Build()
    {
        var streams = new List<(uint Type, Func<int, byte[]> Data)>();
        var body = new List<byte>();
        // stream data is laid out after the header and the directory; each producer gets its own offset
        streams.Add((7, _ => SystemInfo()));
        if (ProcessId is { } pid) streams.Add((15, _ => Misc(pid)));
        streams.Add((4, at => ModuleList(at)));
        streams.Add((3, at => ThreadList(at)));
        if (Exception is { } e) streams.Add((6, at => ExceptionStream(at, e)));
        if (Regions.Count > 0) streams.Add((16, _ => RegionList()));
        if (Threads.Any(t => t.Name != null)) streams.Add((24, at => ThreadNames(at)));
        foreach (var (type, data) in ExtraStreams) streams.Add((type, _ => data));
        streams.Add((FullMemory ? 9u : 5u, at => FullMemory ? Memory64(at) : MemoryList(at)));

        int directory = 32;
        int cursor = directory + streams.Count * 12;
        var file = new List<byte>(new byte[cursor]);
        var entries = new List<(uint Type, uint Size, uint Rva)>();
        foreach (var (type, producer) in streams)
        {
            var data = producer(cursor);
            entries.Add((type, (uint)_streamSize(data, type), (uint)cursor));
            file.AddRange(data);
            cursor = file.Count;
        }
        var bytes = file.ToArray();
        BinaryPrimitives.WriteUInt32LittleEndian(bytes, 0x504D444D);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(4), 0xA793);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(8), (uint)streams.Count);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(12), (uint)directory);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(20), 0x65000000);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(24), FullMemory ? 0x1806UL : 0x1804UL);
        for (int i = 0; i < entries.Count; i++)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(directory + i * 12), entries[i].Type);
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(directory + i * 12 + 4), entries[i].Size);
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(directory + i * 12 + 8), entries[i].Rva);
        }
        return bytes;
    }

    // Memory streams carry their data after the descriptors; the stream size covers the descriptors only.
    private readonly Dictionary<uint, int> _descriptorSizes = [];
    private int _streamSize(byte[] data, uint type) => _descriptorSizes.TryGetValue(type, out var n) ? n : data.Length;

    private byte[] SystemInfo()
    {
        var b = new byte[56];
        BinaryPrimitives.WriteUInt16LittleEndian(b, ProcessorArchitecture);
        BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(2), 6);
        b[6] = 8;
        b[7] = 1;
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(8), 10);
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(16), 26100);
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(20), 2);
        Encoding.ASCII.GetBytes("GenuineIntel").CopyTo(b, 32);
        return b;
    }

    private static byte[] Misc(uint pid)
    {
        var b = new byte[24];
        BinaryPrimitives.WriteUInt32LittleEndian(b, 24);
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(4), 3);
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(8), pid);
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(12), 0x65000000);
        return b;
    }

    private static byte[] MinidumpString(string s)
    {
        var text = Encoding.Unicode.GetBytes(s);
        var b = new byte[4 + text.Length + 2];
        BinaryPrimitives.WriteUInt32LittleEndian(b, (uint)text.Length);
        text.CopyTo(b, 4);
        return b;
    }

    private byte[] ModuleList(int at)
    {
        int table = 4 + Modules.Count * 108;
        var b = new List<byte>(new byte[table]);
        var arr = new byte[table];
        BinaryPrimitives.WriteUInt32LittleEndian(arr, (uint)Modules.Count);
        for (int i = 0; i < Modules.Count; i++)
        {
            var m = Modules[i];
            int e = 4 + i * 108;
            BinaryPrimitives.WriteUInt64LittleEndian(arr.AsSpan(e), m.Base);
            BinaryPrimitives.WriteUInt32LittleEndian(arr.AsSpan(e + 8), m.Size);
            BinaryPrimitives.WriteUInt32LittleEndian(arr.AsSpan(e + 16), m.TimeDateStamp);
            BinaryPrimitives.WriteUInt32LittleEndian(arr.AsSpan(e + 20), (uint)(at + b.Count));
            b.AddRange(MinidumpString(m.Path));
            BinaryPrimitives.WriteUInt32LittleEndian(arr.AsSpan(e + 24), 0xFEEF04BD);
            BinaryPrimitives.WriteUInt32LittleEndian(arr.AsSpan(e + 32), m.VersionMs);
            BinaryPrimitives.WriteUInt32LittleEndian(arr.AsSpan(e + 36), m.VersionLs);
            if (m.PdbGuid is { } g)
            {
                var cv = new List<byte>();
                cv.AddRange(BitConverter.GetBytes(0x53445352u));
                cv.AddRange(g.ToByteArray());
                cv.AddRange(BitConverter.GetBytes(m.PdbAge));
                cv.AddRange(Encoding.UTF8.GetBytes(m.PdbPath));
                cv.Add(0);
                BinaryPrimitives.WriteUInt32LittleEndian(arr.AsSpan(e + 76), (uint)cv.Count);
                BinaryPrimitives.WriteUInt32LittleEndian(arr.AsSpan(e + 80), (uint)(at + b.Count));
                b.AddRange(cv);
            }
        }
        var result = b.ToArray();
        arr.CopyTo(result, 0);
        _descriptorSizes[4] = table;
        return result;
    }

    private byte[] ThreadList(int at)
    {
        int table = 4 + Threads.Count * 48;
        var result = new List<byte>(new byte[table]);
        var arr = new byte[table];
        BinaryPrimitives.WriteUInt32LittleEndian(arr, (uint)Threads.Count);
        for (int i = 0; i < Threads.Count; i++)
        {
            var t = Threads[i];
            int e = 4 + i * 48;
            BinaryPrimitives.WriteUInt32LittleEndian(arr.AsSpan(e), t.Id);
            BinaryPrimitives.WriteUInt64LittleEndian(arr.AsSpan(e + 16), 0x7FF000000000UL + t.Id * 0x2000UL);
            BinaryPrimitives.WriteUInt64LittleEndian(arr.AsSpan(e + 24), t.StackStart);
            var stack = Memory.FirstOrDefault(m => m.Start == t.StackStart);
            BinaryPrimitives.WriteUInt32LittleEndian(arr.AsSpan(e + 32), (uint)(stack.Data?.Length ?? 0));
            // the stack memory itself goes in the memory list; the descriptor's RVA is patched in when memory is laid out
            BinaryPrimitives.WriteUInt32LittleEndian(arr.AsSpan(e + 40), (uint)t.Context.Length);
            BinaryPrimitives.WriteUInt32LittleEndian(arr.AsSpan(e + 44), (uint)(at + result.Count));
            result.AddRange(t.Context);
        }
        var bytes = result.ToArray();
        arr.CopyTo(bytes, 0);
        _descriptorSizes[3] = table;
        return bytes;
    }

    private static byte[] ExceptionStream(int at, (uint ThreadId, uint Code, ulong Address, ulong[] Parameters, byte[] Context) e)
    {
        var b = new byte[168 + e.Context.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(b, e.ThreadId);
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(8), e.Code);
        BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(24), e.Address);
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(32), (uint)e.Parameters.Length);
        for (int i = 0; i < e.Parameters.Length; i++) BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(40 + i * 8), e.Parameters[i]);
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(160), (uint)e.Context.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(164), (uint)(at + 168));
        e.Context.CopyTo(b, 168);
        return b;
    }

    private byte[] RegionList()
    {
        var b = new byte[16 + Regions.Count * 48];
        BinaryPrimitives.WriteUInt32LittleEndian(b, 16);
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(4), 48);
        BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(8), (ulong)Regions.Count);
        for (int i = 0; i < Regions.Count; i++)
        {
            var r = Regions[i];
            int e = 16 + i * 48;
            BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(e), r.Base);
            BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(e + 8), r.Base);
            BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(e + 16), r.Protect);
            BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(e + 24), r.Size);
            BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(e + 32), r.State);
            BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(e + 36), r.Protect);
            BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(e + 40), r.Type);
        }
        return b;
    }

    private byte[] ThreadNames(int at)
    {
        var named = Threads.Where(t => t.Name != null).ToList();
        int table = 4 + named.Count * 12;
        var result = new List<byte>(new byte[table]);
        var arr = new byte[table];
        BinaryPrimitives.WriteUInt32LittleEndian(arr, (uint)named.Count);
        for (int i = 0; i < named.Count; i++)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(arr.AsSpan(4 + i * 12), named[i].Id);
            BinaryPrimitives.WriteUInt64LittleEndian(arr.AsSpan(8 + i * 12), (ulong)(at + result.Count));
            result.AddRange(MinidumpString(named[i].Name!));
        }
        var bytes = result.ToArray();
        arr.CopyTo(bytes, 0);
        _descriptorSizes[24] = table;
        return bytes;
    }

    private byte[] MemoryList(int at)
    {
        int table = 4 + Memory.Count * 16;
        var result = new List<byte>(new byte[table]);
        var arr = new byte[table];
        BinaryPrimitives.WriteUInt32LittleEndian(arr, (uint)Memory.Count);
        for (int i = 0; i < Memory.Count; i++)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(arr.AsSpan(4 + i * 16), Memory[i].Start);
            BinaryPrimitives.WriteUInt32LittleEndian(arr.AsSpan(12 + i * 16), (uint)Memory[i].Data.Length);
            BinaryPrimitives.WriteUInt32LittleEndian(arr.AsSpan(16 + i * 16), (uint)(at + result.Count));
            result.AddRange(Memory[i].Data);
        }
        var bytes = result.ToArray();
        arr.CopyTo(bytes, 0);
        _descriptorSizes[5] = table;
        return bytes;
    }

    private byte[] Memory64(int at)
    {
        int table = 16 + Memory.Count * 16;
        var result = new List<byte>(new byte[table]);
        var arr = new byte[table];
        BinaryPrimitives.WriteUInt64LittleEndian(arr, (ulong)Memory.Count);
        BinaryPrimitives.WriteUInt64LittleEndian(arr.AsSpan(8), (ulong)(at + table));
        for (int i = 0; i < Memory.Count; i++)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(arr.AsSpan(16 + i * 16), Memory[i].Start);
            BinaryPrimitives.WriteUInt64LittleEndian(arr.AsSpan(24 + i * 16), (ulong)Memory[i].Data.Length);
            result.AddRange(Memory[i].Data);
        }
        var bytes = result.ToArray();
        arr.CopyTo(bytes, 0);
        _descriptorSizes[9] = table;
        return bytes;
    }
}
