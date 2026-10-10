using System.Buffers.Binary;
using System.Text;

namespace NetDecompilerMcp.Tests;

/// <summary>Builds MSF 7.0 files from streams, laid out like the linker does (superblock, two free page map blocks, data, directory, block map).</summary>
internal sealed class MsfBuilder
{
    public uint BlockSize { get; init; } = 512;
    public List<byte[]> Streams { get; } = [];

    /// <summary>Called on the finished file before it is returned (to corrupt it in place).</summary>
    public byte[] Build(Action<byte[], Layout>? tamper = null)
    {
        var blocks = new List<byte[]> { new byte[BlockSize], new byte[BlockSize], new byte[BlockSize] };
        var pages = new List<List<uint>>();
        foreach (var s in Streams)
        {
            var list = new List<uint>();
            for (int at = 0; at < s.Length; at += (int)BlockSize)
            {
                var b = new byte[BlockSize];
                s.AsSpan(at, Math.Min((int)BlockSize, s.Length - at)).CopyTo(b);
                list.Add((uint)blocks.Count);
                blocks.Add(b);
            }
            pages.Add(list);
        }
        var dir = new List<byte>();
        void U32(List<byte> l, uint v) { var b = new byte[4]; BinaryPrimitives.WriteUInt32LittleEndian(b, v); l.AddRange(b); }
        U32(dir, (uint)Streams.Count);
        foreach (var s in Streams) U32(dir, (uint)s.Length);
        foreach (var l in pages) foreach (var p in l) U32(dir, p);
        var dirBytes = dir.ToArray();
        var dirPages = new List<uint>();
        for (int at = 0; at < dirBytes.Length; at += (int)BlockSize)
        {
            var b = new byte[BlockSize];
            dirBytes.AsSpan(at, Math.Min((int)BlockSize, dirBytes.Length - at)).CopyTo(b);
            dirPages.Add((uint)blocks.Count);
            blocks.Add(b);
        }
        uint mapBlock = (uint)blocks.Count;
        var map = new byte[BlockSize];
        for (int i = 0; i < dirPages.Count; i++) BinaryPrimitives.WriteUInt32LittleEndian(map.AsSpan(i * 4), dirPages[i]);
        blocks.Add(map);

        var sb = blocks[0];
        "Microsoft C/C++ MSF 7.00\r\n\u001aDS\0\0\0"u8.CopyTo(sb);
        BinaryPrimitives.WriteUInt32LittleEndian(sb.AsSpan(32), BlockSize);
        BinaryPrimitives.WriteUInt32LittleEndian(sb.AsSpan(36), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(sb.AsSpan(40), (uint)blocks.Count);
        BinaryPrimitives.WriteUInt32LittleEndian(sb.AsSpan(44), (uint)dirBytes.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(sb.AsSpan(52), mapBlock);
        var file = blocks.SelectMany(b => b).ToArray();
        tamper?.Invoke(file, new Layout(BlockSize, mapBlock, dirPages, pages));
        return file;
    }

    public sealed record Layout(uint BlockSize, uint MapBlock, List<uint> DirectoryPages, List<List<uint>> StreamPages);
}

/// <summary>Builds a small PDB: info stream, DBI (one or more modules, section headers, optional OMAP), symbol records and module streams.</summary>
internal sealed class PdbBuilder
{
    public Guid Guid { get; init; } = new("11223344-5566-7788-99aa-bbccddeeff00");
    public uint Age { get; init; } = 3;
    public List<(string Name, uint Va, uint Size)> Sections { get; init; } = [(".text", 0x1000, 0x1000), (".data", 0x3000, 0x200)];
    /// <summary>Original sections and OMAP-from-source entries; when set, symbols address the original layout.</summary>
    public List<(string Name, uint Va, uint Size)>? OriginalSections { get; init; }
    public List<(uint From, uint To)>? OmapFromSource { get; init; }
    public List<byte[]> GlobalRecords { get; } = [];
    public List<(string Name, List<byte[]> Records)> Modules { get; } = [];

    public static byte[] Record(ushort kind, Action<List<byte>> body, bool align = true)
    {
        var b = new List<byte>();
        body(b);
        int len = 2 + b.Count;
        if (align) while ((len + 2) % 4 != 0) { b.Add(0); len++; }
        var r = new List<byte>();
        r.AddRange(BitConverter.GetBytes((ushort)len));
        r.AddRange(BitConverter.GetBytes(kind));
        r.AddRange(b);
        return r.ToArray();
    }

    private static void Name(List<byte> b, string s) { b.AddRange(Encoding.UTF8.GetBytes(s)); b.Add(0); }

    public static byte[] Pub(string name, ushort seg, uint off, bool function) =>
        Record(0x110E, b => { b.AddRange(BitConverter.GetBytes(function ? 2u : 0u)); b.AddRange(BitConverter.GetBytes(off)); b.AddRange(BitConverter.GetBytes(seg)); Name(b, name); });

    public static byte[] Data(string name, ushort seg, uint off, bool global) =>
        Record(global ? (ushort)0x110D : (ushort)0x110C, b => { b.AddRange(BitConverter.GetBytes(0x74u)); b.AddRange(BitConverter.GetBytes(off)); b.AddRange(BitConverter.GetBytes(seg)); Name(b, name); });

    public static byte[] Proc(string name, ushort seg, uint off, uint len, bool global) =>
        Record(global ? (ushort)0x1110 : (ushort)0x110F, b =>
        {
            for (int i = 0; i < 3; i++) b.AddRange(BitConverter.GetBytes(0u)); // parent, end, next
            b.AddRange(BitConverter.GetBytes(len));
            b.AddRange(BitConverter.GetBytes(0u)); b.AddRange(BitConverter.GetBytes(len)); // debug start / end
            b.AddRange(BitConverter.GetBytes(0x1001u)); // type
            b.AddRange(BitConverter.GetBytes(off)); b.AddRange(BitConverter.GetBytes(seg)); b.Add(0);
            Name(b, name);
        });

    public static byte[] End() => Record(0x0006, _ => { });

    public MsfBuilder Msf(uint blockSize = 512)
    {
        var msf = new MsfBuilder { BlockSize = blockSize };
        var info = new List<byte>();
        info.AddRange(BitConverter.GetBytes(20000404u));
        info.AddRange(BitConverter.GetBytes(0x5F000000u));
        info.AddRange(BitConverter.GetBytes(Age));
        info.AddRange(Guid.ToByteArray());
        info.AddRange(BitConverter.GetBytes(0u)); // empty named stream map
        msf.Streams.Add([]);                 // 0: old directory
        msf.Streams.Add(info.ToArray());     // 1: PDB info
        msf.Streams.Add([]);                 // 2: TPI
        msf.Streams.Add([]);                 // 3: DBI, filled below
        msf.Streams.Add(SectionStream(Sections)); // 4: section headers
        msf.Streams.Add(GlobalRecords.SelectMany(r => r).ToArray()); // 5: symbol records
        int next = 6;
        int omapStream = 0xFFFF, origStream = 0xFFFF;
        if (OriginalSections != null && OmapFromSource != null)
        {
            omapStream = next++;
            msf.Streams.Add(OmapFromSource.SelectMany(e => BitConverter.GetBytes(e.From).Concat(BitConverter.GetBytes(e.To))).ToArray());
            origStream = next++;
            msf.Streams.Add(SectionStream(OriginalSections));
        }
        var modInfo = new List<byte>();
        foreach (var (name, records) in Modules)
        {
            var body = new List<byte>(BitConverter.GetBytes(4u));
            foreach (var r in records) body.AddRange(r);
            int stream = next++;
            msf.Streams.Add(body.ToArray());
            var m = new byte[64];
            BinaryPrimitives.WriteUInt16LittleEndian(m.AsSpan(34), (ushort)stream);
            BinaryPrimitives.WriteUInt32LittleEndian(m.AsSpan(36), (uint)body.Count);
            modInfo.AddRange(m);
            Name(modInfo, name);
            Name(modInfo, name);
            while (modInfo.Count % 4 != 0) modInfo.Add(0);
        }
        var dbg = new byte[22];
        for (int i = 0; i < 11; i++) BinaryPrimitives.WriteUInt16LittleEndian(dbg.AsSpan(i * 2), 0xFFFF);
        BinaryPrimitives.WriteUInt16LittleEndian(dbg.AsSpan(5 * 2), 4);
        BinaryPrimitives.WriteUInt16LittleEndian(dbg.AsSpan(4 * 2), (ushort)omapStream);
        BinaryPrimitives.WriteUInt16LittleEndian(dbg.AsSpan(10 * 2), (ushort)origStream);
        var h = new byte[64];
        BinaryPrimitives.WriteInt32LittleEndian(h, -1);
        BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(4), 19990903);
        BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(8), Age);
        BinaryPrimitives.WriteUInt16LittleEndian(h.AsSpan(12), 0xFFFF);
        BinaryPrimitives.WriteUInt16LittleEndian(h.AsSpan(16), 0xFFFF);
        BinaryPrimitives.WriteUInt16LittleEndian(h.AsSpan(20), 5);
        BinaryPrimitives.WriteInt32LittleEndian(h.AsSpan(24), modInfo.Count);
        BinaryPrimitives.WriteInt32LittleEndian(h.AsSpan(48), dbg.Length);
        BinaryPrimitives.WriteUInt16LittleEndian(h.AsSpan(58), 0x8664);
        msf.Streams[3] = [.. h, .. modInfo, .. dbg];
        return msf;
    }

    public byte[] Build(uint blockSize = 512) => Msf(blockSize).Build();

    private static byte[] SectionStream(List<(string Name, uint Va, uint Size)> sections)
    {
        var bytes = new byte[sections.Count * 40];
        for (int i = 0; i < sections.Count; i++)
        {
            var s = bytes.AsSpan(i * 40, 40);
            Encoding.ASCII.GetBytes(sections[i].Name).AsSpan(0, Math.Min(8, sections[i].Name.Length)).CopyTo(s);
            BinaryPrimitives.WriteUInt32LittleEndian(s[8..], sections[i].Size);
            BinaryPrimitives.WriteUInt32LittleEndian(s[12..], sections[i].Va);
        }
        return bytes;
    }

    /// <summary>The sample used by most tests: a C++ method (public + procedure), a static function, global data.</summary>
    public static PdbBuilder Sample(Guid? guid = null, uint age = 3)
    {
        var p = new PdbBuilder { Guid = guid ?? new Guid("11223344-5566-7788-99aa-bbccddeeff00"), Age = age };
        p.GlobalRecords.Add(Pub("?Foo@Bar@@QEAAHH@Z", 1, 0x10, function: true));
        p.GlobalRecords.Add(Pub("g_value", 2, 8, function: false));
        p.GlobalRecords.Add(Data("g_value", 2, 8, global: true));
        p.Modules.Add(("C:\\src\\bar.obj", [Proc("Bar::Foo", 1, 0x10, 0x20, global: true), End(), Proc("helper", 1, 0x40, 8, global: false), End()]));
        return p;
    }
}
