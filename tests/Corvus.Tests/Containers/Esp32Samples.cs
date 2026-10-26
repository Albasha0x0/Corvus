using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Corvus.Core.Firmware;

namespace Corvus.Tests;

/// <summary>ESP32 images, partition tables, NVS partitions and flash images laid out as esptool, gen_esp32part.py and the NVS library write them.</summary>
internal static class Esp32Samples
{
    public const uint AppEntry = 0x40080400, BootEntry = 0x400805B0;

    /// <summary>An image: the 24-byte header, the segments, the XOR checksum ending a 16-byte block, then the SHA-256 when <paramref name="hash"/>.</summary>
    public static byte[] Image(int chip, uint entry, (uint Load, byte[] Data)[] segments, bool hash = true, byte mode = 2, byte sizeFreq = 0x20)
    {
        var m = new MemoryStream();
        m.Write([0xE9, (byte)segments.Length, mode, sizeFreq]);
        Span<byte> u = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(u, entry);
        m.Write(u);
        var ext = new byte[16];
        ext[0] = 0xEE;
        BinaryPrimitives.WriteUInt16LittleEndian(ext.AsSpan(4), (ushort)chip);
        ext[6] = 1;
        BinaryPrimitives.WriteUInt16LittleEndian(ext.AsSpan(7), 100);
        BinaryPrimitives.WriteUInt16LittleEndian(ext.AsSpan(9), 399);
        ext[15] = (byte)(hash ? 1 : 0);
        m.Write(ext);
        byte sum = 0xEF;
        foreach (var (load, data) in segments)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(u, load);
            m.Write(u);
            BinaryPrimitives.WriteUInt32LittleEndian(u, (uint)data.Length);
            m.Write(u);
            m.Write(data);
            foreach (var b in data) sum ^= b;
        }
        while (m.Length % 16 != 15) m.WriteByte(0);
        m.WriteByte(sum);
        if (hash) m.Write(SHA256.HashData(m.ToArray()));
        return m.ToArray();
    }

    /// <summary>esp_app_desc_t (256 bytes) followed by <paramref name="rest"/>.</summary>
    public static byte[] AppDescription(string project, string version, string idf, byte[]? rest = null)
    {
        var d = new byte[256 + (rest?.Length ?? 0)];
        BinaryPrimitives.WriteUInt32LittleEndian(d, 0xABCD5432);
        BinaryPrimitives.WriteUInt32LittleEndian(d.AsSpan(4), 3);
        Encoding.ASCII.GetBytes(version).CopyTo(d, 16);
        Encoding.ASCII.GetBytes(project).CopyTo(d, 48);
        Encoding.ASCII.GetBytes("12:34:56").CopyTo(d, 80);
        Encoding.ASCII.GetBytes("Jan  2 2025").CopyTo(d, 96);
        Encoding.ASCII.GetBytes(idf).CopyTo(d, 112);
        for (int i = 0; i < 32; i++) d[144 + i] = (byte)(0xA0 + i);
        BinaryPrimitives.WriteUInt16LittleEndian(d.AsSpan(176), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(d.AsSpan(178), 199);
        d[180] = 16;
        rest?.CopyTo(d, 256);
        return d;
    }

    /// <summary>esp_bootloader_desc_t (80 bytes) followed by <paramref name="rest"/>.</summary>
    public static byte[] BootloaderDescription(string idf, byte[]? rest = null)
    {
        var d = new byte[80 + (rest?.Length ?? 0)];
        d[0] = 0x50;
        BinaryPrimitives.WriteUInt32LittleEndian(d.AsSpan(4), 1);
        Encoding.ASCII.GetBytes(idf).CopyTo(d, 8);
        Encoding.ASCII.GetBytes("Jan  2 2025 12:00:00").CopyTo(d, 40);
        rest?.CopyTo(d, 80);
        return d;
    }

    public static byte[] Fill(int n, int seed) => [.. Enumerable.Range(0, n).Select(i => (byte)(i * 13 + seed))];

    /// <summary>An ESP32 (chip 0) app with DROM, IROM and IRAM segments.</summary>
    public static byte[] App(string project = "sensor", string version = "1.4.2") => Image(0, AppEntry,
    [
        (0x3F400020, AppDescription(project, version, "v5.4", Fill(100, 1))),
        (0x400D0020, Fill(300, 2)),
        (0x40080000, Fill(64, 3)),
    ]);

    /// <summary>An ESP32 bootloader with its description in a DRAM segment.</summary>
    public static byte[] Bootloader() => Image(0, BootEntry, [(0x3FFF0030, BootloaderDescription("v5.4", Fill(40, 4))), (0x40078000, Fill(200, 5))]);

    public sealed record Part(string Label, int Type, int Subtype, uint Offset, uint Size, int Flags = 0);

    /// <summary>A table as gen_esp32part.py writes it: the entries, the MD5 entry, then 0xFF to 3 KiB.</summary>
    public static byte[] Table(Part[] parts, bool md5 = true)
    {
        var t = Enumerable.Repeat((byte)0xFF, 0xC00).ToArray();
        int at = 0;
        foreach (var p in parts)
        {
            var e = t.AsSpan(at, 32);
            e.Clear();
            e[0] = 0xAA; e[1] = 0x50; e[2] = (byte)p.Type; e[3] = (byte)p.Subtype;
            BinaryPrimitives.WriteUInt32LittleEndian(e[4..], p.Offset);
            BinaryPrimitives.WriteUInt32LittleEndian(e[8..], p.Size);
            Encoding.ASCII.GetBytes(p.Label).CopyTo(e[12..]);
            BinaryPrimitives.WriteUInt32LittleEndian(e[28..], (uint)p.Flags);
            at += 32;
        }
        if (md5)
        {
            var hash = MD5.HashData(t.AsSpan(0, at));
            t[at] = t[at + 1] = 0xEB;
            hash.CopyTo(t, at + 16);
        }
        return t;
    }

    public static readonly Part[] Layout =
    [
        new("nvs", 1, 2, 0x9000, 0x3000),
        new("phy_init", 1, 1, 0xC000, 0x1000),
        new("factory", 0, 0, 0x10000, 0x10000),
        new("ota_0", 0, 0x10, 0x20000, 0x10000, Flags: 1),
        new("storage", 1, 0x81, 0x30000, 0x10000, Flags: 2),
    ];

    /// <summary>
    /// An ESP32 flash image from flash address 0x1000: the bootloader, the table at 0x8000, <paramref name="nvs"/> at
    /// 0x9000 and the app at 0x10000; the file ends 0x2000 into ota_0, so storage lies past its end.
    /// </summary>
    public static byte[] Flash(byte[] nvs)
    {
        const uint Base = 0x1000;
        var f = Enumerable.Repeat((byte)0xFF, (int)(0x22000 - Base)).ToArray();
        Bootloader().CopyTo(f, 0);
        Table(Layout).CopyTo(f, 0x8000 - Base);
        nvs.CopyTo(f, 0x9000 - Base);
        App().CopyTo(f, 0x10000 - Base);
        Fill(0x2000, 6).CopyTo(f, 0x20000 - Base);
        return f;
    }

    /// <summary>zlib crc32(data, 0xFFFFFFFF), as the NVS library computes it.</summary>
    public static uint NvsCrc(ReadOnlySpan<byte> b) => ~Crc.Raw(0, b);

    /// <summary>The settings and network namespaces of <see cref="NvsWriter.Sample"/>: (namespace, key, type, value) as the reader reports them.</summary>
    public static readonly (string Ns, string Key, string Type, string Value)[] SampleValues =
    [
        ("settings", "level", "uint8_t", "200"), ("settings", "offset", "int8_t", "-5"), ("settings", "port", "uint16_t", "8080"),
        ("settings", "delta", "int16_t", "-1234"), ("settings", "count", "uint32_t", "4000000000"), ("settings", "temp", "int32_t", "-123456"),
        ("settings", "serial", "uint64_t", "18000000000000000000"), ("settings", "skew", "int64_t", "-9000000000000000000"),
        ("settings", "name", "string", "sample device"), ("network", "ssid", "string", "lab-network"),
    ];
}

/// <summary>Writes NVS pages entry by entry, as the NVS library lays them out: header, entry-state bitmap, 126 entries.</summary>
internal sealed class NvsWriter
{
    private const int Page = 4096, Entries = 126;
    private readonly List<byte[]> _pages = [];
    private int _next;

    public NvsWriter() => NewPage();

    private byte[] Current => _pages[^1];

    public void NewPage()
    {
        var p = Enumerable.Repeat((byte)0xFF, Page).ToArray();
        _pages.Add(p);
        _next = 0;
    }

    /// <summary>The page and entry index the next entry takes.</summary>
    public (int Page, int Index) Position => (_pages.Count - 1, _next);

    public void Namespace(string name, byte index) => Entry(0, 0x01, name, [index, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], []);

    public void Number(byte ns, string key, byte type, long value)
    {
        var d = Enumerable.Repeat((byte)0xFF, 8).ToArray();
        BinaryPrimitives.WriteInt64LittleEndian(d, value);
        for (int i = type & 0xF; i < 8; i++) d[i] = 0xFF;
        Entry(ns, type, key, d, []);
    }

    /// <summary>A string (0x21), legacy blob (0x41) or blob chunk (0x42); <paramref name="badCrc"/> stores a wrong data CRC.</summary>
    public void Variable(byte ns, string key, byte type, byte[] data, byte chunk = 0xFF, bool badCrc = false)
    {
        var d = new byte[8];
        BinaryPrimitives.WriteUInt16LittleEndian(d, (ushort)data.Length);
        d[2] = d[3] = 0xFF;
        BinaryPrimitives.WriteUInt32LittleEndian(d.AsSpan(4), Esp32Samples.NvsCrc(data) ^ (badCrc ? 1u : 0));
        Entry(ns, type, key, d, data, chunk);
    }

    public void BlobIndex(byte ns, string key, uint size, byte count, byte start)
    {
        var d = Enumerable.Repeat((byte)0xFF, 8).ToArray();
        BinaryPrimitives.WriteUInt32LittleEndian(d, size);
        d[4] = count;
        d[5] = start;
        Entry(ns, 0x48, key, d, []);
    }

    /// <summary>Marks an entry erased (state 00) in its page's bitmap.</summary>
    public void Erase(int page, int index) => _pages[page][32 + index / 4] &= (byte)~(3 << (index % 4 * 2));

    /// <summary>Flips a bit in an entry's key, so its CRC no longer matches.</summary>
    public void Damage(int page, int index) => _pages[page][64 + index * 32 + 8] ^= 0x20;

    private void Entry(byte ns, byte type, string key, byte[] data, byte[] payload, byte chunk = 0xFF)
    {
        int span = 1 + (payload.Length + 31) / 32;
        if (_next + span > Entries) NewPage();
        var p = Current;
        var e = p.AsSpan(64 + _next * 32, 32);
        e[0] = ns; e[1] = type; e[2] = (byte)span; e[3] = chunk;
        e.Slice(8, 16).Clear();
        Encoding.ASCII.GetBytes(key).CopyTo(e[8..]);
        data.CopyTo(e[24..]);
        Span<byte> covered = stackalloc byte[28];
        e[..4].CopyTo(covered);
        e[8..].CopyTo(covered[4..]);
        BinaryPrimitives.WriteUInt32LittleEndian(e[4..], Esp32Samples.NvsCrc(covered));
        payload.CopyTo(p.AsSpan(64 + (_next + 1) * 32));
        for (int i = _next; i < _next + span; i++) p[32 + i / 4] &= (byte)~(1 << (i % 4 * 2));
        _next += span;
    }

    /// <summary>The partition: written pages Full, the last one Active, then <paramref name="empty"/> erased pages.</summary>
    public byte[] Build(int empty = 1)
    {
        var all = new List<byte>();
        for (int i = 0; i < _pages.Count; i++)
        {
            var p = _pages[i];
            BinaryPrimitives.WriteUInt32LittleEndian(p, i == _pages.Count - 1 ? 0xFFFFFFFE : 0xFFFFFFFC);
            BinaryPrimitives.WriteUInt32LittleEndian(p.AsSpan(4), (uint)i);
            p[8] = 0xFE;
            BinaryPrimitives.WriteUInt32LittleEndian(p.AsSpan(28), Esp32Samples.NvsCrc(p.AsSpan(4, 24)));
            all.AddRange(p);
        }
        all.AddRange(Enumerable.Repeat((byte)0xFF, empty * Page));
        return [.. all];
    }

    /// <summary>
    /// Two namespaces with every integer type, two strings, a legacy blob, and a v2 blob of 5,000 bytes in two chunks
    /// on two pages (indexed after the second).
    /// </summary>
    public static (NvsWriter Writer, byte[] Blob) Sample()
    {
        var w = new NvsWriter();
        w.Namespace("settings", 1);
        w.Number(1, "level", 0x01, 200);
        w.Number(1, "offset", 0x11, -5);
        w.Number(1, "port", 0x02, 8080);
        w.Number(1, "delta", 0x12, -1234);
        w.Number(1, "count", 0x04, 4000000000);
        w.Number(1, "temp", 0x14, -123456);
        w.Number(1, "serial", 0x08, unchecked((long)18000000000000000000));
        w.Number(1, "skew", 0x18, -9000000000000000000);
        w.Variable(1, "name", 0x21, Encoding.ASCII.GetBytes("sample device\0"));
        w.Variable(1, "legacy", 0x41, [1, 2, 3, 4, 5]);
        var blob = Esp32Samples.Fill(5000, 7);
        w.Variable(1, "calib", 0x42, blob[..3000], chunk: 0);
        w.NewPage();
        w.Variable(1, "calib", 0x42, blob[3000..], chunk: 1);
        w.BlobIndex(1, "calib", 5000, 2, 0);
        w.Namespace("network", 2);
        w.Variable(2, "ssid", 0x21, Encoding.ASCII.GetBytes("lab-network\0"));
        return (w, blob);
    }
}
