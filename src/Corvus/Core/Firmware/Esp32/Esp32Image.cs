using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Corvus.Core.Firmware.Esp32;

/// <summary>An ESP32-family application or bootloader image (magic 0xE9) as esptool image_info reads it.</summary>
internal sealed class Esp32Image
{
    public const byte Magic = 0xE9;
    private const int HeaderSize = 24, SegmentHeaderSize = 8, MaxSegments = 16, AppDescMagic = unchecked((int)0xABCD5432);
    private const byte ChecksumSeed = 0xEF, NoWpPin = 0xEE;

    /// <summary>A chip as esptool names it: its image chip id, bootloader flash offset, flash frequency labels and memory map.</summary>
    public sealed record Chip(int Id, string Name, uint BootloaderOffset, IReadOnlyDictionary<int, string> Frequencies, (uint Start, uint End, string Name)[] Regions);

    // esptool 5.6.0 targets: IMAGE_CHIP_ID, BOOTLOADER_FLASH_OFFSET, FLASH_FREQUENCY (the first label of a value) and MEMORY_MAP.
    public static readonly Chip[] Chips =
    [
        new(0, "ESP32", 0x1000, new Dictionary<int, string> { [0] = "40m", [1] = "26m", [2] = "20m", [15] = "80m" },
            [(0x0, 0x10000, "PADDING"), (0x3F400000, 0x3F800000, "DROM"), (0x3F800000, 0x3FC00000, "EXTRAM_DATA"), (0x3FF80000, 0x3FF82000, "RTC_DRAM"), (0x3FF90000, 0x40000000, "BYTE_ACCESSIBLE"), (0x3FFAE000, 0x40000000, "DRAM"), (0x3FFE0000, 0x3FFFFFFC, "DIRAM_DRAM"), (0x40000000, 0x40070000, "IROM"), (0x40070000, 0x40078000, "CACHE_PRO"), (0x40078000, 0x40080000, "CACHE_APP"), (0x40080000, 0x400A0000, "IRAM"), (0x400A0000, 0x400BFFFC, "DIRAM_IRAM"), (0x400C0000, 0x400C2000, "RTC_IRAM"), (0x400D0000, 0x40400000, "IROM"), (0x50000000, 0x50002000, "RTC_DATA")]),
        new(2, "ESP32-S2", 0x1000, new Dictionary<int, string> { [0] = "40m", [1] = "26m", [2] = "20m", [15] = "80m" },
            [(0x0, 0x10000, "PADDING"), (0x3F000000, 0x3FF80000, "DROM"), (0x3F500000, 0x3FF80000, "EXTRAM_DATA"), (0x3FF9E000, 0x3FFA0000, "RTC_DRAM"), (0x3FF9E000, 0x40000000, "BYTE_ACCESSIBLE"), (0x3FF9E000, 0x40072000, "MEM_INTERNAL"), (0x3FFB0000, 0x40000000, "DRAM"), (0x40000000, 0x4001A100, "IROM_MASK"), (0x40020000, 0x40070000, "IRAM"), (0x40070000, 0x40072000, "RTC_IRAM"), (0x40080000, 0x40800000, "IROM"), (0x50000000, 0x50002000, "RTC_DATA")]),
        new(9, "ESP32-S3", 0x0, new Dictionary<int, string> { [0] = "40m", [1] = "26m", [2] = "20m", [15] = "80m" },
            [(0x0, 0x10000, "PADDING"), (0x3C000000, 0x3D000000, "DROM"), (0x3D000000, 0x3E000000, "EXTRAM_DATA"), (0x600FE000, 0x60100000, "RTC_DRAM"), (0x3FC88000, 0x3FD00000, "BYTE_ACCESSIBLE"), (0x3FC88000, 0x403E2000, "MEM_INTERNAL"), (0x3FC88000, 0x3FD00000, "DRAM"), (0x40000000, 0x4001A100, "IROM_MASK"), (0x40370000, 0x403E0000, "IRAM"), (0x600FE000, 0x60100000, "RTC_IRAM"), (0x42000000, 0x42800000, "IROM"), (0x50000000, 0x50002000, "RTC_DATA")]),
        new(5, "ESP32-C3", 0x0, new Dictionary<int, string> { [0] = "40m", [1] = "26m", [2] = "20m", [15] = "80m" },
            [(0x0, 0x10000, "PADDING"), (0x3C000000, 0x3C800000, "DROM"), (0x3FC80000, 0x3FCE0000, "DRAM"), (0x3FC88000, 0x3FD00000, "BYTE_ACCESSIBLE"), (0x3FF00000, 0x3FF20000, "DROM_MASK"), (0x40000000, 0x40060000, "IROM_MASK"), (0x42000000, 0x42800000, "IROM"), (0x4037C000, 0x403E0000, "IRAM"), (0x50000000, 0x50002000, "RTC_IRAM"), (0x50000000, 0x50002000, "RTC_DRAM"), (0x600FE000, 0x60100000, "MEM_INTERNAL2")]),
        new(12, "ESP32-C2", 0x0, new Dictionary<int, string> { [0] = "30m", [1] = "20m", [2] = "15m", [15] = "60m" },
            [(0x0, 0x10000, "PADDING"), (0x3C000000, 0x3C400000, "DROM"), (0x3FCA0000, 0x3FCE0000, "DRAM"), (0x3FC88000, 0x3FD00000, "BYTE_ACCESSIBLE"), (0x3FF00000, 0x3FF50000, "DROM_MASK"), (0x40000000, 0x40090000, "IROM_MASK"), (0x42000000, 0x42400000, "IROM"), (0x4037C000, 0x403C0000, "IRAM")]),
        new(13, "ESP32-C6", 0x0, new Dictionary<int, string> { [0] = "80m", [2] = "20m" },
            [(0x0, 0x10000, "PADDING"), (0x42000000, 0x43000000, "DROM"), (0x40800000, 0x40880000, "DRAM"), (0x40800000, 0x40880000, "BYTE_ACCESSIBLE"), (0x4004AC00, 0x40050000, "DROM_MASK"), (0x40000000, 0x4004AC00, "IROM_MASK"), (0x42000000, 0x43000000, "IROM"), (0x40800000, 0x40880000, "IRAM"), (0x50000000, 0x50004000, "RTC_IRAM"), (0x50000000, 0x50004000, "RTC_DRAM"), (0x600FE000, 0x60100000, "MEM_INTERNAL2")]),
        new(20, "ESP32-C61", 0x0, new Dictionary<int, string> { [0] = "40m", [2] = "20m", [15] = "80m" },
            [(0x0, 0x10000, "PADDING"), (0x42000000, 0x44000000, "DROM"), (0x40800000, 0x40860000, "DRAM"), (0x40800000, 0x40860000, "BYTE_ACCESSIBLE"), (0x4004AC00, 0x40050000, "DROM_MASK"), (0x40000000, 0x4004AC00, "IROM_MASK"), (0x42000000, 0x44000000, "IROM"), (0x40800000, 0x40860000, "IRAM"), (0x50000000, 0x50004000, "RTC_IRAM"), (0x50000000, 0x50004000, "RTC_DRAM"), (0x600FE000, 0x60100000, "MEM_INTERNAL2")]),
        new(23, "ESP32-C5", 0x2000, new Dictionary<int, string> { [0] = "40m", [2] = "20m", [15] = "80m" },
            [(0x0, 0x10000, "PADDING"), (0x42000000, 0x44000000, "DROM"), (0x40800000, 0x40860000, "DRAM"), (0x40800000, 0x40860000, "BYTE_ACCESSIBLE"), (0x4003A000, 0x40040000, "DROM_MASK"), (0x40000000, 0x4003A000, "IROM_MASK"), (0x42000000, 0x44000000, "IROM"), (0x40800000, 0x40860000, "IRAM"), (0x50000000, 0x50004000, "RTC_IRAM"), (0x50000000, 0x50004000, "RTC_DRAM"), (0x600FE000, 0x60100000, "MEM_INTERNAL2")]),
        new(31, "ESP32-E22", 0x0, new Dictionary<int, string> { [0] = "40m", [1] = "26m", [2] = "20m", [15] = "80m" },
            [(0x0, 0x10000, "PADDING"), (0x3C000000, 0x40000000, "DROM"), (0x31000000, 0x31200000, "DRAM"), (0x31000000, 0x31200000, "BYTE_ACCESSIBLE"), (0x30000000, 0x30120000, "DROM_MASK"), (0x30000000, 0x30120000, "IROM_MASK"), (0x3C000000, 0x40000000, "IROM"), (0x30FE0000, 0x31200000, "IRAM"), (0xC0000000, 0xC0008000, "RTC_IRAM"), (0xC0000000, 0xC0008000, "RTC_DRAM")]),
        new(16, "ESP32-H2", 0x0, new Dictionary<int, string> { [0] = "24m", [1] = "16m", [2] = "12m", [15] = "48m" },
            [(0x0, 0x10000, "PADDING"), (0x42000000, 0x43000000, "DROM"), (0x40800000, 0x40880000, "DRAM"), (0x40800000, 0x40880000, "BYTE_ACCESSIBLE"), (0x4004AC00, 0x40050000, "DROM_MASK"), (0x40000000, 0x4004AC00, "IROM_MASK"), (0x42000000, 0x43000000, "IROM"), (0x40800000, 0x40880000, "IRAM"), (0x50000000, 0x50004000, "RTC_IRAM"), (0x50000000, 0x50004000, "RTC_DRAM"), (0x600FE000, 0x60100000, "MEM_INTERNAL2")]),
        new(25, "ESP32-H21", 0x0, new Dictionary<int, string> { [0] = "24m", [15] = "48m" },
            [(0x0, 0x10000, "PADDING"), (0x42000000, 0x43000000, "DROM"), (0x40800000, 0x40850000, "DRAM"), (0x40800000, 0x40850000, "BYTE_ACCESSIBLE"), (0x40000000, 0x40020000, "DROM_MASK"), (0x40000000, 0x40020000, "IROM_MASK"), (0x42000000, 0x43000000, "IROM"), (0x40800000, 0x40850000, "IRAM"), (0x50000000, 0x50001000, "RTC_IRAM"), (0x50000000, 0x50001000, "RTC_DRAM"), (0x40800000, 0x40850000, "MEM_INTERNAL")]),
        new(18, "ESP32-P4", 0x2000, new Dictionary<int, string> { [0] = "40m", [1] = "26m", [2] = "20m", [15] = "80m" },
            [(0x0, 0x10000, "PADDING"), (0x40000000, 0x4C000000, "DROM"), (0x4FF00000, 0x4FFA0000, "DRAM"), (0x4FF00000, 0x4FFA0000, "BYTE_ACCESSIBLE"), (0x4FC00000, 0x4FC20000, "DROM_MASK"), (0x4FC00000, 0x4FC20000, "IROM_MASK"), (0x40000000, 0x4C000000, "IROM"), (0x4FF00000, 0x4FFA0000, "IRAM"), (0x50108000, 0x50110000, "RTC_IRAM"), (0x50108000, 0x50110000, "RTC_DRAM"), (0x600FE000, 0x60100000, "MEM_INTERNAL2")]),
        new(28, "ESP32-H4", 0x2000, new Dictionary<int, string> { [0] = "24m", [15] = "48m" },
            [(0x0, 0x10000, "PADDING"), (0x42000000, 0x44000000, "DROM"), (0x40810000, 0x40860000, "DRAM"), (0x40810000, 0x40860000, "BYTE_ACCESSIBLE"), (0x40000000, 0x40020000, "DROM_MASK"), (0x40000000, 0x40020000, "IROM_MASK"), (0x42000000, 0x44000000, "IROM"), (0x40810000, 0x40860000, "IRAM"), (0x40810000, 0x40860000, "MEM_INTERNAL")]),
        new(32, "ESP32-S31", 0x2000, new Dictionary<int, string> { [0] = "40m", [2] = "20m", [15] = "80m" },
            [(0x0, 0x10000, "PADDING"), (0x40000000, 0x54000000, "DROM"), (0x2F000000, 0x2F080000, "DRAM"), (0x2F000000, 0x2F080000, "BYTE_ACCESSIBLE"), (0x2F800000, 0x2F850000, "DROM_MASK"), (0x2F800000, 0x2F850000, "IROM_MASK"), (0x40000000, 0x54000000, "IROM"), (0x2F000000, 0x2F080000, "IRAM"), (0x2E000000, 0x2E008000, "RTC_IRAM"), (0x2E000000, 0x2E008000, "RTC_DRAM")]),
    ];

    private static readonly string[] Sizes = ["1MB", "2MB", "4MB", "8MB", "16MB", "32MB", "64MB", "128MB"];
    private static readonly string[] Modes = ["QIO", "QOUT", "DIO", "DOUT", "FAST_READ", "SLOW_READ"];

    /// <summary>A segment: where it loads, its bytes' file offset in the image and length, and the memory regions holding its start.</summary>
    public sealed record Segment(uint LoadAddress, int FileOffset, int Length, IReadOnlyList<string> Regions);

    /// <summary>esp_app_desc_t, which starts the first DROM segment of an application.</summary>
    public sealed record AppDescription(string ProjectName, string Version, string CompileTime, string ElfSha256, string IdfVersion,
        string MinEfuseRevision, string MaxEfuseRevision, string? MmuPageSize, uint SecureVersion);

    /// <summary>esp_bootloader_desc_t, which starts the first DRAM segment of a bootloader (ESP-IDF 5.2 and later).</summary>
    public sealed record BootloaderDescription(uint Version, string IdfVersion, string CompileTime);

    public uint Entry { get; private init; }
    public string? FlashSize { get; private init; }
    public string? FlashFrequency { get; private init; }
    public string? FlashMode { get; private init; }
    public int WpPin { get; private init; }
    public bool WpPinDisabled => WpPin == NoWpPin;
    /// <summary>clk, q, d, cs0, hd and wp drive settings, in that order.</summary>
    public IReadOnlyList<int> DriveSettings { get; private init; } = [];
    public int ChipId { get; private init; }
    public Chip? ChipInfo { get; private init; }
    public int LegacyMinRevision { get; private init; }
    public string MinChipRevision { get; private init; } = "";
    public string MaxChipRevision { get; private init; } = "";
    public IReadOnlyList<Segment> Segments { get; private init; } = [];
    public byte Checksum { get; private init; }
    public byte ComputedChecksum { get; private init; }
    public bool HashAppended { get; private init; }
    public string? Sha256 { get; private init; }
    public bool? Sha256Valid { get; private init; }
    /// <summary>The image's length: through the checksum and the appended SHA-256.</summary>
    public int Length { get; private init; }
    public AppDescription? App { get; private init; }
    public BootloaderDescription? Bootloader { get; private init; }

    /// <summary>Whether <paramref name="b"/> starts like an image: the magic, 1-16 segments and a known flash mode.</summary>
    public static bool Looks(ReadOnlySpan<byte> b) => b.Length >= HeaderSize && b[0] == Magic && b[1] is > 0 and <= MaxSegments && b[2] < Modes.Length;

    /// <summary>Parses the image at the start of <paramref name="data"/>; throws <see cref="InvalidDataException"/> when the header or a segment is unreadable.</summary>
    public static Esp32Image Read(ReadOnlySpan<byte> data)
    {
        if (!Looks(data)) throw new InvalidDataException("not an ESP32 image: no 0xE9 header with 1-16 segments");
        int count = data[1], sizeFreq = data[3];
        var e = data[8..HeaderSize];
        int chipId = BinaryPrimitives.ReadUInt16LittleEndian(e[4..]);
        var chip = Array.Find(Chips, c => c.Id == chipId);
        if (e[15] > 1) throw new InvalidDataException($"the hash-appended flag is 0x{e[15]:X2}, not 0 or 1");
        int at = HeaderSize;
        byte sum = ChecksumSeed;
        var segments = new List<Segment>(count);
        for (int i = 0; i < count; i++)
        {
            if (at + SegmentHeaderSize > data.Length) throw new InvalidDataException($"segment {i} starts past the end ({data.Length:N0} bytes)");
            uint load = BinaryPrimitives.ReadUInt32LittleEndian(data[at..]);
            uint length = BinaryPrimitives.ReadUInt32LittleEndian(data[(at + 4)..]);
            if (length > data.Length - at - SegmentHeaderSize) throw new InvalidDataException($"segment {i} ({length:N0} bytes at 0x{load:X}) runs past the end");
            at += SegmentHeaderSize;
            foreach (var b in data.Slice(at, (int)length)) sum ^= b;
            segments.Add(new Segment(load, at, (int)length, chip?.Regions.Where(r => r.Start <= load && load < r.End).Select(r => r.Name).ToList() ?? []));
            at += (int)length;
        }
        // The checksum is the last byte of a 16-byte block.
        at += 15 - at % 16;
        if (at >= data.Length) throw new InvalidDataException("the image ends before its checksum");
        int end = at + 1;
        bool hashed = e[15] == 1;
        byte[]? digest = null;
        if (hashed)
        {
            if (end + 32 > data.Length) throw new InvalidDataException("the image ends before its appended SHA-256");
            digest = SHA256.HashData(data[..end]);
        }
        return new Esp32Image
        {
            Entry = BinaryPrimitives.ReadUInt32LittleEndian(data[4..]),
            FlashMode = Modes[data[2]],
            FlashSize = (sizeFreq >> 4) < Sizes.Length ? Sizes[sizeFreq >> 4] : null,
            FlashFrequency = chip?.Frequencies.GetValueOrDefault(sizeFreq & 0xF),
            WpPin = e[0],
            DriveSettings = [e[1] & 0xF, e[1] >> 4, e[2] & 0xF, e[2] >> 4, e[3] & 0xF, e[3] >> 4],
            ChipId = chipId,
            ChipInfo = chip,
            LegacyMinRevision = e[6],
            MinChipRevision = Revision(BinaryPrimitives.ReadUInt16LittleEndian(e[7..])),
            MaxChipRevision = Revision(BinaryPrimitives.ReadUInt16LittleEndian(e[9..])),
            Segments = segments,
            Checksum = data[at],
            ComputedChecksum = sum,
            HashAppended = hashed,
            Sha256 = digest == null ? null : Convert.ToHexStringLower(digest),
            Sha256Valid = digest == null ? null : data.Slice(end, 32).SequenceEqual(digest),
            Length = end + (hashed ? 32 : 0),
            App = AppOf(data, segments),
            Bootloader = BootloaderOf(data, segments),
        };
    }

    private static string Revision(int full) => $"v{full / 100}.{full % 100}";

    // As image_info: the first DROM segment holds the app description; a bootloader's is in a DRAM segment of 80 bytes or more.
    private static AppDescription? AppOf(ReadOnlySpan<byte> data, IReadOnlyList<Segment> segments)
    {
        var drom = segments.FirstOrDefault(s => s.Regions.Contains("DROM"));
        if (drom == null || drom.Length < 256) return null;
        var d = data.Slice(drom.FileOffset, 256);
        if (BinaryPrimitives.ReadInt32LittleEndian(d) != AppDescMagic) return null;
        int min = BinaryPrimitives.ReadUInt16LittleEndian(d[176..]), max = BinaryPrimitives.ReadUInt16LittleEndian(d[178..]), page = d[180];
        return new AppDescription(Text(d.Slice(48, 32)), Text(d.Slice(16, 32)), Text(d.Slice(96, 16)) + " " + Text(d.Slice(80, 16)),
            Convert.ToHexStringLower(d.Slice(144, 32)), Text(d.Slice(112, 32)), $"{min / 100}.{min % 100}", $"{max / 100}.{max % 100}",
            page != 0 ? $"{(1L << page) / 1024} KB" : null, BinaryPrimitives.ReadUInt32LittleEndian(d[4..]));
    }

    private static BootloaderDescription? BootloaderOf(ReadOnlySpan<byte> data, IReadOnlyList<Segment> segments)
    {
        if (segments.Any(s => s.Regions.Contains("DROM"))) return null;
        Segment? dram = null;
        foreach (var s in segments)
            if (s.Regions.Contains("DRAM") && s.Length >= 80) dram = s;
        if (dram == null) return null;
        var d = data.Slice(dram.FileOffset, 80);
        if (d[0] != 0x50) return null;
        return new BootloaderDescription(BinaryPrimitives.ReadUInt32LittleEndian(d[4..]), Text(d.Slice(8, 32)), Text(d.Slice(40, 24)));
    }

    private static string Text(ReadOnlySpan<byte> b) => Encoding.UTF8.GetString(b).Replace("\0", "", StringComparison.Ordinal);
}
