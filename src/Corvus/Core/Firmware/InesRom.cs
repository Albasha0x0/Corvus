using System.Buffers.Binary;

namespace Corvus.Core.Firmware;

/// <summary>An iNES or NES 2.0 ROM image and the 6502's power-on view of PRG-ROM at 0x8000-0xFFFF with its vectors.</summary>
public sealed class InesRom
{
    public const int HeaderSize = 16, TrainerSize = 512, PrgBank = 0x4000, ChrBank = 0x2000, CpuBase = 0x8000, CpuWindow = 0x8000;

    public bool Nes2 { get; private init; }
    public int Mapper { get; private init; }
    public int Submapper { get; private init; }
    public string Mirroring { get; private init; } = "";
    public bool Battery { get; private init; }
    public bool HasTrainer { get; private init; }
    public long PrgSize { get; private init; }
    public long ChrSize { get; private init; }
    /// <summary>"NES", "Vs. System", "PlayChoice-10" or "extended".</summary>
    public string Console { get; private init; } = "";
    public long PrgOffset => HeaderSize + (HasTrainer ? TrainerSize : 0);
    public long ChrOffset => PrgOffset + PrgSize;
    /// <summary>The 16 KiB PRG banks at 0x8000 and 0xC000 at power-on; one bank in both for a 16 KiB image.</summary>
    public (int Low, int High) CpuBanks { get; private init; }
    /// <summary>Whether the mapper switches the banks shown (anything but NROM-style fixed PRG).</summary>
    public bool Switchable { get; private init; }
    public ushort Nmi { get; private set; }
    public ushort Reset { get; private set; }
    public ushort Irq { get; private set; }
    public List<string> Issues { get; } = [];

    // Mappers that switch all 32 KiB at once (AxROM, Color Dreams, BNROM, GxROM): the last 32 KiB is shown.
    private static readonly HashSet<int> Switch32 = [7, 11, 34, 66];
    // Mappers whose PRG does not switch (NROM, CNROM, and CHR-only boards).
    private static readonly HashSet<int> Fixed = [0, 3, 13, 87, 185];

    /// <summary>The file starts with "NES" and 0x1A.</summary>
    public static bool Looks(ReadOnlySpan<byte> head) => head.Length >= HeaderSize && head.StartsWith("NES\x1A"u8);

    /// <summary>Reads the header and maps PRG-ROM; throws <see cref="InvalidDataException"/> when there is no header or no PRG-ROM.</summary>
    public static InesRom Read(ReadOnlySpan<byte> data)
    {
        if (!Looks(data)) throw new InvalidDataException("no iNES header");
        byte f6 = data[6], f7 = data[7];
        bool nes2 = (f7 & 0x0C) == 0x08;
        long prg, chr;
        int mapper = f6 >> 4 | f7 & 0xF0, sub = 0;
        if (nes2)
        {
            mapper |= (data[8] & 0x0F) << 8;
            sub = data[8] >> 4;
            prg = Size(data[4], data[9] & 0x0F, PrgBank);
            chr = Size(data[5], data[9] >> 4, ChrBank);
        }
        else
        {
            prg = data[4] * (long)PrgBank;
            chr = data[5] * (long)ChrBank;
            // Headers written before iNES 1.0 carry text in bytes 12-15, and that text also overwrote byte 7's mapper nibble.
            if (data.Slice(12, 4).ContainsAnyExcept((byte)0)) mapper &= 0x0F;
        }
        if (prg < PrgBank) throw new InvalidDataException($"PRG-ROM is {prg:N0} bytes, under one 16 KiB bank");
        int banks = (int)Math.Min(prg / PrgBank, int.MaxValue);
        var rom = new InesRom
        {
            Nes2 = nes2, Mapper = mapper, Submapper = sub, Battery = (f6 & 2) != 0, HasTrainer = (f6 & 4) != 0, PrgSize = prg, ChrSize = chr,
            Mirroring = (f6 & 8) != 0 ? "four-screen" : (f6 & 1) != 0 ? "vertical" : "horizontal",
            Console = (f7 & 3) switch { 0 => "NES", 1 => "Vs. System", 2 => "PlayChoice-10", _ => "extended" },
            CpuBanks = Switch32.Contains(mapper) && banks >= 2 ? (banks - 2, banks - 1) : (0, banks - 1),
            Switchable = !Fixed.Contains(mapper) && banks > 2,
        };
        if (prg % PrgBank != 0) rom.Issues.Add($"PRG-ROM is {prg:N0} bytes, not whole 16 KiB banks");
        long need = rom.ChrOffset + chr;
        if (data.Length < rom.ChrOffset) rom.Issues.Add($"the file ends at {data.Length:N0}, inside PRG-ROM (it ends at {rom.ChrOffset:N0})");
        else if (data.Length < need) rom.Issues.Add($"the file ends at {data.Length:N0}, inside CHR-ROM (it ends at {need:N0})");
        else if (data.Length > need) rom.Issues.Add($"{data.Length - need:N0} bytes follow CHR-ROM");
        if (data.Length >= rom.PrgOffset + (long)(rom.CpuBanks.High + 1) * PrgBank)
        {
            var cpu = rom.CpuView(data);
            rom.Nmi = BinaryPrimitives.ReadUInt16LittleEndian(cpu.AsSpan(0x7FFA));
            rom.Reset = BinaryPrimitives.ReadUInt16LittleEndian(cpu.AsSpan(0x7FFC));
            rom.Irq = BinaryPrimitives.ReadUInt16LittleEndian(cpu.AsSpan(0x7FFE));
            if (rom.Reset < CpuBase) rom.Issues.Add($"the reset vector 0x{rom.Reset:X4} is outside PRG-ROM");
        }
        return rom;
    }

    // NES 2.0 sizes: an MSB nibble of 0xF selects the exponent-multiplier form.
    private static long Size(byte lsb, int msb, int unit) =>
        msb == 0xF ? (1L << Math.Min(lsb >> 2, 40)) * ((lsb & 3) * 2 + 1) : ((long)msb << 8 | lsb) * unit;

    /// <summary>The 32 KiB the CPU reads at 0x8000: the two power-on banks, one bank twice for a 16 KiB image.</summary>
    public byte[] CpuView(ReadOnlySpan<byte> data)
    {
        var view = new byte[CpuWindow];
        data.Slice((int)(PrgOffset + (long)CpuBanks.Low * PrgBank), PrgBank).CopyTo(view);
        data.Slice((int)(PrgOffset + (long)CpuBanks.High * PrgBank), PrgBank).CopyTo(view.AsSpan(PrgBank));
        return view;
    }
}

/// <summary>An iNES ROM as files: the CPU's view of PRG-ROM at 0x8000, each PRG bank, CHR-ROM and the trainer.</summary>
internal sealed class InesRomReader : IContainerReader
{
    public string Kind => "ines rom";

    public bool Accepts(ReadOnlySpan<byte> data, string name) => InesRom.Looks(data);

    public ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        InesRom rom;
        try { rom = InesRom.Read(data); }
        catch (InvalidDataException ex) { throw new ToolError(ErrorCode.MalformedInput, $"{name}: {ex.Message}."); }
        var items = new List<ExtractedItem>();
        var entries = new List<ContainerEntry>();
        var notes = new List<string>
        {
            $"{(rom.Nes2 ? "NES 2.0" : "iNES")} ROM image, mapper {rom.Mapper}" + (rom.Submapper > 0 ? $".{rom.Submapper}" : "") +
            $", {rom.PrgSize / 1024:N0} KiB PRG-ROM, {rom.ChrSize / 1024:N0} KiB CHR-ROM, {rom.Mirroring} mirroring" +
            (rom.Battery ? ", battery-backed PRG-RAM" : "") + (rom.Console != "NES" ? $", {rom.Console}" : ""),
        };
        notes.AddRange(rom.Issues);
        void Add(string path, long start, long length, string detail)
        {
            ct.ThrowIfCancellationRequested();
            entries.Add(new ContainerEntry(path, length, detail));
            if (start + length > data.Length || items.Count >= limits.MaxItems) return;
            items.Add(new ExtractedItem(path, data.AsSpan((int)start, (int)length).ToArray(), detail));
        }
        int banks = (int)(rom.PrgSize / InesRom.PrgBank);
        if (data.Length >= rom.PrgOffset + (long)(rom.CpuBanks.High + 1) * InesRom.PrgBank)
        {
            var (low, high) = rom.CpuBanks;
            string shown = low == high ? $"PRG bank {low} at 0x8000 and its mirror at 0xC000" : $"PRG banks {low} at 0x8000 and {high} at 0xC000";
            var cpu = rom.CpuView(data);
            entries.Add(new ContainerEntry("prg-cpu.bin", cpu.Length, $"the CPU's 0x8000-0xFFFF: {shown}"));
            items.Add(new ExtractedItem("prg-cpu.bin", cpu, $"the CPU's 0x8000-0xFFFF: {shown}"));
            notes.Add($"Vectors: NMI 0x{rom.Nmi:X4}, reset 0x{rom.Reset:X4}, IRQ 0x{rom.Irq:X4}. Load prg-cpu.bin with format=raw arch=6502 base=0x8000 entry=0x{rom.Reset:X4}.");
            if (rom.Switchable) notes.Add($"Mapper {rom.Mapper} switches PRG banks: prg-cpu.bin shows the power-on banks; the other {banks - (low == high ? 1 : 2)} are prg-bank-N.bin.");
        }
        if (banks > 2)
            for (int b = 0; b < banks; b++) Add($"prg-bank-{b}.bin", rom.PrgOffset + (long)b * InesRom.PrgBank, InesRom.PrgBank, $"PRG-ROM bank {b} (16 KiB)");
        if (rom.HasTrainer) Add("trainer.bin", InesRom.HeaderSize, InesRom.TrainerSize, "trainer, loaded at 0x7000");
        if (rom.ChrSize > 0) Add("chr-rom.bin", rom.ChrOffset, rom.ChrSize, $"CHR-ROM ({rom.ChrSize / 1024:N0} KiB)");
        return new ContainerContents("ines rom", items, notes) { Entries = entries };
    }
}
