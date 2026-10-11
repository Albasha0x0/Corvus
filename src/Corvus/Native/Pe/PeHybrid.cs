using System.Buffers.Binary;

namespace Corvus.Native.Pe;

/// <summary>A code range of a hybrid image's CHPE code map: ARM64, ARM64EC or x64 code.</summary>
public sealed record HybridCodeRange(uint Rva, uint Length, string Arch);

/// <summary>
/// An ARM64X or ARM64EC image. ARM64X: an ARM64 file (native view) whose ARM64X dynamic relocations turn its headers into an
/// x64 view (<see cref="ViewMachine"/>, <see cref="ViewEntryRva"/>, the data directories it replaces). ARM64EC: an x64 file holding
/// ARM64EC code. Both carry CHPE metadata: its version, the code map, the alternate entry point and the auxiliary IAT.
/// </summary>
public sealed record PeHybrid(string Kind, uint MetadataVersion, IReadOnlyList<HybridCodeRange> CodeRanges, uint? AlternateEntryRva, uint? AuxiliaryIatRva,
    int Arm64XFixups, string? ViewMachine, uint? ViewEntryRva, IReadOnlyList<string> ViewDirectories)
{
    private const int MaxRanges = 1 << 16;
    private const ulong Arm64XSymbol = 6;

    /// <summary>The hybrid metadata of <paramref name="pe"/>, or null for an ordinary image.</summary>
    public static PeHybrid? Of(PeFile pe)
    {
        if (pe.LoadConfig is not { ChpeMetadataPointer: not 0 } lc || !pe.Is64Bit || !pe.TryVaToRva(lc.ChpeMetadataPointer, out uint meta)) return null;
        string kind = pe.Coff.Machine switch { 0xAA64 => "ARM64X", 0x8664 => "ARM64EC", _ => "" };
        if (kind.Length == 0) return null;
        Span<byte> m = stackalloc byte[80];
        if (pe.Read(meta, m) < 64) return null;
        uint version = U32(m, 0), codeMap = U32(m, 4), codeMapCount = U32(m, 8), alternateEntry = U32(m, 40), auxIat = U32(m, 44);
        var ranges = new List<HybridCodeRange>();
        var entry = new byte[8];
        for (uint i = 0; i < Math.Min(codeMapCount, MaxRanges); i++)
        {
            if (pe.Read(codeMap + i * 8, entry) < 8) break;
            uint start = U32(entry, 0), length = U32(entry, 4);
            ranges.Add(new HybridCodeRange(start & ~3u, length, (start & 3) switch { 0 => "ARM64", 1 => "ARM64EC", 2 => "x64", _ => "unknown" }));
        }
        var (fixups, machine, entryRva, directories) = Arm64XView(pe);
        return new PeHybrid(kind, version, ranges, alternateEntry != 0 ? alternateEntry : null, auxIat != 0 ? auxIat : null, fixups,
            machine is { } mc ? PeNames.Machine(mc) : null, entryRva, directories);
    }

    private static uint U32(ReadOnlySpan<byte> b, int at) => BinaryPrimitives.ReadUInt32LittleEndian(b[at..]);

    /// <summary>
    /// The ARM64X dynamic relocations (IMAGE_DYNAMIC_RELOCATION_TABLE version 1, symbol 6): how many, and what they write into the
    /// headers: the view's machine, entry point and the data directories it replaces.
    /// </summary>
    private static (int Fixups, ushort? Machine, uint? Entry, List<string> Directories) Arm64XView(PeFile pe)
    {
        var directories = new List<string>();
        ushort? machine = null;
        uint? entry = null;
        int fixups = 0;
        var lcDir = pe.Directory(PeDirectory.LoadConfig);
        Span<byte> lc = stackalloc byte[232];
        if (lcDir.Rva == 0 || pe.Read(lcDir.Rva, lc) < 230 || U32(lc, 0) < 230) return (0, null, null, directories);
        uint tableOffset = U32(lc, 224);
        ushort sectionIndex = BinaryPrimitives.ReadUInt16LittleEndian(lc[228..]);
        if (sectionIndex == 0 || sectionIndex > pe.Sections.Count) return (0, null, null, directories);
        uint table = pe.Sections[sectionIndex - 1].Rva + tableOffset;
        Span<byte> head = stackalloc byte[8];
        if (pe.Read(table, head) < 8 || U32(head, 0) != 1) return (0, null, null, directories);
        uint size = Math.Min(U32(head, 4), 1u << 24);
        var body = new byte[size];
        int n = pe.Read(table + 8, body);
        uint machineRva = pe.PeHeaderOffset + 4, entryRva = (uint)pe.OptionalHeaderOffset + 16;
        uint dirs = (uint)pe.OptionalHeaderOffset + 112;
        for (int p = 0; p + 12 <= n;)
        {
            ulong symbol = BinaryPrimitives.ReadUInt64LittleEndian(body.AsSpan(p));
            int relocSize = (int)U32(body, p + 8);
            p += 12;
            int end = (int)Math.Min((long)p + relocSize, n);
            if (symbol == Arm64XSymbol)
                for (int b = p; b + 8 <= end;)
                {
                    uint page = U32(body, b), blockSize = U32(body, b + 4);
                    if (blockSize < 8) break;
                    int blockEnd = (int)Math.Min((long)b + blockSize, end);
                    for (int e = b + 8; e + 2 <= blockEnd;)
                    {
                        ushort h = BinaryPrimitives.ReadUInt16LittleEndian(body.AsSpan(e));
                        e += 2;
                        uint at = page + (uint)(h & 0xFFF);
                        int type = (h >> 12) & 3, meta = h >> 14;
                        if (type == 0 && h == 0) continue; // block padding
                        fixups++;
                        if (type == 1)
                        {
                            int width = 1 << meta;
                            if (e + width > blockEnd) break;
                            ulong value = width switch { 1 => body[e], 2 => BinaryPrimitives.ReadUInt16LittleEndian(body.AsSpan(e)), 4 => U32(body, e), _ => BinaryPrimitives.ReadUInt64LittleEndian(body.AsSpan(e)) };
                            e += width;
                            if (at == machineRva && width == 2) machine = (ushort)value;
                            else if (at == entryRva && width == 4) entry = (uint)value;
                            else if (at >= dirs && at < dirs + 16 * 8) Directory(directories, (int)((at - dirs) / 8));
                        }
                        else if (type == 2)
                        {
                            e += 2;
                            if (at >= dirs && at < dirs + 16 * 8) Directory(directories, (int)((at - dirs) / 8));
                        }
                    }
                    b += (int)blockSize;
                }
            p = end;
        }
        return (fixups, machine, entry, directories);
    }

    private static void Directory(List<string> into, int index)
    {
        var name = index switch
        {
            0 => "export", 1 => "import", 2 => "resource", 3 => "exception", 4 => "certificate", 5 => "base relocation", 6 => "debug",
            9 => "TLS", 10 => "load config", 11 => "bound import", 12 => "IAT", 13 => "delay import", 14 => "CLR", _ => $"directory {index}",
        };
        if (!into.Contains(name)) into.Add(name);
    }
}
