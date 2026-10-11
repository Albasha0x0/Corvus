using System.Buffers.Binary;
using Corvus.Native.Pe;

namespace Corvus.Native.Elf;

/// <summary>A PLT stub and the GOT slot it jumps through; <see cref="Symbol"/> is the slot's JUMP_SLOT symbol.</summary>
public sealed record ElfPltEntry(uint StubRva, uint SlotRva, string? Symbol);

public sealed partial class ElfFile
{
    private ImageArea<List<ElfPltEntry>> plt = null!;

    /// <summary>
    /// PLT stubs matched to their JUMP_SLOT slots by decoding the stub patterns (AArch64 ADRP/LDR/BR, x86-64 and x86
    /// indirect JMP, ARM ADD/ADD/LDR), sorted by stub address. Stubs are looked for in .plt* sections, or in the
    /// executable segments when there are no section headers.
    /// </summary>
    public IReadOnlyList<ElfPltEntry> PltEntries => plt.Value;

    private void InitAreas()
    {
        dynamic = new("dynamic", ParseDynamic, new DynamicInfo());
        relocations = new("relocations", ParseRelocations, RelocationInfo.Empty);
        symbols = new("symbols", ParseSymbols, SymbolInfo.Empty);
        notes = new("notes", ParseNotes, []);
        unwind = new("unwind", ParseUnwind, []);
        plt = new("plt", ParsePlt, []);
    }

    private List<ElfPltEntry> ParsePlt(IssueLog log)
    {
        var slots = new Dictionary<uint, string?>();
        foreach (var r in Relocations)
            if (r.Kind == ElfRelocationKind.JumpSlot && TryVaToRva(r.Offset, out uint rva)) slots.TryAdd(rva, r.Symbol);
        if (slots.Count == 0) return [];
        IEnumerable<(uint Rva, uint Size)> ranges = sectionHeaders.Count > 1
            ? sectionHeaders.Where(s => s.IsExecutable && s.Name.StartsWith(".plt", StringComparison.Ordinal) && TryVaToRva(s.Address, out _))
                .Select(s => ((uint)(s.Address - ImageBase), (uint)Math.Min(s.Size, uint.MaxValue)))
            : sections.Where(s => s.IsExecutable).Select(s => (s.Rva, s.VirtualSize));
        ulong pltGot = dynamic.Value.Tag(3) ?? 0;
        var found = new Dictionary<uint, ElfPltEntry>();
        var budget = new WorkBudget(log);
        foreach (var (start, size) in ranges)
        {
            var code = new byte[Math.Min(size, 64u << 20)];
            int n = ReadRaw(start, code);
            int stride = Machine is ElfNames.EmAarch64 or ElfNames.EmArm ? 4 : 1;
            for (int i = 0; i < n && budget.Step(); i += stride)
            {
                if (Match(code.AsSpan(0, n), i, start, pltGot) is not { } m || !slots.TryGetValue(m.Slot, out var symbol)) continue;
                found.TryAdd(m.Stub, new ElfPltEntry(m.Stub, m.Slot, symbol));
            }
        }
        return [.. found.Values.OrderBy(e => e.StubRva)];
    }

    /// <summary>The stub starting at (or matched at) <paramref name="i"/> and the slot it loads, or null.</summary>
    private (uint Stub, uint Slot)? Match(ReadOnlySpan<byte> code, int i, uint baseRva, ulong pltGot)
    {
        uint at = baseRva + (uint)i;
        switch (Machine)
        {
            case ElfNames.EmAarch64:
            {
                // adrp x16, page; ldr x17, [x16, #off]; add x16, x16, #off; br x17 (optionally after bti c)
                uint adrp = Word(code, i, BigEndian), ldr = Word(code, i + 4, BigEndian);
                if ((adrp & 0x9F00001F) != 0x90000010 || (ldr & 0xFFC003FF) != 0xF9400211) return null;
                long imm = ((long)((adrp >> 5) & 0x7FFFF) << 2 | ((adrp >> 29) & 3)) << 43 >> 31;
                ulong page = ((ImageBase + at) & ~0xFFFUL) + (ulong)imm;
                ulong slot = page + ((ldr >> 10) & 0xFFF) * 8;
                uint stub = i >= 4 && Word(code, i - 4, BigEndian) == 0xD503245F ? at - 4 : at;
                return TryVaToRva(slot, out uint rva) ? (stub, rva) : null;
            }
            case ElfNames.EmX64:
            {
                // jmp [rip + disp32], in .plt (ff 25) or .plt.sec (f2 ff 25 after endbr64)
                if (i + 6 > code.Length || code[i] != 0xFF || code[i + 1] != 0x25) return null;
                long target = (long)at + 6 + BinaryPrimitives.ReadInt32LittleEndian(code[(i + 2)..]);
                uint stub = i >= 5 && code[i - 1] == 0xF2 && code[(i - 5)..(i - 1)].SequenceEqual(EndBr64) ? at - 5
                    : i >= 4 && code[(i - 4)..i].SequenceEqual(EndBr64) ? at - 4 : at;
                return target is >= 0 and <= uint.MaxValue ? (stub, (uint)target) : null;
            }
            case ElfNames.EmX86:
            {
                // jmp [ebx + disp32] (PIC, ebx = GOT) or jmp [abs32]
                if (i + 6 > code.Length || code[i] != 0xFF || code[i + 1] is not (0xA3 or 0x25)) return null;
                uint disp = BinaryPrimitives.ReadUInt32LittleEndian(code[(i + 2)..]);
                ulong slot = code[i + 1] == 0xA3 ? (pltGot + disp) & 0xFFFFFFFF : disp;
                return TryVaToRva(slot, out uint rva) ? (at, rva) : null;
            }
            case ElfNames.EmArm:
            {
                // add ip, pc, #imm; add ip, ip, #imm; ldr pc, [ip, #imm]!
                uint a = Word(code, i, BigEndian), b = Word(code, i + 4, BigEndian), c = Word(code, i + 8, BigEndian);
                if ((a & 0xFFFFF000) != 0xE28FC000 || (b & 0xFFFFF000) != 0xE28CC000 || (c & 0xFFFFF000) != 0xE5BCF000) return null;
                ulong slot = ImageBase + at + 8 + ArmImmediate(a) + ArmImmediate(b) + (c & 0xFFF);
                return TryVaToRva(slot & 0xFFFFFFFF, out uint rva) ? (at, rva) : null;
            }
        }
        return null;
    }

    private static uint Word(ReadOnlySpan<byte> code, int at, bool bigEndian) =>
        at >= 0 && at + 4 <= code.Length ? (bigEndian ? BinaryPrimitives.ReadUInt32BigEndian(code[at..]) : BinaryPrimitives.ReadUInt32LittleEndian(code[at..])) : 0;

    private static ReadOnlySpan<byte> EndBr64 => [0xF3, 0x0F, 0x1E, 0xFA];

    /// <summary>An ARM data-processing immediate: imm8 rotated right by twice the rotate field.</summary>
    private static uint ArmImmediate(uint insn) => uint.RotateRight(insn & 0xFF, (int)((insn >> 8) & 0xF) * 2);
}
