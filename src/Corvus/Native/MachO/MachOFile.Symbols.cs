using Corvus.Native.Pe;

namespace Corvus.Native.MachO;

/// <summary>An nlist entry. <see cref="Section"/> is the 1-based index into <see cref="MachOFile.AllSections"/> (0 when none).</summary>
public sealed record MachOSymbol(int Index, string Name, byte Type, byte Section, ushort Description, ulong Value)
{
    public bool IsDebug => (Type & 0xE0) != 0;
    public bool IsExternal => (Type & 0x01) != 0;
    public bool IsDefined => !IsDebug && (Type & 0x0E) is 0x0E or 0x02;
    public bool IsUndefined => !IsDebug && (Type & 0x0E) == 0;
    public bool IsWeakDefinition => (Description & 0x80) != 0;
    /// <summary>Two-level namespace library ordinal of an undefined symbol: 0 self, -1 main executable, -2 flat lookup, n the nth dylib.</summary>
    public int LibraryOrdinal => (Description >> 8) switch { 0xFE => -2, 0xFF => -1, var o => o };
}

public sealed partial class MachOFile
{
    private const int MaxSymbols = 1 << 22;

    private sealed record SymbolInfo(List<MachOSymbol> All, uint[] Indirect, List<ImageSymbol> Image, List<(uint Rva, string Symbol)> Stubs, List<NativeImport> SlotImports)
    {
        public static readonly SymbolInfo Empty = new([], [], [], [], []);
    }

    private ImageArea<SymbolInfo> symbolArea = null!;

    /// <summary>The symbol table (LC_SYMTAB) in table order, debug entries included.</summary>
    public IReadOnlyList<MachOSymbol> SymbolTable => symbolArea.Value.All;
    /// <summary>The indirect symbol table: symbol indexes (or INDIRECT_SYMBOL_LOCAL / _ABS) for stubs and pointer sections.</summary>
    public IReadOnlyList<uint> IndirectSymbols => symbolArea.Value.Indirect;
    /// <summary>Defined, non-debug symbols with section addresses, sorted by RVA.</summary>
    public IReadOnlyList<ImageSymbol> Symbols => symbolArea.Value.Image;
    /// <summary>Symbol stubs (__stubs, __auth_stubs, S_SYMBOL_STUBS) and the symbol each jumps to, by stub address.</summary>
    public IReadOnlyList<(uint Rva, string Symbol)> Stubs => symbolArea.Value.Stubs;

    private SymbolInfo ParseSymbols(IssueLog log)
    {
        var info = new SymbolInfo([], [], [], [], []);
        var budget = new WorkBudget(log);
        if (commands.OfType<MachOSymtabCommand>().FirstOrDefault() is { } symtab)
        {
            int entry = Is64Bit ? 16 : 12;
            uint count = Math.Min(symtab.SymbolCount, MaxSymbols);
            var table = FileWindow(symtab.SymbolOffset, (long)count * entry);
            var strings = FileWindow(symtab.StringOffset, symtab.StringSize);
            if (table.Length < (long)count * entry) log.Add($"the symbol table ({symtab.SymbolCount} entries at 0x{symtab.SymbolOffset:X}) extends past the end of the file");
            if (strings.Length < symtab.StringSize) log.Add($"the string table at 0x{symtab.StringOffset:X}+0x{symtab.StringSize:X} extends past the end of the file");
            count = (uint)Math.Min(count, table.Length / entry);
            int badNames = 0;
            for (int i = 0; i < count && budget.Step(); i++)
            {
                long at = (long)i * entry;
                uint strx = table.U32(at);
                string name = "";
                if (strx != 0)
                {
                    if (strings.CString(strx, MaxNameLength) is { } n && budget.Chars(n.Length)) name = n;
                    else badNames++;
                }
                info.All.Add(new MachOSymbol(i, name, table.U8(at + 4), table.U8(at + 5), table.U16(at + 6), table.Word(at + 8, Is64Bit)));
            }
            if (badNames > 0) log.Add($"{badNames} symbol names lie outside the string table");
        }

        if (commands.OfType<MachODysymtabCommand>().FirstOrDefault() is { IndirectCount: > 0 } dysym)
        {
            uint count = Math.Min(dysym.IndirectCount, MaxSymbols);
            var table = FileWindow(dysym.IndirectOffset, count * 4L);
            if (table.Length < count * 4L) log.Add($"the indirect symbol table ({dysym.IndirectCount} entries at 0x{dysym.IndirectOffset:X}) extends past the end of the file");
            var indirect = new uint[table.Length / 4];
            for (int i = 0; i < indirect.Length; i++) indirect[i] = table.U32(i * 4L);
            info = info with { Indirect = indirect };
        }

        var dylibs = Dependencies;
        foreach (var s in info.All)
        {
            if (!s.IsDefined || s.Name.Length == 0 || (s.Type & 0x0E) != 0x0E || !TryVaToRva(s.Value, out uint rva)) continue;
            var section = s.Section > 0 && s.Section <= AllSections.Count ? AllSections[s.Section - 1] : null;
            if (Arch == NativeArch.Arm && (s.Description & 0x8) != 0) rva &= ~1u; // N_ARM_THUMB_DEF
            var kind = section?.HasInstructions == true ? ImageSymbolKind.Function : section != null ? ImageSymbolKind.Object : ImageSymbolKind.Other;
            var binding = !s.IsExternal ? ImageSymbolBinding.Local : s.IsWeakDefinition ? ImageSymbolBinding.Weak : ImageSymbolBinding.Global;
            info.Image.Add(new ImageSymbol(s.Name, rva, 0, kind, binding, section?.FullName));
        }
        info.Image.Sort((a, b) => a.Rva != b.Rva ? a.Rva.CompareTo(b.Rva) : string.CompareOrdinal(a.Name, b.Name));

        // Stubs and pointer sections name their entries through the indirect table.
        string? Indirect(uint index) => index < info.Indirect.Length && info.Indirect[index] is var sym && (sym & 0xC0000000) == 0 && sym < info.All.Count
            ? info.All[(int)sym].Name : null;
        int pointer = Is64Bit ? 8 : 4;
        foreach (var s in AllSections)
        {
            if (!TryVaToRva(s.Address, out uint start)) continue;
            switch (s.Type)
            {
                case 0x8 when s.Reserved2 > 0:
                    for (ulong i = 0; i < s.Size / s.Reserved2 && i < MaxSymbols; i++)
                        if (Indirect(s.Reserved1 + (uint)i) is { } name) info.Stubs.Add((start + (uint)(i * s.Reserved2), name));
                    break;
                case 0x6 or 0x7 or 0x10:
                    for (ulong i = 0; i < s.Size / (ulong)pointer && i < MaxSymbols; i++)
                    {
                        uint index = s.Reserved1 + (uint)i;
                        if (index >= info.Indirect.Length || (info.Indirect[index] & 0xC0000000) != 0 || info.Indirect[index] >= info.All.Count) continue;
                        var sym = info.All[(int)info.Indirect[index]];
                        if (!sym.IsUndefined || sym.Name.Length == 0) continue;
                        info.SlotImports.Add(new NativeImport(MachONames.Library(sym.LibraryOrdinal, dylibs) ?? $"ordinal {sym.LibraryOrdinal}", sym.Name, null, 0,
                            start + (uint)(i * (ulong)pointer), s.Type != 0x6));
                    }
                    break;
            }
        }
        info.Stubs.Sort((a, b) => a.Rva.CompareTo(b.Rva));
        return info;
    }
}
