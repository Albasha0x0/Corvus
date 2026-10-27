using System.Text;

namespace Corvus.Native.Pe;

public sealed partial class PeFile
{
    /// <summary>Unstripped COFF symbols by RVA; i386 C names lose their leading underscore, as in PDB and DWARF.</summary>
    private IReadOnlyList<ImageSymbol> ParseSymbols(IssueLog log)
    {
        long table = Coff.PointerToSymbolTable;
        long count = Coff.NumberOfSymbols;
        if (table == 0 || count == 0) return [];
        if (table >= data.Length)
        {
            log.Add($"PointerToSymbolTable 0x{table:X} is past the end of the file", table);
            return [];
        }
        if (table + count * 18 > data.Length)
        {
            log.Add($"{count} symbols run past the end of the file; {(data.Length - table) / 18} read", table);
            count = (data.Length - table) / 18;
        }
        if (count > PeLimits.MaxSymbols)
        {
            log.Add($"{count} symbols; the first {PeLimits.MaxSymbols} are read", table);
            count = PeLimits.MaxSymbols;
        }
        long strings = table + count * 18;
        var symbols = new List<ImageSymbol>();
        for (long i = 0; i < count; i++)
        {
            long at = table + i * 18;
            int aux = U8(at + 17);
            short section = (short)U16(at + 12);
            ushort type = U16(at + 14);
            byte storage = U8(at + 16);
            uint value = U32(at + 8);
            i += aux;
            // IMAGE_SYM_CLASS_EXTERNAL or STATIC, defined in a section.
            if (storage is not (2 or 3) || section <= 0 || section > sections.Count) continue;
            var name = SymbolName(at, strings);
            if (name.Length == 0 || name[0] == '.' || name.StartsWith("__imp_", StringComparison.Ordinal)) continue;
            if (Arch == NativeArch.X86 && name.Length > 1 && name[0] == '_') name = name[1..];
            var s = sections[section - 1];
            bool function = (type & 0x30) == 0x20; // IMAGE_SYM_DTYPE_FUNCTION
            if (!function && s.IsExecutable) continue; // a code label, not data
            // Function definition auxiliary record: TotalSize at +4.
            ulong size = function && aux > 0 ? U32(at + 18 + 4) : 0;
            symbols.Add(new ImageSymbol(name, s.Rva + value, size, function ? ImageSymbolKind.Function : ImageSymbolKind.Object,
                storage == 2 ? ImageSymbolBinding.Global : ImageSymbolBinding.Local, s.Name));
        }
        symbols.Sort((x, y) => x.Rva.CompareTo(y.Rva));
        return symbols;
    }

    /// <summary>An 8-byte short name, or (first four bytes zero) an offset into the string table.</summary>
    private string SymbolName(long at, long strings)
    {
        if (U32(at) != 0)
        {
            var raw = data.AsSpan((int)at, 8);
            int len = raw.IndexOf((byte)0);
            return Encoding.UTF8.GetString(raw[..(len < 0 ? 8 : len)]);
        }
        long start = strings + U32(at + 4);
        if (start < strings + 4 || start >= data.Length) return "";
        var rest = data.AsSpan((int)start, (int)Math.Min(data.Length - start, PeLimits.MaxNameLength));
        int end = rest.IndexOf((byte)0);
        return end > 0 ? Encoding.UTF8.GetString(rest[..end]) : "";
    }
}
