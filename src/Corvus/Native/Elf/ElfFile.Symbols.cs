using Corvus.Core;
using Corvus.Core.Firmware;
using Corvus.Native.Pe;

namespace Corvus.Native.Elf;

public sealed partial class ElfFile
{
    private sealed record SymbolInfo(List<ElfSymbol> Static, List<ImageSymbol> Image, List<NativeExport> Exports, List<(uint Rva, char Kind)> Mapping)
    {
        public static readonly SymbolInfo Empty = new([], [], [], []);
    }

    private ImageArea<SymbolInfo> symbols = null!;

    /// <summary>.symtab entries (index 0 included); empty for stripped files.</summary>
    public IReadOnlyList<ElfSymbol> StaticSymbols => symbols.Value.Static;
    /// <summary>
    /// Defined function and object symbols of .dynsym, .symtab and the MiniDebugInfo .symtab (.gnu_debugdata), sorted by
    /// RVA; ARM mapping symbols are left out.
    /// </summary>
    public IReadOnlyList<ImageSymbol> Symbols => symbols.Value.Image;
    /// <summary>Defined global and weak dynamic symbols, in .dynsym order (ordinal 0).</summary>
    public IReadOnlyList<NativeExport> Exports => symbols.Value.Exports;
    /// <summary>ARM and AArch64 mapping symbols ($a, $t, $x code; $d data) of .symtab, sorted by RVA.</summary>
    public IReadOnlyList<(uint Rva, char Kind)> MappingSymbols => symbols.Value.Mapping;

    private SymbolInfo ParseSymbols(IssueLog log)
    {
        var dyn = dynamic.Value.Symbols;
        var result = new SymbolInfo([], [], [], []);
        var budget = new WorkBudget(log);
        if (sectionHeaders.FirstOrDefault(s => s.Type == 2) is { } symtab && symtab.Link < sectionHeaders.Count)
        {
            var strtab = sectionHeaders[(int)symtab.Link];
            var strings = new ByteView(data, (long)Math.Min(strtab.Offset, long.MaxValue / 2), (long)Math.Min(strtab.Size, int.MaxValue), BigEndian);
            ulong entry = Is64Bit ? 24u : 16u;
            ulong count = Math.Min(symtab.Size / entry, MaxSymbols);
            if (symtab.Offset + symtab.Size > (ulong)data.Length) log.Add($".symtab at 0x{symtab.Offset:X}+0x{symtab.Size:X} extends past the end of the file");
            var table = new ByteView(data, (long)Math.Min(symtab.Offset, long.MaxValue / 2), (long)Math.Min(count * entry, int.MaxValue), BigEndian);
            count = Math.Min(count, (ulong)(table.Length / (long)entry));
            for (int i = 0; i < (int)count && budget.Step(); i++) result.Static.Add(ReadSymbol(table, i * (long)entry, i, strings, log, budget));
        }

        var mini = MiniDebugSymbols(log);
        var seen = new HashSet<(string, uint)>();
        foreach (var s in dyn.Concat(result.Static).Concat(mini))
        {
            // absolute symbols (version definitions such as V1.0 = 0) are values, not addresses in the image
            if (!s.IsDefined || s.Name.Length == 0 || s.SectionIndex == ElfSymbol.Absolute || s.Type is ElfSymbol.TypeSection or ElfSymbol.TypeFile or ElfSymbol.TypeTls) continue;
            var va = s.IsFunction ? CodeAddress(s.Value) : s.Value;
            if (!TryVaToRva(va, out uint rva)) continue;
            if (Machine is ElfNames.EmArm or ElfNames.EmAarch64 && s.Name[0] == '$' && s.Name.Length >= 2 && s.Name[1] is 'a' or 't' or 'd' or 'x'
                && (s.Name.Length == 2 || s.Name[2] == '.'))
            {
                result.Mapping.Add((rva, s.Name[1]));
                continue;
            }
            if (Machine == ElfNames.EmArm && s.IsFunction) rva &= ~1u;
            if (!seen.Add((s.Name, rva))) continue;
            var kind = s.IsFunction ? ImageSymbolKind.Function : s.Type is ElfSymbol.TypeObject or ElfSymbol.TypeCommon ? ImageSymbolKind.Object : ImageSymbolKind.Other;
            var binding = s.Binding switch { ElfSymbol.BindLocal => ImageSymbolBinding.Local, ElfSymbol.BindWeak => ImageSymbolBinding.Weak, _ => ImageSymbolBinding.Global };
            // MiniDebugInfo section indexes are the embedded file's.
            string? section = va == s.Value && s.SectionIndex < sectionHeaders.Count && !mini.Contains(s) && s.SectionIndex is > 0 and < 0xFF00 ? sectionHeaders[s.SectionIndex].Name : SectionAt(rva)?.Name;
            result.Image.Add(new ImageSymbol(s.Name, rva, s.Size, kind, binding, section, s.Version));
        }
        result.Image.Sort((a, b) => a.Rva != b.Rva ? a.Rva.CompareTo(b.Rva) : string.CompareOrdinal(a.Name, b.Name));
        result.Mapping.Sort((a, b) => a.Rva.CompareTo(b.Rva));

        foreach (var s in dyn)
        {
            if (!s.IsDefined || s.Name.Length == 0 || s.SectionIndex == ElfSymbol.Absolute || s.Binding == ElfSymbol.BindLocal || s.Visibility is 1 or 2) continue;
            if (s.Type is ElfSymbol.TypeSection or ElfSymbol.TypeFile or ElfSymbol.TypeTls) continue;
            if (!TryVaToRva(s.IsFunction ? CodeAddress(s.Value) : s.Value, out uint rva)) continue;
            if (Machine == ElfNames.EmArm && s.IsFunction) rva &= ~1u;
            if (result.Exports.Count >= PeLimits.MaxExports)
            {
                log.Add($"more than {PeLimits.MaxExports} exports; the rest are not listed");
                break;
            }
            result.Exports.Add(new NativeExport(s.Name, 0, rva, null, s.Version == null ? null : (s.VersionHidden ? "@" : "@@") + s.Version));
        }
        return result;
    }

    /// <summary>Most bytes of .gnu_debugdata unpacked.</summary>
    private const long MaxDebugData = 64L << 20;
    private const string MiniDebugPath = ".gnu_debugdata";

    /// <summary>
    /// The .symtab of the xz-compressed ELF in .gnu_debugdata (MiniDebugInfo, which Android and Fedora libraries keep after
    /// stripping), at the outer file's addresses; empty when there is none or it does not decode, which the log names.
    /// </summary>
    private HashSet<ElfSymbol> MiniDebugSymbols(IssueLog log)
    {
        // One level only: an embedded file's own .gnu_debugdata is not read, which bounds the work.
        if (Path == MiniDebugPath || sectionHeaders.FirstOrDefault(h => h.Name == ".gnu_debugdata" && h.Type != 8) is not { } section) return [];
        if (section.Offset + section.Size > (ulong)data.Length || section.Size > int.MaxValue)
        {
            log.Add($".gnu_debugdata at 0x{section.Offset:X}+0x{section.Size:X} extends past the end of the file");
            return [];
        }
        try
        {
            var inner = FromBytes(FsCodec.DecodeStream("xz", data.AsSpan((int)section.Offset, (int)section.Size), MaxDebugData), MiniDebugPath);
            return new HashSet<ElfSymbol>(inner.StaticSymbols, ReferenceEqualityComparer.Instance);
        }
        catch (Exception e) when (e is InvalidDataException or ToolError)
        {
            log.Add($".gnu_debugdata is not read: {e.Message}");
            return [];
        }
    }
}
