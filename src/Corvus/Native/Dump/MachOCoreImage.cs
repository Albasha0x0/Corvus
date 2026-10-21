using System.Text;
using Corvus.Native.MachO;

namespace Corvus.Native.Dump;

/// <summary>
/// A module of a Mach-O core as the namer reads it: the function symbols of the file matched by UUID, else of the
/// LC_SYMTAB the core's memory holds (through the image's __LINKEDIT). Apple's ABIs keep frame records, so the walk
/// needs no unwind data.
/// </summary>
internal static class MachOCoreImage
{
    private const int MaxHeaderBytes = 0x8000;
    private const int MaxSymbols = 1 << 18;

    /// <summary>The module's file: its recorded path (on macOS), then each folder by file name and as a sysroot; a file whose LC_UUID equals the core's matches.</summary>
    public static (string? Path, bool Matches, string Detail) Find(CoreModule module, IReadOnlyList<string> directories, Func<string, MachOFile?> open)
    {
        string name = module.Module.Path.Split('/')[^1];
        var why = new StringBuilder();
        string? existing = null;
        foreach (var path in CoreImage.Candidates(module.Module.Path, directories, OperatingSystem.IsMacOS()))
        {
            existing ??= path;
            if (open(path) is not { } file) { why.Append($"{path}: not a Mach-O image of the core's CPU; "); continue; }
            if (module.BuildId == null) return (path, true, $"matched by name (the core does not hold the module's UUID{(file.BuildId != null ? $"; the file's is {file.BuildId}" : "")})");
            if (string.Equals(file.BuildId, module.BuildId, StringComparison.OrdinalIgnoreCase)) return (path, true, $"UUID {module.BuildId} matches");
            why.Append($"{path}: UUID {file.BuildId ?? "none"}, the core's is {module.BuildId}; ");
        }
        string detail = why.Length > 0 ? why.ToString().TrimEnd(' ', ';') : name.Length > 0 ? $"no file named {name} in {string.Join(", ", directories)}" : "no file name";
        return (existing, false, detail);
    }

    /// <summary>The module's file on disk, its __TEXT at the module's base.</summary>
    public static CoreImage FromFile(MachOFile file, DumpModule module, IProcessMemory memory, string path, string detail)
    {
        var symbols = file.Symbols.Where(s => s.Kind == ImageSymbolKind.Function)
            .Select(s => new CoreSymbol(module.Base + s.Rva, s.Size, Name(s.Name), s.Binding == ImageSymbolBinding.Local ? "symbol" : "export")).ToList();
        symbols.Sort((a, b) => a.Start.CompareTo(b.Start));
        return CoreImage.FromSymbols(module, memory, symbols,
            (address, destination) => address >= module.Base && address - module.Base < file.SizeOfImage ? file.Read((uint)(address - module.Base), destination) : 0,
            "disk", path, detail);
    }

    /// <summary>The module as the core holds it: N_SECT symbols inside __TEXT; null when its Mach-O header is not captured.</summary>
    public static CoreImage? FromMemory(IProcessMemory memory, DumpModule module, string detail)
    {
        var bytes = new byte[MaxHeaderBytes];
        var h = new ByteView(bytes, 0, memory.ReadMemory(module.Base, bytes), false);
        if (h.Length < 32 || h.U32(0) != 0xFEEDFACF) return null;
        ulong textVm = 0, textSize = 0, linkVm = 0, linkOff = 0;
        uint symoff = 0, nsyms = 0, stroff = 0, strsize = 0;
        long at = 32;
        for (uint i = 0, n = h.U32(16); i < n && h.Has(at, 8); i++)
        {
            uint cmd = h.U32(at), size = h.U32(at + 4);
            if (size < 8 || !h.Has(at, size)) break;
            if (cmd == 0x19 && size >= 72)
            {
                string? seg = h.CString(at + 8, 16);
                if (seg == "__TEXT") (textVm, textSize) = (h.U64(at + 24), h.U64(at + 32));
                else if (seg == "__LINKEDIT") (linkVm, linkOff) = (h.U64(at + 24), h.U64(at + 40));
            }
            else if (cmd == 0x2 && size >= 24) (symoff, nsyms, stroff, strsize) = (h.U32(at + 8), h.U32(at + 12), h.U32(at + 16), h.U32(at + 20));
            at += size;
        }
        if (textSize == 0) return null;
        ulong slide = module.Base - textVm;
        var symbols = new List<CoreSymbol>();
        if (nsyms > 0 && linkVm != 0 && symoff >= linkOff && stroff >= linkOff)
        {
            // A file offset in __LINKEDIT is read at its runtime address.
            ulong Linked(uint offset) => slide + linkVm + (offset - linkOff);
            var table = new byte[(int)Math.Min(nsyms, MaxSymbols) * 16];
            var strings = new byte[(int)Math.Min(strsize, 1u << 24)];
            int tn = memory.ReadMemory(Linked(symoff), table);
            var s = new ByteView(strings, 0, memory.ReadMemory(Linked(stroff), strings), false);
            var t = new ByteView(table, 0, tn, false);
            for (long e = 0; e + 16 <= t.Length; e += 16)
            {
                byte type = t.U8(e + 4);
                ulong value = t.U64(e + 8);
                // Keep N_SECT entries inside __TEXT that are not debug (stab)
                // entries.
                if ((type & 0xE0) != 0 || (type & 0x0E) != 0x0E || value < textVm || value - textVm >= textSize) continue;
                if (s.CString(t.U32(e), 1024) is not { Length: > 0 } text) continue;
                symbols.Add(new CoreSymbol(value + slide, 0, Name(text), (type & 1) != 0 ? "export" : "symbol"));
            }
            symbols.Sort((a, b) => a.Start.CompareTo(b.Start));
        }
        return CoreImage.FromSymbols(module, memory, symbols, null, "core_memory", null, detail);
    }

    /// <summary>A C-level name: Mach-O symbols carry a leading underscore.</summary>
    private static string Name(string symbol) => symbol.Length > 1 && symbol[0] == '_' ? symbol[1..] : symbol;
}
