using Corvus.Native.Msvc;

namespace Corvus.Native.Pdb;

/// <summary>One address the PDB names: the display name, the decorated public name when any, and what is there.</summary>
public sealed record PdbName(uint Rva, string Name, string? Decorated, bool IsFunction, uint Size, PdbSymbolKind Kind);

/// <summary>One name per address from a PDB: procedures over publics, global over local, code over data, then by name.</summary>
public static class PdbNaming
{
    public static IReadOnlyList<PdbName> Choose(PdbFile pdb, uint sizeOfImage = 0, CancellationToken ct = default)
    {
        var best = new Dictionary<uint, (PdbSymbol Sym, int Rank)>();
        var decorated = new Dictionary<uint, string>();
        var procSize = new Dictionary<uint, uint>();
        int n = 0;
        foreach (var s in pdb.Symbols)
        {
            if ((++n & 0xFFFF) == 0) ct.ThrowIfCancellationRequested();
            if (s.Rva is not { } rva || (sizeOfImage != 0 && rva >= sizeOfImage)) continue;
            if (s.IsPublic && IsDecorated(s.Name) && (!decorated.TryGetValue(rva, out var d) || string.CompareOrdinal(s.Name, d) < 0)) decorated[rva] = s.Name;
            if (s.Kind is PdbSymbolKind.GlobalProc or PdbSymbolKind.LocalProc && s.Size > 0) procSize[rva] = Math.Max(procSize.GetValueOrDefault(rva), s.Size);
            int rank = Rank(s.Kind);
            if (!best.TryGetValue(rva, out var cur) || rank < cur.Rank || (rank == cur.Rank && string.CompareOrdinal(s.Name, cur.Sym.Name) < 0))
                best[rva] = (s, rank);
        }
        var list = new List<PdbName>(best.Count);
        foreach (var (rva, (sym, _)) in best.OrderBy(kv => kv.Key))
        {
            string name = sym.IsPublic ? Display(sym.Name) : sym.Name;
            bool function = sym.IsFunction || procSize.ContainsKey(rva);
            list.Add(new PdbName(rva, name, decorated.GetValueOrDefault(rva), function, procSize.GetValueOrDefault(rva, sym.Size), sym.Kind));
        }
        return list;
    }

    private static int Rank(PdbSymbolKind kind) => kind switch
    {
        PdbSymbolKind.GlobalProc => 0,
        PdbSymbolKind.LocalProc => 1,
        PdbSymbolKind.PublicFunction => 2,
        PdbSymbolKind.Thunk => 3,
        PdbSymbolKind.GlobalData => 4,
        PdbSymbolKind.LocalData => 5,
        _ => 6,
    };

    // An x86 C decoration ("_f@8", "@f@8", "f@@8") counts as decorated; an import cell ("__imp__f@8") keeps its name.
    private static bool IsDecorated(string name) => name.Length > 1 && (name[0] == '?'
        || name.Contains('@') && MsvcDemangler.Demangle(name) is { Kind: MsvcSymbolKind.CFunction, IsImport: false });

    /// <summary>The qualified name of a decorated public ("?f@A@@QEAAXXZ" -> "A::f"), else the name as is.</summary>
    public static string Display(string name) =>
        IsDecorated(name) && MsvcDemangler.Undecorate(name, MsvcNameStyle.NameOnly) is { Length: > 0 } plain ? plain : name;

    /// <summary>The full undecorated signature of a decorated name, or null.</summary>
    public static string? Signature(string? decorated) =>
        decorated != null && IsDecorated(decorated) ? MsvcDemangler.Undecorate(decorated, MsvcNameStyle.Full) : null;
}
