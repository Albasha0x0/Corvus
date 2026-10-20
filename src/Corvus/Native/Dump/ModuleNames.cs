using System.Buffers.Binary;
using Corvus.Native.Pdb;
using Corvus.Native.Pe;

namespace Corvus.Native.Dump;

/// <summary>A name for an address inside a module.</summary>
/// <param name="Name">The function name, or null when the function is known but has no name.</param>
/// <param name="Source">pdb, symbol (the image's COFF symbol table), export, nearest_export (the closest export below: a guess) or none.</param>
/// <param name="Start">RVA of the named function (or of the function from .pdata when unnamed); null when unknown.</param>
public sealed record ModuleSymbol(string? Name, string Source, uint? Start);

/// <summary>
/// Lightweight names for a module image without a code index: PDB functions (a matching local PDB, no network), the
/// image's COFF function symbols and exports, with x64 function ranges from .pdata (chained fragments resolved to their primary function).
/// </summary>
public sealed class ModuleNames
{
    private readonly PeFile _image;
    private readonly uint[] _starts;
    private readonly string[] _names;
    private readonly string[] _sources;
    private readonly uint[] _sizes;

    public ModuleNames(PeFile image, IReadOnlyList<PdbName>? pdb, string? pdbPath)
    {
        _image = image;
        PdbPath = pdbPath;
        var map = new SortedDictionary<uint, (string Name, string Source, uint Size)>();
        foreach (var e in image.Exports)
            if (e.ForwardedTo == null && e.Name != null) map.TryAdd(e.Rva, (e.Name, "export", 0u));
        foreach (var f in image.Symbols)
            if (f.Kind == ImageSymbolKind.Function)
            {
                map[f.Rva] = (f.Name, "symbol", (uint)Math.Min(f.Size, uint.MaxValue));
                HasSymbols = true;
            }
        if (pdb != null)
            foreach (var n in pdb)
                if (n.IsFunction) map[n.Rva] = (n.Name, "pdb", n.Size);
        _starts = [.. map.Keys];
        _names = map.Values.Select(v => v.Name).ToArray();
        _sources = map.Values.Select(v => v.Source).ToArray();
        _sizes = map.Values.Select(v => v.Size).ToArray();
    }

    /// <summary>The PDB the names came from, or null (exports only).</summary>
    public string? PdbPath { get; }
    /// <summary>The image's COFF symbol table named functions.</summary>
    public bool HasSymbols { get; }
    public int Count => _starts.Length;

    public ModuleSymbol Lookup(uint rva)
    {
        uint? function = FunctionStart(rva);
        int i = Array.BinarySearch(_starts, rva);
        if (i < 0) i = ~i - 1;
        if (function is { } start)
        {
            int at = Array.BinarySearch(_starts, start);
            if (at >= 0) return new ModuleSymbol(_names[at], _sources[at], start);
            // a PDB procedure whose range covers the address (the .pdata entry may be a separated fragment)
            if (i >= 0 && _sizes[i] > 0 && rva - _starts[i] < _sizes[i]) return new ModuleSymbol(_names[i], _sources[i], _starts[i]);
            return new ModuleSymbol(null, "none", start);
        }
        if (i < 0) return new ModuleSymbol(null, "none", null);
        if (_sizes[i] > 0)
            return rva - _starts[i] < _sizes[i] ? new ModuleSymbol(_names[i], _sources[i], _starts[i]) : new ModuleSymbol(null, "none", null);
        return new ModuleSymbol(_names[i], _sources[i] == "export" ? "nearest_export" : _sources[i], _starts[i]);
    }

    /// <summary>The primary function containing <paramref name="rva"/> from .pdata, following chained unwind info.</summary>
    private uint? FunctionStart(uint rva)
    {
        var table = _image.RuntimeFunctions;
        if (table.Count == 0) return null;
        RuntimeFunction? f = Find(table, rva);
        if (f == null) return null;
        if (_image.Arch != NativeArch.X64) return f.BeginRva;
        Span<byte> head = stackalloc byte[4];
        Span<byte> chained = stackalloc byte[12];
        for (int depth = 0; depth < 32; depth++)
        {
            if (_image.Read(f.UnwindInfoRva, head) < 4 || ((head[0] >> 3) & 4) == 0) return f.BeginRva;
            int count = head[2];
            if (_image.Read(f.UnwindInfoRva + 4 + (uint)((count + 1) & ~1) * 2, chained) < 12) return f.BeginRva;
            uint begin = BinaryPrimitives.ReadUInt32LittleEndian(chained);
            uint end = BinaryPrimitives.ReadUInt32LittleEndian(chained[4..]);
            uint unwind = BinaryPrimitives.ReadUInt32LittleEndian(chained[8..]);
            if (begin == f.BeginRva || end <= begin) return f.BeginRva;
            f = new RuntimeFunction(begin, end, unwind);
        }
        return f.BeginRva;
    }

    private static RuntimeFunction? Find(IReadOnlyList<RuntimeFunction> table, uint rva)
    {
        int lo = 0, hi = table.Count - 1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >>> 1;
            var f = table[mid];
            if (rva < f.BeginRva) hi = mid - 1;
            else if (rva >= f.EndRva) lo = mid + 1;
            else return f;
        }
        return null;
    }
}
