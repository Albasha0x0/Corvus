using System.Security.Cryptography;
using System.Text;

namespace Corvus.Core.WebAssembly;

/// <summary>An import or export that differs between two builds: added, removed, or changed (its type or target), with both descriptions.</summary>
public sealed record WasmInterfaceChange(string Kind, string Name, string Change, string? Old, string? New);

/// <summary>A function of both builds: how it was paired (name, or an identical body), and whether its signature and body changed.</summary>
public sealed record WasmFunctionPair(uint Old, uint New, string Name, string Basis, bool SignatureChanged, bool BodyChanged, int OldSize, int NewSize);

/// <summary>Two builds' interfaces and functions compared.</summary>
public sealed record WasmComparison(IReadOnlyList<WasmInterfaceChange> Interface, IReadOnlyList<WasmFunctionPair> Pairs, IReadOnlyList<uint> OnlyOld,
    IReadOnlyList<uint> OnlyNew, int Imports, int Exports);

/// <summary>Compares two builds of a module: imports, exports, and functions paired by unique name, then unique body hash.</summary>
/// <remarks>Body hashes replace indexes with names and signatures, so moved code keeps its hash.</remarks>
public static class WasmInterface
{
    public static WasmComparison Compare(WasmBinary a, IReadOnlyList<string> aNames, IReadOnlyList<string> aSources, WasmBinary b, IReadOnlyList<string> bNames,
        IReadOnlyList<string> bSources, CancellationToken ct = default)
    {
        var changes = new List<WasmInterfaceChange>();
        var oldImports = a.Imports.GroupBy(i => (i.Module, i.Name, i.Kind)).ToDictionary(g => g.Key, g => Describe(a, g.First()));
        var newImports = b.Imports.GroupBy(i => (i.Module, i.Name, i.Kind)).ToDictionary(g => g.Key, g => Describe(b, g.First()));
        foreach (var (key, text) in oldImports.OrderBy(k => k.Key.Module, StringComparer.Ordinal).ThenBy(k => k.Key.Name, StringComparer.Ordinal))
        {
            string name = $"{key.Module}.{key.Name}";
            if (!newImports.TryGetValue(key, out var other)) changes.Add(new WasmInterfaceChange("import", name, "removed", text, null));
            else if (other != text) changes.Add(new WasmInterfaceChange("import", name, "changed", text, other));
        }
        foreach (var (key, text) in newImports.OrderBy(k => k.Key.Module, StringComparer.Ordinal).ThenBy(k => k.Key.Name, StringComparer.Ordinal))
            if (!oldImports.ContainsKey(key)) changes.Add(new WasmInterfaceChange("import", $"{key.Module}.{key.Name}", "added", null, text));
        var oldExports = a.Exports.GroupBy(e => e.Name).ToDictionary(g => g.Key, g => Describe(a, g.First()), StringComparer.Ordinal);
        var newExports = b.Exports.GroupBy(e => e.Name).ToDictionary(g => g.Key, g => Describe(b, g.First()), StringComparer.Ordinal);
        foreach (var (name, text) in oldExports.OrderBy(k => k.Key, StringComparer.Ordinal))
        {
            if (!newExports.TryGetValue(name, out var other)) changes.Add(new WasmInterfaceChange("export", name, "removed", text, null));
            else if (other != text) changes.Add(new WasmInterfaceChange("export", name, "changed", text, other));
        }
        foreach (var (name, text) in newExports.OrderBy(k => k.Key, StringComparer.Ordinal))
            if (!oldExports.ContainsKey(name)) changes.Add(new WasmInterfaceChange("export", name, "added", null, text));

        var oldHashes = Hashes(a, aNames, ct);
        var newHashes = Hashes(b, bNames, ct);
        var pairs = new List<WasmFunctionPair>();
        var usedOld = new HashSet<uint>();
        var usedNew = new HashSet<uint>();
        void Pair(uint o, uint n, string basis)
        {
            usedOld.Add(o);
            usedNew.Add(n);
            bool signature = Signature(a.FunctionType(o)) != Signature(b.FunctionType(n));
            bool body = !oldHashes[o].AsSpan().SequenceEqual(newHashes[n]);
            pairs.Add(new WasmFunctionPair(o, n, aNames[(int)o], basis, signature, body, Size(a, o), Size(b, n)));
        }
        // By a name the module gives (not an index name), unique on both sides.
        var oldByName = Unique(Enumerable.Range(0, a.FunctionCount).Where(i => aSources[i] != "index").Select(i => ((uint)i, aNames[i])));
        var newByName = Unique(Enumerable.Range(0, b.FunctionCount).Where(i => bSources[i] != "index").Select(i => ((uint)i, bNames[i])));
        foreach (var (name, o) in oldByName)
            if (newByName.TryGetValue(name, out var n)) Pair(o, n, "name");
        // Then by a unique identical body among the rest.
        var oldByHash = Unique(Enumerable.Range(0, a.FunctionCount).Where(i => !usedOld.Contains((uint)i) && i >= a.ImportedFunctions).Select(i => ((uint)i, Convert.ToHexString(oldHashes[i]))));
        var newByHash = Unique(Enumerable.Range(0, b.FunctionCount).Where(i => !usedNew.Contains((uint)i) && i >= b.ImportedFunctions).Select(i => ((uint)i, Convert.ToHexString(newHashes[i]))));
        foreach (var (hash, o) in oldByHash)
            if (newByHash.TryGetValue(hash, out var n)) Pair(o, n, "identical_body");
        pairs.Sort((x, y) => x.Old.CompareTo(y.Old));
        var onlyOld = Enumerable.Range(0, a.FunctionCount).Select(i => (uint)i).Where(i => !usedOld.Contains(i)).ToList();
        var onlyNew = Enumerable.Range(0, b.FunctionCount).Select(i => (uint)i).Where(i => !usedNew.Contains(i)).ToList();
        return new WasmComparison(changes, pairs, onlyOld, onlyNew, newImports.Count, newExports.Count);
    }

    private static Dictionary<string, uint> Unique(IEnumerable<(uint Index, string Key)> items) =>
        items.GroupBy(x => x.Key, StringComparer.Ordinal).Where(g => g.Count() == 1).ToDictionary(g => g.Key, g => g.First().Index, StringComparer.Ordinal);

    private static int Size(WasmBinary m, uint f) => m.BodyOf(f) is { } body ? body.End - body.Start : 0;

    public static string Signature(WasmFuncType? t) =>
        t == null ? "?" : $"({string.Join(", ", t.Params.Select(t => WasmBinary.TypeName(t)))}) -> ({string.Join(", ", t.Results.Select(t => WasmBinary.TypeName(t)))})";

    private static string Describe(WasmBinary m, WasmImport i) => i.Kind switch
    {
        WasmExternal.Func => "func " + Signature(i.TypeIndex < m.Types.Count ? m.Types[(int)i.TypeIndex] : null),
        WasmExternal.Global => $"global {(i.Global!.Value.Mutable ? "mut " : "")}{WasmBinary.TypeName(i.Global.Value.Type)}",
        WasmExternal.Memory => $"memory {i.Memory!.Value.Min}" + (i.Memory.Value.Max is { } max ? $"..{max}" : "") + (i.Memory.Value.Shared ? " shared" : ""),
        WasmExternal.Table => $"table {WasmBinary.TypeName(i.Table!.Element)} {i.Table.Limits.Min}" + (i.Table.Limits.Max is { } tmax ? $"..{tmax}" : ""),
        _ => "tag " + Signature(i.TypeIndex < m.Types.Count ? m.Types[(int)i.TypeIndex] : null),
    };

    private static string Describe(WasmBinary m, WasmExport e) => e.Kind switch
    {
        WasmExternal.Func => "func " + Signature(m.FunctionType(e.Index)),
        WasmExternal.Global => m.GlobalTypeOf(e.Index) is { } g ? $"global {(g.Mutable ? "mut " : "")}{WasmBinary.TypeName(g.Type)}" : "global ?",
        WasmExternal.Memory => "memory",
        WasmExternal.Table => "table",
        _ => "tag",
    };

    /// <summary>SHA-256 of each function's normalized body (imports hash their module, name and type); index immediates replaced by names and signatures.</summary>
    private static byte[][] Hashes(WasmBinary m, IReadOnlyList<string> names, CancellationToken ct)
    {
        var hashes = new byte[Math.Max(m.FunctionCount, names.Count)][];
        for (int i = 0; i < hashes.Length; i++)
        {
            if ((i & 0xFF) == 0) ct.ThrowIfCancellationRequested();
            var sb = new StringBuilder();
            if (m.BodyOf((uint)i) is not { } body)
            {
                sb.Append(i < m.ImportedFunctions && m.ImportAt(WasmExternal.Func, (uint)i) is { } imp ? $"{imp.Module}.{imp.Name} {Describe(m, imp)}" : "missing");
                hashes[i] = SHA256.HashData(Encoding.UTF8.GetBytes(sb.ToString()));
                continue;
            }
            foreach (var (count, type) in body.Locals) sb.Append(count).Append(WasmBinary.TypeName(type)).Append(';');
            var code = new WasmCode(m.Bytes, body.CodeStart, body.End);
            while (code.Next(out var ins))
            {
                sb.Append(ins.Op).Append(' ');
                switch (ins.Info.Imm)
                {
                    case WasmImm.Func: sb.Append(ins.A < names.Count ? names[(int)ins.A] : "?"); break;
                    case WasmImm.Global: sb.Append(m.GlobalTypeOf(ins.A) is { } g ? WasmBinary.TypeName(g.Type) : "?"); break;
                    case WasmImm.CallIndirect: sb.Append(Signature(ins.A < m.Types.Count ? m.Types[(int)ins.A] : null)).Append(ins.B); break;
                    case WasmImm.TypeIndex: sb.Append(Signature(ins.A < m.Types.Count ? m.Types[(int)ins.A] : null)); break;
                    case WasmImm.BlockType: sb.Append(ins.BlockType >= 0 && ins.BlockType < m.Types.Count ? Signature(m.Types[(int)ins.BlockType]) : ins.BlockType.ToString(System.Globalization.CultureInfo.InvariantCulture)); break;
                    // Segment indexes move between builds.
                    case WasmImm.Data or WasmImm.Elem or WasmImm.DataMemory or WasmImm.ElemTable: break;
                    default:
                        sb.Append(Convert.ToHexString(m.Bytes, ins.Offset, ins.Length));
                        break;
                }
                sb.Append('\n');
            }
            hashes[i] = SHA256.HashData(Encoding.UTF8.GetBytes(sb.ToString()));
        }
        return hashes;
    }
}
