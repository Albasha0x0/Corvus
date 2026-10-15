using System.Diagnostics;
using Corvus.Core;
using Corvus.Native.Pdb;

namespace Corvus.Native.Dwarf;

/// <summary>
/// Reads DWARF into the debug-info model the PDB reader fills (<see cref="PdbFile"/>): functions (with code) and global
/// and static variables (with a static address) as symbols, named by their qualified source names ("ns::Class::f"),
/// their linkage names kept; units as modules; types as CodeView records (<see cref="DwarfTypes"/>); and a lookup of
/// source lines and inlined functions by address that reads the line tables and entries again on demand. One pass over
/// the units, one unit in memory at a time: sections larger than <see cref="DebugContainer.WholeSectionBytes"/> are read
/// a unit or a page at a time, so a debug file of any size is read within a bounded working set plus the results.
/// </summary>
internal static class DwarfDebugInfo
{
    /// <summary>Most symbols kept.</summary>
    public const int MaxSymbols = PdbLimits.MaxSymbols;

    /// <summary>Whether <paramref name="container"/> has DWARF entries to read.</summary>
    public static bool HasDwarf(DebugContainer container) => container.Has(".debug_info") && container.Has(".debug_abbrev");

    /// <summary>
    /// Reads the DWARF of <paramref name="container"/> for <paramref name="image"/> (addresses become the image's RVAs).
    /// <paramref name="reopen"/> opens the same file again for the source lookup.
    /// </summary>
    public static PdbFile Read(DebugContainer container, INativeImage image, Func<DebugContainer> reopen, CancellationToken ct = default)
    {
        var issues = new List<ParseIssue>();
        var truncations = new List<string>();
        foreach (var n in container.Notes) issues.Add(new ParseIssue("dwarf", n));
        var reader = new DwarfReader(container);
        foreach (var p in reader.Problems) issues.Add(new ParseIssue("dwarf", p));
        int pointerSize = image.Is64Bit ? 8 : 4;
        var types = new DwarfTypes(reader, pointerSize);
        var modules = new List<PdbModule>();
        var symbols = new List<PdbSymbol>();
        var unitRanges = new List<(ulong Low, ulong High, int Header)>();
        int lineTables = 0, inlined = 0, issuesDropped = 0;
        ulong imageBase = image.ImageBase;
        uint sizeOfImage = image.SizeOfImage;

        for (int h = 0; h < reader.UnitHeaders.Count; h++)
        {
            ct.ThrowIfCancellationRequested();
            var unit = reader.Parse(reader.UnitHeaders[h], h, ct);
            if (unit.Problem != null)
            {
                if (issues.Count < 200) issues.Add(new ParseIssue("dwarf", $"unit at 0x{unit.Offset & (DwarfReader.TypesFlag - 1):X}: {unit.Problem}"));
                else issuesDropped++;
            }
            if (unit.Dies.Count == 0) continue;
            types.Begin(unit);
            reader.Remember(unit);
            var root = unit.Dies[0];
            int module = -1;
            if (root.Tag is Dw.TagCompileUnit or Dw.TagPartialUnit or Dw.TagSkeletonUnit)
            {
                module = modules.Count;
                modules.Add(new PdbModule(module, unit.Name ?? "", unit.CompDir ?? "", -1, 0));
                if (unit.StmtList >= 0) lineTables++;
                foreach (var (lo, hi) in reader.RangesOf(unit, root))
                    if (!DwarfLineTable.Tombstone(lo)) unitRanges.Add((lo, hi, h));
            }
            bool unitHasRanges = unitRanges.Count > 0 && unitRanges[^1].Header == h;
            for (int i = 0; i < unit.Dies.Count; i++)
            {
                if ((i & 0x3FFF) == 0) ct.ThrowIfCancellationRequested();
                var d = unit.Dies[i];
                switch (d.Tag)
                {
                    case Dw.TagSubprogram when !d.Declaration && ((d.Pc & 1) != 0 || d.Ranges >= 0):
                    {
                        var ranges = reader.RangesOf(unit, d);
                        if (ranges.Count == 0 && (d.Pc & 1) != 0) ranges.Add((d.LowPc, d.LowPc)); // empty, folded onto another function
                        if (ranges.Count == 0 || DwarfLineTable.Tombstone(ranges[0].Low)) break;
                        var (low, high) = (d.Pc & 1) != 0 ? ranges.FirstOrDefault(r => r.Low == d.LowPc, ranges[0]) : ranges[0];
                        if (!unitHasRanges) foreach (var r in ranges) unitRanges.Add((r.Low, r.High, h));
                        var named = Naming(reader, unit, d);
                        if (named.Name == null) break;
                        uint? rva = Rva(low, imageBase, sizeOfImage);
                        var parameters = new List<string?>();
                        uint type = types.Procedure(named.Unit, named.Die, named.ReturnType, parameters);
                        if (symbols.Count >= MaxSymbols) { Truncate(truncations, $"symbols beyond {MaxSymbols:N0}"); break; }
                        symbols.Add(new PdbSymbol(named.External ? PdbSymbolKind.GlobalProc : PdbSymbolKind.LocalProc, named.Name, 0, rva ?? 0, rva,
                            (uint)Math.Min(high - low, uint.MaxValue), module, type) { LinkageName = named.Linkage, ParameterNames = parameters.Count > 0 ? parameters : null });
                        break;
                    }
                    case Dw.TagVariable when d.HasLocation && !DwarfLineTable.Tombstone(d.Location):
                    {
                        var named = Naming(reader, unit, d);
                        if (named.Name == null) break;
                        uint? rva = Rva(d.Location, imageBase, sizeOfImage);
                        long typeOffset = d.Type >= 0 ? d.Type : named.Die.Type;
                        uint type = types.TypeOf(named.Unit, typeOffset);
                        long size = types.SizeOf(type);
                        if (symbols.Count >= MaxSymbols) { Truncate(truncations, $"symbols beyond {MaxSymbols:N0}"); break; }
                        symbols.Add(new PdbSymbol(named.External ? PdbSymbolKind.GlobalData : PdbSymbolKind.LocalData, named.Name, 0, rva ?? 0, rva,
                            (uint)Math.Clamp(size, 0, uint.MaxValue), module, type) { LinkageName = named.Linkage });
                        break;
                    }
                    case Dw.TagInlinedSubroutine:
                        inlined++;
                        break;
                    case Dw.TagStructureType or Dw.TagClassType or Dw.TagUnionType or Dw.TagEnumerationType or Dw.TagTypedef
                        when d.Name != null && !d.Declaration && TopLevel(unit, d):
                        types.TypeOf(unit, d.Offset);
                        break;
                }
            }
            if (types.Full) Truncate(truncations, $"type records beyond {DwarfTypes.MaxBytes:N0} bytes");
        }
        if (issuesDropped > 0) issues.Add(new ParseIssue("dwarf", $"{issuesDropped} more units with problems"));
        if (types.Skipped.Count > 0)
            issues.Add(new ParseIssue("dwarf", "types not written: " + string.Join(", ", types.Skipped.OrderByDescending(kv => kv.Value).Take(8).Select(kv => $"{kv.Value} {kv.Key}"))));
        var built = types.Build();
        var notes = new List<string>();
        if (types.Full) notes.Add($"type records past {DwarfTypes.MaxBytes:N0} bytes are not written");
        unitRanges.Sort((a, b) => a.Low.CompareTo(b.Low));
        var source = new SourceLookup(reopen, imageBase, unitRanges.ToArray(), lineTables, inlined);
        return PdbFile.FromDebugInfo(container.Path, container.FileLength, container.BuildId, modules, symbols, types.Typedefs,
            (built.Bytes, built.Offsets, notes), issues, truncations, source);
    }

    private static void Truncate(List<string> truncations, string text)
    {
        if (!truncations.Contains(text)) truncations.Add(text);
    }

    private static uint? Rva(ulong address, ulong imageBase, uint sizeOfImage) =>
        address >= imageBase && address - imageBase < sizeOfImage ? (uint)(address - imageBase) : null;

    /// <summary>Types named at file, namespace or class scope (not local to a function).</summary>
    private static bool TopLevel(DwarfUnit u, DwarfDie d)
    {
        for (var p = u.ParentOf(d); p != null; p = u.ParentOf(p))
        {
            if (Dw.IsUnit(p.Tag)) return true;
            if (!Dw.IsScope(p.Tag)) return false;
        }
        return true;
    }

    internal readonly record struct Named(string? Name, string? Linkage, bool External, DwarfUnit Unit, DwarfDie Die, long ReturnType);

    /// <summary>
    /// The qualified name of a function or variable entry, following its specification and abstract origin (out-of-line
    /// definitions of class members, concrete instances of inline functions) to the entry that names it.
    /// </summary>
    internal static Named Naming(DwarfReader reader, DwarfUnit unit, DwarfDie die)
    {
        var (u, d) = (unit, die);
        string? linkage = d.LinkageName;
        bool external = d.External;
        long returnType = d.Type;
        for (int hop = 0; hop < 8 && d.Name == null; hop++)
        {
            long next = d.Specification >= 0 ? d.Specification : d.AbstractOrigin;
            if (next < 0 || reader.Entry(next, u) is not { } e) break;
            (u, d) = e;
            linkage ??= d.LinkageName;
            external |= d.External;
            if (returnType < 0) returnType = d.Type;
        }
        // the declaration may be one more hop away (an abstract origin that has a specification)
        var (su, sd) = (u, d);
        for (int hop = 0; hop < 4 && sd.Specification >= 0; hop++)
        {
            if (reader.Entry(sd.Specification, su) is not { } e) break;
            (su, sd) = e;
            linkage ??= sd.LinkageName;
            external |= sd.External;
            if (returnType < 0) returnType = sd.Type;
        }
        if (d.Name == null) return new Named(null, linkage, external, unit, die, returnType);
        return new Named(DwarfTypes.Qualify(su, sd, d.Name, reader), linkage != d.Name ? linkage : null, external, unit, die, returnType);
    }

    /// <summary>Source lines and inlined frames by address: the unit is found by its address ranges, then read again with its line table.</summary>
    private sealed class SourceLookup(Func<DebugContainer> reopen, ulong imageBase, (ulong Low, ulong High, int Header)[] units, int lineTables, int inlined)
        : IDebugSourceLookup
    {
        public int LineTables => lineTables;
        public int InlinedInstances => inlined;

        public IReadOnlyList<DebugSourceInfo?> Lookup(IReadOnlyList<uint> rvas, CancellationToken ct = default)
        {
            var result = new DebugSourceInfo?[rvas.Count];
            if (units.Length == 0) return result;
            DebugContainer container;
            // the debug file may have been moved or deleted since it was read
            try { container = reopen(); }
            catch (Exception ex) when (ex is ToolError or IOException or UnauthorizedAccessException) { return result; }
            using var _ = container;
            var reader = new DwarfReader(container);
            var parsed = new Dictionary<int, (DwarfUnit Unit, DwarfLineTable? Lines)>();
            for (int i = 0; i < rvas.Count; i++)
            {
                ct.ThrowIfCancellationRequested();
                ulong address = imageBase + rvas[i];
                foreach (var h in Units(address))
                {
                    if (h >= reader.UnitHeaders.Count) continue;
                    if (!parsed.TryGetValue(h, out var entry))
                    {
                        var unit = reader.Parse(reader.UnitHeaders[h], h, ct);
                        DwarfLineTable? lines = null;
                        if (unit.StmtList >= 0 && reader.Line != null)
                            lines = DwarfLineTable.Read(reader.Line, unit.StmtList, unit.AddressSize, reader.BigEndian, unit.CompDir, container.Section(".debug_str"),
                                container.Section(".debug_line_str"), _ => null);
                        reader.Remember(unit);
                        parsed[h] = entry = (unit, lines);
                    }
                    if (Describe(reader, entry.Unit, entry.Lines, address) is { } info) { result[i] = info; break; }
                }
            }
            return result;
        }

        private IEnumerable<int> Units(ulong address)
        {
            int lo = 0, hi = units.Length - 1, last = -1;
            while (lo <= hi)
            {
                int mid = (lo + hi) >>> 1;
                if (units[mid].Low <= address) { last = mid; lo = mid + 1; }
                else hi = mid - 1;
            }
            var seen = new HashSet<int>();
            for (int k = last; k >= 0 && _reach[k] > address; k--)
                if (address < units[k].High && seen.Add(units[k].Header)) yield return units[k].Header;
        }

        // the highest end among ranges [0..k]: no earlier range reaches an address at or past it
        private readonly ulong[] _reach = Reach(units);

        private static ulong[] Reach((ulong Low, ulong High, int Header)[] units)
        {
            var reach = new ulong[units.Length];
            for (int i = 0; i < units.Length; i++) reach[i] = Math.Max(units[i].High, i > 0 ? reach[i - 1] : 0);
            return reach;
        }

        private static DebugSourceInfo? Describe(DwarfReader reader, DwarfUnit unit, DwarfLineTable? lines, ulong address)
        {
            // the chain of entries whose ranges contain the address: the function, then inlined functions inside it
            var chain = new List<DwarfDie>();
            for (int i = 1; i < unit.Dies.Count; i++)
            {
                var d = unit.Dies[i];
                if (d.Tag is not (Dw.TagSubprogram or Dw.TagInlinedSubroutine)) continue;
                if (chain.Count > 0 && !Within(unit, d, chain[0])) break; // past the function's entries
                if (d.Tag == Dw.TagSubprogram && (d.Declaration || ((d.Pc & 1) == 0 && d.Ranges < 0))) continue;
                if (chain.Count > 0 && !Within(unit, d, chain[^1])) continue;
                if (!reader.RangesOf(unit, d).Any(r => address >= r.Low && address < r.High)) continue;
                chain.Add(d);
            }
            var row = lines?.At(address);
            if (chain.Count == 0) return row is { Line: > 0 } r0 ? new DebugSourceInfo(lines!.File(r0.File), r0.Line, []) : null;
            var frames = new List<DebugSourceFrame>();
            string? file = row is { } r ? lines!.File(r.File) : null;
            int line = row?.Line ?? 0;
            for (int k = chain.Count - 1; k >= 0; k--)
            {
                var d = chain[k];
                var name = Naming(reader, unit, d).Name ?? "?";
                frames.Add(new DebugSourceFrame(name, file, line));
                file = d.CallFile > 0 || lines?.FirstFile == 0 ? lines?.File(d.CallFile) : null;
                line = d.CallLine;
            }
            return new DebugSourceInfo(row is { } rr ? lines!.File(rr.File) : null, row?.Line ?? 0, frames);
        }

        private static bool Within(DwarfUnit unit, DwarfDie d, DwarfDie ancestor)
        {
            for (var p = unit.ParentOf(d); p != null; p = unit.ParentOf(p))
                if (ReferenceEquals(p, ancestor)) return true;
            return false;
        }
    }
}
