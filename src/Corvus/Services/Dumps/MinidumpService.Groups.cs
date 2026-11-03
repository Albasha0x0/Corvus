using System.Text.RegularExpressions;
using Corvus.Native;
using Corvus.Native.Dump;
using Corvus.Native.Dump.Rebuild;

namespace Corvus.Services;

public sealed partial class MinidumpService
{
    /// <summary>Changed ranges that share a module, section, kind and shape, with the first row's description.</summary>
    public sealed record ChangeGroupRow(string Module, string Section, string Kind, string Shape, int Count, string FirstAddress,
        string LastAddress, long Bytes, string? Description);

    /// <summary>
    /// The change rows of <see cref="Changes"/> grouped by shape, in address order of each group's first row and paged from
    /// <paramref name="offset"/>. A kind the grouping does not know is its own shape, keyed by kind. Shapes of code read the
    /// first <see cref="ImageChanges.MaxBytes"/> bytes of a row, and a row in an unreadable module header groups by length.
    /// </summary>
    public (string Id, IReadOnlyList<ChangeGroupRow> Rows, int Total, IReadOnlyList<string> Notes) ChangeGroups(string path,
        string? imageDirectories, string? module, int offset, int limit, CancellationToken ct, string? compareWith = null)
    {
        // The first call fills the cache; later pages read the kept rows.
        var first = Changes(path, imageDirectories, module, 0, MaxListLimit, ct, compareWith);
        var rows = new List<ModuleChange>(first.Rows);
        while (rows.Count < first.Total)
        {
            ct.ThrowIfCancellationRequested();
            var next = Changes(path, imageDirectories, module, rows.Count, MaxListLimit, ct, compareWith);
            if (next.Rows.Count == 0) break;
            rows.AddRange(next.Rows);
        }

        var machines = Machines(path, imageDirectories, rows);
        var inputs = rows.Select(r => ShapeInput(r, machines)).ToList();
        var groups = ChangePatterns.Group(inputs);
        var all = groups.Select(g =>
        {
            var head = rows[g.FirstIndex];
            return new ChangeGroupRow(head.Module, head.Section, head.Kind, g.Shape, g.Count, $"0x{g.FirstAddress:X}",
                $"0x{g.LastAddress:X}", g.TotalBytes, head.Description);
        }).ToList();
        var page = all.Skip(Math.Max(0, offset)).Take(Math.Clamp(limit, 1, MaxListLimit)).ToList();
        return (first.Id, page, all.Count, first.Notes);
    }

    private static readonly Regex TargetText = new(@"\(([^()]+)\)", RegexOptions.CultureInvariant);

    private static ChangeShapeInput ShapeInput(ModuleChange row, Dictionary<string, NativeArch> machines)
    {
        byte[] bytes = string.IsNullOrEmpty(row.MemoryBytes) ? [] : Convert.FromHexString(row.MemoryBytes);
        string? target = null;
        if (row.Kind == "data" && row.Description is { } text && TargetText.Match(text) is { Success: true } m)
            target = m.Groups[1].Value;
        machines.TryGetValue(row.Module, out var machine);
        return new ChangeShapeInput(row.Module, row.Section, row.Kind, ParseAddress(row.Start), row.Length, bytes, machine, target);
    }

    // Reads the machine from each module's captured header; unreadable stays unknown.
    private Dictionary<string, NativeArch> Machines(string path, string? imageDirectories, List<ModuleChange> rows)
    {
        var result = new Dictionary<string, NativeArch>(StringComparer.OrdinalIgnoreCase);
        if (!rows.Any(r => r.Kind == "code")) return result;
        using var s = Open(path, imageDirectories);
        foreach (var row in rows)
        {
            if (row.Kind != "code" || result.ContainsKey(row.Module)) continue;
            if (s.Memory.ModuleAt(ParseAddress(row.Start)) is not { } mod) continue;
            var header = new byte[0x1000];
            int read = s.Memory.ReadMemory(mod.Base, header);
            result[row.Module] = MachineOf(read == header.Length ? header : header[..read]);
        }
        return result;
    }
}
