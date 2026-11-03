using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Dump;
using Corvus.Native.Dump.Rebuild;
using Corvus.Native.Pe;

namespace Corvus.Services;

public sealed partial class MinidumpService
{
    /// <summary>Most bytes of a changed range decoded into a description.</summary>
    private const int MaxDescribedBytes = 4096;

    /// <summary>One range of a module that differs from its file, or a module that could not be compared.</summary>
    /// <param name="Kind"><c>code</c>, <c>data</c>, <c>import</c> or <c>unknown</c>.</param>
    /// <param name="Start">Address of the range, or of the module base when the module is unknown.</param>
    /// <param name="Name">The function, export or section offset; the import for an import slot; null when none.</param>
    /// <param name="FileBytes">Hex of the file bytes, cut to <see cref="ImageChanges.MaxBytes"/>.</param>
    /// <param name="MemoryBytes">Hex of the memory bytes, cut to <see cref="ImageChanges.MaxBytes"/>.</param>
    /// <param name="BeforeBytes">Hex of the bytes in the other dump, set only when two dumps are compared.</param>
    /// <param name="AfterBytes">Hex of the bytes in the dump opened, set only when two dumps are compared.</param>
    public sealed record ModuleChange(string Module, string Section, string Start, string Rva, int Length, string Kind, string? Name,
        string? Description, string? File, string? FileBytes, string? MemoryBytes, string? BeforeBytes = null, string? AfterBytes = null);

    /// <summary>
    /// The ranges changed in memory for each module <paramref name="module"/> names (default all), compared with its file of the same build,
    /// sorted by module then address and paged from <paramref name="offset"/>. A module without such a file, or that cannot be rebuilt,
    /// gives one <c>unknown</c> row with the reason. With <paramref name="compareWith"/> (a dump path or open id) the ranges are those that
    /// differ from that dump; a module in one dump only gives one <c>unknown</c> row naming the dump that lacks it. Notes name each limit reached.
    /// </summary>
    public (string Id, IReadOnlyList<ModuleChange> Rows, int Total, IReadOnlyList<string> Notes) Changes(string path, string? imageDirectories,
        string? module, int offset, int limit, CancellationToken ct, string? compareWith = null)
    {
        var (id, full, directories) = Resolve(path, imageDirectories);
        string selector = string.IsNullOrWhiteSpace(module) ? "all" : module.Trim();
        string? otherFull = string.IsNullOrWhiteSpace(compareWith) ? null : Resolve(compareWith, imageDirectories).Path;
        string key = $"{id}|{Stamp(full)}|{otherFull}|{(otherFull == null ? "" : Stamp(otherFull))}|{selector}|{directories}";

        ChangeSet? set;
        lock (_changeSets) _changeSets.TryGetValue(key, out set);
        if (set == null)
        {
            set = ComputeChanges(path, imageDirectories, selector, compareWith, ct);
            lock (_changeSets)
            {
                if (_changeSets.Count >= MaxCachedChangeSets) _changeSets.Remove(_changeSets.Keys.First());
                _changeSets[key] = set;
            }
        }
        var page = set.Rows.Skip(Math.Max(0, offset)).Take(Math.Clamp(limit, 1, MaxListLimit)).ToList();
        return (id, page, set.Rows.Count, set.Notes);
    }

    private sealed record ChangeSet(IReadOnlyList<ModuleChange> Rows, IReadOnlyList<string> Notes);

    /// <summary>Most change sets kept for paging a view.</summary>
    private const int MaxCachedChangeSets = 4;

    private readonly Dictionary<string, ChangeSet> _changeSets = [];

    /// <summary>Times the changes of a dump were computed; a repeated page reads the kept rows instead.</summary>
    internal int ChangeComputations;

    // Size and write time tell a rewritten file from the one the rows were
    // computed from.
    private static string Stamp(string file)
    {
        try
        {
            var info = new FileInfo(file);
            return $"{info.Length}:{info.LastWriteTimeUtc.Ticks}";
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return "?";
        }
    }

    private ChangeSet ComputeChanges(string path, string? imageDirectories, string selector, string? compareWith, CancellationToken ct)
    {
        Interlocked.Increment(ref ChangeComputations);
        using var s = Open(path, imageDirectories);
        using var other = compareWith == null ? null : Open(compareWith, imageDirectories);
        var targets = ModuleRebuild.Select(s.Memory, selector, ct);
        if (targets.Count == 0)
            throw new ToolError(ErrorCode.NotFound, $"No module matches '{selector}'.", "pass module as a listed file name, a 0x address, all or unlisted");

        var options = RebuildOptions.Default with
        {
            Layout = OutputLayout.Mapped, Imports = ImportMode.Keep, Base = BaseMode.Loaded, CompareWithDisk = false,
            ImageDirectories = s.Directories.Count == 0 ? null : string.Join(';', s.Directories),
        };
        var notes = new List<string>();
        var all = new List<(string Name, ulong Base, ulong Address, ModuleChange Row)>();
        ExportMap? exports = null;
        var apiSets = other == null ? DumpApiSets(s.Memory, notes) : null;
        var ordered = targets.OrderBy(t => t.Name, StringComparer.OrdinalIgnoreCase).ThenBy(t => t.Base).ToList();
        var counterparts = other == null ? null : Counterparts(ordered, ModuleRebuild.Select(other.Memory, selector, ct), s.Id, all);
        foreach (var target in ordered)
        {
            ct.ThrowIfCancellationRequested();
            exports ??= new ExportMap(s.Memory);
            List<ModuleChange> rows;
            if (other == null) rows = ModuleRows(s.Memory, target, options, exports, apiSets, notes, ct);
            else if (counterparts![target] is { } before) rows = DumpRows(s.Memory, target, other.Memory, before, other.Id, exports, notes, ct);
            else rows = [UnknownModule(target, $"not in {other.Id}")];
            foreach (var row in rows)
                all.Add((target.Name, target.Base, ParseAddress(row.Start), row));
        }
        var sorted = all.OrderBy(r => r.Name, StringComparer.OrdinalIgnoreCase).ThenBy(r => r.Base).ThenBy(r => r.Address).Select(r => r.Row).ToList();
        return new ChangeSet(sorted, notes);
    }

    // Pairs each module with the same-named module of the other dump in address
    // order; the other dump's leftovers become rows.
    private static Dictionary<RebuildTarget, RebuildTarget?> Counterparts(List<RebuildTarget> modules, IReadOnlyList<RebuildTarget> others,
        string id, List<(string Name, ulong Base, ulong Address, ModuleChange Row)> rows)
    {
        var pool = others.OrderBy(t => t.Name, StringComparer.OrdinalIgnoreCase).ThenBy(t => t.Base).ToList();
        var pairs = new Dictionary<RebuildTarget, RebuildTarget?>();
        foreach (var m in modules)
        {
            var match = pool.FirstOrDefault(o => string.Equals(o.Name, m.Name, StringComparison.OrdinalIgnoreCase));
            pairs[m] = match;
            if (match != null) pool.Remove(match);
        }
        foreach (var left in pool)
            rows.Add((left.Name, left.Base, left.Base, UnknownModule(left, $"not in {id}")));
        return pairs;
    }

    // Rows for a module compared with the same module in another dump.
    private static List<ModuleChange> DumpRows(IProcessMemory memory, RebuildTarget target, IProcessMemory otherMemory, RebuildTarget before,
        string otherId, ExportMap exports, List<string> notes, CancellationToken ct)
    {
        var captured = CapturedImageReader.Read(memory, target, ct);
        var oldCaptured = CapturedImageReader.Read(otherMemory, before, ct);
        if (captured == null) return [UnknownModule(target, "the module header is not captured as a PE image")];
        if (oldCaptured == null) return [UnknownModule(target, $"the module header is not captured as a PE image in {otherId}")];
        var set = SnapshotChanges.Compare(oldCaptured, captured);
        if (set.State == "refused") return [UnknownModule(target, set.Reason)];
        if (!DiskCompare.TryParse(captured.Image, out var layout)) return [UnknownModule(target, "the captured headers are not readable")];

        if (set.Truncated) notes.Add($"{target.Name}: {set.Total} changed ranges, the first {set.Limit} are listed.");
        var mapped = captured.Image;
        var names = ImageAddressNames.For(mapped, target.Base);
        var rows = new List<ModuleChange>();
        foreach (var range in set.Ranges)
        {
            uint rva = ParseRva(range.Rva);
            ulong address = target.Base + rva;
            if (range.State == "unknown")
            {
                rows.Add(UnknownRange(target, range.Section, range.Rva, range.Length, names.NameAt(rva),
                    "the page was not captured in both dumps, so the range is not compared", otherId, null));
                continue;
            }
            string start = $"0x{address:X}";
            int described = Math.Min(range.Length, MaxDescribedBytes);
            var afterBytes = mapped.AsSpan((int)rva, described).ToArray();
            var beforeBytes = oldCaptured.Image.AsSpan((int)rva, described).ToArray();
            string? description = range.Code
                ? DescribeCode(afterBytes, beforeBytes, address, layout.Is64, memory, exports)
                : DescribeData(afterBytes, beforeBytes, address, layout.Is64, memory);
            rows.Add(new ModuleChange(target.Name, range.Section, start, range.Rva, range.Length, range.Code ? "code" : "data", names.NameAt(rva),
                description, otherId, null, null, range.Before, range.After));
        }
        return rows;
    }

    private static uint ParseRva(string hex) =>
        uint.Parse(hex.AsSpan(2), System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture);

    private static ulong ParseAddress(string hex) => ulong.Parse(hex.AsSpan(2), System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture);

    // A range with an absent page is reported as unknown, not as unchanged.
    private static ModuleChange UnknownRange(RebuildTarget t, string section, string rva, int length, string? name, string reason,
        string? file, string? fileBytes) =>
        new(t.Name, section, $"0x{t.Base + ParseRva(rva):X}", rva, length, "unknown", name, reason, file, fileBytes, null);

    private static ModuleChange UnknownModule(RebuildTarget t, string reason) =>
        new(t.Name, "", $"0x{t.Base:X}", "0x0", 0, "unknown", null, reason, null, null, null);

    // The map of the dumped process; null falls back to the system map.
    private static ApiSetSchema? DumpApiSets(IProcessMemory memory, List<string> notes)
    {
        var address = ProcessEnvironment.ApiSetMapAddress(memory, out string? reason);
        if (address is { } at)
        {
            if (ImportRedirects.ReadApiSetMap(memory, at) is { } map) return map;
            reason = $"0x{at:X} does not hold a version 6 map";
        }
        if (memory is MinidumpFile) notes.Add($"API set map of the dump not read, the system map resolves contracts: {reason}.");
        return null;
    }

    private static List<ModuleChange> ModuleRows(IProcessMemory memory, RebuildTarget target, RebuildOptions options, ExportMap exports,
        ApiSetSchema? apiSets, List<string> notes, CancellationToken ct)
    {
        var rebuilt = ModuleRebuild.Rebuild(memory, target, options, ct);
        if (rebuilt.Bytes == null) return [UnknownModule(target, $"not rebuilt: {rebuilt.Refused}")];
        if (rebuilt.Format != "pe") return [UnknownModule(target, $"a {rebuilt.Format} image is not compared with a file")];
        var captured = CapturedImageReader.Read(memory, target, ct);
        if (captured == null) return [UnknownModule(target, "the memory does not hold the image headers")];
        if (!DumpImages.TryHeader(captured.Image, out uint stamp, out uint size, out _))
            return [UnknownModule(target, "the captured headers do not give a build")];

        var candidates = DiskCompare.Candidates(target, options);
        byte[]? file = null;
        string? filePath = null;
        foreach (var candidate in candidates)
        {
            if (!DiskCompare.SameBuild(candidate, stamp, size)) continue;
            file = DiskCompare.ReadFile(candidate);
            if (file == null) continue;
            filePath = candidate;
            break;
        }
        if (file == null)
        {
            string searched = candidates.Count == 0 ? "no path recorded and no image directories" : string.Join("; ", candidates);
            return [UnknownModule(target, $"no file of the same build found; searched {searched}")];
        }

        PeFile disk;
        try { disk = PeFile.FromBytes(file); }
        catch (Exception e) when (e is InvalidDataException or ArgumentException or IOException)
        {
            return [UnknownModule(target, "the file of the same build is not readable")];
        }

        var mapped = rebuilt.Bytes;
        var set = ImageChanges.Compare(mapped, captured, file);
        if (set.Truncated) notes.Add($"{target.Name}: {set.Total} changed ranges, the first {set.Limit} are listed.");
        var names = ImageAddressNames.For(mapped, target.Base);
        var rows = new List<ModuleChange>();
        foreach (var range in set.Ranges)
        {
            uint rva = ParseRva(range.Rva);
            ulong address = target.Base + rva;
            if (range.State == "unknown")
            {
                rows.Add(UnknownRange(target, range.Section, range.Rva, range.Length, names.NameAt(rva),
                    "the page was not captured, so the range is not compared", filePath, range.FileBytes));
                continue;
            }
            string start = $"0x{address:X}";
            int described = Math.Min(range.Length, MaxDescribedBytes);
            var memoryBytes = mapped.AsSpan((int)rva, described).ToArray();
            var fileBytes = new byte[described];
            disk.Read(rva, fileBytes);
            string kind = range.Code ? "code" : "data";
            string? description = range.Code
                ? DescribeCode(memoryBytes, fileBytes, address, disk.Is64Bit, memory, exports)
                : DescribeData(memoryBytes, fileBytes, address, disk.Is64Bit, memory);
            rows.Add(new ModuleChange(target.Name, range.Section, start, range.Rva, range.Length, kind, names.NameAt(rva), description, filePath,
                range.FileBytes, range.MemoryBytes));
        }

        foreach (var slot in ImportRedirects.Find(captured.Image, captured, exports, memory, apiSets))
        {
            ulong address = target.Base + slot.SlotRva;
            string section = disk.Sections.FirstOrDefault(x => x.Contains(slot.SlotRva))?.Name ?? "";
            bool known = slot.State == "redirected";
            string description = known
                ? $"holds 0x{slot.Actual:X}{Where(memory, exports, slot.Actual)}, the export is at 0x{slot.Expected:X}"
                : slot.Reason ?? "not checked";
            int width = disk.Is64Bit ? 8 : 4;
            rows.Add(new ModuleChange(target.Name, section, $"0x{address:X}", $"0x{slot.SlotRva:X}", width, known ? "import" : "unknown", slot.Import,
                description, filePath, null, known && slot.Actual is { } actual ? Convert.ToHexStringLower(BitConverter.GetBytes(actual)[..width]) : null));
        }
        return rows;
    }

    private static string Where(IProcessMemory memory, ExportMap exports, ulong? address)
    {
        if (address is not { } a) return "";
        if (exports.NameAt(a) is { } named) return $" ({named})";
        return memory.ModuleAt(a) is { } m ? $" ({m.FileName}+0x{a - m.Base:X})" : memory.RegionAt(a) != null ? " (unbacked)" : "";
    }

    private static string DescribeCode(byte[] memoryBytes, byte[] fileBytes, ulong address, bool is64, IProcessMemory memory, ExportMap exports)
    {
        var change = CodeChangeKinds.Describe(memoryBytes, fileBytes, address, is64);
        if (change.Target is not { } target) return "bytes changed";
        string where = Where(memory, exports, target);
        return change.Indirect ? $"{change.Kind} through the pointer at 0x{target:X}{where}" : $"{change.Kind} to 0x{target:X}{where}";
    }

    private static string DescribeData(byte[] memoryBytes, byte[] fileBytes, ulong address, bool is64, IProcessMemory memory)
    {
        var values = DataChangeValues.Decode(memoryBytes, fileBytes, address, is64, memory);
        if (values.Count == 0) return "bytes changed";
        var shown = values.Take(3).Select(v => $"0x{v.Address:X}: 0x{v.Old:X} to 0x{v.New:X} ({v.Target})");
        return string.Join("; ", shown) + (values.Count > 3 ? $"; {values.Count - 3} more values" : "");
    }
}
