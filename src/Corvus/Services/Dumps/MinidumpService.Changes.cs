using Corvus.Core;
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
    public sealed record ModuleChange(string Module, string Section, string Start, string Rva, int Length, string Kind, string? Name,
        string? Description, string? File, string? FileBytes, string? MemoryBytes);

    /// <summary>
    /// The ranges changed in memory for each module <paramref name="module"/> names (default all), compared with its file of the same build,
    /// sorted by module then address and paged from <paramref name="offset"/>. A module without such a file, or that cannot be rebuilt,
    /// gives one <c>unknown</c> row with the reason. Notes name each limit reached.
    /// </summary>
    public (string Id, IReadOnlyList<ModuleChange> Rows, int Total, IReadOnlyList<string> Notes) Changes(string path, string? imageDirectories,
        string? module, int offset, int limit, CancellationToken ct)
    {
        using var s = Open(path, imageDirectories);
        string selector = string.IsNullOrWhiteSpace(module) ? "all" : module.Trim();
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
        foreach (var target in targets.OrderBy(t => t.Name, StringComparer.OrdinalIgnoreCase).ThenBy(t => t.Base))
        {
            ct.ThrowIfCancellationRequested();
            exports ??= new ExportMap(s.Memory);
            foreach (var row in ModuleRows(s.Memory, target, options, exports, notes, ct))
                all.Add((target.Name, target.Base, ParseAddress(row.Start), row));
        }
        var sorted = all.OrderBy(r => r.Name, StringComparer.OrdinalIgnoreCase).ThenBy(r => r.Base).ThenBy(r => r.Address).Select(r => r.Row).ToList();
        var page = sorted.Skip(Math.Max(0, offset)).Take(Math.Clamp(limit, 1, MaxListLimit)).ToList();
        return (s.Id, page, sorted.Count, notes);
    }

    private static ulong ParseAddress(string hex) => ulong.Parse(hex.AsSpan(2), System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture);

    private static ModuleChange UnknownModule(RebuildTarget t, string reason) =>
        new(t.Name, "", $"0x{t.Base:X}", "0x0", 0, "unknown", null, reason, null, null, null);

    private static List<ModuleChange> ModuleRows(IProcessMemory memory, RebuildTarget target, RebuildOptions options, ExportMap exports,
        List<string> notes, CancellationToken ct)
    {
        var rebuilt = ModuleRebuild.Rebuild(memory, target, options, ct);
        if (rebuilt.Bytes == null) return [UnknownModule(target, $"not rebuilt: {rebuilt.Refused}")];
        if (rebuilt.Format != "pe") return [UnknownModule(target, $"a {rebuilt.Format} image is not compared with a file")];
        var captured = CapturedImageReader.Read(memory, target, ct);
        if (captured == null) return [UnknownModule(target, "the memory does not hold the image headers")];
        if (!DumpImages.TryHeader(captured.Image, out uint stamp, out uint size, out _))
            return [UnknownModule(target, "the captured headers do not give a build")];

        var candidates = ChangeCandidates(target, options);
        byte[]? file = null;
        string? filePath = null;
        foreach (var candidate in candidates)
        {
            file = ReadSameBuild(candidate, stamp, size);
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
            uint rva = uint.Parse(range.Rva.AsSpan(2), System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture);
            ulong address = target.Base + rva;
            string start = $"0x{address:X}";
            if (range.State == "unknown")
            {
                rows.Add(new ModuleChange(target.Name, range.Section, start, range.Rva, range.Length, "unknown", names.NameAt(rva),
                    "the page was not captured, so the range is not compared", filePath, range.FileBytes, null));
                continue;
            }
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

        foreach (var slot in ImportRedirects.Find(captured.Image, captured, exports, memory))
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

    private static List<string> ChangeCandidates(RebuildTarget target, RebuildOptions options)
    {
        var list = new List<string>();
        if (!string.IsNullOrWhiteSpace(target.Path)) list.Add(target.Path);
        string name = Path.GetFileName(target.Path ?? target.Name);
        if (name.Length == 0) name = target.Name;
        foreach (var dir in (options.ImageDirectories ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            try { list.Add(Path.Combine(dir, name)); }
            catch (ArgumentException) { }
        }
        return [.. list.Distinct(StringComparer.OrdinalIgnoreCase)];
    }

    // The file's bytes when its time stamp and image size equal the captured headers; null otherwise.
    private static byte[]? ReadSameBuild(string path, uint stamp, uint size)
    {
        try
        {
            if (!File.Exists(path) || new FileInfo(path).Length > ModuleRebuild.MaxImageBytes) return null;
            var bytes = File.ReadAllBytes(path);
            return DumpImages.TryHeader(bytes, out uint fileStamp, out uint fileSize, out _) && fileStamp == stamp && fileSize == size ? bytes : null;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return null;
        }
    }
}
