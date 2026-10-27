using System.Buffers.Binary;

namespace Corvus.Native.Pe;

/// <summary>IMAGE_EXPORT_DIRECTORY; <see cref="NamesSorted"/> false means GetProcAddress by name can miss names.</summary>
public sealed record PeExportDirectory(
    string? DllName,
    uint TimeDateStamp,
    ushort MajorVersion,
    ushort MinorVersion,
    uint OrdinalBase,
    uint NumberOfFunctions,
    uint NumberOfNames,
    uint FunctionTableRva,
    uint NameTableRva,
    uint OrdinalTableRva,
    bool NamesSorted);

public sealed partial class PeFile
{
    private sealed record ExportTable(PeExportDirectory? Directory, IReadOnlyList<NativeExport> Entries)
    {
        public static readonly ExportTable Empty = new(null, []);
    }

    /// <summary>Export entries joined with names; unnamed zero entries are skipped, entries inside the directory are forwarders.</summary>
    private ExportTable ParseExports(IssueLog log)
    {
        var dir = Directory(PeDirectory.Export);
        if (dir.Rva == 0) return ExportTable.Empty;
        var budget = new WorkBudget(log);
        var d = ReadBlock(dir.Rva, 40);
        if (d == null)
        {
            log.Add($"export directory at RVA 0x{dir.Rva:X} is outside the mapped image");
            return ExportTable.Empty;
        }
        uint stamp = Le32(d, 4), nameRva = Le32(d, 12), ordinalBase = Le32(d, 16);
        uint functionCount = Le32(d, 20), nameCount = Le32(d, 24), eatRva = Le32(d, 28), namesRva = Le32(d, 32), ordinalsRva = Le32(d, 36);
        string? dllName = nameRva == 0 ? null : ReadName(nameRva, budget, log, "export DLL name");

        uint[] eat = ReadTable32(eatRva, functionCount, "export address table", log);
        uint[] namePointers = ReadTable32(namesRva, nameCount, "export name table", log);
        ushort[] ordinals = ReadTable16(ordinalsRva, (uint)namePointers.Length, "export ordinal table", log);

        var named = new List<(int Index, string Name)>(ordinals.Length);
        bool sorted = true;
        string? previous = null;
        for (int j = 0; j < ordinals.Length; j++)
        {
            if (!budget.Step()) break;
            var name = ReadName(namePointers[j], budget, log, "export name");
            if (name == null)
            {
                if (budget.Exhausted) break;
                log.Add($"export name {j} at RVA 0x{namePointers[j]:X} is outside the mapped image");
                continue;
            }
            if (previous != null && string.CompareOrdinal(previous, name) > 0) sorted = false;
            previous = name;
            int index = ordinals[j];
            if (index >= eat.Length)
            {
                log.Add($"export name '{name}' refers to function index {index}, past the {eat.Length} read from the address table");
                continue;
            }
            named.Add((index, name));
        }
        if (!sorted) log.Add("export names are not sorted; GetProcAddress by name can miss some of them");

        // Stable: name table order within an index.
        var byIndex = named.OrderBy(n => n.Index).ToList();
        var entries = new List<NativeExport>(Math.Max(eat.Length, byIndex.Count));
        long forwardStart = dir.Rva, forwardEnd = (long)dir.Rva + dir.Size;
        int k = 0;
        for (int i = 0; i < eat.Length && !budget.Exhausted; i++)
        {
            if (!budget.Step()) break;
            uint rva = eat[i];
            uint ordinal = unchecked(ordinalBase + (uint)i);
            int first = k;
            while (k < byIndex.Count && byIndex[k].Index == i) k++;
            if (rva == 0 && first == k) continue;
            string? forwarder = null;
            if (rva >= forwardStart && rva < forwardEnd)
                forwarder = ReadName(rva, budget, log, "export forwarder") ?? "";
            else if (Arch == NativeArch.Arm) rva &= ~1u; // Thumb bit
            if (first == k) entries.Add(new NativeExport(null, ordinal, rva, forwarder));
            for (int n = first; n < k; n++) entries.Add(new NativeExport(byIndex[n].Name, ordinal, rva, forwarder));
        }
        var directory = new PeExportDirectory(dllName, stamp, Le16(d, 8), Le16(d, 10), ordinalBase, functionCount, nameCount,
            eatRva, namesRva, ordinalsRva, sorted);
        return new ExportTable(directory, entries);
    }

    /// <summary><paramref name="count"/> 32-bit values at <paramref name="rva"/>, cut and recorded at the limit or the image end.</summary>
    private uint[] ReadTable32(uint rva, uint count, string what, IssueLog log)
    {
        if (count == 0) return [];
        if (count > PeLimits.MaxExports)
        {
            log.Add($"{what} declares {count} entries; the first {PeLimits.MaxExports} are read");
            count = PeLimits.MaxExports;
        }
        var bytes = new byte[Math.Min(count, FitCount(rva, 4)) * 4];
        int read = rva == 0 ? 0 : Read(rva, bytes) / 4;
        if (read < count) log.Add($"{what} at RVA 0x{rva:X} runs out of the mapped image after {read} of {count} entries", RvaToOffsetOrNull(rva));
        var values = new uint[read];
        for (int i = 0; i < read; i++) values[i] = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(i * 4));
        return values;
    }

    private ushort[] ReadTable16(uint rva, uint count, string what, IssueLog log)
    {
        if (count == 0) return [];
        var bytes = new byte[Math.Min(count, FitCount(rva, 2)) * 2];
        int read = rva == 0 ? 0 : Read(rva, bytes) / 2;
        if (read < count) log.Add($"{what} at RVA 0x{rva:X} runs out of the mapped image after {read} of {count} entries", RvaToOffsetOrNull(rva));
        var values = new ushort[read];
        for (int i = 0; i < read; i++) values[i] = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(i * 2));
        return values;
    }
}
