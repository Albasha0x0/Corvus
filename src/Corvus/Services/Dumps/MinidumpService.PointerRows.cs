using Corvus.Native.Dump;
using Corvus.Native.Dump.Rebuild;
using Corvus.Native.Pe;

namespace Corvus.Services;

public sealed partial class MinidumpService
{
    /// <summary>Most slot names a pointer row lists before it counts the rest.</summary>
    private const int MaxPointerNames = 8;

    /// <summary>Rows for data that holds pointers, and the RVA ranges they cover; both empty when there are none.</summary>
    internal static (IReadOnlyList<ModuleChange> Rows, IReadOnlyList<(uint Start, uint End)> Covered) PointerRows(RebuildTarget target,
        byte[] mapped, CapturedImage captured, PeFile file, IProcessMemory memory, ExportMap exports)
    {
        var rows = new List<ModuleChange>();
        var covered = new List<(uint Start, uint End)>();
        int width = file.Is64Bit ? 8 : 4;
        foreach (var run in LateBoundPointers.Find(mapped, captured, file, memory, exports).OrderBy(r => r.SlotRvas[0]))
        {
            uint start = run.SlotRvas[0];
            int length = run.SlotRvas.Count * width;
            string description = run.IsTable
                ? $"{run.SlotRvas.Count} slots: {string.Join(", ", run.Names.Take(MaxPointerNames))}"
                  + (run.Names.Count > MaxPointerNames ? $", and {run.Names.Count - MaxPointerNames} more" : "")
                : run.Names[0];
            int shown = Math.Min(length, ImageChanges.MaxBytes);
            string section = file.Sections.FirstOrDefault(x => x.Contains(start))?.Name ?? "";
            rows.Add(new ModuleChange(target.Name, section, $"0x{target.Base + start:X}", $"0x{start:X}", length, "pointer",
                run.IsTable ? null : run.Names[0], description, null, null,
                Convert.ToHexStringLower(mapped.AsSpan((int)start, shown))));
            covered.Add((start, start + (uint)length));
        }
        return (rows, covered);
    }
}
