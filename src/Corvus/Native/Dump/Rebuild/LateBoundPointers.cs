using System.Buffers.Binary;
using Corvus.Native.Pe;

namespace Corvus.Native.Dump.Rebuild;

/// <summary>Consecutive slots of one module that hold export addresses the file leaves zero.</summary>
/// <param name="Module">File name of the module that holds the slots.</param>
/// <param name="SlotRvas">RVA of each slot, ascending.</param>
/// <param name="Names">The <c>module!name</c> each slot points at, in slot order.</param>
public sealed record LateBoundRun(string Module, IReadOnlyList<uint> SlotRvas, IReadOnlyList<string> Names)
{
    /// <summary>True when the run has 2 or more slots; one slot is a single pointer.</summary>
    public bool IsTable => SlotRvas.Count >= 2;
}

/// <summary>Finds export addresses a module wrote at run time into data its file holds as zeros.</summary>
public static class LateBoundPointers
{
    /// <summary>
    /// Scans each non-code section of <paramref name="mapped"/> for slots the file holds as zeros: bytes past the raw
    /// data, the whole section when it has none, and slots inside the raw data whose file bytes are zero when
    /// <paramref name="fileHasRawData"/> is set. Returns runs in RVA order, empty when nothing is found.
    /// A run ends at a zero value, a value that names no export, a value into the image itself or another module
    /// without an export there, or a page not captured.
    /// </summary>
    public static IReadOnlyList<LateBoundRun> Find(byte[] mapped, CapturedImage captured, PeFile file, IProcessMemory memory, ExportMap exports,
        bool fileHasRawData = true)
    {
        var runs = new List<LateBoundRun>();
        int width = file.Is64Bit ? 8 : 4;
        foreach (var section in file.Sections.OrderBy(s => s.Rva))
        {
            if (DiskCompare.IsCode(section.Characteristics)) continue;
            long rawSize = section.RawOffset == 0 ? 0 : section.RawSize;
            long start = section.Rva + rawSize;
            if (fileHasRawData && rawSize > 0) start = section.Rva;
            long end = Math.Min(section.Rva + (long)section.MappedSize, mapped.Length);
            start = (start + width - 1) / width * width;

            var rvas = new List<uint>();
            var names = new List<string>();
            for (long at = start; at + width <= end; at += width)
            {
                string? name = !ZeroInFile(file, section, rawSize, at, width, fileHasRawData) ? null : Name(mapped, captured, memory, exports, at, width);
                if (name is not null)
                {
                    rvas.Add((uint)at);
                    names.Add(name);
                    continue;
                }
                Flush(runs, captured, rvas, names);
            }
            Flush(runs, captured, rvas, names);
        }
        return runs;
    }

    // Past the raw data is zero by definition; inside it the file bytes decide,
    // and a straddling slot is skipped.
    private static bool ZeroInFile(PeFile file, NativeSection section, long rawSize, long at, int width, bool fileHasRawData)
    {
        long offset = at - section.Rva;
        if (offset >= rawSize) return true;
        if (!fileHasRawData || offset + width > rawSize) return false;
        long position = section.RawOffset + offset;
        var bytes = file.FileBytes.Span;
        if (position + width > bytes.Length) return false;
        return !bytes.Slice((int)position, width).ContainsAnyExcept((byte)0);
    }

    private static string? Name(byte[] mapped, CapturedImage captured, IProcessMemory memory, ExportMap exports, long at, int width)
    {
        if (!captured.PageCaptured((uint)at) || !captured.PageCaptured((uint)(at + width - 1))) return null;
        var slot = mapped.AsSpan((int)at, width);
        ulong value = width == 8 ? BinaryPrimitives.ReadUInt64LittleEndian(slot) : BinaryPrimitives.ReadUInt32LittleEndian(slot);
        if (value == 0 || memory.ModuleAt(value) is not { } module || module.Base == captured.Target.Base) return null;
        // Target names the export, else module+offset, which is not a slot.
        string target = DataChangeValues.Target(value, memory, exports);
        return exports.NameAt(value) == target ? target : null;
    }

    private static void Flush(List<LateBoundRun> runs, CapturedImage captured, List<uint> rvas, List<string> names)
    {
        if (rvas.Count > 0) runs.Add(new LateBoundRun(captured.Target.Name, rvas.ToArray(), names.ToArray()));
        rvas.Clear();
        names.Clear();
    }
}
