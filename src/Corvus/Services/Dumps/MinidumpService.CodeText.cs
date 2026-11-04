using Corvus.Native;
using Corvus.Native.Dump;
using Corvus.Native.Dump.Rebuild;
using Corvus.Native.Pe;

namespace Corvus.Services;

public sealed partial class MinidumpService
{
    /// <summary>Most bytes read before a changed range to reach a known instruction start.</summary>
    internal const int MaxLeadInBytes = 1024;

    /// <summary>Bytes read after a changed range, so the instruction holding its last byte is whole.</summary>
    private const int TrailBytes = 15;

    /// <summary>
    /// Returns <c>code changed: </c> and the first instructions of a changed code range, or null when none
    /// decode. The buffers start at <paramref name="address"/>; <paramref name="knownStart"/> is the offset
    /// in them of an instruction boundary at or before the range, or negative when none is known;
    /// <paramref name="rangeStart"/> and <paramref name="rangeEnd"/> are the offsets where the range begins and ends.
    /// </summary>
    internal static string? CodeText(byte[] memoryBytes, byte[] fileBytes, ulong address, NativeArch machine, int knownStart,
        IProcessMemory memory, ExportMap exports, int rangeStart = 0, int rangeEnd = -1)
    {
        string? Name(ulong target)
        {
            if (exports.NameAt(target) is { } named) return named;
            return memory.ModuleAt(target) is { } m ? $"{m.FileName}+0x{target - m.Base:X}" : null;
        }
        var text = CodeChangeText.Describe(memoryBytes, fileBytes, address, machine, knownStart, Name, rangeStart, rangeEnd);
        if (text == null) return null;
        return text.StartsWith("bytes changed: ", StringComparison.Ordinal) ? text : "code changed: " + text;
    }

    /// <summary>Buffers of a changed range that begin at a known instruction start, when there is one.</summary>
    internal readonly record struct CodeWindow(byte[] Memory, byte[] File, ulong Address, int KnownStart, int RangeStart, int RangeEnd);

    internal static CodeWindow Window(Func<uint, int, byte[]> readMemory, Func<uint, int, byte[]> readFile, ulong address,
        uint rva, int length, int leadIn, int imageLength)
    {
        // Without a known start the window still begins on a 4-byte boundary,
        // so a fixed-width instruction holding the range start is whole.
        uint back = leadIn >= 0 ? (uint)leadIn : Math.Min(rva & 3, rva);
        int count = (int)back + length + (int)Math.Clamp((long)imageLength - rva - length, 0, TrailBytes);
        return new CodeWindow(readMemory(rva - back, count), readFile(rva - back, count), address - back, leadIn < 0 ? -1 : 0, (int)back, (int)back + length);
    }

    /// <summary>
    /// Returns the sorted instruction start RVAs an image states: function table entries, non-forwarded
    /// export addresses and the entry point.
    /// </summary>
    internal static IReadOnlyList<uint> StartFacts(PeFile image)
    {
        var starts = new SortedSet<uint>(image.RuntimeFunctions.Select(f => f.BeginRva));
        foreach (var export in image.Exports)
            if (export.ForwardedTo == null && export.Rva != 0) starts.Add(export.Rva);
        if (image.EntryPointRva != 0) starts.Add(image.EntryPointRva);
        return [.. starts];
    }

    // Bytes from the nearest start before the range among the function holding\n    // it, the section start and starts; negative when it is farther back than\n    // MaxLeadInBytes.
    internal static int LeadIn(IReadOnlyList<RuntimeFunction> table, uint sectionRva, uint rva,
        IReadOnlyList<uint>? starts = null)
    {
        uint start = sectionRva;
        int low = 0, high = table.Count - 1;
        while (low <= high)
        {
            int mid = (low + high) >>> 1;
            var f = table[mid];
            if (rva < f.BeginRva) high = mid - 1;
            else if (rva >= f.EndRva) low = mid + 1;
            else { start = f.BeginRva; break; }
        }
        if (starts != null)
        {
            int at = LastAtOrBefore(starts, rva);
            if (at >= 0 && starts[at] >= sectionRva && starts[at] > start) start = starts[at];
        }
        return start <= rva && rva - start <= MaxLeadInBytes ? (int)(rva - start) : -1;
    }

    private static int LastAtOrBefore(IReadOnlyList<uint> sorted, uint value)
    {
        int low = 0, high = sorted.Count - 1, found = -1;
        while (low <= high)
        {
            int mid = (low + high) >>> 1;
            if (sorted[mid] <= value) { found = mid; low = mid + 1; }
            else high = mid - 1;
        }
        return found;
    }
}