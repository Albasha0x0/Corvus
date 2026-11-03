using Corvus.Native;
using Corvus.Native.Dump;
using Corvus.Native.Dump.Rebuild;

namespace Corvus.Services;

public sealed partial class MinidumpService
{
    /// <summary>
    /// Instruction text for a changed code range, or null when none is produced. <paramref name="knownStart"/> is the offset
    /// from the range start of an instruction boundary, zero or negative.
    /// </summary>
    internal static string? CodeText(byte[] memoryBytes, byte[] fileBytes, ulong address, NativeArch machine, int knownStart,
        IProcessMemory memory, ExportMap exports) => null;

    // The function holding the range when the file has a function table, else
    // the section start.
    private static int KnownStart(IReadOnlyList<RuntimeFunction> table, uint sectionRva, uint rva)
    {
        int low = 0, high = table.Count - 1;
        while (low <= high)
        {
            int mid = (low + high) >>> 1;
            var f = table[mid];
            if (rva < f.BeginRva) high = mid - 1;
            else if (rva >= f.EndRva) low = mid + 1;
            else return (int)((long)f.BeginRva - rva);
        }
        return (int)((long)sectionRva - rva);
    }
}
