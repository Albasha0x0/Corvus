using System.Buffers.Binary;

namespace Corvus.Native.Dump.Rebuild;

/// <summary>One pointer-size value that differs between memory and file, and where the new value points.</summary>
public sealed record DataValueChange(ulong Address, ulong Old, ulong New, string Target);

/// <summary>Decodes the pointer-size values of a changed data range and names what each new value points at.</summary>
public static class DataChangeValues
{
    /// <summary>Most changed values returned for one range; the rest are dropped.</summary>
    public const int MaxValues = 4096;

    private const uint Committed = 0x1000;

    /// <summary>
    /// Lists each aligned value that differs between <paramref name="memory"/> and <paramref name="file"/> for the range at
    /// <paramref name="address"/>, with the old and new value and the new target: <c>module!export</c>,
    /// <c>module+0x..</c>, <c>unbacked</c>, <c>committed memory</c> or <c>not a pointer</c>. A short buffer limits the
    /// range to the shorter one.
    /// </summary>
    public static IReadOnlyList<DataValueChange> Decode(ReadOnlySpan<byte> memory, ReadOnlySpan<byte> file, ulong address, bool is64, IProcessMemory process) =>
        Decode(memory, file, address, is64, process, null);

    /// <summary>
    /// As <see cref="Decode(ReadOnlySpan{byte}, ReadOnlySpan{byte}, ulong, bool, IProcessMemory)"/>, naming targets from
    /// <paramref name="exports"/> so a caller decoding many ranges builds the map once; null builds it on the first changed value.
    /// </summary>
    public static IReadOnlyList<DataValueChange> Decode(ReadOnlySpan<byte> memory, ReadOnlySpan<byte> file, ulong address, bool is64, IProcessMemory process,
        ExportMap? exports)
    {
        int width = is64 ? 8 : 4;
        int length = Math.Min(memory.Length, file.Length);
        int first = (int)((ulong)width - address % (ulong)width) % width;
        var rows = new List<DataValueChange>();
        for (int at = first; at + width <= length && rows.Count < MaxValues; at += width)
        {
            ulong now = Read(memory.Slice(at, width));
            ulong was = Read(file.Slice(at, width));
            if (now == was) continue;
            exports ??= new ExportMap(process);
            rows.Add(new DataValueChange(address + (ulong)at, was, now, Target(now, process, exports)));
        }
        return rows;
    }

    private static ulong Read(ReadOnlySpan<byte> value) =>
        value.Length == 8 ? BinaryPrimitives.ReadUInt64LittleEndian(value) : BinaryPrimitives.ReadUInt32LittleEndian(value);

    /// <summary>Names what <paramref name="value"/> points at: <c>module!export</c>, <c>module+0x..</c>, <c>unbacked</c>, <c>committed memory</c> or <c>not a pointer</c>.</summary>
    internal static string Target(ulong value, IProcessMemory process, ExportMap exports)
    {
        if (value == 0) return "not a pointer";
        if (process.ModuleAt(value) is { } module)
            return exports.NameAt(value) ?? $"{module.FileName}+0x{value - module.Base:X}";
        if (process.RegionAt(value) is { } region)
        {
            if (region.State != Committed) return "not a pointer";
            return region.IsExecutable && region.Type != 0x1000000 ? "unbacked" : "committed memory";
        }
        return process.ReadableExtent(value, 1) > 0 ? "committed memory" : "not a pointer";
    }
}
