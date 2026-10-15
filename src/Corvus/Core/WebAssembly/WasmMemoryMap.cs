namespace Corvus.Core.WebAssembly;

/// <summary>
/// Where linear memory addresses come from in the file: the active data segments of memory 0 placed at constant offsets,
/// sorted by address. A constant address inside one maps to the file offset of its initial bytes.
/// </summary>
public sealed class WasmMemoryMap
{
    private readonly (ulong Address, int Length, int FileStart)[] _segments;

    public WasmMemoryMap(WasmBinary m)
    {
        var list = new List<(ulong, int, int)>();
        foreach (var d in m.Data)
        {
            if (d.Mode != WasmSegmentMode.Active || d.Memory != 0 || d.Length == 0) continue;
            var code = new WasmCode(m.Bytes, d.Offset!.Value.Start, d.Offset.Value.End);
            if (!code.Next(out var ins) || ins.Op is not (0x41 or 0x42)) continue;
            ulong at = ins.Op == 0x41 ? (uint)(int)ins.Value : (ulong)ins.Value;
            list.Add((at, d.Length, d.Start));
        }
        list.Sort((a, b) => a.Item1.CompareTo(b.Item1));
        _segments = [.. list];
    }

    public int Count => _segments.Length;

    /// <summary>The file offset holding the initial byte at memory <paramref name="address"/>, or null outside the data segments.</summary>
    public int? FileOffset(ulong address)
    {
        int lo = 0, hi = _segments.Length - 1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >>> 1;
            var s = _segments[mid];
            if (address < s.Address) hi = mid - 1;
            else if (address - s.Address >= (ulong)s.Length) lo = mid + 1;
            else return s.FileStart + (int)(address - s.Address);
        }
        return null;
    }

    /// <summary>The memory address of the byte at file offset <paramref name="offset"/>, or null when no data segment holds it.</summary>
    public ulong? Address(int offset)
    {
        foreach (var s in _segments)
            if (offset >= s.FileStart && offset < s.FileStart + s.Length) return s.Address + (ulong)(offset - s.FileStart);
        return null;
    }

    /// <summary>A NUL-terminated printable string of at least <paramref name="min"/> characters at file offset <paramref name="at"/>, or null.</summary>
    public static string? CString(byte[] bytes, int at, int min = 4, int max = 512)
    {
        int end = at;
        while (end < bytes.Length && end - at < max && bytes[end] != 0)
        {
            byte c = bytes[end];
            if (c < 0x20 && c is not (9 or 10 or 13) || c == 0x7F) return null;
            end++;
        }
        if (end >= bytes.Length || bytes[end] != 0 || end - at < min) return null;
        return System.Text.Encoding.UTF8.GetString(bytes, at, end - at);
    }
}
