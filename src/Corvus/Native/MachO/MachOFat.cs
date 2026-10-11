using System.Buffers.Binary;
using Corvus.Core;

namespace Corvus.Native.MachO;

/// <summary>One architecture of a universal file; <see cref="Name"/> is unique per CPU subtype (arm64 and arm64e differ).</summary>
public sealed record MachOSlice(int Index, uint CpuType, uint CpuSubType, string Name, long Offset, long Size, uint Align);

/// <summary>Universal (fat) Mach-O headers: FAT_MAGIC and FAT_MAGIC_64, always big-endian.</summary>
public static class MachOFat
{
    private const int MaxSlices = 64;

    public static bool IsFat(ReadOnlySpan<byte> bytes) => NativeImageLoader.Detect(bytes) == NativeFileKind.MachOFat;

    /// <summary>The slices of a universal file; slices that do not lie inside the file are left out.</summary>
    public static IReadOnlyList<MachOSlice> Read(ReadOnlySpan<byte> bytes)
    {
        if (!IsFat(bytes)) return [];
        bool fat64 = BinaryPrimitives.ReadUInt32BigEndian(bytes) == 0xCAFEBABF;
        uint count = Math.Min(BinaryPrimitives.ReadUInt32BigEndian(bytes[4..]), MaxSlices);
        int entry = fat64 ? 32 : 20;
        var result = new List<MachOSlice>();
        var names = new Dictionary<string, int>(StringComparer.Ordinal);
        for (int i = 0; i < count; i++)
        {
            int at = 8 + i * entry;
            if (at + entry > bytes.Length) break;
            var e = bytes[at..];
            uint cpu = BinaryPrimitives.ReadUInt32BigEndian(e), sub = BinaryPrimitives.ReadUInt32BigEndian(e[4..]);
            long offset = fat64 ? (long)Math.Min(BinaryPrimitives.ReadUInt64BigEndian(e[8..]), long.MaxValue) : BinaryPrimitives.ReadUInt32BigEndian(e[8..]);
            long size = fat64 ? (long)Math.Min(BinaryPrimitives.ReadUInt64BigEndian(e[16..]), long.MaxValue) : BinaryPrimitives.ReadUInt32BigEndian(e[12..]);
            uint align = BinaryPrimitives.ReadUInt32BigEndian(e[(fat64 ? 24 : 16)..]);
            if (offset <= 0 || size <= 0 || offset > bytes.Length || size > bytes.Length - offset) continue;
            var name = MachONames.CpuName(cpu, sub);
            names[name] = names.GetValueOrDefault(name) + 1;
            if (names[name] > 1) name += "#" + names[name];
            result.Add(new MachOSlice(i, cpu, sub, name, offset, size, align));
        }
        return result;
    }

    /// <summary>
    /// The slice named or numbered by <paramref name="slice"/>; by default the first of arm64e, arm64, x86_64, then
    /// the first slice.
    /// </summary>
    public static MachOSlice Select(IReadOnlyList<MachOSlice> slices, string? slice)
    {
        if (slices.Count == 0) throw new ToolError(ErrorCode.MalformedInput, "the universal file holds no readable slice");
        if (string.IsNullOrWhiteSpace(slice))
            return slices.FirstOrDefault(s => s.Name == "arm64e") ?? slices.FirstOrDefault(s => s.Name == "arm64")
                ?? slices.FirstOrDefault(s => s.Name == "x86_64") ?? slices[0];
        var key = slice.Trim();
        if (int.TryParse(key, out int index) && slices.FirstOrDefault(s => s.Index == index) is { } byIndex) return byIndex;
        return slices.FirstOrDefault(s => s.Name.Equals(key, StringComparison.OrdinalIgnoreCase))
            ?? throw new ToolError(ErrorCode.InvalidArgument, $"no slice '{key}'; the file holds {string.Join(", ", slices.Select(s => $"{s.Name} ({s.Index})"))}",
                "pass one of the slice names or indexes");
    }
}
