using System.Buffers.Binary;

namespace Corvus.Native.Dump;

/// <summary>One x64 RUNTIME_FUNCTION as absolute addresses: [Begin, End) and the unwind data address.</summary>
public sealed record RegisteredFunction(ulong Begin, ulong End, ulong UnwindInfo);

/// <summary>A registered function table: its address range, base address and entries.</summary>
public sealed record RegisteredFunctionTable(
    ulong MinimumAddress, ulong MaximumAddress, ulong BaseAddress, IReadOnlyList<RegisteredFunction> Functions);

/// <summary>The function tables a program registered with RtlAddFunctionTable.</summary>
public sealed record FunctionTableStream(IReadOnlyList<RegisteredFunctionTable> Tables);

/// <summary>Reads the function table stream (MINIDUMP_FUNCTION_TABLE_STREAM) of a minidump.</summary>
public static class MinidumpFunctionTables
{
    /// <summary>Entries read across all tables before the stream is refused.</summary>
    public const int MaxEntries = 1 << 20;

    private const uint FunctionTableStreamType = 13;
    private const int HeaderBytes = 24, DescriptorBytes = 32, EntryBytes = 12;

    /// <summary>
    /// The registered function tables of <paramref name="dump"/>. Null with a null
    /// <paramref name="reason"/> when the dump has no such stream; null with the reason
    /// when the stream is malformed, truncated or over <see cref="MaxEntries"/>.
    /// </summary>
    public static FunctionTableStream? Read(MinidumpFile dump, out string? reason)
    {
        reason = null;
        var stream = dump.Streams.FirstOrDefault(s => s.Type == FunctionTableStreamType);
        if (stream == null) return null;
        if (stream.Size > MinidumpLimits.MaxStreamBytes)
        {
            reason = $"the function table stream is 0x{stream.Size:X} bytes; the limit is {MinidumpLimits.MaxStreamBytes}";
            return null;
        }
        var data = dump.ReadStream(FunctionTableStreamType) ?? [];
        return Parse(data, out reason);
    }

    private static FunctionTableStream? Parse(byte[] data, out string? reason)
    {
        reason = null;
        if (data.Length < HeaderBytes)
        {
            reason = $"the function table stream is truncated: {data.Length} bytes, the header needs {HeaderBytes}";
            return null;
        }
        uint headerSize = U32(data, 0), descriptorSize = U32(data, 4), nativeSize = U32(data, 8),
            entrySize = U32(data, 12), count = U32(data, 16);
        if (headerSize < HeaderBytes || descriptorSize < DescriptorBytes || entrySize < EntryBytes)
        {
            reason = $"the function table header is inconsistent: header {headerSize}, descriptor {descriptorSize}, entry {entrySize} bytes";
            return null;
        }
        var tables = new List<RegisteredFunctionTable>();
        long at = headerSize, total = 0;
        for (uint i = 0; i < count; i++)
        {
            if (at + DescriptorBytes > data.Length)
            {
                reason = $"the function table stream is truncated in descriptor {i} of {count}";
                return null;
            }
            var d = data.AsSpan((int)at);
            ulong min = U64(d, 0), max = U64(d, 8), baseAddress = U64(d, 16);
            uint entries = U32(d, 24), pad = U32(d, 28);
            total += entries;
            if (total > MaxEntries)
            {
                reason = $"the function table stream declares more than {MaxEntries} entries, the limit";
                return null;
            }
            long entriesAt = at + descriptorSize + nativeSize;
            long end = entriesAt + (long)entries * entrySize;
            if (end > data.Length)
            {
                reason = $"the function table stream is truncated in descriptor {i} of {count}: {entries} entries need {end} bytes, the stream has {data.Length}";
                return null;
            }
            var functions = new List<RegisteredFunction>((int)entries);
            for (uint e = 0; e < entries; e++)
            {
                var r = data.AsSpan((int)(entriesAt + e * (long)entrySize));
                functions.Add(new RegisteredFunction(baseAddress + U32(r, 0), baseAddress + U32(r, 4), baseAddress + U32(r, 8)));
            }
            tables.Add(new RegisteredFunctionTable(min, max, baseAddress, functions));
            at = end + pad;
        }
        return new FunctionTableStream(tables);
    }

    private static uint U32(ReadOnlySpan<byte> b, int o) => BinaryPrimitives.ReadUInt32LittleEndian(b[o..]);

    private static ulong U64(ReadOnlySpan<byte> b, int o) => BinaryPrimitives.ReadUInt64LittleEndian(b[o..]);
}
