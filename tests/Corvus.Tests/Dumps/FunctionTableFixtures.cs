using System.Buffers.Binary;

namespace Corvus.Tests;

/// <summary>Writes function table stream bytes (type 13) for synthetic minidumps.</summary>
internal static class FunctionTableFixtures
{
    public const uint StreamType = 13;

    public sealed record Table(ulong Minimum, ulong Maximum, ulong Base, (uint Begin, uint End, uint Unwind)[] Entries);

    /// <summary>A stream with a 24-byte header, then per table a descriptor, a native descriptor and 12-byte entries.</summary>
    public static byte[] Stream(Table[] tables, int nativeBytes = 8)
    {
        var bytes = new List<byte>();
        void U32(uint v) { var b = new byte[4]; BinaryPrimitives.WriteUInt32LittleEndian(b, v); bytes.AddRange(b); }
        void U64(ulong v) { var b = new byte[8]; BinaryPrimitives.WriteUInt64LittleEndian(b, v); bytes.AddRange(b); }
        U32(24); U32(32); U32((uint)nativeBytes); U32(12); U32((uint)tables.Length); U32(0);
        foreach (var t in tables)
        {
            U64(t.Minimum); U64(t.Maximum); U64(t.Base); U32((uint)t.Entries.Length); U32(0);
            bytes.AddRange(new byte[nativeBytes]);
            foreach (var (begin, end, unwind) in t.Entries) { U32(begin); U32(end); U32(unwind); }
        }
        return bytes.ToArray();
    }

    /// <summary>A minidump file holding <paramref name="stream"/> as its function table stream; returns its path.</summary>
    public static string Dump(TempDir dir, byte[] stream, string name = "tables.dmp")
    {
        var b = new MinidumpBuilder();
        b.ExtraStreams.Add((StreamType, stream));
        var path = dir.File(name);
        File.WriteAllBytes(path, b.Build());
        return path;
    }
}
