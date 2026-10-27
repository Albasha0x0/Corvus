using System.Buffers.Binary;
using System.Text;

namespace Corvus.Tests.Accuracy;

/// <summary>A stripped ELF copy, layout unchanged: symbol and debug sections zeroed; .dynsym, .eh_frame and relocations kept.</summary>
public static class ElfStrip
{
    public static byte[] Strip(byte[] input)
    {
        var d = (byte[])input.Clone();
        bool is64 = d[4] == 2;
        ulong shoff = is64 ? BinaryPrimitives.ReadUInt64LittleEndian(d.AsSpan(40)) : BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan(32));
        int shentsize = BinaryPrimitives.ReadUInt16LittleEndian(d.AsSpan(is64 ? 58 : 46));
        int shnum = BinaryPrimitives.ReadUInt16LittleEndian(d.AsSpan(is64 ? 60 : 48));
        int shstrndx = BinaryPrimitives.ReadUInt16LittleEndian(d.AsSpan(is64 ? 62 : 50));
        (uint Name, uint Type, ulong Offset, ulong Size) Header(int i)
        {
            int o = (int)shoff + i * shentsize;
            var s = d.AsSpan(o);
            return is64
                ? (BinaryPrimitives.ReadUInt32LittleEndian(s), BinaryPrimitives.ReadUInt32LittleEndian(s[4..]), BinaryPrimitives.ReadUInt64LittleEndian(s[24..]), BinaryPrimitives.ReadUInt64LittleEndian(s[32..]))
                : (BinaryPrimitives.ReadUInt32LittleEndian(s), BinaryPrimitives.ReadUInt32LittleEndian(s[4..]), BinaryPrimitives.ReadUInt32LittleEndian(s[16..]), BinaryPrimitives.ReadUInt32LittleEndian(s[20..]));
        }
        var names = Header(shstrndx);
        var drop = new List<int>();
        for (int i = 0; i < shnum; i++)
        {
            var h = Header(i);
            int start = (int)names.Offset + (int)h.Name;
            int end = Array.IndexOf(d, (byte)0, start);
            string name = Encoding.ASCII.GetString(d, start, end - start);
            if (name is ".symtab" or ".strtab" or ".gnu_debuglink" or ".gnu_debugdata" || name.StartsWith(".debug", StringComparison.Ordinal) || name.StartsWith(".zdebug", StringComparison.Ordinal))
                drop.Add(i);
        }
        foreach (var i in drop)
        {
            var h = Header(i);
            if (h.Type != 8) Array.Clear(d, (int)h.Offset, (int)h.Size);
            int o = (int)shoff + i * shentsize;
            BinaryPrimitives.WriteUInt32LittleEndian(d.AsSpan(o + 4), 0);
            if (is64) BinaryPrimitives.WriteUInt64LittleEndian(d.AsSpan(o + 32), 0);
            else BinaryPrimitives.WriteUInt32LittleEndian(d.AsSpan(o + 20), 0);
        }
        return d;
    }
}
