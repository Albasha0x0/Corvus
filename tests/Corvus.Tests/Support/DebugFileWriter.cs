using System.IO.Compression;
using System.Text;

namespace Corvus.Tests;

/// <summary>Writes an ELF64 little-endian debug file of streamed sections, optionally compressed (SHF_COMPRESSED zlib or zstd, or .zdebug_).</summary>
internal static class DebugFileWriter
{
    public enum Packing { None, Zlib, Zstd, GnuZlib }

    public sealed record Section(string Name, uint Type, Action<Stream> Write, Packing Packing = Packing.None);

    public static Section Bytes(string name, byte[] data, Packing packing = Packing.None) => new(name, 1, s => s.Write(data), packing);

    /// <summary>A .note.gnu.build-id section with <paramref name="id"/> (hex).</summary>
    public static Section BuildId(string id)
    {
        var desc = Convert.FromHexString(id);
        var note = new MemoryStream();
        using (var w = new BinaryWriter(note, Encoding.UTF8, leaveOpen: true))
        {
            w.Write(4); w.Write(desc.Length); w.Write(3);
            w.Write("GNU\0"u8.ToArray());
            w.Write(desc);
            while (note.Length % 4 != 0) w.Write((byte)0);
        }
        return new Section(".note.gnu.build-id", 7, s => s.Write(note.ToArray()));
    }

    public static void Write(string path, IReadOnlyList<Section> sections, ushort machine = 62)
    {
        using var file = new FileStream(path, FileMode.Create, FileAccess.ReadWrite, FileShare.None, 1 << 20);
        file.Write(new byte[64]);
        var names = new MemoryStream();
        names.WriteByte(0);
        var headers = new List<(uint Name, uint Type, ulong Flags, long Offset, long Size)>();
        foreach (var s in sections)
        {
            long start = file.Position;
            string name = s.Packing == Packing.GnuZlib ? ".z" + s.Name[1..] : s.Name;
            ulong flags = 0;
            if (s.Packing == Packing.None) s.Write(file);
            else
            {
                var plain = new MemoryStream();
                s.Write(plain);
                var w = new BinaryWriter(file, Encoding.UTF8, leaveOpen: true);
                if (s.Packing == Packing.GnuZlib)
                {
                    w.Write("ZLIB"u8.ToArray());
                    var size = BitConverter.GetBytes((ulong)plain.Length);
                    Array.Reverse(size);
                    w.Write(size);
                }
                else
                {
                    flags = 0x800; // SHF_COMPRESSED: Elf64_Chdr
                    w.Write(s.Packing == Packing.Zlib ? 1 : 2); w.Write(0); w.Write((ulong)plain.Length); w.Write(1UL);
                }
                w.Flush();
                plain.Position = 0;
                using Stream packer = s.Packing == Packing.Zstd ? new ZstdSharp.CompressionStream(file, leaveOpen: true) : new ZLibStream(file, CompressionLevel.Fastest, leaveOpen: true);
                plain.CopyTo(packer);
            }
            headers.Add(((uint)names.Position, s.Type, flags, start, file.Position - start));
            names.Write(Encoding.UTF8.GetBytes(name + "\0"));
        }
        long namesAt = file.Position;
        uint namesName = (uint)names.Position;
        names.Write(".shstrtab\0"u8);
        names.Position = 0;
        names.CopyTo(file);
        headers.Add((namesName, 3, 0, namesAt, names.Length));
        while (file.Position % 8 != 0) file.WriteByte(0);
        long shoff = file.Position;
        var hw = new BinaryWriter(file, Encoding.UTF8, leaveOpen: true);
        hw.Write(new byte[64]);
        foreach (var (name, type, flags, offset, size) in headers)
        {
            hw.Write(name); hw.Write(type); hw.Write(flags); hw.Write(0UL); hw.Write((ulong)offset); hw.Write((ulong)size);
            hw.Write(0u); hw.Write(0u); hw.Write(1UL); hw.Write(0UL);
        }
        hw.Flush();
        file.Position = 0;
        var head = new BinaryWriter(file, Encoding.UTF8, leaveOpen: true);
        head.Write([0x7F, (byte)'E', (byte)'L', (byte)'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        head.Write((ushort)3); head.Write(machine); head.Write(1u); head.Write(0UL); head.Write(0UL); head.Write((ulong)shoff);
        head.Write(0u); head.Write((ushort)64); head.Write((ushort)56); head.Write((ushort)0); head.Write((ushort)64);
        head.Write((ushort)(headers.Count + 1)); head.Write((ushort)headers.Count);
        head.Flush();
    }
}
