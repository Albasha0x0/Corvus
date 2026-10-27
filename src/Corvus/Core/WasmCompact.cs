namespace Corvus.Core;

/// <summary>A large WebAssembly module without its bulk: data past <see cref="KeepData"/> and custom sections past <see cref="KeepCustom"/> dropped.</summary>
/// <remarks>Data segments keep their headers; name and producers sections are always kept.</remarks>
public sealed class WasmCompact
{
    /// <summary>A data section up to this size is kept whole.</summary>
    public const long KeepData = 16L << 20;

    /// <summary>A custom section up to this size is kept.</summary>
    public const long KeepCustom = 1L << 20;

    private static readonly HashSet<string> KeptCustom = ["name", "producers", "target_features", "dylink", "dylink.0"];

    /// <summary>The module with the bulk left out.</summary>
    public byte[] Bytes { get; private set; } = [];

    /// <summary>Every section of the file as <see cref="WasmModule.Sections"/> names and sizes them.</summary>
    public List<(string Name, int Size)> Sections { get; } = [];

    /// <summary>Bytes left out: data segment contents and custom sections.</summary>
    public long Omitted { get; private set; }

    /// <summary>Bytes left out before the code section: code offsets in the module are this much lower than in the file.</summary>
    public long OmittedBeforeCode { get; private set; }

    /// <summary>The module in <paramref name=s/> (seekable); sections up to <paramref name=keepData/> / <paramref name=keepCustom/> bytes are kept whole.</summary>
    public static WasmCompact Read(Stream s, CancellationToken ct, long keepData = KeepData, long keepCustom = KeepCustom)
    {
        var compact = new WasmCompact();
        var o = new MemoryStream();
        var header = new byte[(int)Math.Min(8, s.Length)];
        s.Position = 0;
        s.ReadExactly(header);
        o.Write(header);
        bool pastCode = false;
        long length = s.Length;
        while (s.Position < length)
        {
            ct.ThrowIfCancellationRequested();
            long start = s.Position;
            int id = s.ReadByte();
            // The reader reports it.
            if (!Leb(s, out ulong size) || size > (ulong)(length - s.Position)) { Copy(s, o, start, length - start); break; }
            long payload = s.Position, end = payload + (long)size;
            string name = id < WasmModule.Names.Length ? WasmModule.Names[id] : $"id {id}";
            long nameBytes = 0;
            if (id == 0 && Leb(s, out ulong nameLength) && s.Position <= end && nameLength <= (ulong)(end - s.Position) && nameLength < 4096)
            {
                var text = new byte[nameLength];
                s.ReadExactly(text);
                name = System.Text.Encoding.UTF8.GetString(text);
                nameBytes = s.Position - payload;
            }
            compact.Sections.Add((name, (int)Math.Min(int.MaxValue, (long)size - nameBytes)));
            if (id == 0 && (long)size > keepCustom && !KeptCustom.Contains(name))
            {
                compact.Omitted += end - start;
                if (!pastCode) compact.OmittedBeforeCode += end - start;
            }
            else if (id == 11 && (long)size > keepData && DataHeaders(s, payload, end) is { } data)
            {
                o.WriteByte(11);
                WriteLeb(o, (ulong)data.Length);
                o.Write(data);
                compact.Omitted += (long)size - data.Length;
            }
            else Copy(s, o, start, end - start);
            if (id == 10) pastCode = true;
            s.Position = end;
        }
        compact.Bytes = o.ToArray();
        return compact;
    }

    /// <summary>A data section's segments with their bytes left out (lengths 0); null when an offset expression is not one this reads.</summary>
    private static byte[]? DataHeaders(Stream s, long payload, long end)
    {
        s.Position = payload;
        var o = new MemoryStream();
        if (!Leb(s, out ulong count) || count > 1_000_000) return null;
        WriteLeb(o, count);
        for (ulong i = 0; i < count; i++)
        {
            if (!Leb(s, out ulong flags) || flags > 2) return null;
            WriteLeb(o, flags);
            if (flags == 2)
            {
                if (!Leb(s, out ulong memory)) return null;
                WriteLeb(o, memory);
            }
            if (flags != 1 && !ConstExpr(s, o)) return null;
            if (!Leb(s, out ulong bytes) || bytes > (ulong)(end - s.Position)) return null;
            s.Position += (long)bytes;
            WriteLeb(o, 0);
        }
        return s.Position == end ? o.ToArray() : null;
    }

    /// <summary>Copies a constant expression up to its end opcode.</summary>
    private static bool ConstExpr(Stream s, Stream o)
    {
        for (int ops = 0; ops < 64; ops++)
        {
            int op = s.ReadByte();
            if (op < 0) return false;
            o.WriteByte((byte)op);
            switch (op)
            {
                case 0x0B: return true;
                case 0x41 or 0x42 or 0x23 or 0xD2 or 0xD0:
                    while (true)
                    {
                        int b = s.ReadByte();
                        if (b < 0) return false;
                        o.WriteByte((byte)b);
                        if ((b & 0x80) == 0) break;
                    }
                    break;
                case 0x43: if (!CopyBytes(s, o, 4)) return false; break;
                case 0x44: if (!CopyBytes(s, o, 8)) return false; break;
                case 0x6A or 0x6B or 0x6C or 0x7C or 0x7D or 0x7E: break;
                default: return false;
            }
        }
        return false;
    }

    private static bool CopyBytes(Stream s, Stream o, int n)
    {
        for (int i = 0; i < n; i++)
        {
            int b = s.ReadByte();
            if (b < 0) return false;
            o.WriteByte((byte)b);
        }
        return true;
    }

    private static void Copy(Stream s, Stream o, long at, long count)
    {
        s.Position = at;
        var buffer = new byte[(int)Math.Min(count, 1 << 20)];
        for (long done = 0; done < count;)
        {
            int n = s.Read(buffer, 0, (int)Math.Min(buffer.Length, count - done));
            if (n <= 0) break;
            o.Write(buffer, 0, n);
            done += n;
        }
    }

    private static bool Leb(Stream s, out ulong value)
    {
        value = 0;
        for (int shift = 0; shift < 64; shift += 7)
        {
            int b = s.ReadByte();
            if (b < 0) return false;
            value |= (ulong)(b & 0x7F) << shift;
            if ((b & 0x80) == 0) return true;
        }
        return false;
    }

    private static void WriteLeb(Stream o, ulong v)
    {
        do
        {
            byte b = (byte)(v & 0x7F);
            v >>= 7;
            o.WriteByte(v != 0 ? (byte)(b | 0x80) : b);
        } while (v != 0);
    }
}
