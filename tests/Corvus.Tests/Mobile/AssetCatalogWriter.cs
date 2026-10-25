using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;

namespace Corvus.Tests;

/// <summary>
/// Builds little-endian compiled asset catalogs: a BOM store with CARHEADER, EXTENDED_METADATA, KEYFORMAT, FACETKEYS,
/// APPEARANCEKEYS and RENDITIONS. Rendition keys hold scale, idiom, identifier and appearance, in that order.
/// </summary>
internal sealed class AssetCatalogWriter
{
    public static readonly int[] KeyTypes = [12, 15, 17, 7];

    private readonly List<(string Name, int Id)> _facets = [];
    private readonly List<(string Name, int Id)> _appearances = [];
    private readonly List<(int[] Key, byte[] Csi)> _renditions = [];
    private int? _declared;

    public AssetCatalogWriter Facet(string name, int identifier) { _facets.Add((name, identifier)); return this; }

    public AssetCatalogWriter Appearance(string name, int id) { _appearances.Add((name, id)); return this; }

    public AssetCatalogWriter Declared(int count) { _declared = count; return this; }

    /// <summary>A rendition: key (scale, idiom, identifier, appearance), CSI fields, TLVs and the payload after them.</summary>
    public AssetCatalogWriter Rendition(int[] key, string name, int layout, string pixelFormat, int width, int height, int scale, byte[] payload, byte[]? tlvs = null)
    {
        tlvs ??= [];
        var csi = new byte[184 + tlvs.Length + payload.Length];
        var s = csi.AsSpan();
        Code("CTSI").CopyTo(s);
        BinaryPrimitives.WriteUInt32LittleEndian(s[4..], 1);
        BinaryPrimitives.WriteUInt32LittleEndian(s[12..], (uint)width);
        BinaryPrimitives.WriteUInt32LittleEndian(s[16..], (uint)height);
        BinaryPrimitives.WriteUInt32LittleEndian(s[20..], (uint)scale);
        Code(pixelFormat).CopyTo(s[24..]);
        BinaryPrimitives.WriteUInt16LittleEndian(s[36..], (ushort)layout);
        Encoding.UTF8.GetBytes(name).CopyTo(s[40..]);
        BinaryPrimitives.WriteUInt32LittleEndian(s[168..], (uint)tlvs.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(s[172..], 1);
        BinaryPrimitives.WriteUInt32LittleEndian(s[180..], (uint)payload.Length);
        tlvs.CopyTo(s[184..]);
        payload.CopyTo(s[(184 + tlvs.Length)..]);
        _renditions.Add((key, csi));
        return this;
    }

    public byte[] Build()
    {
        var bom = new Bom();
        var header = new byte[436];
        "RATC"u8.CopyTo(header);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(16), (uint)(_declared ?? _renditions.Count));
        Encoding.ASCII.GetBytes("Xcode 26.0 (17A000) via AssetCatalogAgent").CopyTo(header.AsSpan(148));
        bom.Variable("CARHEADER", header);
        var meta = new byte[1028];
        "ATEM"u8.CopyTo(meta);
        Encoding.ASCII.GetBytes("17.0").CopyTo(meta.AsSpan(260));
        Encoding.ASCII.GetBytes("ios").CopyTo(meta.AsSpan(516));
        bom.Variable("EXTENDED_METADATA", meta);
        var format = new byte[12 + 4 * KeyTypes.Length];
        Code("kfmt").CopyTo(format);
        BinaryPrimitives.WriteUInt32LittleEndian(format.AsSpan(8), (uint)KeyTypes.Length);
        for (int i = 0; i < KeyTypes.Length; i++) BinaryPrimitives.WriteUInt32LittleEndian(format.AsSpan(12 + 4 * i), (uint)KeyTypes[i]);
        bom.Variable("KEYFORMAT", format);
        bom.Tree("FACETKEYS", _facets.Select(f =>
        {
            var value = new byte[10];
            BinaryPrimitives.WriteUInt16LittleEndian(value.AsSpan(4), 1);
            BinaryPrimitives.WriteUInt16LittleEndian(value.AsSpan(6), 17);
            BinaryPrimitives.WriteUInt16LittleEndian(value.AsSpan(8), (ushort)f.Id);
            return (Encoding.UTF8.GetBytes(f.Name), value);
        }).ToList());
        bom.Tree("APPEARANCEKEYS", _appearances.Select(a => (Encoding.UTF8.GetBytes(a.Name), U16(a.Id))).ToList());
        bom.Tree("RENDITIONS", _renditions.Select(r => (r.Key.SelectMany(U16).ToArray(), r.Csi)).ToList());
        return bom.Build();
    }

    /// <summary>A four-character code as little-endian CAR data stores it: the number, so the bytes reversed.</summary>
    public static byte[] Code(string code) => [.. Encoding.ASCII.GetBytes(code).Reverse()];

    public static byte[] Celm(uint compression, byte[] data)
    {
        var celm = new byte[16 + data.Length];
        Code("CELM").CopyTo(celm, 0);
        BinaryPrimitives.WriteUInt32LittleEndian(celm.AsSpan(8), compression);
        BinaryPrimitives.WriteUInt32LittleEndian(celm.AsSpan(12), (uint)data.Length);
        data.CopyTo(celm, 16);
        return celm;
    }

    public static byte[] Rawd(byte[] data)
    {
        var rawd = new byte[12 + data.Length];
        Code("RAWD").CopyTo(rawd, 0);
        BinaryPrimitives.WriteUInt32LittleEndian(rawd.AsSpan(8), (uint)data.Length);
        data.CopyTo(rawd, 12);
        return rawd;
    }

    public static byte[] Color(uint space, params double[] components)
    {
        var colr = new byte[16 + 8 * components.Length];
        Code("COLR").CopyTo(colr, 0);
        BinaryPrimitives.WriteUInt32LittleEndian(colr.AsSpan(8), space);
        BinaryPrimitives.WriteUInt32LittleEndian(colr.AsSpan(12), (uint)components.Length);
        for (int i = 0; i < components.Length; i++) BinaryPrimitives.WriteDoubleLittleEndian(colr.AsSpan(16 + 8 * i), components[i]);
        return colr;
    }

    public static byte[] Gradient(int stops)
    {
        var argg = new byte[8];
        "ARGG"u8.CopyTo(argg);
        BinaryPrimitives.WriteUInt32LittleEndian(argg.AsSpan(4), (uint)stops);
        return argg;
    }

    /// <summary>The internal link TLV (1010): a rectangle with a lower-left origin in the packed rendition the key names.</summary>
    public static byte[] Link(int x, int y, int width, int height, int[] key)
    {
        var tlv = new byte[8 + 30 + 4 * key.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(tlv, 1010);
        BinaryPrimitives.WriteUInt32LittleEndian(tlv.AsSpan(4), (uint)(tlv.Length - 8));
        var v = tlv.AsSpan(8);
        BinaryPrimitives.WriteUInt32LittleEndian(v[8..], (uint)x);
        BinaryPrimitives.WriteUInt32LittleEndian(v[12..], (uint)y);
        BinaryPrimitives.WriteUInt32LittleEndian(v[16..], (uint)width);
        BinaryPrimitives.WriteUInt32LittleEndian(v[20..], (uint)height);
        BinaryPrimitives.WriteUInt32LittleEndian(v[26..], (uint)(4 * key.Length));
        for (int i = 0; i < key.Length; i++)
        {
            BinaryPrimitives.WriteUInt16LittleEndian(v[(30 + 4 * i)..], (ushort)KeyTypes[i]);
            BinaryPrimitives.WriteUInt16LittleEndian(v[(32 + 4 * i)..], (ushort)key[i]);
        }
        return tlv;
    }

    /// <summary>An LZFSE stream of raw (bvx-) blocks.</summary>
    public static byte[] Lzfse(byte[] data)
    {
        using var o = new MemoryStream();
        o.Write("bvx-"u8);
        o.Write(BitConverter.GetBytes((uint)data.Length));
        o.Write(data);
        o.Write("bvx$"u8);
        return o.ToArray();
    }

    /// <summary>A raw LZVN stream of literal runs and its end-of-stream opcode.</summary>
    public static byte[] Lzvn(byte[] data)
    {
        using var o = new MemoryStream();
        for (int at = 0; at < data.Length;)
        {
            int n = Math.Min(271, data.Length - at);
            if (n < 16) o.WriteByte((byte)(0xE0 | n));
            else { o.WriteByte(0xE0); o.WriteByte((byte)(n - 16)); }
            o.Write(data, at, n);
            at += n;
        }
        o.Write([6, 0, 0, 0, 0, 0, 0, 0]);
        return o.ToArray();
    }

    public static byte[] Gzip(byte[] data)
    {
        using var o = new MemoryStream();
        using (var z = new GZipStream(o, CompressionLevel.Fastest, leaveOpen: true)) z.Write(data);
        return o.ToArray();
    }

    /// <summary>KCBC chunks: each holds <paramref name="rowsPerChunk"/> rows of <paramref name="row"/> bytes, packed by <paramref name="pack"/>.</summary>
    public static byte[] Kcbc(byte[] rows, int row, int rowsPerChunk, Func<byte[], byte[]> pack)
    {
        using var o = new MemoryStream();
        for (int at = 0; at < rows.Length; at += row * rowsPerChunk)
        {
            int count = Math.Min(rowsPerChunk, (rows.Length - at) / row);
            var packed = pack(rows.AsSpan(at, count * row).ToArray());
            o.Write("KCBC"u8);
            o.Write(new byte[8]);
            o.Write(BitConverter.GetBytes((uint)count));
            o.Write(BitConverter.GetBytes((uint)packed.Length));
            o.Write(packed);
        }
        return o.ToArray();
    }

    /// <summary>A deepmap-2 blob of four-component (BGRA) pixels: the container, method and the method's data.</summary>
    public static byte[] Deepmap(int method, int width, int height, byte[] data, uint? descriptor = null)
    {
        int extra = descriptor is null ? 0 : 4;
        var blob = new byte[28 + extra + data.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(blob, 1);
        BinaryPrimitives.WriteUInt64LittleEndian(blob.AsSpan(8), (ulong)(blob.Length - 16));
        "dmp2"u8.CopyTo(blob.AsSpan(16));
        blob[20] = (byte)method;
        blob[21] = 1;
        blob[23] = 4;
        BinaryPrimitives.WriteUInt16LittleEndian(blob.AsSpan(24), (ushort)width);
        BinaryPrimitives.WriteUInt16LittleEndian(blob.AsSpan(26), (ushort)height);
        if (descriptor is { } d) BinaryPrimitives.WriteUInt32LittleEndian(blob.AsSpan(28), d);
        data.CopyTo(blob, 28 + extra);
        return blob;
    }

    public static byte[] DeepmapRaw(int width, int height, byte[] bgra) => Deepmap(1, width, height, bgra);

    /// <summary>Lossless deepmap-2: the stored pixels split into LZFSE segments at <paramref name="splits"/>.</summary>
    public static byte[] DeepmapLossless(int width, int height, byte[] bgra, params int[] splits)
    {
        var cuts = splits.Prepend(0).Append(bgra.Length).ToArray();
        var segments = Enumerable.Range(0, cuts.Length - 1).Select(i => Lzfse(bgra[cuts[i]..cuts[i + 1]])).ToList();
        using var o = new MemoryStream();
        o.Write(segments[0]);
        foreach (var s in segments.Skip(1))
        {
            o.Write(BitConverter.GetBytes((uint)s.Length));
            o.Write(s);
        }
        return Deepmap(3, width, height, o.ToArray(), (uint)segments[0].Length);
    }

    /// <summary>Palette deepmap-2 of whole pixels: the entries, then an LZVN stream of one-byte indices.</summary>
    public static byte[] DeepmapPalette(int width, int height, byte[] bgra)
    {
        var entries = new List<uint>();
        var indices = new byte[width * height];
        for (int i = 0; i < indices.Length; i++)
        {
            uint px = BinaryPrimitives.ReadUInt32LittleEndian(bgra.AsSpan(4 * i));
            int at = entries.IndexOf(px);
            if (at < 0) { at = entries.Count; entries.Add(px); }
            indices[i] = (byte)at;
        }
        var stream = Lzvn(indices);
        var data = new byte[4 * entries.Count + 4 + stream.Length];
        for (int i = 0; i < entries.Count; i++) BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(4 * i), entries[i]);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(4 * entries.Count), (uint)stream.Length);
        stream.CopyTo(data, 4 * entries.Count + 4);
        return Deepmap(4, width, height, data, (uint)(entries.Count | 4 << 16));
    }

    /// <summary>
    /// Default deepmap-2: forward YCoCg-R residuals with one predictor per row (0 none, 2 left, 3 up), in one LZFSE
    /// segment. Each pixel's B - R and G - (R + (B - R) / 2) must be even, as the stored chroma is halved.
    /// </summary>
    public static byte[] DeepmapDefault(int width, int height, byte[] bgra, byte[] predictors)
    {
        int n = width * height;
        var values = new int[n * 3];
        for (int i = 0; i < n; i++)
        {
            int b = bgra[4 * i], g = bgra[4 * i + 1], r = bgra[4 * i + 2];
            int co = b - r, t = r + co / 2, cg = g - t;
            if (co % 2 != 0 || cg % 2 != 0) throw new ArgumentException($"pixel {i} has odd chroma");
            (values[3 * i], values[3 * i + 1], values[3 * i + 2]) = (t + cg / 2, co / 2, cg / 2);
        }
        var plane = new byte[n + height + 6 * n];
        for (int y = 0; y < height; y++)
        {
            plane[n + y] = predictors[y];
            for (int x = 0; x < width; x++)
                for (int c = 0; c < 3; c++)
                {
                    int i = (y * width + x) * 3 + c, v = values[i];
                    int predicted = predictors[y] switch
                    {
                        2 when x > 0 => values[i - 3],
                        3 when y > 0 => values[i - 3 * width],
                        _ => 0,
                    };
                    int residual = v - predicted, encoded = Math.Abs(residual) << 1 | (residual < 0 ? 1 : 0);
                    plane[n + height + i] = (byte)(encoded >> 8);
                    plane[n + height + 3 * n + i] = (byte)encoded;
                }
        }
        for (int i = 0; i < n; i++) plane[i] = bgra[4 * i + 3];
        var segment = Lzfse(plane);
        return Deepmap(2, width, height, segment, (uint)segment.Length);
    }

    private static byte[] U16(int v) => BitConverter.GetBytes((ushort)v);

    // Big-endian BOM store: header, blocks, the block index, then the variables table. Trees of more than two entries
    // get one leaf per two entries under a branch, so readers follow the forward links.
    private sealed class Bom
    {
        private readonly List<byte[]> _blocks = [[]];
        private readonly List<(string Name, int Id)> _variables = [];

        public void Variable(string name, byte[] block) => _variables.Add((name, Add(block)));

        public void Tree(string name, List<(byte[] Key, byte[] Value)> entries)
        {
            var leaves = entries.Chunk(2).Select(c => c.Select(e => (Add(e.Value), Add(e.Key))).ToArray()).ToList();
            var ids = leaves.Select(_ => Add([])).ToList();
            for (int i = 0; i < leaves.Count; i++) _blocks[ids[i]] = Node(true, leaves[i], i + 1 < ids.Count ? ids[i + 1] : 0);
            int root = ids.Count switch
            {
                0 => Add(Node(true, [], 0)),
                1 => ids[0],
                _ => Add(Node(false, [.. ids.Select(id => (id, 0))], 0)),
            };
            var header = new byte[21];
            "tree"u8.CopyTo(header);
            BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(4), 1);
            BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(8), (uint)root);
            BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(12), 4096);
            BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(16), (uint)entries.Count);
            Variable(name, header);
        }

        private static byte[] Node(bool leaf, (int Value, int Key)[] entries, int forward)
        {
            var node = new byte[12 + 8 * entries.Length];
            BinaryPrimitives.WriteUInt16BigEndian(node, (ushort)(leaf ? 1 : 0));
            BinaryPrimitives.WriteUInt16BigEndian(node.AsSpan(2), (ushort)entries.Length);
            BinaryPrimitives.WriteUInt32BigEndian(node.AsSpan(4), (uint)forward);
            for (int i = 0; i < entries.Length; i++)
            {
                BinaryPrimitives.WriteUInt32BigEndian(node.AsSpan(12 + 8 * i), (uint)entries[i].Value);
                BinaryPrimitives.WriteUInt32BigEndian(node.AsSpan(16 + 8 * i), (uint)entries[i].Key);
            }
            return node;
        }

        private int Add(byte[] block)
        {
            _blocks.Add(block);
            return _blocks.Count - 1;
        }

        public byte[] Build()
        {
            using var o = new MemoryStream();
            o.Write(new byte[32]);
            var at = new uint[_blocks.Count];
            for (int i = 1; i < _blocks.Count; i++)
            {
                at[i] = (uint)o.Position;
                o.Write(_blocks[i]);
            }
            uint index = (uint)o.Position;
            o.Write(Be(_blocks.Count));
            for (int i = 0; i < _blocks.Count; i++)
            {
                o.Write(Be((int)at[i]));
                o.Write(Be(_blocks[i].Length));
            }
            uint vars = (uint)o.Position;
            o.Write(Be(_variables.Count));
            foreach (var (name, id) in _variables)
            {
                o.Write(Be(id));
                o.WriteByte((byte)name.Length);
                o.Write(Encoding.ASCII.GetBytes(name));
            }
            var file = o.ToArray();
            "BOMStore"u8.CopyTo(file);
            BinaryPrimitives.WriteUInt32BigEndian(file.AsSpan(8), 1);
            BinaryPrimitives.WriteUInt32BigEndian(file.AsSpan(12), (uint)(_blocks.Count - 1));
            BinaryPrimitives.WriteUInt32BigEndian(file.AsSpan(16), index);
            BinaryPrimitives.WriteUInt32BigEndian(file.AsSpan(20), vars - index);
            BinaryPrimitives.WriteUInt32BigEndian(file.AsSpan(24), vars);
            BinaryPrimitives.WriteUInt32BigEndian(file.AsSpan(28), (uint)(file.Length - vars));
            return file;
        }

        private static byte[] Be(int v)
        {
            var b = new byte[4];
            BinaryPrimitives.WriteInt32BigEndian(b, v);
            return b;
        }
    }
}
