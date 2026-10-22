using System.Buffers.Binary;
using System.Text;
using Corvus.Core.Unity;

namespace Corvus.Tests;

/// <summary>A type tree node as a writer lists it: depth, type, name, byte size (-1 variable), flags and array marker.</summary>
internal sealed record TreeNode(int Level, string Type, string Name, int Size, int Flags = 0, bool Array = false);

/// <summary>Writes Unity serialized files (formats 17 and 22, with or without type trees), object data and UnityFS bundles.</summary>
internal sealed class UnityFileWriter(int format, bool typeTrees, string version = "2021.3.5f1")
{
    public sealed record Type(int ClassId, short ScriptIndex, IReadOnlyList<TreeNode>? Tree);

    public readonly List<Type> Types = [];
    public readonly List<(long PathId, int TypeIndex, byte[] Data)> Objects = [];
    public readonly List<string> Externals = [];

    public byte[] Build()
    {
        var m = new Data();
        m.CString(version);
        m.I32(19);
        m.U8(typeTrees ? (byte)1 : (byte)0);
        m.I32(Types.Count);
        foreach (var t in Types)
        {
            m.I32(t.ClassId);
            m.U8(0);
            m.I16(t.ScriptIndex);
            if (t.ClassId == SerializedFile.ClassMonoBehaviour) m.Zero(16);
            m.Zero(16);
            if (!typeTrees) continue;
            Tree(m, t.Tree ?? throw new InvalidOperationException("a file with type trees needs one for every type"));
            if (format >= 21) m.I32(0);
        }
        int header = format >= 22 ? 48 : 20;
        // Object data starts on a 16-byte boundary past the metadata, each object on 8 bytes.
        var starts = new List<long>();
        long at = 0;
        foreach (var o in Objects)
        {
            at = (at + 7) & ~7L;
            starts.Add(at);
            at += o.Data.Length;
        }
        m.I32(Objects.Count);
        for (int i = 0; i < Objects.Count; i++)
        {
            m.Align(header);
            m.I64(Objects[i].PathId);
            if (format >= 22) m.I64(starts[i]);
            else m.I32((int)starts[i]);
            m.I32(Objects[i].Data.Length);
            m.I32(Objects[i].TypeIndex);
        }
        m.I32(0);
        m.I32(Externals.Count);
        foreach (var e in Externals)
        {
            m.CString("");
            m.Zero(16);
            m.I32(0);
            m.CString(e);
        }
        if (format >= 20) m.I32(0);
        m.CString("");
        var meta = m.ToArray();
        long dataOffset = (header + meta.Length + 15) & ~15L;
        long size = dataOffset + at;
        var file = new byte[size];
        if (format >= 22)
        {
            BinaryPrimitives.WriteInt32BigEndian(file.AsSpan(8), format);
            BinaryPrimitives.WriteInt32BigEndian(file.AsSpan(20), meta.Length);
            BinaryPrimitives.WriteInt64BigEndian(file.AsSpan(24), size);
            BinaryPrimitives.WriteInt64BigEndian(file.AsSpan(32), dataOffset);
        }
        else
        {
            BinaryPrimitives.WriteInt32BigEndian(file.AsSpan(0), meta.Length);
            BinaryPrimitives.WriteInt32BigEndian(file.AsSpan(4), (int)size);
            BinaryPrimitives.WriteInt32BigEndian(file.AsSpan(8), format);
            BinaryPrimitives.WriteInt32BigEndian(file.AsSpan(12), (int)dataOffset);
        }
        meta.CopyTo(file, header);
        for (int i = 0; i < Objects.Count; i++) Objects[i].Data.CopyTo(file, dataOffset + starts[i]);
        return file;
    }

    /// <summary>A blob type tree; names the engine shares are written as offsets into its common strings.</summary>
    private void Tree(Data m, IReadOnlyList<TreeNode> nodes)
    {
        var strings = new MemoryStream();
        var local = new Dictionary<string, uint>();
        uint Offset(string s)
        {
            int common = SerializedFile.CommonOffset(s);
            if (common >= 0) return 0x80000000u | (uint)common;
            if (!local.TryGetValue(s, out uint o))
            {
                local[s] = o = (uint)strings.Length;
                strings.Write(Encoding.UTF8.GetBytes(s + "\0"));
            }
            return o;
        }
        var encoded = nodes.Select(n => (n, Type: Offset(n.Type), Name: Offset(n.Name))).ToList();
        m.I32(nodes.Count);
        m.I32((int)strings.Length);
        for (int i = 0; i < encoded.Count; i++)
        {
            var (n, type, name) = encoded[i];
            m.I16(1);
            m.U8((byte)n.Level);
            m.U8(n.Array ? (byte)1 : (byte)0);
            m.I32((int)type);
            m.I32((int)name);
            m.I32(n.Size);
            m.I32(i);
            m.I32(n.Flags);
            if (format >= 19) m.Zero(8);
        }
        m.Bytes(strings.ToArray());
    }

    /// <summary>A UnityFS bundle (format 6) of the files with one data block, its block info and data packed with <paramref name="codec"/> (0 none, 1 LZMA, 2 LZ4).</summary>
    public static byte[] Bundle(int codec, params (string Path, byte[] Bytes)[] files)
    {
        var whole = files.SelectMany(f => f.Bytes).ToArray();
        var block = Pack(codec, whole);
        var info = new MemoryStream();
        void Be32(int v) { Span<byte> b = stackalloc byte[4]; BinaryPrimitives.WriteInt32BigEndian(b, v); info.Write(b); }
        void Be64(long v) { Span<byte> b = stackalloc byte[8]; BinaryPrimitives.WriteInt64BigEndian(b, v); info.Write(b); }
        info.Write(new byte[16]);
        Be32(1);
        Be32(whole.Length);
        Be32(block.Length);
        info.Write([0, (byte)codec]);
        Be32(files.Length);
        long offset = 0;
        foreach (var (path, bytes) in files)
        {
            Be64(offset);
            Be64(bytes.Length);
            Be32(4);
            info.Write(Encoding.UTF8.GetBytes(path + "\0"));
            offset += bytes.Length;
        }
        var rawInfo = info.ToArray();
        var packedInfo = Pack(codec, rawInfo);
        var head = new MemoryStream();
        head.Write("UnityFS\0"u8);
        var h = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(h, 6);
        head.Write(h);
        head.Write("5.x.x\0"u8);
        head.Write("2021.3.5f1\0"u8);
        long total = head.Length + 8 + 12 + packedInfo.Length + block.Length;
        var tail = new byte[20];
        BinaryPrimitives.WriteInt64BigEndian(tail, total);
        BinaryPrimitives.WriteInt32BigEndian(tail.AsSpan(8), packedInfo.Length);
        BinaryPrimitives.WriteInt32BigEndian(tail.AsSpan(12), rawInfo.Length);
        BinaryPrimitives.WriteInt32BigEndian(tail.AsSpan(16), 0x40 | codec);
        head.Write(tail);
        head.Write(packedInfo);
        head.Write(block);
        return head.ToArray();
    }

    private static byte[] Pack(int codec, byte[] data)
    {
        switch (codec)
        {
            case 0:
                return data;
            case 2:
            {
                var dst = new byte[K4os.Compression.LZ4.LZ4Codec.MaximumOutputSize(data.Length)];
                int n = K4os.Compression.LZ4.LZ4Codec.Encode(data, dst, K4os.Compression.LZ4.LZ4Level.L09_HC);
                return dst[..n];
            }
            case 1:
            {
                var output = new MemoryStream();
                using (var lzma = SharpCompress.Compressors.LZMA.LzmaStream.Create(new SharpCompress.Compressors.LZMA.LzmaEncoderProperties(), false, output))
                {
                    output.Write(lzma.Properties);
                    lzma.Write(data);
                }
                return output.ToArray();
            }
            default:
                throw new ArgumentOutOfRangeException(nameof(codec));
        }
    }

    /// <summary>Little-endian object data, aligned to 4 bytes from its start as the engine writes it.</summary>
    public sealed class Data
    {
        private readonly MemoryStream _s = new();

        public int Length => (int)_s.Length;
        public Data U8(byte v) { _s.WriteByte(v); return this; }
        public Data Bool(bool v) => U8(v ? (byte)1 : (byte)0);
        public Data I16(short v) { Span<byte> b = stackalloc byte[2]; BinaryPrimitives.WriteInt16LittleEndian(b, v); _s.Write(b); return this; }
        public Data I32(int v) { Span<byte> b = stackalloc byte[4]; BinaryPrimitives.WriteInt32LittleEndian(b, v); _s.Write(b); return this; }
        public Data I64(long v) { Span<byte> b = stackalloc byte[8]; BinaryPrimitives.WriteInt64LittleEndian(b, v); _s.Write(b); return this; }
        public Data F32(float v) => I32(BitConverter.SingleToInt32Bits(v));
        public Data Zero(int n) { _s.Write(new byte[n]); return this; }
        public Data Bytes(byte[] b) { _s.Write(b); return this; }
        public Data CString(string s) { _s.Write(Encoding.UTF8.GetBytes(s + "\0")); return this; }

        /// <summary>Pads to 4 bytes; <paramref name="from"/> is where the aligned region's offsets count from.</summary>
        public Data Align(int from = 0)
        {
            while ((_s.Length + from) % 4 != 0) _s.WriteByte(0);
            return this;
        }

        public Data String(string s)
        {
            var b = Encoding.UTF8.GetBytes(s);
            I32(b.Length);
            Bytes(b);
            return Align();
        }

        public Data Pointer(int file, long path) => I32(file).I64(path);
        public byte[] ToArray() => _s.ToArray();
    }
}
