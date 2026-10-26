using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;

namespace Corvus.Tests;

/// <summary>Model files built here: safetensors and GGUF headers, ONNX protobuf messages, pickles and a torch.save zip.</summary>
internal static class ModelSamples
{
    public static byte[] Safetensors(string json, int dataBytes)
    {
        var header = Encoding.UTF8.GetBytes(json);
        var b = new byte[8 + header.Length + dataBytes];
        BinaryPrimitives.WriteUInt64LittleEndian(b, (ulong)header.Length);
        header.CopyTo(b, 8);
        return b;
    }

    /// <summary>A GGUF v3 header: metadata written by <paramref name="kv"/>, then the tensor infos, aligned to <paramref name="alignment"/>.</summary>
    public static byte[] Gguf(Action<GgufWriter> kv, int kvCount, (string Name, uint Type, ulong[] Dims, ulong Offset)[] tensors, int alignment = 32, int dataBytes = 0)
    {
        var w = new GgufWriter();
        w.Raw("GGUF"u8);
        w.U32(3);
        w.U64((ulong)tensors.Length);
        w.U64((ulong)kvCount);
        kv(w);
        foreach (var (name, type, dims, offset) in tensors)
        {
            w.String(name);
            w.U32((uint)dims.Length);
            foreach (var d in dims) w.U64(d);
            w.U32(type);
            w.U64(offset);
        }
        while (w.Length % alignment != 0) w.Raw([0]);
        w.Raw(new byte[dataBytes]);
        return w.ToArray();
    }

    public sealed class GgufWriter
    {
        private readonly MemoryStream _m = new();
        public long Length => _m.Length;
        public void Raw(ReadOnlySpan<byte> b) => _m.Write(b);
        public void U32(uint v) { Span<byte> b = stackalloc byte[4]; BinaryPrimitives.WriteUInt32LittleEndian(b, v); _m.Write(b); }
        public void U64(ulong v) { Span<byte> b = stackalloc byte[8]; BinaryPrimitives.WriteUInt64LittleEndian(b, v); _m.Write(b); }
        public void String(string s) { var b = Encoding.UTF8.GetBytes(s); U64((ulong)b.Length); _m.Write(b); }
        public void Key(string key, uint type) { String(key); U32(type); }
        public byte[] ToArray() => _m.ToArray();
    }

    // Protobuf fields.
    public static byte[] Varint(ulong v)
    {
        var b = new List<byte>();
        do { byte x = (byte)(v & 0x7F); v >>= 7; b.Add(v != 0 ? (byte)(x | 0x80) : x); } while (v != 0);
        return [.. b];
    }

    public static byte[] V(int field, ulong value) => [.. Varint((ulong)field << 3), .. Varint(value)];
    public static byte[] L(int field, params byte[][] body)
    {
        var all = body.SelectMany(x => x).ToArray();
        return [.. Varint((ulong)field << 3 | 2), .. Varint((ulong)all.Length), .. all];
    }
    public static byte[] S(int field, string s) => L(field, Encoding.UTF8.GetBytes(s));

    /// <summary>
    /// IR 9 from "writer" 2.0 at opset 18: input x FLOAT[N,3], output y FLOAT[N,3]; nodes Add, Relu and an If with two
    /// one-node branches; an inline initializer b FLOAT[3] and an external one w INT64[4,4] in "w.bin" at 128; metadata.
    /// </summary>
    public static byte[] Onnx()
    {
        byte[] TensorType(int elem, params object[] dims) =>
            L(1, V(1, (ulong)elem), L(2, [.. dims.SelectMany(d => L(1, d is string p ? S(2, p) : V(1, (ulong)(int)d)))]));
        byte[] Branch(string op) => L(6, L(1, S(1, "x"), S(2, "o"), S(4, op)), S(2, op));
        var graph = L(7,
            L(1, S(1, "x"), S(1, "b"), S(2, "s"), S(3, "add0"), S(4, "Add")),
            L(1, S(1, "s"), S(2, "r"), S(4, "Relu")),
            L(1, S(1, "c"), S(2, "y"), S(4, "If"), L(5, S(1, "then_branch"), Branch("Identity")), L(5, S(1, "else_branch"), Branch("Neg"))),
            S(2, "main"),
            L(5, V(1, 3), V(2, 1), S(8, "b"), L(9, new byte[12])),
            L(5, L(1, [.. Varint(4), .. Varint(4)]), V(2, 7), S(8, "w"), L(13, S(1, "location"), S(2, "w.bin")), L(13, S(1, "offset"), S(2, "128")),
                L(13, S(1, "length"), S(2, "128")), V(14, 1)),
            L(11, S(1, "x"), L(2, TensorType(1, "N", 3))),
            L(12, S(1, "y"), L(2, TensorType(1, "N", 3))));
        return [.. V(1, 9), .. S(2, "writer"), .. S(3, "2.0"), .. graph, .. L(8, S(1, ""), V(2, 18)), .. L(14, S(1, "author"), S(2, "tests"))];
    }

    /// <summary>Pickle opcodes as torch.save and pickle.dump write them.</summary>
    public sealed class Pickle
    {
        private readonly MemoryStream _m = new();
        public Pickle Op(char c) { _m.WriteByte((byte)c); return this; }
        public Pickle Op(byte c) { _m.WriteByte(c); return this; }
        public Pickle Proto(int p) => Op(0x80).Op((byte)p);
        public Pickle Global(string module, string name) { Op('c'); _m.Write(Encoding.UTF8.GetBytes($"{module}\n{name}\n")); return this; }
        public Pickle Str(string s)
        {
            var b = Encoding.UTF8.GetBytes(s);
            Op('X');
            _m.Write(BitConverter.GetBytes(b.Length));
            _m.Write(b);
            return this;
        }
        public Pickle Short(string s) { var b = Encoding.UTF8.GetBytes(s); Op(0x8c).Op((byte)b.Length); _m.Write(b); return this; }
        public Pickle Int(int i) { Op('J'); _m.Write(BitConverter.GetBytes(i)); return this; }
        public Pickle Put(byte i) => Op('q').Op(i);
        public Pickle Get(byte i) => Op('h').Op(i);
        public Pickle Tuple(params int[] items)
        {
            Op('(');
            foreach (var i in items) Int(i);
            return Op('t');
        }
        public byte[] ToArray() => _m.ToArray();
    }

    /// <summary>
    /// A torch.save state dict at protocol 2: "weight" float32 [3, 4] on storage "0" and "bias" float16 [3] on storage "1",
    /// both rebuilt with torch._utils._rebuild_tensor_v2 in a collections.OrderedDict.
    /// </summary>
    public static byte[] StateDict()
    {
        var p = new Pickle().Proto(2).Global("collections", "OrderedDict").Put(0).Op(')').Op('R').Put(1).Op('(');
        void Tensor(string name, string storage, string key, int numel, int[] shape, int[] stride, bool first)
        {
            p.Str(name);
            if (first) p.Global("torch._utils", "_rebuild_tensor_v2").Put(2); else p.Get(2);
            p.Op('(').Op('(').Str("storage").Global("torch", storage).Str(key).Str("cpu").Int(numel).Op('t').Op('Q').Int(0).Tuple(shape).Tuple(stride)
                .Op(0x89).Get(0).Op(')').Op('R').Op('t').Op('R');
        }
        Tensor("weight", "FloatStorage", "0", 12, [3, 4], [4, 1], true);
        Tensor("bias", "HalfStorage", "1", 3, [3], [1], false);
        return p.Op('u').Op('.').ToArray();
    }

    /// <summary>A zip as torch.save writes it, under "archive/"; <paramref name="storageBytes"/> sizes data/0 and data/1.</summary>
    public static byte[] TorchZip(int weightBytes = 48, int biasBytes = 6)
    {
        var m = new MemoryStream();
        using (var zip = new ZipArchive(m, ZipArchiveMode.Create, leaveOpen: true))
        {
            void Add(string name, byte[] data)
            {
                using var s = zip.CreateEntry(name, CompressionLevel.NoCompression).Open();
                s.Write(data);
            }
            Add("archive/data.pkl", StateDict());
            Add("archive/byteorder", "little"u8.ToArray());
            Add("archive/data/0", new byte[weightBytes]);
            Add("archive/data/1", new byte[biasBytes]);
            Add("archive/version", "3\n"u8.ToArray());
        }
        return m.ToArray();
    }
}
