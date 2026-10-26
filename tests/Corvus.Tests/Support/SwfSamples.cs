using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;

namespace Corvus.Tests;

/// <summary>Builds SWF files (SWF File Format Specification 19) and ActionScript 3 blocks (AVM2 Overview) for reader tests.</summary>
internal static class SwfSamples
{
    /// <summary>A tag record: the short form below 63 bytes, the long form otherwise (or when <paramref name="longForm"/>).</summary>
    public static byte[] Tag(int code, ReadOnlySpan<byte> body, bool longForm = false)
    {
        var s = new MemoryStream();
        Span<byte> w = stackalloc byte[4];
        if (body.Length < 63 && !longForm)
        {
            BinaryPrimitives.WriteUInt16LittleEndian(w, (ushort)(code << 6 | body.Length));
            s.Write(w[..2]);
        }
        else
        {
            BinaryPrimitives.WriteUInt16LittleEndian(w, (ushort)(code << 6 | 0x3F));
            s.Write(w[..2]);
            BinaryPrimitives.WriteInt32LittleEndian(w, body.Length);
            s.Write(w);
        }
        s.Write(body);
        return s.ToArray();
    }

    public static byte[] U16(int v) => BitConverter.GetBytes((ushort)v);

    public static byte[] U32(uint v) => BitConverter.GetBytes(v);

    public static byte[] Z(params byte[] data)
    {
        var s = new MemoryStream();
        using (var z = new ZLibStream(s, CompressionLevel.Optimal, leaveOpen: true)) z.Write(data);
        return s.ToArray();
    }

    /// <summary>A file of <paramref name="tags"/> (an End tag is appended): 550x400 px, 24 fps, "FWS", "CWS" or "ZWS".</summary>
    public static byte[] File(char compression, int version, int frames, params byte[][] tags)
    {
        // RECT with 15-bit fields: 0, 11000, 0, 8000 twips.
        var rect = new Bits();
        rect.Put(15, 5);
        foreach (int v in new[] { 0, 11000, 0, 8000 }) rect.Put(v, 15);
        var body = new MemoryStream();
        body.Write(rect.ToArray());
        body.Write(U16(24 << 8));
        body.Write(U16(frames));
        foreach (var t in tags) body.Write(t);
        body.Write(Tag(0, []));
        var raw = body.ToArray();
        var file = new MemoryStream();
        file.Write([(byte)compression, (byte)'W', (byte)'S', (byte)version]);
        file.Write(U32((uint)(8 + raw.Length)));
        switch (compression)
        {
            case 'F':
                file.Write(raw);
                break;
            case 'C':
                file.Write(Z(raw));
                break;
            default:
                var packed = new MemoryStream();
                byte[] props;
                using (var lzma = SharpCompress.Compressors.LZMA.LzmaStream.Create(new SharpCompress.Compressors.LZMA.LzmaEncoderProperties(), false, packed))
                {
                    props = lzma.Properties;
                    lzma.Write(raw);
                }
                file.Write(U32((uint)packed.Length));
                file.Write(props);
                file.Write(packed.ToArray());
                break;
        }
        return file.ToArray();
    }

    /// <summary>Most significant bit first, as SWF packs RECT fields.</summary>
    private sealed class Bits
    {
        private readonly List<byte> _bytes = [];
        private int _bit;

        public void Put(int value, int n)
        {
            for (int i = n - 1; i >= 0; i--, _bit++)
            {
                if (_bit % 8 == 0) _bytes.Add(0);
                if ((value >> i & 1) != 0) _bytes[^1] |= (byte)(0x80 >> (_bit % 8));
            }
        }

        public byte[] ToArray() => [.. _bytes];
    }

    /// <summary>
    /// An ActionScript 3 block of two classes: interface sample:IRunner, and sample:Runner extending flash.display:Sprite
    /// and implementing it, with a public slot, a private slot, a method, a getter and a static const.
    /// </summary>
    public static byte[] Abc()
    {
        var a = new AbcWriter();
        int sNone = a.Str(""), sPkg = a.Str("sample"), sFlash = a.Str("flash.display"), sRunner = a.Str("Runner"), sIRunner = a.Str("IRunner"),
            sSprite = a.Str("Sprite"), sCount = a.Str("count"), sSecret = a.Str("secret"), sRun = a.Str("run"), sSize = a.Str("size"),
            sLimit = a.Str("LIMIT"), sVector = a.Str("Vector"), sAs3 = a.Str("__AS3__.vec"), sPriv = a.Str("sample:Runner");
        int nPkg = a.Ns(0x16, sPkg), nFlash = a.Ns(0x16, sFlash), nPub = a.Ns(0x16, sNone), nPriv = a.Ns(0x05, sPriv), nVec = a.Ns(0x16, sAs3);
        int mRunner = a.QName(nPkg, sRunner), mIRunner = a.QName(nPkg, sIRunner), mSprite = a.QName(nFlash, sSprite), mCount = a.QName(nPub, sCount),
            mSecret = a.QName(nPriv, sSecret), mRun = a.QName(nPub, sRun), mSize = a.QName(nPub, sSize), mLimit = a.QName(nPub, sLimit),
            mVector = a.QName(nVec, sVector);
        int mVectorOfRunner = a.TypeName(mVector, mRunner);
        int iinit = a.Method(sNone), cinit = a.Method(sNone), run = a.Method(sRun), size = a.Method(sSize), iiinit = a.Method(sNone), icinit = a.Method(sNone), script = a.Method(sNone);
        a.Ints.Add(7);
        a.Ints.Add(-300);
        a.Uints.Add(4_000_000_000);
        a.Doubles.Add(1.5);
        // Interface first, then the class that implements it.
        a.Instance(mIRunner, 0, 0x04 | 0x01, [], iiinit, []);
        a.Instance(mRunner, mSprite, 0x01, [mIRunner], iinit, [(mCount, 0, 0, mVectorOfRunner), (mSecret, 0, 0, 0), (mRun, 1, run, 0), (mSize, 2, size, 0)]);
        a.Class(icinit, []);
        a.Class(cinit, [(mLimit, 6, 0, 0)]);
        a.Script(script, [(mIRunner, 4, 0, 0), (mRunner, 4, 1, 0)]);
        foreach (int m in new[] { iinit, cinit, run, size, iiinit, icinit, script }) a.Body(m, [0xD0, 0x30, 0x47]);
        return a.ToArray();
    }

    /// <summary>An ABC writer: constant pools, methods, instances, classes, scripts and bodies, written in the format's order.</summary>
    public sealed class AbcWriter
    {
        public List<int> Ints { get; } = [];
        public List<uint> Uints { get; } = [];
        public List<double> Doubles { get; } = [];
        private readonly List<string> _strings = [];
        private readonly List<(byte Kind, int Name)> _ns = [];
        private readonly List<byte[]> _multinames = [];
        private readonly List<int> _methods = [];
        private readonly List<byte[]> _instances = [], _classes = [], _scripts = [], _bodies = [];

        public int Str(string s) { _strings.Add(s); return _strings.Count; }
        public int Ns(byte kind, int name) { _ns.Add((kind, name)); return _ns.Count; }
        public int QName(int ns, int name) { _multinames.Add([0x07, .. U30(ns), .. U30(name)]); return _multinames.Count; }
        public int TypeName(int name, params int[] parameters) { _multinames.Add([0x1D, .. U30(name), .. U30(parameters.Length), .. parameters.SelectMany(U30)]); return _multinames.Count; }
        public int Method(int name) { _methods.Add(name); return _methods.Count - 1; }

        /// <summary>Traits as (name, kind, method or class index, slot type).</summary>
        private static byte[] Traits((int Name, int Kind, int Index, int Type)[] traits)
        {
            var s = new List<byte>(U30(traits.Length));
            foreach (var (name, kind, index, type) in traits)
            {
                s.AddRange(U30(name));
                s.Add((byte)kind);
                if (kind is 0 or 6) s.AddRange([.. U30(0), .. U30(type), .. U30(0)]);
                else s.AddRange([.. U30(0), .. U30(index)]);
            }
            return [.. s];
        }

        public void Instance(int name, int super, byte flags, int[] interfaces, int init, (int, int, int, int)[] traits) =>
            _instances.Add([.. U30(name), .. U30(super), flags, .. U30(interfaces.Length), .. interfaces.SelectMany(U30), .. U30(init), .. Traits(traits)]);

        public void Class(int init, (int, int, int, int)[] traits) => _classes.Add([.. U30(init), .. Traits(traits)]);

        public void Script(int init, (int, int, int, int)[] traits) => _scripts.Add([.. U30(init), .. Traits(traits)]);

        public void Body(int method, byte[] code) =>
            _bodies.Add([.. U30(method), .. U30(1), .. U30(1), .. U30(0), .. U30(1), .. U30(code.Length), .. code, .. U30(0), .. U30(0)]);

        public byte[] ToArray()
        {
            var s = new List<byte>();
            s.AddRange(U16(16));
            s.AddRange(U16(46));
            s.AddRange(U30(Ints.Count + 1));
            foreach (int v in Ints) s.AddRange(U30((uint)v));
            s.AddRange(U30(Uints.Count + 1));
            foreach (uint v in Uints) s.AddRange(U30(v));
            s.AddRange(U30(Doubles.Count + 1));
            foreach (double v in Doubles) s.AddRange(BitConverter.GetBytes(v));
            s.AddRange(U30(_strings.Count + 1));
            foreach (var x in _strings) { var b = Encoding.UTF8.GetBytes(x); s.AddRange(U30(b.Length)); s.AddRange(b); }
            s.AddRange(U30(_ns.Count + 1));
            foreach (var (kind, name) in _ns) { s.Add(kind); s.AddRange(U30(name)); }
            s.AddRange(U30(1));
            s.AddRange(U30(_multinames.Count + 1));
            foreach (var m in _multinames) s.AddRange(m);
            s.AddRange(U30(_methods.Count));
            foreach (int name in _methods) s.AddRange([.. U30(0), .. U30(0), .. U30(name), 0]);
            s.AddRange(U30(0));
            s.AddRange(U30(_instances.Count));
            foreach (var x in _instances) s.AddRange(x);
            foreach (var x in _classes) s.AddRange(x);
            s.AddRange(U30(_scripts.Count));
            foreach (var x in _scripts) s.AddRange(x);
            s.AddRange(U30(_bodies.Count));
            foreach (var x in _bodies) s.AddRange(x);
            return [.. s];
        }
    }

    /// <summary>A variable-length unsigned integer of ABC: 7 bits per byte, low bits first.</summary>
    public static byte[] U30(int v) => U30((uint)v);

    public static byte[] U30(uint v)
    {
        var s = new List<byte>();
        do
        {
            byte b = (byte)(v & 0x7F);
            v >>= 7;
            s.Add(v != 0 ? (byte)(b | 0x80) : b);
        }
        while (v != 0);
        return [.. s];
    }
}
