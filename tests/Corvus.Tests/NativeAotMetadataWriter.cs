using System.Buffers.Binary;
using System.Text;
using Corvus.Native.NativeAot;

namespace Corvus.Tests;

/// <summary>
/// Writes NativeFormat metadata blobs in a given dialect for reader tests. Field values follow the schema codes:
/// h <see cref="MdHandle"/>, t uint offset or <see cref="Fwd"/>, c list of offsets or handles, u uint, i int, s string,
/// b byte, 1 byte[]. Collections of fixed-kind handles take offsets (uint), handle collections take handles. A <see cref="Fwd"/> is written as a 5-byte integer and patched in <see cref="ToArray"/>.
/// </summary>
internal sealed class NativeAotMetadataWriter
{
    public sealed class Fwd
    {
        public uint Value;
        /// <summary>Set for a handle field: the patched integer is the encoded handle of this kind.</summary>
        public MdRecord? Record;
    }

    private readonly List<byte> bytes = [];
    private readonly List<(int At, Fwd Ref)> patches = [];
    private readonly List<object> scopes = [];
    public NativeAotFormat Format { get; }

    public NativeAotMetadataWriter(ushort rtrMajor)
    {
        Format = NativeAotFormats.For(rtrMajor);
        U32(NativeAotMetadata.Signature);
        Fixed(new Fwd()); // scope count, patched
        Fixed(new Fwd()); // first scope, patched
        Fixed(new Fwd()); // second scope slot, patched
    }

    public uint Here => (uint)bytes.Count;

    public void AddScope(object scope) => scopes.Add(scope);

    public void Unsigned(uint v)
    {
        if (v < 0x80) bytes.Add((byte)(v << 1));
        else if (v < 0x4000) { bytes.Add((byte)((v << 2) | 1)); bytes.Add((byte)(v >> 6)); }
        else if (v < 0x200000) { bytes.Add((byte)((v << 3) | 3)); bytes.Add((byte)(v >> 5)); bytes.Add((byte)(v >> 13)); }
        else if (v < 0x10000000) { bytes.Add((byte)((v << 4) | 7)); bytes.Add((byte)(v >> 4)); bytes.Add((byte)(v >> 12)); bytes.Add((byte)(v >> 20)); }
        else { bytes.Add(0x0F); U32(v); }
    }

    public void Signed(int v)
    {
        if (v is >= -64 and < 64) bytes.Add((byte)(v << 1));
        else if (v is >= -8192 and < 8192) { bytes.Add((byte)((v << 2) | 1)); bytes.Add((byte)(v >> 6)); }
        else { bytes.Add(0x0F); U32((uint)v); }
    }

    private void U32(uint v) { for (int i = 0; i < 4; i++) bytes.Add((byte)(v >> (8 * i))); }

    private void Fixed(Fwd r)
    {
        patches.Add((bytes.Count + 1, r));
        bytes.Add(0x0F);
        U32(0);
    }

    public uint RawHandle(MdHandle h) => h.IsNull ? 0 : (h.Offset << Format.RecordHandleTypeBits) | NativeAotSchema.RawType(Format.Metadata, h.Record);

    public uint Token(MdHandle h) => (NativeAotSchema.RawType(Format.Metadata, h.Record) << Format.TokenShift) | h.Offset;

    /// <summary>Writes a record of <paramref name="record"/>; returns its handle.</summary>
    public MdHandle Record(MdRecord record, params object?[] fields)
    {
        var layout = NativeAotSchema.For(Format.Metadata, record);
        Assert.Equal(layout.Codes.Length, fields.Length);
        uint at = Here;
        for (int i = 0; i < fields.Length; i++)
        {
            var f = fields[i];
            switch (layout.Codes[i])
            {
                case 'h':
                    if (f is Fwd fh) Fixed(fh);
                    else Unsigned(RawHandle(f is MdHandle h ? h : default));
                    break;
                case 't' or 'u':
                    if (f is Fwd r) Fixed(r);
                    else Unsigned(f is MdHandle th ? th.Offset : Convert.ToUInt32(f ?? 0u));
                    break;
                case 'i': Signed(Convert.ToInt32(f ?? 0)); break;
                case 'b': bytes.Add(Convert.ToByte(f ?? 0)); break;
                case 's':
                    var s = Encoding.UTF8.GetBytes((string)f!);
                    Unsigned((uint)s.Length);
                    bytes.AddRange(s);
                    break;
                case 'c':
                    var items = f switch
                    {
                        null => [],
                        IEnumerable<MdHandle> hs => hs.Select(RawHandle).ToList(),
                        IEnumerable<uint> us => us.ToList(),
                        _ => throw new ArgumentException($"field {i} of {record}"),
                    };
                    Unsigned((uint)items.Count);
                    foreach (var v in items) Unsigned(v);
                    break;
                case '1':
                    var b = (byte[]?)f ?? [];
                    Unsigned((uint)b.Length);
                    bytes.AddRange(b);
                    break;
                default: throw new NotSupportedException(layout.Codes[i].ToString());
            }
        }
        return new MdHandle(record, at);
    }

    public MdHandle String(string s) => Record(MdRecord.ConstantStringValue, s);

    public byte[] ToArray()
    {
        var a = bytes.ToArray();
        void Put(int at, uint v) => BinaryPrimitives.WriteUInt32LittleEndian(a.AsSpan(at), v);
        Assert.InRange(scopes.Count, 0, 2);
        // Header: count then up to two scope offsets; a single scope leaves a trailing padding integer.
        Put(5, (uint)scopes.Count);
        for (int i = 0; i < scopes.Count; i++) Put(10 + 5 * i, scopes[i] is MdHandle h ? h.Offset : ((Fwd)scopes[i]).Value);
        foreach (var (at, r) in patches.Skip(3)) Put(at, r.Record is { } kind ? RawHandle(new MdHandle(kind, r.Value)) : r.Value);
        return a;
    }
}
