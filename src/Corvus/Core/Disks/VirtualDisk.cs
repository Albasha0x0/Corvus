using System.Buffers.Binary;
using Corvus.Core.Firmware;

namespace Corvus.Core.Disks;

/// <summary>A read-only view of a virtual disk's sectors: blocks mapped to their place in the file, unallocated ones read as zeros.</summary>
internal abstract class DiskStream : Stream
{
    protected readonly FsSource Source;
    private long _position;

    protected DiskStream(FsSource source, long length)
    {
        Source = source;
        Length = length;
    }

    public override long Length { get; }
    public override bool CanRead => true;
    public override bool CanSeek => true;
    public override bool CanWrite => false;
    public override long Position { get => _position; set => _position = value; }
    public abstract string Format { get; }

    /// <summary>The file offset holding virtual byte <paramref name="at"/> and how many bytes from there stay contiguous; -1 for an unallocated run.</summary>
    protected abstract (long FileOffset, long Run) Map(long at);

    public override int Read(byte[] buffer, int offset, int count)
    {
        if (_position >= Length) return 0;
        int total = (int)Math.Min(count, Length - _position);
        int done = 0;
        while (done < total)
        {
            var (file, run) = Map(_position);
            int n = (int)Math.Min(total - done, Math.Max(1, run));
            if (file < 0 || file >= Source.Length) Array.Clear(buffer, offset + done, n);
            else
            {
                var bytes = Source.ReadUpTo(file, n);
                bytes.CopyTo(buffer, offset + done);
                if (bytes.Length < n) Array.Clear(buffer, offset + done + bytes.Length, n - bytes.Length);
            }
            done += n;
            _position += n;
        }
        return total;
    }

    public override long Seek(long offset, SeekOrigin origin) => _position = origin switch
    {
        SeekOrigin.Begin => offset, SeekOrigin.Current => _position + offset, _ => Length + offset,
    };

    public override void Flush() { }
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    /// <summary>The disk of a VHD or VHDX file, or null for any other file.</summary>
    public static DiskStream? Open(FsSource src)
    {
        if (src.Length >= 512 && src.ReadUpTo(0, 8).AsSpan().SequenceEqual("vhdxfile"u8)) return Vhdx.Open(src);
        if (src.Length >= 512 && src.ReadUpTo(src.Length - 512, 8).AsSpan().SequenceEqual("conectix"u8)) return Vhd.Open(src, src.ReadUpTo(src.Length - 512, 512));
        if (src.Length >= 1024 && src.ReadUpTo(0, 8).AsSpan().SequenceEqual("conectix"u8)) return Vhd.Open(src, src.ReadUpTo(0, 512));
        return null;
    }
}

/// <summary>Virtual PC / Hyper-V VHD: a fixed disk is its data then the footer; a dynamic one maps 2 MiB blocks through its block allocation table.</summary>
internal sealed class Vhd : DiskStream
{
    private readonly uint[] _bat = [];
    private readonly long _blockSize;
    private readonly int _bitmapBytes;
    private readonly string _format;

    private Vhd(FsSource src, long size, string format, uint[] bat, long blockSize) : base(src, size)
    {
        _format = format;
        _bat = bat;
        _blockSize = blockSize;
        _bitmapBytes = blockSize > 0 ? (int)((blockSize / 512 / 8 + 511) / 512 * 512) : 0;
    }

    public override string Format => _format;

    public static Vhd Open(FsSource src, byte[] footer)
    {
        long size = BinaryPrimitives.ReadInt64BigEndian(footer.AsSpan(48));
        uint type = BinaryPrimitives.ReadUInt32BigEndian(footer.AsSpan(60));
        if (size <= 0) throw src.Malformed("the VHD footer gives no disk size");
        if (type == 2) return new Vhd(src, Math.Min(size, src.Length - 512), "VHD (fixed)", [], 0);
        if (type is not (3 or 4)) throw src.Malformed($"VHD disk type {type} is not read");
        long header = BinaryPrimitives.ReadInt64BigEndian(footer.AsSpan(16));
        var dyn = src.Read(header, 1024);
        if (!dyn.AsSpan(0, 8).SequenceEqual("cxsparse"u8)) throw src.Malformed("no dynamic disk header where the footer names it");
        long table = BinaryPrimitives.ReadInt64BigEndian(dyn.AsSpan(16));
        int entries = (int)Math.Min(BinaryPrimitives.ReadUInt32BigEndian(dyn.AsSpan(28)), 1 << 24);
        long blockSize = BinaryPrimitives.ReadUInt32BigEndian(dyn.AsSpan(32));
        if (blockSize is < 512 or > 256 << 20) throw src.Malformed($"VHD block size {blockSize} is out of range");
        var raw = src.Read(table, entries * 4);
        var bat = new uint[entries];
        for (int i = 0; i < entries; i++) bat[i] = BinaryPrimitives.ReadUInt32BigEndian(raw.AsSpan(i * 4));
        return new Vhd(src, size, type == 3 ? "VHD (dynamic)" : "VHD (differencing; parent blocks read as zeros)", bat, blockSize);
    }

    protected override (long, long) Map(long at)
    {
        if (_blockSize == 0) return (at, Length - at);
        long block = at / _blockSize, within = at % _blockSize;
        long run = _blockSize - within;
        if (block >= _bat.Length || _bat[block] == 0xFFFFFFFF) return (-1, run);
        return ((long)_bat[block] * 512 + _bitmapBytes + within, run);
    }
}

/// <summary>Hyper-V VHDX: the region table's block allocation table and metadata (block size, disk size, sector size); payload blocks fully present are read.</summary>
internal sealed class Vhdx : DiskStream
{
    private static readonly Guid BatRegion = new("2DC27766-F623-4200-9D64-115E9BFD4A08");
    private static readonly Guid MetadataRegion = new("8B7CA206-4790-4B9A-B8FE-575F050F886E");
    private static readonly Guid FileParameters = new("CAA16737-FA36-4D43-B3B6-33F0AA44E76B");
    private static readonly Guid DiskSize = new("2FA54224-CD1B-4876-B211-5DBED83BF4B8");
    private static readonly Guid SectorSize = new("8141BF1D-A96F-4709-BA47-F233A8FAAB5F");

    private readonly ulong[] _bat;
    private readonly long _blockSize;
    private readonly long _chunkRatio;
    private readonly bool _parent;

    private Vhdx(FsSource src, long size, ulong[] bat, long blockSize, long chunkRatio, bool parent) : base(src, size)
    {
        _bat = bat;
        _blockSize = blockSize;
        _chunkRatio = chunkRatio;
        _parent = parent;
    }

    public override string Format => _parent ? "VHDX (differencing; parent blocks read as zeros)" : "VHDX";

    public static new Vhdx Open(FsSource src)
    {
        var regions = src.Read(192 << 10, 64 << 10);
        if (!regions.AsSpan(0, 4).SequenceEqual("regi"u8)) regions = src.Read(256 << 10, 64 << 10);
        if (!regions.AsSpan(0, 4).SequenceEqual("regi"u8)) throw src.Malformed("no VHDX region table");
        int count = (int)Math.Min(BinaryPrimitives.ReadUInt32LittleEndian(regions.AsSpan(8)), 2047);
        long batAt = -1, batLength = 0, metaAt = -1;
        for (int i = 0; i < count; i++)
        {
            var e = regions.AsSpan(16 + i * 32, 32);
            var id = new Guid(e[..16]);
            long offset = BinaryPrimitives.ReadInt64LittleEndian(e[16..]);
            uint length = BinaryPrimitives.ReadUInt32LittleEndian(e[24..]);
            if (id == BatRegion) (batAt, batLength) = (offset, length);
            else if (id == MetadataRegion) metaAt = offset;
        }
        if (batAt < 0 || metaAt < 0) throw src.Malformed("the VHDX region table names no allocation table or metadata");
        var meta = src.Read(metaAt, 64 << 10);
        if (!meta.AsSpan(0, 8).SequenceEqual("metadata"u8)) throw src.Malformed("no VHDX metadata table");
        int items = Math.Min(BinaryPrimitives.ReadUInt16LittleEndian(meta.AsSpan(10)), (ushort)2047);
        long blockSize = 0, size = 0, sector = 512;
        bool parent = false;
        for (int i = 0; i < items; i++)
        {
            var e = meta.AsSpan(32 + i * 32, 32);
            var id = new Guid(e[..16]);
            uint offset = BinaryPrimitives.ReadUInt32LittleEndian(e[16..]);
            var v = src.Read(metaAt + offset, 8);
            if (id == FileParameters) { blockSize = BinaryPrimitives.ReadUInt32LittleEndian(v); parent = (v[4] & 2) != 0; }
            else if (id == DiskSize) size = BinaryPrimitives.ReadInt64LittleEndian(v);
            else if (id == SectorSize) sector = BinaryPrimitives.ReadUInt32LittleEndian(v);
        }
        if (blockSize is < 1 << 20 or > 256 << 20 || size <= 0 || sector is not (512 or 4096)) throw src.Malformed("the VHDX metadata gives no usable block, disk or sector size");
        long chunkRatio = (1L << 23) * sector / blockSize;
        int entries = (int)Math.Min(batLength / 8, 1 << 24);
        var raw = src.Read(batAt, entries * 8);
        var bat = new ulong[entries];
        for (int i = 0; i < entries; i++) bat[i] = BinaryPrimitives.ReadUInt64LittleEndian(raw.AsSpan(i * 8));
        return new Vhdx(src, size, bat, blockSize, chunkRatio, parent);
    }

    protected override (long, long) Map(long at)
    {
        long block = at / _blockSize, within = at % _blockSize;
        long run = _blockSize - within;
        long index = block + block / _chunkRatio; // a sector bitmap entry follows every chunk of payload entries
        if (index >= _bat.Length) return (-1, run);
        ulong e = _bat[index];
        int state = (int)(e & 7);
        if (state is not (6 or 7)) return (-1, run); // not present, zero, unmapped: zeros
        return ((long)(e >> 20) * (1 << 20) + within, run);
    }
}
