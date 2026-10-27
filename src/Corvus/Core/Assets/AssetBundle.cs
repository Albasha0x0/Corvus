using System.Buffers.Binary;
using System.Text;
using Corvus.Core.Firmware;

namespace Corvus.Core.Assets;

/// <summary>A file inside an asset bundle: its path and bytes.</summary>
public sealed record AssetBundleEntry(string Path, byte[] Bytes);

/// <summary>A UnityFS asset bundle (format 6 and later) with its files decompressed; damaged input ends the read with an issue.</summary>
public sealed class AssetBundle
{
    public int Format { get; private set; }
    public string? PlayerVersion { get; private set; }
    public string? EngineVersion { get; private set; }
    public IReadOnlyList<AssetBundleEntry> Entries => _entries;
    public IReadOnlyList<string> Issues => _issues;

    private readonly List<AssetBundleEntry> _entries = [];
    private readonly List<string> _issues = [];

    /// <summary>Whether <paramref name="head"/> starts with the UnityFS signature.</summary>
    public static bool IsBundle(ReadOnlySpan<byte> head) => head.StartsWith("UnityFS\0"u8);

    /// <summary>The engine version in a UnityFS, UnityWeb or UnityRaw header, or null.</summary>
    public static string? VersionOf(ReadOnlySpan<byte> head)
    {
        var parts = new List<string>();
        for (int at = 0; parts.Count < 3 && at < head.Length;)
        {
            int zero = head[at..].IndexOf((byte)0);
            if (zero < 0) return null;
            parts.Add(Encoding.ASCII.GetString(head.Slice(at, zero)));
            // The format number follows the signature.
            at += zero + 1 + (parts.Count == 1 ? 4 : 0);
        }
        return parts is [("UnityFS" or "UnityWeb" or "UnityRaw"), _, var version] ? version : null;
    }

    /// <summary>Reads the bundle; at most <paramref name="maxBytes"/> bytes are decompressed in all. Never throws for damaged input.</summary>
    public static AssetBundle Read(byte[] data, long maxBytes)
    {
        var b = new AssetBundle();
        try
        {
            b.ReadAll(data, maxBytes);
        }
        catch (InvalidDataException e)
        {
            b._issues.Add(e.Message);
        }
        return b;
    }

    private void ReadAll(byte[] data, long maxBytes)
    {
        var r = new AssetBinary(data, true);
        if (r.CString(16) != "UnityFS") throw new InvalidDataException("no UnityFS signature");
        Format = r.I32();
        PlayerVersion = r.CString(64);
        EngineVersion = r.CString(64);
        r.Skip(8);
        int packedInfo = r.I32(), infoSize = r.I32(), flags = r.I32();
        if (packedInfo < 0 || infoSize < 0 || infoSize > 1 << 26) throw new InvalidDataException($"block info of {infoSize} bytes");
        if (Format >= 7) r.Align(16);
        int infoAt = (flags & 0x80) != 0 ? data.Length - packedInfo : r.Position;
        if (infoAt < 0 || infoAt > data.Length - packedInfo) throw new InvalidDataException("the block info is outside the file");
        var info = Decode(flags & 0x3F, data.AsSpan(infoAt, packedInfo), infoSize);
        if ((flags & 0x80) == 0) r.Position = infoAt + packedInfo;
        var ir = new AssetBinary(info, true);
        ir.Skip(16);
        int blockCount = ir.I32();
        if (blockCount is < 0 or > 1 << 20) throw new InvalidDataException($"{blockCount} blocks");
        var blocks = new (int Size, int Packed, int Flags)[blockCount];
        long total = 0;
        for (int i = 0; i < blockCount; i++)
        {
            blocks[i] = ((int)ir.U32(), (int)ir.U32(), ir.U16());
            total += (uint)blocks[i].Size;
        }
        if (total > maxBytes) throw new InvalidDataException($"the bundle holds {total} bytes, over the {maxBytes} byte limit");
        int nodeCount = ir.I32();
        if (nodeCount is < 0 or > 100_000) throw new InvalidDataException($"{nodeCount} files");
        var nodes = new List<(long Offset, long Size, string Path)>();
        for (int i = 0; i < nodeCount; i++)
        {
            long offset = ir.I64(), size = ir.I64();
            ir.Skip(4);
            nodes.Add((offset, size, ir.CString()));
        }
        // Bundles from engine 2019.4 on pad the data to 16 bytes after the block info.
        if ((flags & 0x200) != 0) r.Align(16);
        var whole = new byte[total];
        int at = 0;
        foreach (var (size, packed, blockFlags) in blocks)
        {
            if (size < 0 || packed < 0 || r.Remaining < packed) throw new InvalidDataException("a block runs past the end of the file");
            var block = Decode(blockFlags & 0x3F, data.AsSpan(r.Position, packed), size);
            r.Position += packed;
            block.CopyTo(whole, at);
            at += size;
        }
        foreach (var (offset, size, path) in nodes)
        {
            if (offset < 0 || size < 0 || offset > whole.Length - size) { _issues.Add($"{path} is outside the bundle data"); continue; }
            _entries.Add(new AssetBundleEntry(path, whole.AsSpan((int)offset, (int)size).ToArray()));
        }
    }

    private static byte[] Decode(int codec, ReadOnlySpan<byte> src, int size)
    {
        if (size < 0) throw new InvalidDataException("a negative block size");
        var dst = new byte[size];
        int written;
        switch (codec)
        {
            case 0:
                if (src.Length != size) throw new InvalidDataException("a stored block whose sizes differ");
                src.CopyTo(dst);
                return dst;
            case 1:
            {
                // Bundles store the 5 LZMA property bytes without the unpacked size of the "alone" header.
                if (src.Length < 5) throw new InvalidDataException("an LZMA block without its properties");
                var alone = new byte[13 + src.Length - 5];
                src[..5].CopyTo(alone);
                BinaryPrimitives.WriteInt64LittleEndian(alone.AsSpan(5), size);
                src[5..].CopyTo(alone.AsSpan(13));
                written = FsCodec.Decode("lzma", alone, dst);
                break;
            }
            case 2 or 3:
                written = FsCodec.Decode("lz4", src, dst);
                break;
            default:
                throw new InvalidDataException($"block compression {codec} is not one this reader decodes");
        }
        return written == size ? dst : throw new InvalidDataException($"a block decoded to {written} of {size} bytes");
    }
}
