using System.Buffers.Binary;
using Microsoft.Win32.SafeHandles;
using Corvus.Core;
using Corvus.Native.Pe;

namespace Corvus.Native.Pdb;

/// <summary>Hard limits for PDB reading; reaching one records an issue.</summary>
public static class PdbLimits
{
    /// <summary>Largest PDB file opened (read page by page, never whole).</summary>
    public const long MaxFileSize = 16L << 30;
    public const int MaxDirectoryBytes = 64 << 20;
    public const int MaxStreams = 1 << 20;
    public const int MaxModules = 1 << 18;
    public const int MaxSymbols = 8_000_000;
    public const int MaxNameLength = 4096;
    /// <summary>Symbol bytes read per stream (module or global symbol records).</summary>
    public const long MaxSymbolStreamBytes = 2L << 30;
    public const int MaxSections = 4096;
    public const int MaxOmapEntries = 1 << 24;
}

/// <summary>Random access to the bytes of a PDB: a file read on demand, or memory (tests).</summary>
internal interface IMsfSource : IDisposable
{
    long Length { get; }
    /// <summary>Reads up to <paramref name="buffer"/>.Length bytes at <paramref name="offset"/>; returns the count read.</summary>
    int Read(long offset, Span<byte> buffer);
}

internal sealed class MemoryMsfSource(byte[] bytes) : IMsfSource
{
    public long Length => bytes.Length;

    public int Read(long offset, Span<byte> buffer)
    {
        if (offset < 0 || offset >= bytes.Length) return 0;
        int n = (int)Math.Min(buffer.Length, bytes.Length - offset);
        bytes.AsSpan((int)offset, n).CopyTo(buffer);
        return n;
    }

    public void Dispose() { }
}

internal sealed class FileMsfSource(SafeFileHandle handle, long length) : IMsfSource
{
    public long Length => length;

    public int Read(long offset, Span<byte> buffer)
    {
        if (offset < 0 || offset >= length) return 0;
        int total = 0;
        while (total < buffer.Length)
        {
            int n = RandomAccess.Read(handle, buffer[total..], offset + total);
            if (n <= 0) break;
            total += n;
        }
        return total;
    }

    public void Dispose() => handle.Dispose();
}

/// <summary>An MSF 7.0 (PDB container) file read page by page; throws only for a bad superblock, other problems go to <see cref="Issues"/>.</summary>
internal sealed class MsfFile : IDisposable
{
    internal static ReadOnlySpan<byte> Magic => "Microsoft C/C++ MSF 7.00\r\n\u001aDS\0\0\0"u8;
    private static ReadOnlySpan<byte> OldMagic => "Microsoft C/C++ program database 2.00\r\n"u8;

    private readonly IMsfSource _source;
    private readonly IssueLog _log;
    private readonly uint[][] _pages;
    private readonly uint[] _sizes;

    public uint BlockSize { get; }
    public uint BlockCount { get; }
    public int StreamCount => _sizes.Length;
    public long FileLength => _source.Length;

    public IReadOnlyList<ParseIssue> Issues => _log.ToList();

    private MsfFile(IMsfSource source, uint blockSize, uint blockCount, uint[] sizes, uint[][] pages, IssueLog log)
    {
        _source = source;
        BlockSize = blockSize;
        BlockCount = blockCount;
        _sizes = sizes;
        _pages = pages;
        _log = log;
    }

    public static MsfFile Open(string path)
    {
        FileInfo info;
        try { info = new FileInfo(InputFiles.RequireRegularFile(path, "PDB file")); }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            throw new ToolError(ErrorCode.InvalidArgument, $"invalid path '{path}': {ex.Message}");
        }
        if (!info.Exists) throw Targets.FileNotFound(path);
        if (info.Length > PdbLimits.MaxFileSize)
            throw new ToolError(ErrorCode.LimitExceeded, $"{path} is {info.Length} bytes; PDB files up to {PdbLimits.MaxFileSize} bytes are read");
        SafeFileHandle handle;
        try { handle = File.OpenHandle(info.FullName, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete, FileOptions.RandomAccess); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new ToolError(ErrorCode.IoError, $"cannot read {path}: {ex.Message}");
        }
        try { return Open(new FileMsfSource(handle, info.Length), path); }
        catch { handle.Dispose(); throw; }
    }

    public static MsfFile FromBytes(byte[] bytes) => Open(new MemoryMsfSource(bytes), "");

    private static ToolError NotMsf(string path, string why) =>
        new(ErrorCode.MalformedInput, $"{(path.Length > 0 ? path : "the file")} is not a PDB (MSF 7.0) file: {why}");

    private static MsfFile Open(IMsfSource source, string path)
    {
        Span<byte> sb = stackalloc byte[56];
        if (source.Read(0, sb) < 56)
        {
            if (source.Read(0, sb[..OldMagic.Length]) == OldMagic.Length && sb[..OldMagic.Length].SequenceEqual(OldMagic))
                throw new ToolError(ErrorCode.Unsupported, $"{path} is a PDB 2.0 (MSF 2.0) file; only PDB 7.0 is read");
            throw NotMsf(path, "the file is shorter than the superblock");
        }
        if (!sb[..32].SequenceEqual(Magic))
        {
            if (sb[..OldMagic.Length].SequenceEqual(OldMagic))
                throw new ToolError(ErrorCode.Unsupported, $"{path} is a PDB 2.0 (MSF 2.0) file; only PDB 7.0 is read",
                    "rebuild with a current linker, or let IDA read it");
            throw NotMsf(path, "no MSF 7.00 signature");
        }
        uint blockSize = BinaryPrimitives.ReadUInt32LittleEndian(sb[32..]);
        uint blockCount = BinaryPrimitives.ReadUInt32LittleEndian(sb[40..]);
        uint dirBytes = BinaryPrimitives.ReadUInt32LittleEndian(sb[44..]);
        uint mapBlock = BinaryPrimitives.ReadUInt32LittleEndian(sb[52..]);
        if (blockSize is < 512 or > 65536 || (blockSize & (blockSize - 1)) != 0)
            throw NotMsf(path, $"block size {blockSize} is not a power of two between 512 and 65536");

        var log = new IssueLog("msf");
        long fileBlocks = (source.Length + blockSize - 1) / blockSize;
        if (blockCount > fileBlocks)
        {
            log.Add($"{blockCount} blocks declared but the file holds {fileBlocks}; blocks past the end read as missing");
            blockCount = (uint)fileBlocks;
        }
        var empty = new MsfFile(source, blockSize, blockCount, [], [], log);
        if (dirBytes == 0 || dirBytes > PdbLimits.MaxDirectoryBytes)
        {
            log.Add($"stream directory size {dirBytes} is out of range (1..{PdbLimits.MaxDirectoryBytes})");
            return empty;
        }
        // The directory's page list starts at the block map block and may continue into the following blocks.
        int dirPageCount = (int)((dirBytes + blockSize - 1) / blockSize);
        var dirPageBytes = new byte[dirPageCount * 4];
        if (mapBlock >= blockCount || source.Read((long)mapBlock * blockSize, dirPageBytes) < dirPageBytes.Length)
        {
            log.Add($"directory page list at block {mapBlock} is outside the file");
            return empty;
        }
        var dirPages = new uint[dirPageCount];
        for (int i = 0; i < dirPageCount; i++) dirPages[i] = BinaryPrimitives.ReadUInt32LittleEndian(dirPageBytes.AsSpan(i * 4));
        var dir = new byte[dirBytes];
        int got = ReadPages(source, blockSize, blockCount, dirPages, 0, dir, log, "directory");
        if (got < dir.Length)
        {
            log.Add($"stream directory is truncated: {got} of {dirBytes} bytes readable");
            dir = dir[..got];
        }
        var (sizes, pages) = ParseDirectory(dir, blockSize, blockCount, log);
        return new MsfFile(source, blockSize, blockCount, sizes, pages, log);
    }

    private static (uint[] Sizes, uint[][] Pages) ParseDirectory(byte[] dir, uint blockSize, uint blockCount, IssueLog log)
    {
        if (dir.Length < 4) { log.Add("stream directory has no stream count"); return ([], []); }
        uint declared = BinaryPrimitives.ReadUInt32LittleEndian(dir);
        long fit = (dir.Length - 4) / 4;
        long count = Math.Min(declared, Math.Min(fit, PdbLimits.MaxStreams));
        if (count < declared) log.Add($"{declared} streams declared; {count} fit in the directory and limits");
        var sizes = new uint[count];
        var pages = new uint[count][];
        int at = 4 + (int)count * 4;
        for (int i = 0; i < count; i++)
        {
            uint size = BinaryPrimitives.ReadUInt32LittleEndian(dir.AsSpan(4 + i * 4));
            if (size == uint.MaxValue) size = 0; // nil stream
            long need = (size + (long)blockSize - 1) / blockSize;
            long avail = (dir.Length - at) / 4;
            if (need > avail)
            {
                log.Add($"stream {i}: {need} pages needed, {avail} left in the directory; streams from {i} on are cut short");
                need = avail;
                size = (uint)Math.Min(size, need * blockSize);
            }
            var list = new uint[need];
            for (int p = 0; p < need; p++, at += 4)
            {
                uint block = BinaryPrimitives.ReadUInt32LittleEndian(dir.AsSpan(at));
                if (block >= blockCount)
                {
                    // The stream stays readable up to the bad page.
                    log.Add($"stream {i}: page {p} names block {block}, past the {blockCount} blocks of the file; the stream ends there");
                    at += (int)(need - p) * 4;
                    list = list[..p];
                    size = (uint)Math.Min(size, (long)p * blockSize);
                    break;
                }
                list[p] = block;
            }
            sizes[i] = size;
            pages[i] = list;
        }
        return (sizes, pages);
    }

    private static int ReadPages(IMsfSource source, uint blockSize, uint blockCount, uint[] pages, long offset, Span<byte> dst, IssueLog? log, string what)
    {
        int done = 0;
        while (done < dst.Length)
        {
            long pos = offset + done;
            long page = pos / blockSize;
            if (page >= pages.Length) break;
            uint block = pages[page];
            if (block >= blockCount)
            {
                log?.Add($"{what}: page {page} names block {block}, past the end of the file");
                break;
            }
            int inPage = (int)(pos % blockSize);
            int n = (int)Math.Min(blockSize - inPage, dst.Length - done);
            int r = source.Read((long)block * blockSize + inPage, dst.Slice(done, n));
            done += r;
            if (r < n) break;
        }
        return done;
    }

    /// <summary>Size of stream <paramref name="index"/>; 0 for a missing or nil stream.</summary>
    public long StreamSize(int index) => index >= 0 && index < _sizes.Length ? _sizes[index] : 0;

    public bool HasStream(int index) => StreamSize(index) > 0;

    /// <summary>Reads stream bytes at <paramref name="offset"/>; returns the count read (short at the end of the stream).</summary>
    public int Read(int stream, long offset, Span<byte> dst)
    {
        long size = StreamSize(stream);
        if (offset < 0 || offset >= size) return 0;
        if (dst.Length > size - offset) dst = dst[..(int)(size - offset)];
        return ReadPages(_source, BlockSize, BlockCount, _pages[stream], offset, dst, null, "");
    }

    /// <summary>A whole stream, or its first <paramref name="max"/> bytes; empty when missing.</summary>
    public byte[] ReadStream(int stream, int max = int.MaxValue)
    {
        long size = Math.Min(StreamSize(stream), max);
        if (size <= 0) return [];
        var buf = new byte[size];
        int n = Read(stream, 0, buf);
        return n == buf.Length ? buf : buf[..n];
    }

    public void Dispose() => _source.Dispose();
}

/// <summary>Sequential reads over a stream (or a window of it) through a fixed buffer.</summary>
internal sealed class MsfStreamReader
{
    private readonly MsfFile _msf;
    private readonly int _stream;
    private readonly long _end;
    private readonly byte[] _buffer;
    private long _bufferStart;
    private int _bufferLength;

    public long Position { get; set; }
    public long End => _end;
    public long Remaining => Math.Max(0, _end - Position);

    public MsfStreamReader(MsfFile msf, int stream, long start = 0, long length = long.MaxValue, int bufferSize = 64 * 1024)
    {
        _msf = msf;
        _stream = stream;
        long size = msf.StreamSize(stream);
        Position = Math.Clamp(start, 0, size);
        _end = Math.Min(size, Position + Math.Max(0, Math.Min(length, size)));
        _buffer = new byte[bufferSize];
    }

    /// <summary>Copies <paramref name="dst"/>.Length bytes at the position and advances; false (position unchanged) when short.</summary>
    public bool TryRead(Span<byte> dst)
    {
        if (dst.Length > Remaining) return false;
        long pos = Position;
        int done = 0;
        while (done < dst.Length)
        {
            if (pos < _bufferStart || pos >= _bufferStart + _bufferLength)
            {
                _bufferStart = pos;
                _bufferLength = _msf.Read(_stream, pos, _buffer.AsSpan(0, (int)Math.Min(_buffer.Length, _end - pos)));
                if (_bufferLength <= 0) return false;
            }
            int off = (int)(pos - _bufferStart);
            int n = Math.Min(_bufferLength - off, dst.Length - done);
            _buffer.AsSpan(off, n).CopyTo(dst[done..]);
            done += n;
            pos += n;
        }
        Position = pos;
        return true;
    }

    public bool TryReadU16(out ushort value)
    {
        Span<byte> b = stackalloc byte[2];
        value = 0;
        if (!TryRead(b)) return false;
        value = BinaryPrimitives.ReadUInt16LittleEndian(b);
        return true;
    }
}
