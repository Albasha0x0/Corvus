using Microsoft.Win32.SafeHandles;

namespace Corvus.Native.Dump;

/// <summary>Random-access bytes of a dump file; reads past the end return fewer bytes, never throw.</summary>
public interface IDumpSource : IDisposable
{
    long Length { get; }

    /// <summary>Copies up to <c>destination.Length</c> bytes from <paramref name="offset"/>; returns the number copied.</summary>
    int Read(long offset, Span<byte> destination);
}

/// <summary>A dump file read through positional reads, so a full-memory dump is never loaded into one array.</summary>
public sealed class FileDumpSource : IDumpSource
{
    private readonly SafeFileHandle _handle;

    public FileDumpSource(string path)
    {
        _handle = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, FileOptions.RandomAccess);
        Length = RandomAccess.GetLength(_handle);
    }

    public long Length { get; }

    public int Read(long offset, Span<byte> destination)
    {
        if (offset < 0 || offset >= Length || destination.IsEmpty) return 0;
        if (destination.Length > Length - offset) destination = destination[..(int)(Length - offset)];
        int done = 0;
        try
        {
            while (done < destination.Length)
            {
                int n = RandomAccess.Read(_handle, destination[done..], offset + done);
                if (n <= 0) break;
                done += n;
            }
        }
        catch (IOException) { }
        catch (ObjectDisposedException) { }
        return done;
    }

    public void Dispose() => _handle.Dispose();
}

/// <summary>A dump held in memory (synthetic dumps in tests).</summary>
public sealed class BytesDumpSource(byte[] bytes) : IDumpSource
{
    public long Length => bytes.Length;

    public int Read(long offset, Span<byte> destination)
    {
        if (offset < 0 || offset >= bytes.Length) return 0;
        int n = (int)Math.Min(destination.Length, bytes.Length - offset);
        bytes.AsSpan((int)offset, n).CopyTo(destination);
        return n;
    }

    public void Dispose() { }
}
