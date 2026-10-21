using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Corvus.Native.Dump.Managed;

/// <summary>ClrMD's typed reads (values, pointers) over a data reader's byte reads, and its context copy.</summary>
public abstract class ByteDataReader
{
    public abstract int PointerSize { get; }

    public abstract int Read(ulong address, Span<byte> buffer);

    public bool Read<T>(ulong address, out T value) where T : unmanaged
    {
        Span<byte> b = stackalloc byte[Unsafe.SizeOf<T>()];
        if (Read(address, b) == b.Length)
        {
            value = MemoryMarshal.Read<T>(b);
            return true;
        }
        value = default;
        return false;
    }

    public T Read<T>(ulong address) where T : unmanaged => Read(address, out T value) ? value : default;

    public bool ReadPointer(ulong address, out ulong value)
    {
        Span<byte> b = stackalloc byte[8];
        int size = PointerSize;
        if (Read(address, b[..size]) != size)
        {
            value = 0;
            return false;
        }
        value = size == 8 ? BinaryPrimitives.ReadUInt64LittleEndian(b) : BinaryPrimitives.ReadUInt32LittleEndian(b);
        return true;
    }

    public ulong ReadPointer(ulong address) => ReadPointer(address, out var value) ? value : 0;

    /// <summary>A stored thread context into ClrMD's buffer; false for none.</summary>
    protected static bool CopyContext(byte[] bytes, Span<byte> context)
    {
        if (bytes.Length == 0) return false;
        context.Clear();
        bytes.AsSpan(0, Math.Min(bytes.Length, context.Length)).CopyTo(context);
        return true;
    }
}
