using System.Buffers.Binary;
using Corvus.Native;
using Corvus.Native.Code;

namespace Corvus.Tests;

/// <summary>Handlers of a 16-bit dispatch table: every entry of the table a reached <c>call [bx+table]</c> names.</summary>
public sealed class RealModeDispatchTests
{
    public const int Handlers = 540;

    /// <summary>
    /// An MZ executable (CS:IP 0:0) calling each of <see cref="Handlers"/> handlers through one table, then exiting:
    /// <code>
    ///   xor si, si
    /// l: mov bx, si ; shl bx, 1 ; call [bx+table] ; inc si ; cmp si, 540 ; jb l
    ///   mov ax, 4C00h ; int 21h
    /// handler i: mov ax, i ; ret   (no prologue: nothing marks it as a function start)
    /// table: dw handler 0 .. handler 539
    /// </code>
    /// Returns the file and the handlers' load-module offsets.
    /// </summary>
    public static (byte[] File, uint[] Handlers) Mz(int count = Handlers)
    {
        const int code = 0x16, size = 4;
        int table = code + count * size;
        var module = new byte[table + count * 2];
        byte[] main = [0x31, 0xF6, 0x89, 0xF3, 0xD1, 0xE3, 0xFF, 0x97, (byte)table, (byte)(table >> 8), 0x46, 0x81, 0xFE, (byte)count, (byte)(count >> 8),
            0x72, 0xF1, 0xB8, 0x00, 0x4C, 0xCD, 0x21];
        main.CopyTo(module, 0);
        var handlers = new uint[count];
        for (int i = 0; i < count; i++)
        {
            int at = code + i * size;
            handlers[i] = (uint)at;
            new byte[] { 0xB8, (byte)i, (byte)(i >> 8), 0xC3 }.CopyTo(module, at);
            BinaryPrimitives.WriteUInt16LittleEndian(module.AsSpan(table + i * 2), (ushort)at);
        }
        var header = new byte[32];
        "MZ"u8.CopyTo(header);
        int total = header.Length + module.Length;
        BinaryPrimitives.WriteUInt16LittleEndian(header.AsSpan(2), (ushort)(total % 512));
        BinaryPrimitives.WriteUInt16LittleEndian(header.AsSpan(4), (ushort)((total + 511) / 512));
        BinaryPrimitives.WriteUInt16LittleEndian(header.AsSpan(8), 2); // header paragraphs
        BinaryPrimitives.WriteUInt16LittleEndian(header.AsSpan(10), 0x20); // min alloc
        BinaryPrimitives.WriteUInt16LittleEndian(header.AsSpan(12), 0xFFFF);
        BinaryPrimitives.WriteUInt16LittleEndian(header.AsSpan(14), (ushort)((module.Length + 15) / 16)); // SS after the module
        BinaryPrimitives.WriteUInt16LittleEndian(header.AsSpan(16), 0x200); // SP
        BinaryPrimitives.WriteUInt16LittleEndian(header.AsSpan(24), 0x1C); // relocation table offset (none)
        return ([.. header, .. module], handlers);
    }

    [Fact]
    public void Every_handler_of_the_table_is_found()
    {
        var (file, handlers) = Mz();
        var image = RealModeDispatch.Of(file, RawLayout.Parse("dos-mz", null, null, file.Length))!.Value;
        Assert.Equal(handlers, RealModeDispatch.Handlers(image));
    }

    [Fact]
    public void A_com_file_maps_pointers_from_its_base()
    {
        // The same code as a .COM at 0x100: pointers are offsets in CS, which starts 0x100 before the file.
        var (mz, handlers) = Mz(4);
        var module = mz[32..];
        for (int i = 0; i < 4; i++) BinaryPrimitives.WriteUInt16LittleEndian(module.AsSpan(0x16 + 4 * 4 + i * 2), (ushort)(handlers[i] + 0x100));
        BinaryPrimitives.WriteUInt16LittleEndian(module.AsSpan(8), (ushort)(0x16 + 4 * 4 + 0x100));
        var image = RealModeDispatch.Of(module, RawLayout.Parse("x86-16", "0x100", null, module.Length))!.Value;
        Assert.Equal(handlers, RealModeDispatch.Handlers(image));
    }
}
