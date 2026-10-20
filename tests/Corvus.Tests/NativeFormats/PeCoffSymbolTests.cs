using System.Buffers.Binary;
using System.Text;
using Corvus.Native;
using Corvus.Native.Code;
using Corvus.Native.Pe;

namespace Corvus.Tests;

/// <summary>The COFF symbol table a GNU-style link keeps in a PE image: function and data names, short and long.</summary>
public sealed class PeCoffSymbolTests
{
    /// <summary>A PE with .text (two functions of ret) and .data, and a COFF symbol table after the sections.</summary>
    private static byte[] Image(bool is64, params (string Name, short Section, uint Value, ushort Type, byte Class, byte Aux)[] symbols)
    {
        var b = new PeBuilder { Is64 = is64, Machine = is64 ? (ushort)0x8664 : (ushort)0x14C, ImageBase = is64 ? 0x140000000UL : 0x400000UL };
        var code = new byte[0x40];
        code[0x10] = 0xC3;
        code[0x20] = 0xC3;
        b.Add(".text", code, 0x60000020);
        b.Add(".data", new byte[0x20], 0xC0000040);
        b.EntryPoint = 0x1010;
        var table = new List<byte>();
        var strings = new List<byte> { 0, 0, 0, 0 };
        foreach (var s in symbols)
        {
            var entry = new byte[18];
            if (s.Name.Length <= 8) Encoding.ASCII.GetBytes(s.Name).CopyTo(entry, 0);
            else
            {
                BinaryPrimitives.WriteInt32LittleEndian(entry.AsSpan(4), strings.Count);
                strings.AddRange(Encoding.ASCII.GetBytes(s.Name + "\0"));
            }
            BinaryPrimitives.WriteUInt32LittleEndian(entry.AsSpan(8), s.Value);
            BinaryPrimitives.WriteInt16LittleEndian(entry.AsSpan(12), s.Section);
            BinaryPrimitives.WriteUInt16LittleEndian(entry.AsSpan(14), s.Type);
            entry[16] = s.Class;
            entry[17] = s.Aux;
            table.AddRange(entry);
            for (int i = 0; i < s.Aux; i++) table.AddRange(new byte[18]);
        }
        BinaryPrimitives.WriteInt32LittleEndian(System.Runtime.InteropServices.CollectionsMarshal.AsSpan(strings), strings.Count);
        b.Overlay = [.. table, .. strings];
        var file = b.Build();
        int coff = PeBuilder.PeOffset + 4;
        BinaryPrimitives.WriteInt32LittleEndian(file.AsSpan(coff + 8), file.Length - b.Overlay.Length);
        BinaryPrimitives.WriteInt32LittleEndian(file.AsSpan(coff + 12), table.Count / 18);
        return file;
    }

    [Fact]
    public void Functions_and_data_are_named_and_the_code_index_uses_them()
    {
        var pe = PeFile.FromBytes(Image(true,
            (".text", 1, 0, 0, 3, 1),                          // section symbol: left out
            ("main", 1, 0x10, 0x20, 2, 1),                     // external function with its definition record
            ("compress_block_fast", 1, 0x20, 0x20, 3, 0),      // static function, long name
            ("g_level", 2, 0x8, 0, 2, 0),                      // external data
            ("__imp_Sleep", 2, 0x10, 0, 2, 0),                 // import slot: left out
            ("undefined", 0, 0, 0x20, 2, 0)));                 // not defined here: left out
        Assert.Equal([("main", 0x1010u, ImageSymbolKind.Function, ImageSymbolBinding.Global), ("compress_block_fast", 0x1020u, ImageSymbolKind.Function, ImageSymbolBinding.Local),
            ("g_level", 0x2008u, ImageSymbolKind.Object, ImageSymbolBinding.Global)], pe.Symbols.Select(s => (s.Name, s.Rva, s.Kind, s.Binding)));
        Assert.Empty(pe.Issues);
        // the static function is called by nothing: its symbol makes it a function start
        Assert.Equal([0x1010u, 0x1020u], pe.DeclaredFunctions.Select(d => d.Rva));
        var index = NativeCodeIndex.Build(pe);
        Assert.Equal("compress_block_fast", index.NameAt(0x1020));
    }

    [Fact]
    public void I386_names_lose_their_leading_underscore()
    {
        var pe = PeFile.FromBytes(Image(false, ("_main", 1, 0x10, 0x20, 2, 0), ("__ZN5Codec5flushEv", 1, 0x20, 0x20, 2, 0)));
        Assert.Equal(["main", "_ZN5Codec5flushEv"], pe.Symbols.Select(s => s.Name));
    }

    [Fact]
    public void A_table_past_the_end_reads_what_is_there()
    {
        var file = Image(true, ("main", 1, 0x10, 0x20, 2, 0));
        BinaryPrimitives.WriteInt32LittleEndian(file.AsSpan(PeBuilder.PeOffset + 4 + 12), 1_000_000);
        var pe = PeFile.FromBytes(file);
        Assert.Equal("main", Assert.Single(pe.Symbols).Name);
        Assert.Contains(pe.Issues, i => i.Message.Contains("run past the end"));
    }
}
