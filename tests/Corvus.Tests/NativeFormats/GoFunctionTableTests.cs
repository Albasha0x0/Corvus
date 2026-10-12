using System.Buffers.Binary;
using System.Text;
using Corvus.Native;
using Corvus.Native.Code;
using Corvus.Native.Elf;
using Corvus.Native.Go;
using Corvus.Native.MachO;

namespace Corvus.Tests.NativeFormats;

public sealed class GoFunctionTableTests
{
    private static readonly string[] Names = ["main.main", "runtime.morestack", "github.com/x/y.(*T).Method", "main.init.func1", "type:.eq.[2]interface {}"];

    /// <summary>
    /// A Go function table of <paramref name="version"/>: functions every 0x20 bytes from <paramref name="textVa"/>; with
    /// <paramref name="ownSize"/>, each function's pcsp table ends there (the rest of its 0x20 bytes is padding).
    /// </summary>
    internal static byte[] Pclntab(GoTableVersion version, int ptr, ulong textVa, int count, int ownSize = 0)
    {
        var entries = Enumerable.Range(0, count).Select(i => textVa + (ulong)(i * 0x20)).ToArray();
        ulong end = textVa + (ulong)(count * 0x20);
        var names = new MemoryStream();
        var nameOffsets = new List<int>();
        for (int i = 0; i < count; i++)
        {
            nameOffsets.Add((int)names.Length);
            names.Write(Encoding.UTF8.GetBytes(Names[i % Names.Length] + (i >= Names.Length ? i.ToString() : "")));
            names.WriteByte(0);
        }
        var t = new byte[0x2000];
        uint magic = version switch { GoTableVersion.Go12 => 0xFFFFFFFB, GoTableVersion.Go116 => 0xFFFFFFFA, GoTableVersion.Go118 => 0xFFFFFFF0, _ => 0xFFFFFFF1 };
        BinaryPrimitives.WriteUInt32LittleEndian(t, magic);
        t[6] = 1;
        t[7] = (byte)ptr;
        void Ptr(int at, ulong v) { if (ptr == 8) BinaryPrimitives.WriteUInt64LittleEndian(t.AsSpan(at), v); else BinaryPrimitives.WriteUInt32LittleEndian(t.AsSpan(at), (uint)v); }
        void U32(int at, uint v) => BinaryPrimitives.WriteUInt32LittleEndian(t.AsSpan(at), v);
        Ptr(8, (ulong)count);
        bool wide = version is GoTableVersion.Go12 or GoTableVersion.Go116;
        int fields = version switch { GoTableVersion.Go12 => 1, GoTableVersion.Go116 => 7, _ => 8 };
        int nameBase = 8 + fields * ptr;
        if (version == GoTableVersion.Go12) nameBase = 0x1000;
        names.ToArray().CopyTo(t, nameBase);
        int functab = (nameBase + (int)names.Length + 15) & ~7;
        if (version == GoTableVersion.Go12) functab = 8 + ptr;
        int entrySize = wide ? 2 * ptr : 8;
        int records = functab + (count + 1) * entrySize + 8;
        int recordSize = wide ? ptr + 24 : 28;
        // one pcsp table shared by every function (offset 0 means none): sp delta 0 up to ownSize (zigzag value delta, pc delta, end)
        const int PcTables = 0x1800;
        int pctab = version == GoTableVersion.Go12 ? 0 : PcTables;
        if (ownSize > 0) new byte[] { 2, (byte)(ownSize | 0x80), (byte)(ownSize >> 7), 0 }.CopyTo(t, PcTables + 1);
        int recordBase = version == GoTableVersion.Go12 ? 0 : functab;
        int nameRel = version == GoTableVersion.Go12 ? nameBase : 0;
        switch (version)
        {
            case GoTableVersion.Go116:
                Ptr(8 + 2 * ptr, (ulong)nameBase);
                Ptr(8 + 5 * ptr, (ulong)pctab);
                Ptr(8 + 6 * ptr, (ulong)functab);
                break;
            case GoTableVersion.Go118 or GoTableVersion.Go120:
                Ptr(8 + 2 * ptr, textVa);
                Ptr(8 + 3 * ptr, (ulong)nameBase);
                Ptr(8 + 6 * ptr, (ulong)pctab);
                Ptr(8 + 7 * ptr, (ulong)functab);
                break;
        }
        for (int i = 0; i <= count; i++)
        {
            int e = functab + i * entrySize;
            int record = records + i * recordSize;
            ulong va = i < count ? entries[i] : end;
            if (wide) { Ptr(e, va); Ptr(e + ptr, (ulong)(record - recordBase)); }
            else { U32(e, (uint)(va - textVa)); U32(e + 4, (uint)(record - recordBase)); }
            if (i == count) break;
            if (wide) { Ptr(record, va); U32(record + ptr, (uint)(nameRel + nameOffsets[i])); }
            else { U32(record, (uint)(va - textVa)); U32(record + 4, (uint)nameOffsets[i]); }
            if (ownSize > 0) U32(record + (wide ? ptr + 12 : 16), (uint)(PcTables + 1 - pctab));
        }
        return t;
    }

    private static byte[] Rets(int count, byte ret)
    {
        var text = new byte[count * 0x20];
        Array.Fill(text, (byte)0xCC);
        for (int i = 0; i < count; i++) text[i * 0x20] = ret;
        return text;
    }

    [Theory]
    [InlineData(GoTableVersion.Go12, true)]
    [InlineData(GoTableVersion.Go116, true)]
    [InlineData(GoTableVersion.Go118, true)]
    [InlineData(GoTableVersion.Go120, true)]
    [InlineData(GoTableVersion.Go12, false)]
    [InlineData(GoTableVersion.Go120, false)]
    public void Elf_section_gives_every_function_and_its_name(GoTableVersion version, bool is64)
    {
        const ulong Base = 0x400000;
        const int Count = 12;
        var w = new ElfWriter
        {
            Machine = is64 ? ElfWriter.EmX64 : ElfWriter.EmX86, Is64 = is64, Type = 2, Base = Base, Entry = ElfWriter.TextRva,
            Text = Rets(Count, 0xC3), Hash = ElfWriter.HashKind.None, DataSectionName = ".gopclntab",
            Data = Pclntab(version, is64 ? 8 : 4, Base + ElfWriter.TextRva, Count, ownSize: 0x11),
        };
        var image = ElfFile.FromBytes(w.Build(), "gobin");
        var table = Assert.IsType<GoFunctionTable>(GoFunctionTable.Of(image));
        Assert.Equal(version, table.Version);
        Assert.Equal(Count, table.Functions.Count);
        // sizes are the code the pcsp tables cover, not the 0x20 to the next entry (int3 padding)
        Assert.All(table.Functions, f => Assert.Equal((0x11u, true), (f.Size, f.OwnSize)));

        var index = NativeCodeIndex.Build(image);
        for (int i = 0; i < Count; i++)
        {
            var f = index.FunctionByStart(ElfWriter.TextRva + (uint)(i * 0x20));
            Assert.NotNull(f);
            Assert.True(f.Sources.HasFlag(FunctionSource.GoTable));
            Assert.Equal(Names[i % Names.Length] + (i >= Names.Length ? i.ToString() : ""), f.Name);
        }
        Assert.Equal(ElfWriter.TextRva + 0x20, index.AddressOfName("runtime.morestack"));
    }

    [Theory]
    [InlineData(0, 0x20u, false)]    // no pc-value tables: the gap to the next entry
    [InlineData(0x30, 0x20u, false)] // a table running into the next function is not believed
    [InlineData(0x1C, 0x1Cu, true)]
    public void Sizes_fall_back_to_the_next_entry_only_when_the_tables_do_not_give_one(int ownSize, uint size, bool own)
    {
        const ulong Base = 0x400000;
        var w = new ElfWriter
        {
            Machine = ElfWriter.EmX64, Type = 2, Base = Base, Entry = ElfWriter.TextRva, Text = Rets(4, 0xC3), Hash = ElfWriter.HashKind.None,
            DataSectionName = ".gopclntab", Data = Pclntab(GoTableVersion.Go120, 8, Base + ElfWriter.TextRva, 4, ownSize),
        };
        var table = GoFunctionTable.Of(ElfFile.FromBytes(w.Build(), "gobin"))!;
        Assert.All(table.Functions, f => Assert.Equal((size, own), (f.Size, f.OwnSize)));
    }

    [Fact]
    public void Declared_only_index_ends_functions_at_their_own_size()
    {
        // RISC-V code is not decoded: function extents come from the table alone
        const ulong Base = 0x10000;
        var w = new ElfWriter
        {
            Machine = 243, Type = 2, Base = Base, Entry = ElfWriter.TextRva, Text = new byte[4 * 0x20], Hash = ElfWriter.HashKind.None,
            DataSectionName = ".gopclntab", Data = Pclntab(GoTableVersion.Go120, 8, Base + ElfWriter.TextRva, 4, ownSize: 0x14),
        };
        var index = NativeCodeIndex.Build(ElfFile.FromBytes(w.Build(), "gobin"));
        Assert.Equal(CodeSupport.DeclaredFunctionsOnly, index.Support);
        Assert.All(index.Functions, f => Assert.Equal(0x14u, f.Size));
        Assert.Null(index.FunctionAt(ElfWriter.TextRva + 0x18));
    }

    [Fact]
    public void Pe_without_a_section_name_is_found_by_its_header()
    {
        const int Count = 6;
        var probe = CodeTestImage.Synthetic(NativeArch.X64, Rets(Count, 0xC3));
        var data = new byte[0x2400];
        Pclntab(GoTableVersion.Go120, 8, probe.ImageBase + CodeTestImage.SyntheticCodeRva, Count).CopyTo(data, 0x400);
        var image = CodeTestImage.Synthetic(NativeArch.X64, Rets(Count, 0xC3), data);
        var table = Assert.IsType<GoFunctionTable>(GoFunctionTable.Of(image));
        Assert.Equal(CodeTestImage.SyntheticDataRva + 0x400, table.Rva);
        var index = NativeCodeIndex.Build(image);
        Assert.Equal("github.com/x/y.(*T).Method", index.FunctionByStart(CodeTestImage.SyntheticCodeRva + 0x40)?.Name);
        Assert.Equal(Count, index.Functions.Count(f => f.Sources.HasFlag(FunctionSource.GoTable)));
    }

    [Fact]
    public void Windows_arm_go_functions_are_arm_state()
    {
        // Go emits A32 even on Windows, whose other ARM code is Thumb only: bx lr per function
        const int Count = 4;
        var text = new byte[Count * 0x20];
        for (int i = 0; i < Count; i++) BinaryPrimitives.WriteUInt32LittleEndian(text.AsSpan(i * 0x20), 0xE12FFF1E);
        var probe = CodeTestImage.Synthetic(NativeArch.Arm, text);
        var data = new byte[0x2400];
        Pclntab(GoTableVersion.Go118, 4, probe.ImageBase + CodeTestImage.SyntheticCodeRva, Count).CopyTo(data, 0x400);
        var index = NativeCodeIndex.Build(CodeTestImage.Synthetic(NativeArch.Arm, text, data));
        var dis = index.CreateDisassembler();
        for (int i = 0; i < Count; i++)
        {
            uint start = CodeTestImage.SyntheticCodeRva + (uint)(i * 0x20);
            var f = index.FunctionByStart(start)!;
            Assert.Equal((false, 1, FunctionFlags.None), (dis.ThumbAt(start), f.InstructionCount, f.Flags & FunctionFlags.InvalidCode));
        }
    }

    [Fact]
    public void MachO_arm64_table_in_constant_data_names_functions()
    {
        const int Count = 8;
        var text = new byte[Count * 0x20];
        for (int i = 0; i < Count; i++) new byte[] { 0xC0, 0x03, 0x5F, 0xD6 }.CopyTo(text, i * 0x20); // ret
        var w = new MachOWriter { FileType = 2, Text = text };
        w.Const = Pclntab(GoTableVersion.Go118, 8, w.TextVm + MachOWriter.TextOffset, Count);
        var image = MachOFile.FromBytes(w.Build(), "gobin");
        var index = NativeCodeIndex.Build(image);
        Assert.Equal("main.init.func1", index.FunctionByStart(MachOWriter.TextOffset + 0x60)?.Name);
    }

    [Fact]
    public async Task Tools_show_the_table_and_its_names()
    {
        const ulong Base = 0x400000;
        var w = new ElfWriter
        {
            Machine = ElfWriter.EmX64, Type = 2, Base = Base, Entry = ElfWriter.TextRva, Text = Rets(5, 0xC3), Hash = ElfWriter.HashKind.None,
            DataSectionName = ".gopclntab", Data = Pclntab(GoTableVersion.Go120, 8, Base + ElfWriter.TextRva, 5),
        };
        using var dir = new TempDir();
        var path = dir.File("gobin");
        File.WriteAllBytes(path, w.Build());
        using var h = new NativeToolHarness(backgroundIndexing: false);
        Assert.Contains("Go function table: 5 functions with names (go1.20+ layout)", await h.Native.GetPeInfo(path));
        Assert.Contains("github.com/x/y.(*T).Method", await h.CodeTools.ListFunctions(path));
    }

    [Fact]
    public void Images_without_a_table_have_none()
    {
        Assert.Null(GoFunctionTable.Of(CodeTestImage.Synthetic(NativeArch.X64, [0xC3])));
        // a header with entries outside code is not a table
        var data = Pclntab(GoTableVersion.Go120, 8, 0x7000_0000, 4);
        Assert.Null(GoFunctionTable.Of(CodeTestImage.Synthetic(NativeArch.X64, [0xC3], data)));
    }
}
