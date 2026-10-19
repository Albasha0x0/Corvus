using System.Buffers.Binary;
using System.Text;
using Corvus.Native.Itanium;
using Corvus.Native.Pascal;
using Corvus.Native.Pe;

namespace Corvus.Tests;

/// <summary>Object Pascal class recovery from VMTs: synthetic Delphi and Free Pascal images with a class chain, and images without VMTs.</summary>
public class PascalVmtTests
{
    private const uint CodeRva = 0x1000, DataRva = 0x2000;

    /// <summary>Pointer-size words with label fixups, laid out at <see cref="DataRva"/>.</summary>
    private sealed class VmtWriter(int ptr, ulong imageBase)
    {
        private readonly List<byte> _bytes = [];
        private readonly Dictionary<string, int> _labels = [];
        private readonly List<(int At, string Label)> _fixups = [];

        public int PointerSize => ptr;
        public void Label(string name) => _labels[name] = _bytes.Count;
        public void Byte(byte v) => _bytes.Add(v);
        public void Word(ulong v) { for (int i = 0; i < ptr; i++) _bytes.Add((byte)(v >> (8 * i))); }
        public void Ptr(string? label) { if (label != null) _fixups.Add((_bytes.Count, label)); Word(0); }
        public void Code(int i) => Word(imageBase + CodeRva + (uint)(i * 16));
        public void U16(ushort v) { _bytes.Add((byte)v); _bytes.Add((byte)(v >> 8)); }
        public void U32(uint v) { U16((ushort)v); U16((ushort)(v >> 16)); }
        public void Str(string s) { _bytes.Add((byte)s.Length); _bytes.AddRange(Encoding.ASCII.GetBytes(s)); }
        public void Align() { while (_bytes.Count % ptr != 0) _bytes.Add(0); }
        public uint Rva(string label) => DataRva + (uint)_labels[label];

        public byte[] Build()
        {
            var b = _bytes.ToArray();
            foreach (var (at, label) in _fixups)
            {
                ulong va = imageBase + Rva(label);
                if (ptr == 8) BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(at), va);
                else BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(at), (uint)va);
            }
            return b;
        }
    }

    private sealed record Spec(string Name, string? Parent, uint Size, int UserSlots, bool Published = false);

    private static PeFile Image(bool is64, Action<VmtWriter> write)
    {
        var pe = is64 ? new PeBuilder() : new PeBuilder { Is64 = false, Machine = 0x14C, ImageBase = 0x400000, Characteristics = 0x0102 };
        var code = Enumerable.Repeat((byte)0xC3, 0x400).ToArray();
        pe.Add(".text", code, 0x60000020);
        var w = new VmtWriter(is64 ? 8 : 4, pe.ImageBase);
        write(w);
        pe.Add(".data", w.Build(), 0xC0000040);
        return PeFile.FromBytes(pe.Build());
    }

    /// <summary>
    /// Delphi 2009+ VMTs: the header of 11 pointers before the 11 TObject virtual methods, the VMT, the class's own slots,
    /// then its name, method, field and type info tables. The published method fills the last slot; the field is of the parent class.
    /// </summary>
    private static void Delphi(VmtWriter w, Spec[] classes, int objectVirtuals = 11)
    {
        foreach (var c in classes)
        {
            w.Label(c.Name + ".self");
            w.Ptr(c.Name);
            for (int i = 0; i < 3; i++) w.Word(0); // interface, automation, init tables
            w.Ptr(c.Published ? c.Name + ".ti" : null);
            w.Ptr(c.Published ? c.Name + ".fields" : null);
            w.Ptr(c.Published ? c.Name + ".methods" : null);
            w.Word(0); // dynamic table
            w.Ptr(c.Name + ".name");
            w.Word(c.Size);
            w.Ptr(c.Parent != null ? c.Parent + ".self" : null);
            for (int i = 0; i < objectVirtuals; i++) w.Code(i);
            w.Label(c.Name);
            for (int i = 0; i < c.UserSlots; i++) w.Code(c.Published && i == c.UserSlots - 1 ? 30 : 20 + i);
            w.Label(c.Name + ".name");
            w.Str(c.Name);
            w.Align();
            if (!c.Published) continue;
            w.Label(c.Name + ".methods");
            w.U16(1);
            w.U16((ushort)(2 + w.PointerSize + 1 + "ButtonClick".Length));
            w.Code(30);
            w.Str("ButtonClick");
            w.Align();
            w.Label(c.Name + ".classtab");
            w.U16(1);
            w.Ptr(c.Parent + ".self");
            w.Align();
            w.Label(c.Name + ".fields");
            w.U16(1);
            w.Ptr(c.Name + ".classtab");
            w.U32((uint)w.PointerSize * 2);
            w.U16(0);
            w.Str("Button1");
            w.Align();
            w.Label(c.Name + ".ti");
            TypeInfo(w, 7, c.Name);
        }
    }

    /// <summary>Free Pascal 3.x VMTs: size, -size, parent reference, name and table pointers, the 13 TObject virtual methods, the class's own slots, nil.</summary>
    private static void FreePascal(VmtWriter w, Spec[] classes)
    {
        foreach (var c in classes)
        {
            w.Label(c.Name);
            w.Word(c.Size);
            w.Word((ulong)-(long)c.Size);
            w.Ptr(c.Parent != null ? c.Parent + ".ref" : null);
            w.Ptr(c.Name + ".name");
            w.Word(0);
            w.Ptr(c.Published ? c.Name + ".methods" : null);
            w.Ptr(c.Published ? c.Name + ".fields" : null);
            w.Ptr(c.Published ? c.Name + ".ti" : null);
            for (int i = 0; i < 4; i++) w.Word(0);
            for (int i = 0; i < 13; i++) w.Code(i);
            for (int i = 0; i < c.UserSlots; i++) w.Code(c.Published && i == c.UserSlots - 1 ? 30 : 20 + i);
            w.Word(0);
            w.Label(c.Name + ".ref");
            w.Ptr(c.Name);
            w.Label(c.Name + ".name");
            w.Str(c.Name);
            w.Align();
            if (!c.Published) continue;
            w.Label(c.Name + ".mname");
            w.Str("ButtonClick");
            w.Align();
            w.Label(c.Name + ".methods");
            w.U32(1);
            w.Ptr(c.Name + ".mname");
            w.Code(30);
            w.Align();
            w.Label(c.Name + ".classtab");
            w.U16(1);
            w.Ptr(c.Parent + ".ref");
            w.Align();
            w.Label(c.Name + ".fields");
            w.U16(1);
            w.Ptr(c.Name + ".classtab");
            w.Word((ulong)w.PointerSize * 2);
            w.U16(1);
            w.Str("Button1");
            w.Align();
            w.Label(c.Name + ".ti");
            TypeInfo(w, 15, c.Name);
        }
    }

    /// <summary>Kind, name, ClassType, ParentInfo, PropCount, UnitName.</summary>
    private static void TypeInfo(VmtWriter w, byte kind, string name)
    {
        w.Byte(kind);
        w.Str(name);
        w.Ptr(name);
        w.Word(0);
        w.U16(0);
        w.Str("Unit1");
        w.Align();
    }

    private static readonly Spec[] Chain =
    [
        new("TObject", null, 8, 0),
        new("TBase", "TObject", 16, 1),
        new("TForm1", "TBase", 24, 2, Published: true),
    ];

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void DelphiChain(bool is64)
    {
        var image = Image(is64, w => Delphi(w, Chain));
        CheckChain(image, CppRtti.Analyze(image), "Delphi", firstUser: 0);
    }

    [Fact]
    public void DelphiChainWithCppAbiSlots()
    {
        // 64-bit Windows Delphi: CPP_ABI_1..3 follow Destroy, so the header starts three pointers further down
        var image = Image(true, w => Delphi(w, Chain, objectVirtuals: 14));
        var result = CppRtti.Analyze(image);
        CheckChain(image, result, "Delphi", firstUser: 0);
        var p = result.Classes.Single(c => c.Name == "TForm1").Pascal!;
        Assert.Equal(["TObject.Destroy", "TObject.CPP_ABI_1", "TObject.CPP_ABI_2", "TObject.CPP_ABI_3"], p.VirtualMethods.Where(m => m.Offset < 0).TakeLast(4).Select(m => m.Name));
    }

    [Fact]
    public void FreePascalChain64()
    {
        var image = Image(true, w => FreePascal(w, Chain));
        CheckChain(image, CppRtti.Analyze(image), "Free Pascal", firstUser: 25);
    }

    private static void CheckChain(PeFile image, Corvus.Native.Msvc.MsvcRttiResult result, string compiler, int firstUser)
    {
        int ptr = image.Is64Bit ? 8 : 4;
        Assert.Equal(["TBase", "TForm1", "TObject"], result.Classes.Select(c => c.Name));
        var form = result.Classes.Single(c => c.Name == "TForm1");
        Assert.Equal(["TBase", "TObject"], form.Bases.Select(b => b.Name));
        Assert.Equal([1, 2], form.Bases.Select(b => b.Depth));
        var p = Assert.IsType<PascalClass>(form.Pascal);
        Assert.Equal(compiler, p.Compiler);
        Assert.Equal(24u, p.InstanceSize);
        Assert.Equal("Unit1", p.Unit);
        Assert.Equal("Unit1.TForm1", form.DecoratedName);
        var user = p.VirtualMethods.Where(m => !m.Name.StartsWith("TObject.", StringComparison.Ordinal)).ToList();
        Assert.Equal([("TBase.vmt_" + firstUser, firstUser * ptr), ("TForm1.ButtonClick", (firstUser + 1) * ptr)], user.Select(m => (m.Name, m.Offset)));
        Assert.Contains(p.VirtualMethods, m => m.Name == "TObject.Destroy");
        var method = Assert.Single(p.PublishedMethods);
        Assert.Equal(("ButtonClick", CodeRva + 30 * 16), (method.Name, method.Rva));
        var field = Assert.Single(p.PublishedFields);
        Assert.Equal(("Button1", (uint)(2 * ptr), "TBase"), (field.Name, field.Offset, field.Type));
        var vtable = Assert.Single(form.Vtables);
        Assert.Equal(firstUser == 0 ? 2 : 15, vtable.SlotRvas.Count);
        Assert.Empty(result.Classes.Single(c => c.Name == "TObject").Bases);
    }

    [Fact]
    public void ChainWithoutTObjectIsRejected()
    {
        // a self pointer and a class name, but the parentless class is not TObject
        var image = Image(false, w => Delphi(w, [new("TFoo", null, 8, 0), new("TBar", "TFoo", 8, 1)]));
        var result = PascalVmt.Analyze(image);
        Assert.Empty(result.Classes);
        Assert.Contains(result.Skipped, s => s.Reason == "parent chain does not end at TObject");
    }

    [Fact]
    public void ImagesWithoutVmtsYieldNothing()
    {
        Assert.Empty(PascalVmt.Analyze(PeFile.Open(typeof(PascalVmt).Assembly.Location)).Classes);
        var notepad = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "notepad.exe");
        if (File.Exists(notepad)) Assert.Empty(PascalVmt.Analyze(PeFile.Open(notepad)).Classes);
    }
}
