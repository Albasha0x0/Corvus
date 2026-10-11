using System.Buffers.Binary;
using System.Text;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Code;
using NetDecompilerMcp.Native.Elf;
using NetDecompilerMcp.Native.Itanium;
using NetDecompilerMcp.Services;
using NetDecompilerMcp.Tests.NativeFormats;
using NetDecompilerMcp.Tools;

namespace NetDecompilerMcp.Tests;

/// <summary>Itanium C++ ABI RTTI: typeinfos, hierarchies and vtables on ELF and Mach-O, and virtual calls resolved through them.</summary>
public class ItaniumRttiTests
{
    private const uint D = ElfWriter.DataRva;
    private const uint TiA = D, TiB = D + 0x10, TiC = D + 0x28, VtC = D + 0x70, Names = D + 0x100;
    private static readonly uint[] Fn = [ElfWriter.TextRva, ElfWriter.TextRva + 0x10, ElfWriter.TextRva + 0x20, ElfWriter.TextRva + 0x30];

    /// <summary>
    /// A { virtual f4 }; B : A (single); C : virtual A, B at +8 (multiple, diamond flag). C's vtable group: primary [f1, f2],
    /// B-in-C at +8 [f3], virtual A at +16 [f4, __cxa_pure_virtual]. f1 calls slot 1 through this (rdi, x0, r0). ARM32 uses
    /// the same offsets with 4-byte pointers in 8-byte cells.
    /// </summary>
    private static ElfFile Sample(NativeArch arch = NativeArch.X64)
    {
        var text = new byte[0x40];
        bool arm32 = arch == NativeArch.Arm;
        int p = arm32 ? 4 : 8;
        (uint abs, uint rel) = arch switch { NativeArch.Arm64 => (257u, 1027u), NativeArch.Arm => (2u, 23u), _ => (1u, 8u) };
        void Code(int at, params uint[] words) { foreach (var w in words) { BinaryPrimitives.WriteUInt32LittleEndian(text.AsSpan(at), w); at += 4; } }
        switch (arch)
        {
            case NativeArch.Arm64:
                for (int i = 0; i < text.Length; i += 4) Code(i, 0xD65F03C0); // ret
                Code(0, 0xF9400008, 0xF9400508, 0xD63F0100); // ldr x8, [x0]; ldr x8, [x8, #8]; blr x8
                break;
            case NativeArch.Arm:
                for (int i = 0; i < text.Length; i += 4) Code(i, 0xE12FFF1E); // bx lr
                Code(0, 0xE5903000, 0xE5933004, 0xE12FFF33); // ldr r3, [r0]; ldr r3, [r3, #4]; blx r3
                break;
            default:
                Array.Fill(text, (byte)0xC3);
                // f1: mov rax, [rdi]; call [rax+8]; ret
                new byte[] { 0x48, 0x8B, 0x07, 0xFF, 0x50, 0x08, 0xC3 }.CopyTo(text, 0);
                break;
        }
        var data = new byte[0x200];
        var relocs = new List<ElfWriter.Reloc>();
        // offsets in 8-byte cells; ARM32 halves them
        uint At(uint at) => arm32 ? D + (at - D) / 2 : at;
        void Ptr(uint at, uint target)
        {
            at = At(at);
            if (target >= D) target = At(target);
            BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan((int)(at - D)), target);
            relocs.Add(new ElfWriter.Reloc(at, rel, null, target));
        }
        void Import(uint at, string name) => relocs.Add(new ElfWriter.Reloc(At(at), abs, name, name.StartsWith("_ZTV", StringComparison.Ordinal) ? 2 * p : 0));
        void Word(uint at, long value)
        {
            if (arm32) BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan((int)(At(at) - D)), (int)value);
            else BinaryPrimitives.WriteInt64LittleEndian(data.AsSpan((int)(at - D)), value);
        }
        void Name(uint at, string text) => Encoding.ASCII.GetBytes(text + "\0").CopyTo(data, (int)(At(at) - D));
        Name(Names, "1A");
        Name(Names + 8, "1B");
        Name(Names + 16, "1C");
        Import(TiA, "_ZTVN10__cxxabiv117__class_type_infoE"); Ptr(TiA + 8, Names);
        Import(TiB, "_ZTVN10__cxxabiv120__si_class_type_infoE"); Ptr(TiB + 8, Names + 8); Ptr(TiB + 16, TiA);
        Import(TiC, "_ZTVN10__cxxabiv121__vmi_class_type_infoE"); Ptr(TiC + 8, Names + 16);
        // flags and count: two 32-bit words in one cell (ARM32: the cell's two halves, as 8 bytes)
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan((int)(At(TiC + 16) - D)), 2);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan((int)(At(TiC + 16) - D + 4)), 2);
        uint bases = arm32 ? TiC + 32 : TiC + 24; // ARM32: the 8 flag bytes take a full 8-byte cell's place
        Ptr(bases, TiA); Word(bases + 8, -(3 * p) << 8 | 3); // virtual public A, its offset at vtable -3 pointers
        Ptr(bases + 16, TiB); Word(bases + 24, p << 8 | 2); // public B at +1 pointer
        // primary: vbase offset 16, offset-to-top 0, typeinfo, f1, f2
        Word(VtC, 16); Word(VtC + 8, 0); Ptr(VtC + 16, TiC); Ptr(VtC + 24, Fn[0]); Ptr(VtC + 32, Fn[1]);
        // B-in-C
        Word(VtC + 40, -p); Ptr(VtC + 48, TiC); Ptr(VtC + 56, Fn[2]);
        // virtual A
        Word(VtC + 64, -2 * p); Ptr(VtC + 72, TiC); Ptr(VtC + 80, Fn[3]); Import(VtC + 88, "__cxa_pure_virtual");
        var w = new ElfWriter
        {
            Machine = arch switch { NativeArch.Arm64 => ElfWriter.EmAarch64, NativeArch.Arm => ElfWriter.EmArm, _ => ElfWriter.EmX64 },
            Is64 = !arm32, UseRel = arm32, Text = text, Data = data, Relocations = relocs,
            Symbols =
            [
                new("_ZTVN10__cxxabiv117__class_type_infoE", Defined: false, Type: 1), new("_ZTVN10__cxxabiv120__si_class_type_infoE", Defined: false, Type: 1),
                new("_ZTVN10__cxxabiv121__vmi_class_type_infoE", Defined: false, Type: 1), new("__cxa_pure_virtual", Defined: false),
                new("f1", Fn[0], 16), new("f2", Fn[1], 4), new("f3", Fn[2], 4), new("f4", Fn[3], 4),
            ],
        };
        return ElfFile.FromBytes(w.Build(), "libsample.so");
    }

    [Fact]
    public void Typeinfos_give_the_hierarchy_and_vtable_groups()
    {
        var r = CppRtti.Analyze(Sample());
        Assert.Empty(r.Notes);
        Assert.Equal(["A", "B", "C"], r.Classes.Select(c => c.Name));
        var c = r.Classes[2];
        Assert.Equal("_ZTI1C", c.DecoratedName);
        Assert.Equal(TiC, c.TypeDescriptorRva);
        Assert.Equal(["A", "B", "A"], c.Bases.Select(b => b.Name));
        Assert.True(c.Bases[0].IsVirtual);
        Assert.Equal(-24, c.Bases[0].Vdisp);
        Assert.Equal((8, false, 1), (c.Bases[1].Mdisp, c.Bases[1].IsVirtual, c.Bases[1].ContainedBases));
        Assert.Equal((2, 1), (c.Bases[2].Depth, c.Bases[2].Parent!.Value));
        Assert.True(c.Attributes.HasFlag(Native.Msvc.MsvcHierarchyAttributes.VirtualInheritance));
        Assert.Equal([0u, 8, 16], c.Vtables.Select(v => v.Offset));
        Assert.Equal([VtC + 24, VtC + 56, VtC + 80], c.Vtables.Select(v => v.VftableRva));
        Assert.Equal([Fn[0], Fn[1]], c.Vtables[0].SlotRvas);
        Assert.Equal([Fn[3], 0u], c.Vtables[2].SlotRvas);
        Assert.Single(r.Classes[1].Bases);
        Assert.Empty(r.Classes[0].Vtables);
    }

    [Theory]
    [InlineData(NativeArch.X64)]
    [InlineData(NativeArch.Arm64)]
    [InlineData(NativeArch.Arm)]
    public void A_call_through_this_resolves_through_the_vtable(NativeArch arch)
    {
        var image = Sample(arch);
        var rtti = CppRtti.Analyze(image);
        Assert.Equal([Fn[0], Fn[1]], rtti.Classes[2].Vtables[0].SlotRvas);
        Assert.Equal([0u, (uint)(arch == NativeArch.Arm ? 4 : 8), (uint)(arch == NativeArch.Arm ? 8 : 16)], rtti.Classes[2].Vtables.Select(v => v.Offset));
        var index = NativeCodeIndex.Build(image);
        var site = Assert.Single(index.VirtualCalls.Sites);
        Assert.Equal((VirtualCallStatus.Exact, VirtualReceiver.This, 1), (site.Status, site.Receiver, site.Slot));
        Assert.Equal([Fn[1]], index.VirtualTargets(site.Rva));
    }

    [Fact]
    public async Task Tools_list_classes_type_them_and_report_virtual_calls()
    {
        using var dir = new TempDir();
        var path = dir.File("libsample.so");
        File.WriteAllBytes(path, Sample().FileBytes.ToArray());
        var options = new ServerOptions { BackgroundIndexing = false };
        using var workspace = new AssemblyWorkspace(options);
        var code = new NativeCodeService(workspace, options, null, new Native.Annotations.AnnotationStore(dir.File("ann")));
        var engines = new NativeEngineService();
        var classes = await new NativeAnalysisTools(workspace, engines, new OutputPager(options)).ListCppClasses(path, slots: true);
        Assert.Contains("3 classes with RTTI, 3 vftables, 3 typeinfos", classes);
        Assert.Contains("class C : virtual A, B @+0x8", classes);
        Assert.Contains("[1] (import)", classes);

        var type = await new NativeTypeInfoTools(workspace, code).GetNativeType(path, name: "C", source: "rtti");
        Assert.Contains("B", type);

        var calls = await new NativeVirtualCallTools(workspace, code, engines, new NativeTypePush(workspace)).FindVirtualCalls(path);
        Assert.Equal((1, 1), (calls.Sites, calls.Exact));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Real_x64_libraries_list_classes_bases_and_vtables(bool macho)
    {
        var image = NativeImageLoader.Open(macho ? NativeFixtures.OsxX64Coverage : NativeFixtures.LinuxX64Coverage);
        var r = CppRtti.Analyze(image);
        Assert.Equal(0, r.Stats.TypeDescriptorCandidatesRejected);
        var method = Assert.Single(r.Classes, c => c.Name == "vanguard::runtime::CInstrumentationMethod");
        Assert.Contains(method.Bases, b => b is { Name: "IInstrumentationMethod", Depth: 1, Mdisp: 0 });
        Assert.Contains(method.Bases, b => b is { Name: "vanguard::runtime::CModuleRefCount", Depth: 1, Mdisp: 8 });
        Assert.Equal([0u, 8], method.Vtables.Select(v => v.Offset));
        Assert.All(method.Vtables.SelectMany(v => v.SlotRvas), s => Assert.True(image.SectionAt(s) is { IsExecutable: true }));
        Assert.True(r.Stats.Vtables >= 15, $"{r.Stats.Vtables} vtables");
        // a base class in the C++ runtime (another library) keeps its name
        Assert.Contains(r.Classes, c => c.Bases.Any(b => b is { Name: "std::exception", TypeDescriptorRva: 0 }));
    }

    [Trait("Speed", "Slow")]
    [Theory]
    [InlineData(NativeArch.Arm64)]
    [InlineData(NativeArch.Arm)]
    public void Real_arm_libraries_list_classes_and_vtables(NativeArch arch)
    {
        var image = NativeImageLoader.Open(arch == NativeArch.Arm64 ? NativeFixtures.AndroidArm64Tracing : NativeFixtures.AndroidArmTracing);
        Assert.Equal(arch, image.Arch);
        var r = CppRtti.Analyze(image);
        Assert.Equal(0, r.Stats.TypeDescriptorCandidatesRejected);
        Assert.True(r.Classes.Count >= 100 && r.Stats.Vtables >= 100, $"{r.Classes.Count} classes, {r.Stats.Vtables} vtables");
        var node = Assert.Single(r.Classes, c => c.Name == "(anonymous namespace)::itanium_demangle::FunctionEncoding");
        Assert.Equal("(anonymous namespace)::itanium_demangle::Node", Assert.Single(node.Bases).Name);
        // ARM32 Thumb targets: the slot is the function start, bit 0 cleared
        Assert.All(node.Vtables.Single().SlotRvas, s => Assert.True(s % 2 == 0 && image.SectionAt(s) is { IsExecutable: true }));

        // the demangler's nodes print themselves through their own virtual methods: calls through this resolve
        var index = NativeCodeIndex.Build(image);
        var stats = index.VirtualCalls.Stats;
        Assert.True(stats.Sites > 100, $"{stats.Sites} sites");
        // JNIEnv function tables have the same shape: their receiver is a parameter, not this
        Assert.Contains(index.VirtualCalls.Sites, s => s is { Status: VirtualCallStatus.Unresolved, Reason: VirtualCallReason.ReceiverUnknown }
            && index.FunctionAt(s.Rva)?.Name.Contains("CallObjectMethod", StringComparison.Ordinal) == true);
    }
}
