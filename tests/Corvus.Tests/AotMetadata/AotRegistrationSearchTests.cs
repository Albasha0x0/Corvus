using Corvus.Native.Elf;
using Corvus.Services;
using Corvus.Tests.NativeFormats;

namespace Corvus.Tests;

public class AotRegistrationSearchTests
{
    private const uint ArmRelative = 23;

    /// <summary>
    /// A 32-bit ARM library whose data holds three module names (one without ".dll", as the generated module is named), the
    /// code-gen modules, their pointer array and the code registration's last fields (module count, array pointer), all
    /// pointers as REL relocations; plus a pointer to the array under a zero count, which is not a registration.
    /// </summary>
    [Fact]
    public void The_code_registration_is_found_from_the_module_list()
    {
        var data = new PeBlob(ElfWriter.DataRva);
        var relocations = new List<ElfWriter.Reloc>();
        void Pointer(uint target) => relocations.Add(new(data.U32(0), ArmRelative, Addend: target));
        uint[] names = [data.Ascii("Assembly-CSharp.dll"), data.Ascii("__Generated"), data.Ascii("mscorlib.dll")];
        data.Align(4);
        var modules = new List<uint>();
        foreach (uint name in names)
        {
            modules.Add(data.Here);
            Pointer(name);
            data.Zero(12);
        }
        uint array = data.Here;
        foreach (uint module in modules) Pointer(module);
        data.Zero(15 * 4);
        data.U32(3);
        uint field = data.Here;
        Pointer(array);
        data.U32(0);
        // Count 0 before it.
        Pointer(array);

        var w = new ElfWriter { Is64 = false, Machine = ElfWriter.EmArm, UseRel = true, Data = data.ToArray(), Relocations = relocations };
        var image = ElfFile.FromBytes(w.Build(), "libil2cpp.so");
        var found = AotRegistrationSearch.CodeRegistration(image);
        Assert.Equal([new AotRegistrationSearch.Candidate(field, array, 3)], found);
        // A build that fills its registration at run time keeps only the array: found by its module count alone.
        Assert.Equal([(ulong)array], AotRegistrationSearch.ModuleArrays(image, 3));
        Assert.Empty(AotRegistrationSearch.ModuleArrays(image, 2));
    }

    /// <summary>
    /// A 32-bit ARM library whose data holds three tables of Thumb code pointers behind a null entry: a module's method
    /// pointers (excluded by its range), a longer table and the generic method pointers (null + 3) followed by non-code words.
    /// </summary>
    [Fact]
    public void Generic_method_pointers_are_a_null_entry_then_code_pointers()
    {
        var data = new PeBlob(ElfWriter.DataRva);
        var relocations = new List<ElfWriter.Reloc>();
        uint Table(int codePointers)
        {
            uint start = data.U32(0);
            for (int i = 0; i < codePointers; i++) relocations.Add(new(data.U32(0), ArmRelative, Addend: ElfWriter.TextRva + 2 * (uint)i + 1));
            data.U32(0x12345678);
            return start;
        }
        uint module = Table(3), longer = Table(5), generic = Table(3);

        var w = new ElfWriter { Is64 = false, Machine = ElfWriter.EmArm, UseRel = true, Text = new byte[0x20], Data = data.ToArray(), Relocations = relocations };
        var image = ElfFile.FromBytes(w.Build(), "libil2cpp.so");
        (ulong, ulong) moduleRange = (module + 4, module + 16);
        Assert.Equal([(ulong)generic], AotRegistrationSearch.GenericMethodPointers(image, 4, [moduleRange]));
        // Without the exclusion two exact-length tables qualify; the longer one alone is taken when nothing else fits.
        Assert.Equal([(ulong)module, generic], AotRegistrationSearch.GenericMethodPointers(image, 4, []));
        Assert.Equal([(ulong)longer], AotRegistrationSearch.GenericMethodPointers(image, 5, []));
        Assert.Empty(AotRegistrationSearch.GenericMethodPointers(image, 7, []));
    }

    /// <summary>
    /// A 32-bit ARM library whose data holds a module's method pointers (2) directly followed by the invoker table (3),
    /// then a non-code word and another table of 4 Thumb code pointers.
    /// </summary>
    [Fact]
    public void An_invoker_table_next_to_a_modules_method_pointers_is_found_by_its_length()
    {
        var data = new PeBlob(ElfWriter.DataRva);
        var relocations = new List<ElfWriter.Reloc>();
        void Code(int i) => relocations.Add(new(data.U32(0), ArmRelative, Addend: ElfWriter.TextRva + 2 * (uint)i + 1));
        uint module = data.Here;
        for (int i = 0; i < 2; i++) Code(i);
        uint invokers = data.Here;
        for (int i = 0; i < 3; i++) Code(i);
        data.U32(0x12345678);
        uint other = data.Here;
        for (int i = 0; i < 4; i++) Code(i);
        data.U32(0x12345678);

        var w = new ElfWriter { Is64 = false, Machine = ElfWriter.EmArm, UseRel = true, Text = new byte[0x20], Data = data.ToArray(), Relocations = relocations };
        var image = ElfFile.FromBytes(w.Build(), "libil2cpp.so");
        Assert.Equal([(ulong)invokers], AotRegistrationSearch.CodePointerTables(image, 3, [(module, module + 8)]));
        // Without the module's range the two tables read as one run of 5.
        Assert.Empty(AotRegistrationSearch.CodePointerTables(image, 3, []));
        Assert.Equal([(ulong)module], AotRegistrationSearch.CodePointerTables(image, 5, []));
        Assert.Equal([(ulong)other], AotRegistrationSearch.CodePointerTables(image, 4, [(module, module + 8)]));
    }
}
