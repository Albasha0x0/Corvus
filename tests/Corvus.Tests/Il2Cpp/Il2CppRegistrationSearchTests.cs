using Corvus.Native.Elf;
using Corvus.Services;
using Corvus.Tests.NativeFormats;

namespace Corvus.Tests;

public class Il2CppRegistrationSearchTests
{
    private const uint ArmRelative = 23;

    /// <summary>
    /// A 32-bit ARM library whose data holds three module names (one without ".dll", as Unity's generated module), the
    /// code-gen modules, their pointer array and the code registration's last fields (module count, array pointer), all
    /// pointers as REL relocations; plus a pointer to the array under a zero count, which is not a registration.
    /// </summary>
    [Fact]
    public void CodeRegistration_FromTheModuleList()
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
        Pointer(array); // count 0 before it

        var w = new ElfWriter { Is64 = false, Machine = ElfWriter.EmArm, UseRel = true, Data = data.ToArray(), Relocations = relocations };
        var image = ElfFile.FromBytes(w.Build(), "libil2cpp.so");
        var found = Il2CppRegistrationSearch.CodeRegistration(image);
        Assert.Equal([new Il2CppRegistrationSearch.Candidate(field, array, 3)], found);
        // A build that fills its registration at run time keeps only the array: found by its module count alone.
        Assert.Equal([(ulong)array], Il2CppRegistrationSearch.ModuleArrays(image, 3));
        Assert.Empty(Il2CppRegistrationSearch.ModuleArrays(image, 2));
    }

    /// <summary>
    /// A 32-bit ARM library whose data holds three tables of Thumb code pointers behind a null entry: a module's method
    /// pointers (excluded by its range), a longer table and the generic method pointers (null + 3) followed by non-code words.
    /// </summary>
    [Fact]
    public void GenericMethodPointers_NullFirstEntryThenCodePointers()
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
        Assert.Equal([(ulong)generic], Il2CppRegistrationSearch.GenericMethodPointers(image, 4, [moduleRange]));
        // Without the exclusion two exact-length tables qualify; the longer one alone is taken when nothing else fits.
        Assert.Equal([(ulong)module, generic], Il2CppRegistrationSearch.GenericMethodPointers(image, 4, []));
        Assert.Equal([(ulong)longer], Il2CppRegistrationSearch.GenericMethodPointers(image, 5, []));
        Assert.Empty(Il2CppRegistrationSearch.GenericMethodPointers(image, 7, []));
    }
}
