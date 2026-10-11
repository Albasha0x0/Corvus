using NetDecompilerMcp.Native.Elf;
using NetDecompilerMcp.Services;
using NetDecompilerMcp.Tests.NativeFormats;

namespace NetDecompilerMcp.Tests;

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
}
