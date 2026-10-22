using System.Buffers.Binary;
using System.Reflection;
using Corvus.Native;
using Corvus.Native.Code;
using Corvus.Native.Diff;
using Corvus.Native.Itanium;
using Corvus.Native.NativeAot;
using Corvus.Native.Pe;
using Corvus.Services;
using Corvus.Services.Mobile;

namespace Corvus.Tests;

/// <summary>Readers that scan whole sections, given section headers that add 500 MB of zero fill.</summary>
public class DamagedSectionTests
{
    private const int Limit = 64 << 20;
    private const uint Code = 0x60000020, Data = 0xC0000040;

    [Fact]
    public void A_section_past_the_image_reads_no_file_bytes()
    {
        var image = PeFile.FromBytes(Damaged(NativePeTests.KitchenSink(false), Data));
        var section = image.Sections[^1];
        long before = GC.GetAllocatedBytesForCurrentThread();
        Assert.Empty(image.ReadFileBytes(section));
        Assert.True(GC.GetAllocatedBytesForCurrentThread() - before < Limit);
        Assert.Equal(0, image.FileBytesLength(section));
        var intact = image.Sections[0];
        Assert.Equal((int)Math.Min(intact.RawSize, intact.MappedSize), image.ReadFileBytes(intact).Length);
    }

    // Regression: fuzz iteration 1399 gave sections of 1 GB at RVA 0x3F3F3F3F; each reader read them in full.
    [Theory]
    [InlineData("feature trace")]
    [InlineData("itanium rtti")]
    [InlineData("il2cpp registration")]
    [InlineData("code pattern")]
    [InlineData("itanium eh")]
    [InlineData("jni tables")]
    [InlineData("nativeaot dispatch")]
    public void A_reader_allocates_none_of_the_zero_fill_a_damaged_header_adds(string reader)
    {
        var call = Prepare(reader);
        long before = GC.GetAllocatedBytesForCurrentThread();
        call();
        Assert.True(GC.GetAllocatedBytesForCurrentThread() - before < Limit, $"{(GC.GetAllocatedBytesForCurrentThread() - before) >> 20} MB allocated");
    }

    // The reader's call on its damaged image; images and indexes are built here, outside the measurement.
    private static Action Prepare(string reader)
    {
        switch (reader)
        {
            case "feature trace":
                var index = NativeCodeIndex.Build(Pe(Code));
                return () => FeatureTrace.Run(index, "0x12345678", false, FeatureKinds.Constants, 10, 0, [], default);
            case "itanium rtti":
                var rtti = Elf(".data");
                return () => ItaniumRtti.Analyze(rtti);
            case "il2cpp registration":
                var il2cpp = Pe(Data);
                return () => { Il2CppRegistrationSearch.GenericMethodPointers(il2cpp, 4, []); Il2CppRegistrationSearch.CodeRegistration(il2cpp); };
            case "code pattern":
                var pattern = Pe(Data);
                return () => CodePatterns.CodeSections(pattern, allSections: true);
            case "itanium eh":
                var eh = Elf(".eh_frame");
                return () => ItaniumEh.Of(eh);
            case "jni tables":
                var jni = Pe(Data);
                var tables = typeof(JniBindings).GetMethod("Tables", BindingFlags.NonPublic | BindingFlags.Static)!;
                return () => tables.Invoke(null, [jni, CancellationToken.None]);
            case "nativeaot dispatch":
                // The fixture's last section is .reloc; the uninitialized "hydrated" section is the one before it.
                var built = ((PeFile)NativeAotTypeTests.Build(16, dispatchCells: true).Aot.Image).FileBytes.ToArray();
                var aot = NativeAotImage.Open(PeFile.FromBytes(Damaged(built, Data, fromLast: 1)))!;
                return () => NativeAotDispatch.Read(aot);
            default:
                throw new ArgumentException(reader);
        }
    }

    private static PeFile Pe(uint characteristics) => PeFile.FromBytes(Damaged(NativePeTests.KitchenSink(false), characteristics));

    // An ELF shared object with a typeinfo import and an unwind entry, whose section's size reaches 500 MB into zero fill.
    private static INativeImage Elf(string section)
    {
        var w = new NativeFormats.ElfWriter
        {
            Machine = NativeFormats.ElfWriter.EmX64,
            Relocations = [new(NativeFormats.ElfWriter.DataRva, 1, "_ZTVN10__cxxabiv117__class_type_infoE", 16)],
            Symbols = [new("_ZTVN10__cxxabiv117__class_type_infoE", Defined: false, Type: 1)],
            Fdes = [(NativeFormats.ElfWriter.TextRva, 4)],
        };
        var bytes = w.Build();
        int table = (int)BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(0x28));
        int size = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(0x3A)), count = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(0x3C));
        int names = (int)BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(table + size * BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(0x3E)) + 0x18));
        int at = Enumerable.Range(0, count).Select(i => table + size * i)
            .Single(h => System.Text.Encoding.ASCII.GetString(bytes, names + BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(h)), section.Length + 1) == section + "\0");
        // sh_size, and p_memsz of the writable segment, so the section stays inside the image.
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(at + 0x20), 0x1F400000);
        int programs = (int)BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(0x20));
        int entry = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(0x36));
        int load = Enumerable.Range(0, BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(0x38))).Select(i => programs + entry * i)
            .Single(h => BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(h)) == 1 && BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(h + 0x10)) == NativeFormats.ElfWriter.DynamicRva);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(load + 0x28), 0x40000000);
        return Corvus.Native.Elf.ElfFile.FromBytes(bytes, "lib.so");
    }

    // A section header at RVA 0x3F3F3F3F, its raw data past the file, with 500 MB of virtual size (under the readers' caps).
    private static byte[] Damaged(byte[] bytes, uint characteristics, int fromLast = 0)
    {
        int pe = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(0x3C));
        int table = pe + 24 + BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(pe + 20));
        int at = table + 40 * (BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(pe + 6)) - 1 - fromLast);
        foreach (int field in new[] { 12, 16, 20 }) BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(at + field), 0x3F3F3F3F);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(at + 8), 0x1F400000);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(at + 36), characteristics);
        return bytes;
    }
}
