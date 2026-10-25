using Corvus.Core.Archives;
using Corvus.Native.Pe;

namespace Corvus.Tests;

/// <summary>COFF objects and librarian archives read from objects the test writes.</summary>
public sealed class CoffObjectTests
{
    private const ushort Amd64 = 0x8664;

    // mov eax, [rip+disp32]; call rel32; ret: two REL32 relocations, to a data symbol and to an external function.
    private static readonly byte[] Text = [0x8B, 0x05, 0, 0, 0, 0, 0xE8, 0, 0, 0, 0, 0xC3];

    private static byte[] Sample(bool bigObj = false) => CoffFixtures.Object(Amd64,
        [
            new(".text$mn", CoffFixtures.Code, Text, [(2, 2, 4), (7, 3, 4)]),
            new(".data$counters_long_name", CoffFixtures.Data, [1, 0, 0, 0], []),
        ],
        [
            new("read_counter_and_notify", 0, 1, 0x20, 2),
            new("helper", 6, 1, 0x20, 3),
            new("counter", 0, 2, 0, 3),
            new("notify", 0, 0, 0x20, 2),
        ], bigObj);

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void An_object_reads_its_sections_relocations_and_symbols_in_either_header_form(bool bigObj)
    {
        var o = CoffObject.Read(Sample(bigObj), out var reason);
        Assert.Null(reason);
        Assert.Equal((ushort)Amd64, o!.Machine);
        Assert.Equal(Corvus.Native.NativeArch.X64, o.Arch);
        Assert.Equal([".text$mn", ".data$counters_long_name"], o.Sections.Select(s => s.Name));
        Assert.True(o.Sections[0].IsCode);
        Assert.False(o.Sections[1].IsCode);
        Assert.Equal(Text, o.Sections[0].Data);
        Assert.Equal([new CoffRelocation(2, 2, 4), new CoffRelocation(7, 3, 4)], o.Sections[0].Relocations);
        Assert.Equal(["read_counter_and_notify", "helper", "counter", "notify"], o.Symbols.Select(s => s.Name));
        var main = o.Symbols[0];
        Assert.True(main.IsFunction && main.IsExternal);
        Assert.Equal((0u, 1), (main.Value, main.Section));
        Assert.Equal(0, o.Symbols[3].Section);
    }

    [Fact]
    public void Import_and_link_time_code_generation_objects_are_refused_with_their_reason()
    {
        // IMPORT_OBJECT_HEADER: Sig1 0, Sig2 0xFFFF, Version 0.
        var import = new byte[40];
        import[2] = 0xFF; import[3] = 0xFF;
        Assert.Null(CoffObject.Read(import, out var reason));
        Assert.StartsWith("an import object", reason);
        // ANON_OBJECT_HEADER of a /GL object: version 1, a class id other than /bigobj's.
        var anonymous = new byte[64];
        anonymous[2] = 0xFF; anonymous[3] = 0xFF; anonymous[4] = 1;
        Assert.Null(CoffObject.Read(anonymous, out reason));
        Assert.StartsWith("an anonymous object", reason);
    }

    [Fact]
    public void Damaged_objects_are_refused_or_read_and_never_throw()
    {
        var sample = Sample();
        var random = new Random(7);
        for (int n = 0; n < 2000; n++)
        {
            var bytes = n % 2 == 0 ? sample.AsSpan(0, random.Next(sample.Length)).ToArray() : (byte[])sample.Clone();
            if (n % 2 == 1) for (int k = 0; k < 4; k++) bytes[random.Next(bytes.Length)] = (byte)random.Next(256);
            var o = CoffObject.Read(bytes, out var reason);
            Assert.True(o != null || reason != null);
        }
    }

    [Theory]
    [InlineData(0x8664, 1, 8)]   // ADDR64
    [InlineData(0x8664, 4, 4)]   // REL32
    [InlineData(0x8664, 0, 0)]   // ABSOLUTE
    [InlineData(0x014C, 0x14, 4)] // I386 REL32
    [InlineData(0xAA64, 3, 4)]   // ARM64 BRANCH26 rewrites its instruction
    [InlineData(0x01C4, 0x11, 8)] // THUMB_MOV32 rewrites a MOVW and MOVT pair
    public void Each_relocation_type_rewrites_its_width(int machine, int type, int width) =>
        Assert.Equal(width, CoffObject.Width((ushort)machine, (ushort)type));

    [Fact]
    public void Librarian_archive_members_take_their_long_names_up_to_the_nul()
    {
        var library = CoffFixtures.Library(("short.obj", [1, 2, 3]), ("d:\\build\\objects\\read_counter.obj", Sample()), ("other_long_object_name.obj", [4]));
        var members = ArReader.Members(library, "sample.lib", default);
        Assert.Equal(["/", "short.obj", "d:\\build\\objects\\read_counter.obj", "other_long_object_name.obj"], members.Select(m => m.Name));
        var (_, at, size) = members[2];
        Assert.NotNull(CoffObject.Read(library.AsSpan(at, size), out _));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    [FuzzEntry(typeof(CoffObject))]
    public void Fuzzed_objects_are_read_or_refused_with_a_reason(bool bigObj)
    {
        var failures = FormatFuzz.Run(Sample(bigObj), b =>
        {
            var o = CoffObject.Read(b, out var reason);
            if (o == null && reason == null) throw new InvalidOperationException("refused without a reason");
            if (o != null) _ = Corvus.Native.Diff.LibrarySignatures.Functions(o, "x.obj").ToList();
        }, 300);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }
}
