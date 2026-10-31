using System.Buffers.Binary;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using Corvus.Native.Dump;
using Corvus.Native.Pe;

namespace Corvus.Tests;

/// <summary>Managed metadata of module images rebuilt from a dump: readable, partial or unreadable with the reason.</summary>
public sealed class DumpManagedMetadataTests : IDisposable
{
    private const ulong Base = 0x7FF6_2000_0000;
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    /// <summary>A library with 400 types, so its metadata block spans several pages; returns the mapped image and the block's offset and length.</summary>
    private static (byte[] Mapped, int Offset, int Length) ManagedImage()
    {
        var md = new MetadataBuilder();
        md.AddModule(0, md.GetOrAddString("fixture.dll"), md.GetOrAddGuid(Guid.NewGuid()), default, default);
        md.AddAssembly(md.GetOrAddString("fixture"), new Version(1, 0, 0, 0), default, default, 0, AssemblyHashAlgorithm.None);
        md.AddTypeDefinition(default, default, md.GetOrAddString("<Module>"), default, MetadataTokens.FieldDefinitionHandle(1), MetadataTokens.MethodDefinitionHandle(1));
        for (int i = 0; i < 400; i++)
            md.AddTypeDefinition(TypeAttributes.Public, md.GetOrAddString("Ns"), md.GetOrAddString($"Fixture_type_with_a_long_name_{i:D4}"), default,
                MetadataTokens.FieldDefinitionHandle(1), MetadataTokens.MethodDefinitionHandle(1));
        var root = new MetadataRootBuilder(md);
        var pe = new ManagedPEBuilder(new PEHeaderBuilder(imageCharacteristics: Characteristics.Dll | Characteristics.ExecutableImage), root, new BlobBuilder());
        var blob = new BlobBuilder();
        pe.Serialize(blob);
        var file = blob.ToArray();
        var image = PeFile.FromBytes(file);
        var mapped = new byte[image.SizeOfImage];
        for (uint page = 0; page < mapped.Length; page += 0x1000) image.Read(page, mapped.AsSpan((int)page, (int)Math.Min(0x1000, mapped.Length - page)));
        var clr = image.Directory(PeDirectory.ClrRuntimeHeader);
        int offset = (int)BinaryPrimitives.ReadUInt32LittleEndian(mapped.AsSpan((int)clr.Rva + 8));
        int length = (int)BinaryPrimitives.ReadUInt32LittleEndian(mapped.AsSpan((int)clr.Rva + 12));
        return (mapped, offset, length);
    }

    private ExportedModule Export(byte[] mapped, int captured = -1)
    {
        var b = SyntheticCrash.Builder();
        b.Modules.Clear();
        b.Memory.RemoveAll(m => m.Start == SyntheticCrash.Base);
        b.Modules.Add(new MinidumpBuilder.Module(Base, (uint)mapped.Length, 0, @"Z:\app\fixture.dll"));
        b.Memory.Add((Base, captured < 0 ? mapped : mapped[..captured]));
        var path = _dir.File("managed.dmp");
        File.WriteAllBytes(path, b.Build());
        return Assert.Single(DumpModuleExport.Write(path, _dir.File("modules"), default).Written);
    }

    [Fact]
    public void An_intact_managed_image_reports_readable_metadata()
    {
        var written = Export(ManagedImage().Mapped);
        Assert.Equal("readable", written.Metadata);
        Assert.Null(written.MetadataReason);
    }

    [Fact]
    public void A_native_image_reports_no_metadata_state()
    {
        var b = SyntheticCrash.Builder();
        var path = _dir.File("native.dmp");
        File.WriteAllBytes(path, b.Build());
        var written = Assert.Single(DumpModuleExport.Write(path, _dir.File("modules"), default).Written);
        Assert.Null(written.Metadata);
    }

    /// <summary>Offset and size of each metadata stream, from the root at <paramref name="root"/>.</summary>
    private static Dictionary<string, (int Offset, int Size)> Streams(byte[] mapped, int root)
    {
        var result = new Dictionary<string, (int, int)>();
        int at = root + 16 + (int)BinaryPrimitives.ReadUInt32LittleEndian(mapped.AsSpan(root + 12));
        int count = BinaryPrimitives.ReadUInt16LittleEndian(mapped.AsSpan(at + 2));
        at += 4;
        for (int i = 0; i < count; i++)
        {
            int nameLength = mapped.AsSpan(at + 8).IndexOf((byte)0);
            result[System.Text.Encoding.ASCII.GetString(mapped, at + 8, nameLength)] =
                ((int)BinaryPrimitives.ReadUInt32LittleEndian(mapped.AsSpan(at)), (int)BinaryPrimitives.ReadUInt32LittleEndian(mapped.AsSpan(at + 4)));
            at += 8 + ((nameLength + 1 + 3) & ~3);
        }
        return result;
    }

    private static int ClrHeader(byte[] mapped) => (int)PeFile.FromBytes(mapped).Directory(PeDirectory.ClrRuntimeHeader).Rva;

    [Fact]
    public void A_zero_filled_metadata_block_is_named_by_its_root()
    {
        var (mapped, offset, length) = ManagedImage();
        Array.Clear(mapped, offset, length);
        var written = Export(mapped);
        Assert.Equal("unreadable", written.Metadata);
        Assert.Equal("the metadata root is zero-filled", written.MetadataReason);
    }

    [Fact]
    public void A_zeroed_root_before_later_content_is_named_by_its_root()
    {
        var (mapped, offset, _) = ManagedImage();
        Array.Clear(mapped, offset, 16);
        var written = Export(mapped);
        Assert.Equal("unreadable", written.Metadata);
        Assert.Equal("the metadata root is zero-filled", written.MetadataReason);
    }

    [Fact]
    public void A_transformed_metadata_root_is_named_by_its_signature()
    {
        var (mapped, offset, _) = ManagedImage();
        mapped.AsSpan(offset, 4).Fill(0xA5);
        var written = Export(mapped);
        Assert.Equal("unreadable", written.Metadata);
        Assert.Contains("0xA5A5A5A5, not BSJB", written.MetadataReason);
    }

    [Fact]
    public void A_cut_inside_the_tables_stream_is_unreadable_and_names_the_stream()
    {
        var (mapped, offset, length) = ManagedImage();
        var tables = Streams(mapped, offset)["#~"];
        int cut = (offset + tables.Offset + tables.Size) & ~0xFFF;
        Assert.True(cut > offset + tables.Offset && cut < offset + tables.Offset + tables.Size);
        var written = Export(mapped, cut);
        Assert.Equal("unreadable", written.Metadata);
        Assert.StartsWith($"{cut - offset} of {length} metadata bytes were captured; #~ cut at ", written.MetadataReason);
    }

    [Fact]
    public void A_cut_inside_a_heap_after_the_tables_is_partial_and_names_the_heap()
    {
        var (mapped, offset, length) = ManagedImage();
        var streams = Streams(mapped, offset);
        var strings = streams["#Strings"];
        int cut = (offset + strings.Offset + strings.Size / 2) & ~0xFFF;
        Assert.True(cut > offset + streams["#~"].Offset + streams["#~"].Size && cut < offset + strings.Offset + strings.Size);
        var written = Export(mapped, cut);
        Assert.Equal("partial", written.Metadata);
        Assert.StartsWith($"{cut - offset} of {length} metadata bytes were captured; the tables read, #Strings cut at ", written.MetadataReason);
    }

    [Fact]
    public void A_directory_length_ending_inside_a_heap_is_partial_and_names_the_length()
    {
        var (mapped, offset, _) = ManagedImage();
        var strings = Streams(mapped, offset)["#Strings"];
        int shorter = strings.Offset + 4;
        BinaryPrimitives.WriteUInt32LittleEndian(mapped.AsSpan(ClrHeader(mapped) + 12), (uint)shorter);
        var written = Export(mapped);
        Assert.Equal("partial", written.Metadata);
        Assert.StartsWith($"the metadata directory length {shorter} ends inside #Strings cut at 4 of ", written.MetadataReason);
    }

    [Fact]
    public void A_directory_length_below_the_root_size_is_named_as_a_directory_length()
    {
        var (mapped, _, _) = ManagedImage();
        BinaryPrimitives.WriteUInt32LittleEndian(mapped.AsSpan(ClrHeader(mapped) + 12), 8);
        var written = Export(mapped);
        Assert.Equal("unreadable", written.Metadata);
        Assert.Equal("the metadata directory length is 8, below the 16-byte root", written.MetadataReason);
    }

    [Fact]
    public void A_clr_header_without_a_metadata_directory_is_named()
    {
        var (mapped, _, _) = ManagedImage();
        BinaryPrimitives.WriteUInt32LittleEndian(mapped.AsSpan(ClrHeader(mapped) + 8), 0);
        var written = Export(mapped);
        Assert.Equal("unreadable", written.Metadata);
        Assert.Equal("the CLR header has no metadata directory", written.MetadataReason);
    }

    [Fact]
    public void A_zero_filled_clr_header_is_named_as_not_captured()
    {
        var (mapped, _, _) = ManagedImage();
        mapped.AsSpan(ClrHeader(mapped), 72).Clear();
        var written = Export(mapped);
        Assert.Equal("unreadable", written.Metadata);
        Assert.Equal("the CLR header is zero-filled: its page was not captured", written.MetadataReason);
    }

    [Fact]
    public void A_clr_header_past_the_captured_pages_lies_outside_the_image()
    {
        var (mapped, _, _) = ManagedImage();
        int cut = ClrHeader(mapped) & ~0xFFF;
        Assert.True(cut >= 0x1000);
        var written = Export(mapped, cut);
        Assert.Equal("unreadable", written.Metadata);
        Assert.Equal("the CLR header lies outside the captured image", written.MetadataReason);
    }

    [Fact]
    public void A_native_entry_serializes_without_metadata_fields()
    {
        var json = System.Text.Json.JsonSerializer.Serialize(new ExportedModule("a.dll", "0x1", 1, "00", 100), new System.Text.Json.JsonSerializerOptions(System.Text.Json.JsonSerializerDefaults.Web));
        Assert.DoesNotContain("metadata", json, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void A_corrupted_clr_header_size_is_named()
    {
        var (mapped, _, _) = ManagedImage();
        var clr = PeFile.FromBytes(mapped).Directory(PeDirectory.ClrRuntimeHeader);
        BinaryPrimitives.WriteUInt32LittleEndian(mapped.AsSpan((int)clr.Rva), 12);
        var written = Export(mapped);
        Assert.Equal("unreadable", written.Metadata);
        Assert.Contains("size is 12", written.MetadataReason);
    }
}
