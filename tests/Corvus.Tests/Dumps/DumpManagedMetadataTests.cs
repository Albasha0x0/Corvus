using System.Buffers.Binary;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using Corvus.Native.Dump;
using Corvus.Native.Dump.Rebuild;
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

    private ManagedMetadataState Export(byte[] mapped, int captured = -1)
    {
        var b = SyntheticCrash.Builder();
        b.Modules.Clear();
        b.Memory.RemoveAll(m => m.Start == SyntheticCrash.Base);
        b.Modules.Add(new MinidumpBuilder.Module(Base, (uint)mapped.Length, 0, @"Z:\app\fixture.dll"));
        b.Memory.Add((Base, captured < 0 ? mapped : mapped[..captured]));
        var path = _dir.File("managed.dmp");
        File.WriteAllBytes(path, b.Build());
        using var memory = MinidumpFile.Open(path);
        return DumpManagedMetadata.Inspect(memory, Assert.Single(memory.Modules))!;
    }

    private RebuiltModule Rebuilt(string dump)
    {
        using var memory = MinidumpFile.Open(dump);
        var target = Assert.Single(ModuleRebuild.Select(memory, "all", default));
        var rebuilt = ModuleRebuild.Rebuild(memory, target, RebuildOptions.Default with { Layout = OutputLayout.Mapped }, default);
        Assert.Equal(rebuilt.Target.Name, Assert.Single(ModuleWriter.WriteAll([rebuilt], _dir.File("modules"))).File);
        return rebuilt;
    }

    private string ManagedDump(byte[] mapped, int captured)
    {
        var b = SyntheticCrash.Builder();
        b.Modules.Clear();
        b.Memory.RemoveAll(m => m.Start == SyntheticCrash.Base);
        b.Modules.Add(new MinidumpBuilder.Module(Base, (uint)mapped.Length, 0, @"Z:\app\fixture.dll"));
        b.Memory.Add((Base, mapped[..captured]));
        var path = _dir.File("view.dmp");
        File.WriteAllBytes(path, b.Build());
        return path;
    }

    [Fact]
    public void The_modules_view_rows_carry_the_metadata_state_and_reason()
    {
        var (mapped, offset, _) = ManagedImage();
        var row = Assert.Single(new Corvus.Services.MinidumpService().Modules(ManagedDump(mapped, offset + 64), null, 0, 10).Rows);
        Assert.Equal("unreadable", row.Metadata);
        Assert.False(string.IsNullOrEmpty(row.MetadataReason));
        Assert.Null(row.ImageFile);
    }

    [Fact]
    public void The_modules_view_writes_the_page_images_under_outputPath_and_names_each_file()
    {
        var (mapped, _, _) = ManagedImage();
        var folder = _dir.File("rebuilt");
        var row = Assert.Single(new Corvus.Services.MinidumpService().Modules(ManagedDump(mapped, mapped.Length), null, 0, 10, folder).Rows);
        Assert.Equal("readable", row.Metadata);
        Assert.Equal("fixture.dll", row.ImageFile);
        Assert.True(File.Exists(Path.Combine(folder, "fixture.dll")));
    }

    [Fact]
    public void The_modules_view_refuses_an_outputPath_folder_that_is_not_empty()
    {
        var (mapped, _, _) = ManagedImage();
        File.WriteAllText(_dir.File("taken.txt"), "x");
        var error = Assert.Throws<Corvus.Core.ToolError>(() => new Corvus.Services.MinidumpService().Modules(ManagedDump(mapped, mapped.Length), null, 0, 10, _dir.Path));
        Assert.Contains("new or empty folder", error.Message);
    }

    private string HeaderlessDump(uint size, bool captureHeader)
    {
        var (mapped, _, _) = ManagedImage();
        var b = SyntheticCrash.Builder();
        b.Modules.Clear();
        b.Memory.RemoveAll(m => m.Start == SyntheticCrash.Base);
        b.Modules.Add(new MinidumpBuilder.Module(Base, size, 0, @"Z:ppixture.dll"));
        if (captureHeader) b.Memory.Add((Base, mapped[..0x1000]));
        var path = _dir.File("headerless.dmp");
        File.WriteAllBytes(path, b.Build());
        return path;
    }

    [Fact]
    public void A_module_whose_header_page_is_not_captured_reports_unknown_with_a_reason()
    {
        var row = Assert.Single(new Corvus.Services.MinidumpService().Modules(HeaderlessDump(0x9000, false), null, 0, 10).Rows);
        Assert.Equal("unknown", row.Metadata);
        Assert.Equal("the dump does not hold the module header", row.MetadataReason);
    }

    [Fact]
    public void A_managed_image_over_the_size_limit_reports_unknown_with_a_reason()
    {
        var row = Assert.Single(new Corvus.Services.MinidumpService().Modules(HeaderlessDump(0x2400_0000, true), null, 0, 10).Rows);
        Assert.Equal("unknown", row.Metadata);
        Assert.Contains("larger than", row.MetadataReason);
    }

    [Fact]
    public void A_skipped_managed_module_reports_unknown_with_the_skip_reason_under_outputPath()
    {
        var folder = _dir.File("skipped");
        var (_, rows, _, _) = new Corvus.Services.MinidumpService().Modules(HeaderlessDump(0x22000000, true), null, 0, 10, folder);
        var row = Assert.Single(rows);
        Assert.Equal("unknown", row.Metadata);
        Assert.Contains("larger than", row.MetadataReason);
        Assert.Null(row.ImageFile);
    }

    [Fact]
    public void A_native_module_row_has_no_metadata_state()
    {
        var path = _dir.File("native-view.dmp");
        File.WriteAllBytes(path, SyntheticCrash.Builder().Build());
        var rows = new Corvus.Services.MinidumpService().Modules(path, null, 0, 10).Rows;
        Assert.All(rows, r => Assert.Null(r.Metadata));
    }

    [Fact]
    public void The_modules_view_returns_the_resolved_folder_of_the_written_images()
    {
        var (mapped, _, _) = ManagedImage();
        var folder = _dir.File("resolved");
        var (_, _, _, resolved) = new Corvus.Services.MinidumpService().Modules(ManagedDump(mapped, mapped.Length), null, 0, 10, folder);
        Assert.Equal(Path.GetFullPath(folder), resolved);
    }

    [Fact]
    public void A_cancelled_modules_call_writes_no_image()
    {
        var (mapped, _, _) = ManagedImage();
        var folder = _dir.File("cancelled");
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        Assert.ThrowsAny<OperationCanceledException>(() => new Corvus.Services.MinidumpService().Modules(ManagedDump(mapped, mapped.Length), null, 0, 10, folder, cts.Token));
        Assert.Empty(Directory.Exists(folder) ? Directory.GetFiles(folder) : []);
    }

    [Fact]
    public void An_intact_managed_image_reports_readable_metadata()
    {
        var written = Export(ManagedImage().Mapped);
        Assert.Equal("readable", written.State);
        Assert.Null(written.Reason);
    }

    [Fact]
    public void A_native_image_reports_no_metadata_state()
    {
        var b = SyntheticCrash.Builder();
        var path = _dir.File("native.dmp");
        File.WriteAllBytes(path, b.Build());
        var written = Rebuilt(path);
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
        Assert.Equal("unreadable", written.State);
        Assert.Equal("the metadata root is zero-filled", written.Reason);
    }

    [Fact]
    public void A_zeroed_root_before_later_content_is_named_by_its_root()
    {
        var (mapped, offset, _) = ManagedImage();
        Array.Clear(mapped, offset, 16);
        var written = Export(mapped);
        Assert.Equal("unreadable", written.State);
        Assert.Equal("the metadata root is zero-filled", written.Reason);
    }

    [Fact]
    public void A_transformed_metadata_root_is_named_by_its_signature()
    {
        var (mapped, offset, _) = ManagedImage();
        mapped.AsSpan(offset, 4).Fill(0xA5);
        var written = Export(mapped);
        Assert.Equal("unreadable", written.State);
        Assert.Contains("0xA5A5A5A5, not BSJB", written.Reason);
    }

    [Fact]
    public void A_cut_inside_the_tables_stream_is_unreadable_and_names_the_stream()
    {
        var (mapped, offset, length) = ManagedImage();
        var tables = Streams(mapped, offset)["#~"];
        int cut = (offset + tables.Offset + tables.Size) & ~0xFFF;
        Assert.True(cut > offset + tables.Offset && cut < offset + tables.Offset + tables.Size);
        var written = Export(mapped, cut);
        Assert.Equal("unreadable", written.State);
        Assert.StartsWith($"{cut - offset} of {length} metadata bytes were captured; #~ cut at ", written.Reason);
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
        Assert.Equal("partial", written.State);
        Assert.StartsWith($"{cut - offset} of {length} metadata bytes were captured; the tables read, #Strings cut at ", written.Reason);
    }

    [Fact]
    public void A_directory_length_ending_inside_a_heap_is_partial_and_names_the_length()
    {
        var (mapped, offset, _) = ManagedImage();
        var strings = Streams(mapped, offset)["#Strings"];
        int shorter = strings.Offset + 4;
        BinaryPrimitives.WriteUInt32LittleEndian(mapped.AsSpan(ClrHeader(mapped) + 12), (uint)shorter);
        var written = Export(mapped);
        Assert.Equal("partial", written.State);
        Assert.StartsWith($"the metadata directory length {shorter} ends inside #Strings cut at 4 of ", written.Reason);
    }

    [Fact]
    public void A_directory_length_below_the_root_size_is_named_as_a_directory_length()
    {
        var (mapped, _, _) = ManagedImage();
        BinaryPrimitives.WriteUInt32LittleEndian(mapped.AsSpan(ClrHeader(mapped) + 12), 8);
        var written = Export(mapped);
        Assert.Equal("unreadable", written.State);
        Assert.Equal("the metadata directory length is 8, below the 16-byte root", written.Reason);
    }

    [Fact]
    public void A_clr_header_without_a_metadata_directory_is_named()
    {
        var (mapped, _, _) = ManagedImage();
        BinaryPrimitives.WriteUInt32LittleEndian(mapped.AsSpan(ClrHeader(mapped) + 8), 0);
        var written = Export(mapped);
        Assert.Equal("unreadable", written.State);
        Assert.Equal("the CLR header has no metadata directory", written.Reason);
    }

    [Fact]
    public void A_zero_filled_clr_header_is_named_as_not_captured()
    {
        var (mapped, _, _) = ManagedImage();
        mapped.AsSpan(ClrHeader(mapped), 72).Clear();
        var written = Export(mapped);
        Assert.Equal("unreadable", written.State);
        Assert.Equal("the CLR header is zero-filled: its page was not captured", written.Reason);
    }

    [Fact]
    public void A_clr_header_past_the_captured_pages_lies_outside_the_image()
    {
        var (mapped, _, _) = ManagedImage();
        int cut = ClrHeader(mapped) & ~0xFFF;
        Assert.True(cut >= 0x1000);
        var written = Export(mapped, cut);
        Assert.Equal("unreadable", written.State);
        Assert.Equal("the CLR header lies outside the captured image", written.Reason);
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
        Assert.Equal("unreadable", written.State);
        Assert.Contains("size is 12", written.Reason);
    }
}
