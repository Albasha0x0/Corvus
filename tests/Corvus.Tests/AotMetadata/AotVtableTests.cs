using AssetRipper.Primitives;
using Corvus.Services;
using LibCpp2IL.Metadata;

namespace Corvus.Tests;

/// <summary>Vtable slot tables read from the vtable method section of a v29 global-metadata.dat the tests write.</summary>
public sealed class AotVtableTests
{
    private const uint MethodDefKind = 3u << 29, MethodRefKind = 6u << 29;

    // Metadata v29 encoding: kind, index in bits 1-28, flag in bit 0.
    private static uint MethodDef(uint index) => MethodDefKind | (index << 1) | 1;

    private static uint MethodRef(uint index) => MethodRefKind | (index << 1) | 1;

    private static (string[] Images, List<AotBuildModel.Vtable> Vtables, List<string> Reasons) Read(byte[] bytes, CancellationToken ct = default)
    {
        lock (AotMetadataReader.Gate)
        {
            var meta = Il2CppMetadata.ReadFrom(bytes, UnityVersion.Parse("2021.3.0f1"));
            var reasons = new List<string>();
            // Names are read through the library's process-wide metadata.
            LibCpp2IL.LibCpp2IlMain.TheMetadata = meta;
            try
            {
                var (images, vtables) = AotVtables.Read(meta, (_, reason, detail) => reasons.Add(reason == "unreadable_vtable" ? $"{reason}: {detail}" : reason), ct);
                return (images, vtables, reasons);
            }
            finally { LibCpp2IL.LibCpp2IlMain.Reset(); }
        }
    }

    [Fact]
    public void A_type_vtable_keeps_slot_order_and_reports_only_instantiated_slots()
    {
        var bytes = new AotMetadataWriter().Assembly("Assembly-CSharp", "0.0.0.0").Field("a", "N.First").Field("b", "N.Second")
            .Vtable(MethodDef(1), MethodDef(0), MethodRef(7), 0, MethodDef(1)).Build();
        var (images, vtables, reasons) = Read(bytes);
        var program = Assert.Single(vtables);
        Assert.Equal("Assembly-CSharp.dll", images[program.Image]);
        Assert.Equal(0x02000002u, program.Type);
        Assert.Equal([0x06000002u, 0x06000001u, 0u, 0u, 0x06000002u], program.Slots.Select(s => s.Method));
        Assert.Equal(["vtable_slot_not_a_definition"], reasons);
    }

    [Fact]
    public void A_type_without_slots_has_no_vtable()
    {
        var (_, vtables, reasons) = Read(new AotMetadataWriter().Assembly("Assembly-CSharp", "0.0.0.0").Build());
        Assert.Empty(vtables);
        Assert.Empty(reasons);
    }

    [Fact]
    public void A_model_file_returns_its_vtables_by_image_name_without_extension()
    {
        var model = new AotBuildModel
        {
            BinaryPath = "", MetadataPath = "", MetadataVersion = 29, HeaderVersion = 29, EngineVersion = "2021.3.0f1", EngineVersionSource = "test",
            ImageBase = 0, MemoryImage = false, VtableImages = ["Lib.dll", "App.dll"],
            Vtables = [new(1, 0x02000005, [new(0, 0x06000001), new(1, 0x06000009), new(0, 0)])],
        };
        var path = Path.Combine(Path.GetTempPath(), $"vtable-model-{Guid.NewGuid():N}.bin");
        try
        {
            model.Write(path);
            var read = AotBuildModel.Read(path);
            var vtable = read.VtableOf("app", 0x02000005)!.Value;
            Assert.Equal([(0, 0x06000001u), (1, 0x06000009u), (0, 0u)], vtable.Slots.Select(s => (s.Image, s.Method)));
            Assert.Null(read.VtableOf("App.dll", 0x02000006));
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void A_slot_with_an_out_of_range_method_index_keeps_its_place_and_is_reported_once()
    {
        var bytes = new AotMetadataWriter().Assembly("Assembly-CSharp", "0.0.0.0").Field("a", "N.First")
            .Vtable(MethodDef(0), MethodDef(9999), MethodDef(8888)).Build();
        var (_, vtables, reasons) = Read(bytes);
        Assert.Equal([0x06000001u, 0u, 0u], Assert.Single(vtables).Slots.Select(s => s.Method));
        Assert.Equal(["vtable_slot_bad_index"], reasons);
    }

    // Unmasked indices read 2x too large and left the table; a flag-only entry is an empty slot.
    [Fact]
    public void A_v29_slot_decodes_its_index_without_the_flag_bit()
    {
        var bytes = new AotMetadataWriter().Assembly("Assembly-CSharp", "0.0.0.0").Field("a", "N.First")
            .Vtable(MethodDef(0), 1, MethodRef(3)).Build();
        var (_, vtables, reasons) = Read(bytes);
        Assert.Equal([0x06000001u, 0u, 0u], Assert.Single(vtables).Slots.Select(s => s.Method));
        Assert.Equal(["vtable_slot_not_a_definition"], reasons);
    }

    [Fact]
    public void Reading_vtables_honours_cancellation()
    {
        var bytes = new AotMetadataWriter().Assembly("Assembly-CSharp", "0.0.0.0").Vtable(MethodDef(0)).Build();
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        Assert.Throws<OperationCanceledException>(() => Read(bytes, cts.Token));
    }

    [Fact]
    public void A_model_with_a_bad_vtable_image_index_is_rejected()
    {
        var model = new AotBuildModel
        {
            BinaryPath = "", MetadataPath = "", MetadataVersion = 29, HeaderVersion = 29, EngineVersion = "2021.3.0f1", EngineVersionSource = "test",
            ImageBase = 0, MemoryImage = false, VtableImages = ["Lib.dll"], Vtables = [new(0, 0x02000005, [new(5, 0x06000001)])],
        };
        var path = Path.Combine(Path.GetTempPath(), $"vtable-model-{Guid.NewGuid():N}.bin");
        try
        {
            model.Write(path);
            Assert.Throws<IOException>(() => AotBuildModel.Read(path));
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void A_model_file_of_the_previous_format_is_rejected()
    {
        var path = Path.Combine(Path.GetTempPath(), $"vtable-model-{Guid.NewGuid():N}.bin");
        try
        {
            new AotBuildModel
            {
                BinaryPath = "", MetadataPath = "", MetadataVersion = 29, HeaderVersion = 29, EngineVersion = "2021.3.0f1",
                EngineVersionSource = "test", ImageBase = 0, MemoryImage = false,
            }.Write(path);
            var bytes = File.ReadAllBytes(path);
            // The format version follows the four magic bytes.
            bytes[4] = 1;
            File.WriteAllBytes(path, bytes);
            Assert.Throws<IOException>(() => AotBuildModel.Read(path));
        }
        finally { File.Delete(path); }
    }
}
