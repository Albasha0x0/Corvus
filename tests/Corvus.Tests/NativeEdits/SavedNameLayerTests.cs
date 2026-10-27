using System.IO.Compression;
using Corvus.Native.Annotations;
using Corvus.Native.Code;

namespace Corvus.Tests;

/// <summary>Name layers saved in the data folder (PDB, metadata, IDA, NativeAOT names) and read back at load.</summary>
public sealed class SavedNameLayerTests
{
    private const string Sha = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    private static byte[] Saved()
    {
        var layer = new NativeNameLayers.Layer(NativeNameSource.Pdb, new Dictionary<uint, string> { [0x1000] = "Main", [0x1040] = "Helper" },
            new Dictionary<uint, string> { [0x1000] = "entry" }, "test.pdb");
        using var saved = new MemoryStream();
        SavedNameLayer.Write(saved, Sha, "x.dll", layer);
        return saved.ToArray();
    }

    /// <summary>A damaged layer, compressed again so the damage reaches the reader: a layer or null, never an exception.</summary>
    [Fact]
    [FuzzEntry(typeof(SavedNameLayer))]
    public void Damaged_layers_read_as_absent()
    {
        var saved = Saved();
        Assert.Equal(2, SavedNameLayer.Read(new MemoryStream(saved), Sha)!.Names.Count);
        byte[] raw;
        using (var gz = new GZipStream(new MemoryStream(saved), CompressionMode.Decompress))
        using (var plain = new MemoryStream()) { gz.CopyTo(plain); raw = plain.ToArray(); }
        var failures = FormatFuzz.Run(raw, b =>
        {
            using var packed = new MemoryStream();
            using (var gz = new GZipStream(packed, CompressionLevel.Fastest, leaveOpen: true)) gz.Write(b);
            packed.Position = 0;
            SavedNameLayer.Read(packed, Sha);
        }, 1000);
        failures.AddRange(FormatFuzz.Run(saved, b => SavedNameLayer.Read(new MemoryStream(b), Sha), 300));
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(10)));
    }

    // A metadata layer as versions up to 2.7 named it: <sha256>.il2cpp.names.
    [Fact]
    public void A_metadata_layer_saved_under_the_earlier_file_name_loads_and_deletes()
    {
        using var dir = new TempDir();
        var store = new AnnotationStore(dir.File("ann"));
        var layer = new NativeNameLayers.Layer(NativeNameSource.Metadata, new Dictionary<uint, string> { [0x1000] = "App_Main" },
            new Dictionary<uint, string>(), "metadata");
        Assert.Null(store.SaveLayer(Sha, "x.dll", layer));
        var written = store.LayerFileFor(Sha, NativeNameSource.Metadata);
        Assert.EndsWith(".metadata.names", written, StringComparison.Ordinal);
        File.Move(written, Path.Combine(store.Root, Sha + ".il2cpp.names"));

        Assert.Equal("App_Main", store.LoadLayer(Sha, NativeNameSource.Metadata)!.Names[0x1000]);
        Assert.True(store.DeleteLayer(Sha, NativeNameSource.Metadata));
        Assert.Empty(Directory.GetFiles(store.Root, "*.names"));
    }
}
