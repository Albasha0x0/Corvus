using System.IO.Compression;
using System.Text;
using Corvus.Core.Models;
using Corvus.Services.Web.Packages;

namespace Corvus.Tests;

/// <summary>Model files read for what they run or reach when loaded; every fixture is built here from the documented formats.</summary>
public sealed class ModelRiskTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    /// <summary>A protocol 2 pickle that calls <paramref name="module"/>.<paramref name="name"/> on the string "x".</summary>
    internal static byte[] Call(string module, string name) =>
        new ModelSamples.Pickle().Proto(2).Global(module, name).Str("x").Op(0x85).Op('R').Op('.').ToArray();

    /// <summary>An .npy version 1.0 file: a header padded to 64 bytes, then <paramref name="data"/>.</summary>
    internal static byte[] Npy(string descr, byte[] data)
    {
        var header = $"{{'descr': {descr}, 'fortran_order': False, 'shape': (1,), }}";
        header = header.PadRight(64 - 10 - 1) + "\n";
        var b = new List<byte>([0x93, .. "NUMPY"u8.ToArray(), 1, 0]);
        b.AddRange(BitConverter.GetBytes((ushort)header.Length));
        b.AddRange(Encoding.Latin1.GetBytes(header));
        b.AddRange(data);
        return [.. b];
    }

    private static readonly byte[] Hdf5Magic = [0x89, .. "HDF"u8.ToArray(), 0x0D, 0x0A, 0x1A, 0x0A];

    /// <summary>A .keras zip whose config.json holds one layer of class <paramref name="layer"/>.</summary>
    internal static byte[] Keras(string layer, string module = "keras.layers") => ContainerFixtures.Zip(
        ("metadata.json", """{"keras_version":"3.0.0"}"""u8.ToArray()),
        ("config.json", Encoding.UTF8.GetBytes($$$"""{"class_name":"Sequential","config":{"layers":[{"module":"{{{module}}}","class_name":"{{{layer}}}","config":{},"registered_name":"{{{layer}}}"}]}}""")),
        ("model.weights.h5", Hdf5Magic));

    private static byte[] Zlib(byte[] data)
    {
        var m = new MemoryStream();
        using (var z = new ZLibStream(m, CompressionMode.Compress, leaveOpen: true)) z.Write(data);
        return m.ToArray();
    }

    // An LZ4 frame with one stored block; the header checksum byte is not read.
    private static byte[] Lz4(byte[] data) =>
        [0x04, 0x22, 0x4D, 0x18, 0x60, 0x40, 0x00, .. BitConverter.GetBytes((uint)data.Length | 0x80000000u), .. data, 0, 0, 0, 0];

    private static uint Crc32(ReadOnlySpan<byte> data)
    {
        uint crc = ~0u;
        foreach (var x in data)
        {
            crc ^= x;
            for (int i = 0; i < 8; i++) crc = (crc >> 1) ^ (0xEDB88320u & (uint)-(int)(crc & 1));
        }
        return ~crc;
    }

    private static byte[] Le(uint v) => BitConverter.GetBytes(v);

    // An xz stream of one block holding one stored LZMA2 chunk, checked with CRC32.
    private static byte[] Xz(byte[] data)
    {
        byte[] flags = [0, 1];
        byte[] blockHeader = [0x02, 0x00, 0x21, 0x01, 0x16, 0, 0, 0];
        byte[] lzma2 = [0x01, (byte)((data.Length - 1) >> 8), (byte)(data.Length - 1), .. data, 0x00];
        var block = new List<byte>([.. blockHeader, .. Le(Crc32(blockHeader)), .. lzma2]);
        int unpadded = block.Count + 4;
        while (block.Count % 4 != 0) block.Add(0);
        block.AddRange(Le(Crc32(data)));
        byte[] index = [0x00, 0x01, (byte)unpadded, (byte)data.Length];
        index = [.. index, .. Le(Crc32(index))];
        byte[] backward = Le((uint)(index.Length / 4 - 1));
        return [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00, .. flags, .. Le(Crc32(flags)), .. block, .. index, .. Le(Crc32([.. backward, .. flags])), .. backward, .. flags, 0x59, 0x5A];
    }

    private static ModelRisk.Result Scan(string path, byte[] bytes) => ModelRisk.Scan(path, bytes);

    [Fact]
    public void A_pickle_importing_os_system_is_code_and_one_calling_print_is_other()
    {
        Assert.Equal(["os.system"], Scan("m.pkl", Call("os", "system")).Code);
        var print = Scan("m.pkl", Call("builtins", "print"));
        Assert.Empty(print.Code);
        Assert.Equal(["builtins.print"], print.Other);
    }

    [Fact]
    public void A_pickle_importing_importlib_is_code()
    {
        Assert.Equal(["importlib.import_module"], Scan("m.pkl", Call("importlib", "import_module")).Code);
    }

    [Fact]
    public void Plain_weights_report_nothing()
    {
        var r = Scan("m.pt", ModelSamples.TorchZip());
        Assert.Empty(r.Code);
        Assert.Empty(r.Other);
        Assert.Empty(r.Hits);
        Assert.Null(r.NotRead);
    }

    [Fact]
    public void An_npy_object_array_is_review_and_its_pickle_is_read()
    {
        var r = Scan("a.npy", Npy("'|O'", Call("os", "system")));
        Assert.Equal(["os.system"], r.Code);
        Assert.Equal("review", Assert.Single(r.Hits).Level);
    }

    [Fact]
    public void An_npy_number_array_reports_nothing()
    {
        var r = Scan("a.npy", Npy("'<f4'", new byte[4]));
        Assert.Empty(r.Code);
        Assert.Empty(r.Other);
        Assert.Empty(r.Hits);
    }

    [Fact]
    public void An_npz_object_array_is_read_inside_its_zip()
    {
        var r = Scan("a.npz", ContainerFixtures.Zip(("arr_0.npy", Npy("'|O'", Call("subprocess", "call")))));
        Assert.Equal(["subprocess.call"], r.Code);
    }

    [Fact]
    public void A_joblib_array_record_names_nothing_outside_its_structure()
    {
        var p = new ModelSamples.Pickle().Proto(2).Global("joblib.numpy_pickle", "NumpyArrayWrapper").Global("numpy", "dtype").Op('.').ToArray();
        var r = Scan("m.joblib", p);
        Assert.Empty(r.Code);
        Assert.Empty(r.Other);
    }

    [Theory]
    [InlineData("zlib")]
    [InlineData("lz4")]
    [InlineData("xz")]
    public void A_compressed_joblib_pickle_is_read_through_its_codec(string codec)
    {
        var raw = Call("os", "system");
        var packed = codec switch { "zlib" => Zlib(raw), "lz4" => Lz4(raw), _ => Xz(raw) };
        var r = Scan("m.joblib", packed);
        Assert.Equal(["os.system"], r.Code);
        Assert.Null(r.NotRead);
    }

    [Fact]
    public void A_keras_lambda_layer_is_noteworthy_and_a_custom_layer_is_review()
    {
        Assert.Equal("noteworthy", Assert.Single(Scan("m.keras", Keras("Lambda")).Hits).Level);
        Assert.Equal("review", Assert.Single(Scan("m.keras", Keras("Mixer", "my_pkg.layers")).Hits).Level);
    }

    [Fact]
    public void A_keras_model_of_built_in_layers_reports_nothing()
    {
        Assert.Empty(Scan("m.keras", Keras("Dense")).Hits);
    }

    [Fact]
    public void An_hdf5_model_is_named_as_not_read()
    {
        Assert.Equal("HDF5 not read", Scan("m.h5", Hdf5Magic).NotRead);
    }

    private static byte[] ChatTemplate(string template) =>
        ModelSamples.Gguf(w => { w.Key("tokenizer.chat_template", 8); w.String(template); }, 1, []);

    [Fact]
    public void A_chat_template_walking_class_attributes_is_noteworthy()
    {
        var hit = Assert.Single(Scan("m.gguf", ChatTemplate("{{ ''.__class__.__mro__[1].__subclasses__() }}")).Hits);
        Assert.Equal("noteworthy", hit.Level);
        Assert.Contains("__class__", hit.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void A_chat_template_past_the_metadata_clip_is_still_checked()
    {
        var template = new string(' ', 2000) + "{{ x.__globals__ }}";
        Assert.Single(Scan("m.gguf", ChatTemplate(template)).Hits);
    }

    [Fact]
    public void A_chat_template_over_one_mebibyte_is_named_as_not_read()
    {
        var r = Scan("m.gguf", ChatTemplate(new string(' ', (1 << 20) + 1)));
        Assert.Contains("chat_template", r.NotRead, StringComparison.Ordinal);
    }

    [Fact]
    public void A_plain_chat_template_reports_nothing()
    {
        Assert.Empty(Scan("m.gguf", ChatTemplate("{% for m in messages %}{{ m.role }}: {{ m.content }}{% endfor %}")).Hits);
    }

    [Theory]
    [InlineData("../w.bin", true)]
    [InlineData("data/../../w.bin", true)]
    [InlineData("/etc/w.bin", true)]
    [InlineData("C:\\w.bin", true)]
    [InlineData("w.bin", false)]
    [InlineData("data/w.bin", false)]
    public void An_onnx_data_path_that_leaves_the_folder_is_noteworthy(string location, bool noteworthy)
    {
        var hits = Scan("m.onnx", ModelSamples.Onnx(location)).Hits;
        Assert.Equal(noteworthy, hits.Any(h => h.Level == "noteworthy"));
    }

    private PackageReport Review(params (string Path, byte[] Data)[] files)
    {
        var path = _dir.File("tool-1.0-py3-none-any.whl");
        File.WriteAllBytes(path, ContainerFixtures.Zip(
            [("tool-1.0.dist-info/METADATA", "Metadata-Version: 2.1\nName: tool\nVersion: 1.0\n"u8.ToArray()), ("tool/__init__.py", []), .. files]));
        return PackageReview.Review(path, default) ?? throw new InvalidOperationException("not a package");
    }

    [Fact]
    public void A_wheel_pickle_calling_print_is_review_and_one_importing_os_system_is_noteworthy()
    {
        var print = Review(("tool/m.pkl", Call("builtins", "print"))).Findings.Single(f => f.Rule == "package/pickle-code");
        Assert.Equal("review", print.Level);
        var system = Review(("tool/m.pkl", Call("os", "system"))).Findings.Single(f => f.Rule == "package/pickle-code");
        Assert.Equal("noteworthy", system.Level);
    }

    [Fact]
    public void A_wheel_keras_lambda_is_a_noteworthy_model_finding_and_plain_weights_are_not()
    {
        var f = Review(("tool/m.keras", Keras("Lambda"))).Findings.Single(f => f.Rule == "package/model-code");
        Assert.Equal(("noteworthy", "tool/m.keras"), (f.Level, f.Path));
        var plain = Review(("tool/m.pt", ModelSamples.TorchZip()), ("tool/d.keras", Keras("Dense")), ("tool/a.npy", Npy("'<f4'", new byte[4]))).Findings;
        Assert.DoesNotContain(plain, x => x.Rule is "package/pickle-code" or "package/model-code");
    }

    [Fact]
    public void A_wheel_joblib_that_is_cut_short_is_named_in_the_notes()
    {
        var r = Review(("tool/m.joblib", [0x04, 0x22, 0x4D, 0x18, 0x60]));
        Assert.Contains(r.Notes, n => n.StartsWith("tool/m.joblib:", StringComparison.Ordinal) && n.EndsWith("not checked", StringComparison.Ordinal));
    }
}
