using System.IO.Compression;
using System.Text;
using Corvus.Core;
using Corvus.Core.Python;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>Bytecode modules built at test time that hold further code objects as encoded constants.</summary>
public sealed class PythonLayerTests
{
    private static readonly (int, int) V312 = (3, 12);

    private static byte[] Zlib(byte[] data)
    {
        using var ms = new MemoryStream();
        using (var z = new ZLibStream(ms, CompressionLevel.Optimal, leaveOpen: true)) z.Write(data);
        return ms.ToArray();
    }

    private static byte[] Pyc(byte[] marshalled) => PyVersion.WithHeader(PyVersion.MagicOf(V312)!, V312, marshalled);

    // The outer module holds base64(zlib(marshal)) of a module that holds zlib(marshal) of a third.
    private static byte[] Nested()
    {
        var innermost = FrozenPythonTests.Code("stage3.py", "done");
        var middle = FrozenPythonTests.Code("stage2.py", new PyBytes(Zlib(innermost)));
        var outer = FrozenPythonTests.Code("stage1.py", Convert.ToBase64String(Zlib(middle)), "plain constant of text that decodes to nothing");
        return Pyc(outer);
    }

    [Fact]
    public void A_module_holding_encoded_code_lists_each_layer_with_its_encodings()
    {
        var bytes = Nested();
        var view = new PythonFileView().Inspect(new FileInput("stage1.pyc", bytes, Blob.Identify(bytes)), default)!;
        var facts = Assert.IsType<PythonFileView.Bytecode>(view.Detail);
        Assert.Equal(["stage2.py", "stage3.py"], facts.Layers!.Select(l => l.Filename));
        Assert.Equal(["base64 > zlib > marshal", "zlib > marshal"], facts.Layers!.Select(l => l.Encodings));
        Assert.Equal([1, 2], facts.Layers!.Select(l => l.Depth));
        Assert.Contains("2 encoded layers", view.Highlights[0]);
    }

    [Fact]
    public void Each_layer_extracts_as_a_pyc_with_the_header_restored()
    {
        var c = Containers.Open(Nested(), "stage1.pyc", AnalysisLimits.Default, default);
        Assert.Equal("Python bytecode", c.Kind);
        Assert.Equal(["layer1.pyc", "layer2.pyc"], c.Items.Select(i => i.Name));
        var first = c.Items[0].Bytes;
        Assert.True(PyVersion.LooksLikePyc(first));
        Assert.Equal("stage2.py", ((PyCode)PyMarshal.Read(first, V312, PyVersion.HeaderLength(V312))).Filename);
        // The extracted layer is itself a module that holds a layer.
        Assert.Equal("stage3.py", Assert.IsType<PythonFileView.Bytecode>(new PythonFileView().Inspect(new FileInput("layer1.pyc", first, Blob.Identify(first)), default)!.Detail).Layers![0].Filename);
    }

    [Fact]
    [FuzzEntry(typeof(PyLayers))]
    public void Fuzzed_layered_modules_never_throw_past_a_tool_error()
    {
        var failures = FormatFuzz.Run(Nested(), b => PyLayers.Open(b, default), 400);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(10)));
    }

    [Fact]
    public void A_module_without_encoded_code_is_not_a_container()
    {
        var bytes = Pyc(FrozenPythonTests.Code("plain.py", "text that is only text, long enough to be tried"));
        var c = Containers.Open(bytes, "plain.pyc", AnalysisLimits.Default, default);
        Assert.Equal("none", c.Kind);
        Assert.Null(Assert.IsType<PythonFileView.Bytecode>(new PythonFileView().Inspect(new FileInput("plain.pyc", bytes, Blob.Identify(bytes)), default)!.Detail).Layers);
    }

    [Fact]
    public void A_whole_pyc_held_as_a_constant_is_a_layer()
    {
        var inner = Pyc(FrozenPythonTests.Code("inner.py", "x"));
        var bytes = Pyc(FrozenPythonTests.Code("outer.py", new PyBytes(Zlib(inner))));
        var layers = PyLayers.Find((PyCode)PyMarshal.Read(bytes, V312, 16), V312, 1 << 20, default);
        Assert.Equal(("zlib > pyc", "inner.py"), (layers.Single().Encodings, layers.Single().Filename));
    }

    private static List<PyLayer> Layers(byte[] module, long maxBytes = 1 << 20) =>
        PyLayers.Find((PyCode)PyMarshal.Read(Pyc(module), V312, PyVersion.HeaderLength(V312)), V312, maxBytes, default);

    [Fact]
    public void At_most_64_layers_are_listed()
    {
        var consts = Enumerable.Range(0, 80).Select(i => (object)new PyBytes(Zlib(FrozenPythonTests.Code($"m{i}.py", $"constant number {i}")))).ToArray();
        Assert.Equal(64, Layers(FrozenPythonTests.Code("many.py", consts)).Count);
    }

    [Fact]
    public void Layers_nested_past_16_levels_are_not_followed()
    {
        var code = FrozenPythonTests.Code("level0.py", "end");
        for (int i = 1; i <= 20; i++) code = FrozenPythonTests.Code($"level{i}.py", new PyBytes(Zlib(code)));
        var layers = Layers(code);
        Assert.Equal(Enumerable.Range(1, 16), layers.Select(l => l.Depth));
    }

    [Fact]
    public void A_corrupt_zlib_stream_and_broken_base64_give_no_layer()
    {
        var good = Zlib(FrozenPythonTests.Code("inner.py", "x"));
        var torn = good[..(good.Length / 2)];
        var bytes = FrozenPythonTests.Code("outer.py", new PyBytes(torn), "AAAA" + new string('A', 30) + "=!", new string('\u0080', 40));
        Assert.Empty(Layers(bytes));
    }

    [Fact]
    public void A_stream_inflating_past_the_size_limit_is_not_a_layer()
    {
        var bomb = Zlib(new byte[200_000]);
        var bytes = FrozenPythonTests.Code("outer.py", new PyBytes(bomb));
        Assert.Empty(Layers(bytes, maxBytes: 64 * 1024));
    }

    [Fact]
    public void The_decoded_size_of_all_layers_together_is_bounded()
    {
        var one = FrozenPythonTests.Code("m.py", new string('a', 3000));
        var bytes = FrozenPythonTests.Code("outer.py", new PyBytes(Zlib(one)), new PyBytes(Zlib(one)), new PyBytes(Zlib(one)));
        Assert.Equal(2, Layers(bytes, maxBytes: one.Length * 2 + 10).Count);
    }

    [Fact]
    public void A_program_appended_archive_is_peeled_to_the_code_its_module_holds()
    {
        var inner = FrozenPythonTests.Code("payload.py", "done");
        var app = FrozenPythonTests.Code("app.py", Convert.ToBase64String(Zlib(inner)));
        var exe = FrozenPythonTests.Launcher("_MEIPASS", FrozenPythonTests.CArchive(
            ("pyiboot01_bootstrap", 's', FrozenPythonTests.Code("pyiboot01_bootstrap.py"), true),
            ("app", 's', app, true),
            ("python312.dll", 'b', [(byte)'M', (byte)'Z', 0, 0], true)));
        var program = Containers.Open(exe, "app.exe", AnalysisLimits.Default, default, allFiles: true);
        var module = program.Items.Single(i => i.Name == "app.pyc").Bytes;
        var layer = Containers.Open(module, "app.pyc", AnalysisLimits.Default, default);
        Assert.StartsWith("base64 > zlib > marshal in ", layer.Items.Single().Origin);
        Assert.Equal(inner, layer.Items.Single().Bytes[16..]);
    }
}
