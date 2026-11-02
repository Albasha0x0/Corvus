using Corvus.Core;
using Corvus.Native.Pe;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>An embedded CPython runtime is reported by summarize_file and summarize_build from the interpreter section and the Py* exports.</summary>
public sealed class EmbeddedPythonTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static byte[] Image(string? section, int exports)
    {
        var sorted = Enumerable.Range(0, exports).Select(i => $"PyEval_Call{i:D3}").OrderBy(n => n, StringComparer.Ordinal).ToArray();
        var b = new PeBuilder();
        b.Add(".text", new byte[0x40], 0x60000020);
        if (section != null) b.Add(section, new byte[0x40]);
        if (exports > 0)
        {
            uint dir = 0, size = 0;
            b.Add(".edata", rva =>
            {
                var blob = new PeBlob(rva);
                dir = blob.Zero(40);
                uint dll = blob.Ascii("app.exe");
                blob.Align(4);
                uint eat = blob.Here;
                foreach (var _ in sorted) blob.U32(0x1000);
                var nameRvas = sorted.Select(n => blob.Ascii(n)).ToArray();
                blob.Align(4);
                uint names = blob.Here;
                foreach (var n in nameRvas) blob.U32(n);
                uint ordinals = blob.Here;
                for (int i = 0; i < sorted.Length; i++) blob.U16((ushort)i);
                blob.Patch32(dir + 12, dll);
                blob.Patch32(dir + 16, 1);
                blob.Patch32(dir + 20, (uint)sorted.Length);
                blob.Patch32(dir + 24, (uint)sorted.Length);
                blob.Patch32(dir + 28, eat);
                blob.Patch32(dir + 32, names);
                blob.Patch32(dir + 36, ordinals);
                size = blob.Here - dir;
                return blob.ToArray();
            });
            b.Directories[PeDirectory.Export] = (dir, size);
        }
        return b.Build();
    }

    private static NativeFileView.Facts? Facts(byte[] file) =>
        new NativeFileView().Inspect(new FileInput("app.exe", file, Blob.Identify(file)) { Options = new FileViewOptions("native") }, default)?.Detail as NativeFileView.Facts;

    [Fact]
    public void An_interpreter_section_with_python_exports_is_reported_as_an_embedded_runtime()
    {
        var facts = Facts(Image("PyRuntim", 60));
        Assert.Equal("PyRuntim", facts?.Python?.Section);
        Assert.Equal(60, facts?.Python?.Exports);
    }

    [Fact]
    public void Python_exports_alone_are_enough_when_there_are_many()
    {
        Assert.NotNull(Facts(Image(null, 60))?.Python);
        Assert.Null(Facts(Image(null, 3))?.Python);
    }

    [Fact]
    public void An_image_without_the_section_or_exports_has_no_runtime_fact()
    {
        Assert.Null(Facts(Image(null, 0))?.Python);
    }

    [Fact]
    public void A_folder_with_such_an_executable_and_NXPK_archives_is_summarized_as_a_build()
    {
        var folder = Path.Combine(_dir.Path, "App");
        Directory.CreateDirectory(Path.Combine(folder, "res"));
        File.WriteAllBytes(Path.Combine(folder, "App.exe"), Image("PyRuntim", 60));
        File.WriteAllBytes(Path.Combine(folder, "res", "a.pack"), [.. "NXPK"u8, 1, 0, 0, 0]);
        File.WriteAllBytes(Path.Combine(folder, "res", "b.pack"), [.. "NXPK"u8, 2, 0, 0, 0]);
        File.WriteAllBytes(Path.Combine(folder, "res", "c.bin"), [1, 2, 3, 4, 5]);
        File.WriteAllBytes(Path.Combine(folder, "state.data"), [9, 8, 7, 6, 5, 4]);
        var report = BuildSummary.Inspect(folder, false, default);
        Assert.Contains(report.Markers, m => m.Category == "framework" && m.Name == "embedded CPython runtime" && m.Evidence.Contains("PyRuntim"));
        var archives = Assert.Single(report.Markers, m => m.Name == "NXPK archives");
        Assert.Contains("2 file(s)", archives.Evidence);
        Assert.DoesNotContain("c.bin", archives.Evidence);
    }

    [Fact]
    public void An_XML_file_beside_the_executable_is_named_by_its_format()
    {
        var folder = Path.Combine(_dir.Path, "Cfg");
        Directory.CreateDirectory(folder);
        File.WriteAllBytes(Path.Combine(folder, "App.exe"), Image("PyRuntim", 0));
        File.WriteAllBytes(Path.Combine(folder, "a.xml"), [0xC1, 0x59, 0x41, 0x0D, 0, 0, 0, 0, 1, 2]);
        var encoded = Assert.Single(BuildSummary.Inspect(folder, false, default).Markers, m => m.Name == "engine config XML");
        Assert.Equal("a.xml: encoded XML with a string table", encoded.Evidence);
        File.WriteAllText(Path.Combine(folder, "a.xml"), "<?xml version=\"1.0\"?><root/>");
        Assert.Equal("a.xml: text XML", Assert.Single(BuildSummary.Inspect(folder, false, default).Markers, m => m.Name == "engine config XML").Evidence);
    }

    [Fact]
    public void Exports_without_the_section_are_worded_as_a_runtime_not_an_embedded_one()
    {
        var python = EmbeddedPython.Of(Image(null, 60));
        Assert.StartsWith("CPython runtime exports:", python?.Describe());
        Assert.StartsWith("Embedded CPython runtime:", EmbeddedPython.Of(Image("PyRuntim", 0))?.Describe());
    }

    [Fact]
    public void A_truncated_or_invalid_image_has_no_runtime_fact()
    {
        var image = Image("PyRuntim", 60);
        Assert.Null(EmbeddedPython.Of(image[..0x50]));
        Assert.Null(EmbeddedPython.Of([1, 2, 3, 4]));
        Assert.Null(EmbeddedPython.Of(new byte[0x200]));
    }

    [Fact]
    public void A_folder_without_an_engine_or_runtime_is_still_not_a_build()
    {
        var folder = Path.Combine(_dir.Path, "Plain");
        Directory.CreateDirectory(folder);
        File.WriteAllBytes(Path.Combine(folder, "App.exe"), Image(null, 0));
        Assert.Throws<ToolError>(() => BuildSummary.Inspect(folder, false, default));
    }
}