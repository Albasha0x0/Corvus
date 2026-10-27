using System.IO.Compression;
using System.Text;
using Corvus.Core;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>WebGL player data files (plain, gzip, Brotli) built at test time, with the Build folder around them.</summary>
public sealed class WebPlayerDataTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly AssemblyWorkspace _workspace = new(new ServerOptions());

    public void Dispose()
    {
        _workspace.Dispose();
        _dir.Dispose();
    }

    private static readonly byte[] Metadata = [0xAF, 0x1B, 0xB1, 0xFA, 29, 0, 0, 0, 1, 2, 3, 4];

    /// <summary>"UnityWebData1.0\0", header size, then offset, size, name length and name per file; data after the header.</summary>
    public static byte[] Build(params (string Name, byte[] Bytes)[] files)
    {
        var magic = Encoding.ASCII.GetBytes("UnityWebData1.0\0");
        int header = magic.Length + 4 + files.Sum(f => 12 + Encoding.UTF8.GetByteCount(f.Name));
        using var ms = new MemoryStream();
        var w = new BinaryWriter(ms);
        w.Write(magic);
        w.Write((uint)header);
        uint offset = (uint)header;
        foreach (var (name, bytes) in files)
        {
            w.Write(offset);
            w.Write((uint)bytes.Length);
            w.Write((uint)Encoding.UTF8.GetByteCount(name));
            w.Write(Encoding.UTF8.GetBytes(name));
            offset += (uint)bytes.Length;
        }
        foreach (var (_, bytes) in files) w.Write(bytes);
        return ms.ToArray();
    }

    private static byte[] Sample() => Build(
        ("data.unity3d", Encoding.ASCII.GetBytes("UnityFS\0\0\0\0\u00075.x.x\u00002021.3.5f1\0rest")),
        ("Il2CppData/Metadata/global-metadata.dat", Metadata),
        ("Resources/unity_builtin_extra", new byte[32]),
        ("../evil.txt", "x"u8.ToArray()));

    private string BuildFolder(string dataName, byte[] data)
    {
        var build = Directory.CreateDirectory(_dir.File("Build")).FullName;
        File.WriteAllBytes(Path.Combine(build, "app.wasm.br"), [0]);
        File.WriteAllBytes(Path.Combine(build, "app.framework.js.br"), [0]);
        File.WriteAllText(Path.Combine(build, "app.loader.js"), "");
        var path = Path.Combine(build, dataName);
        File.WriteAllBytes(path, data);
        return path;
    }

    [Theory]
    [InlineData("app.data", null)]
    [InlineData("app.data.gz", "gzip")]
    [InlineData("app.data.br", "Brotli")]
    public void Lists_files_with_roles_and_the_build_folder(string name, string? compression)
    {
        var data = Sample();
        if (compression == "gzip") data = Compress(data, s => new GZipStream(s, CompressionLevel.Fastest));
        if (compression == "Brotli") data = Compress(data, s => new BrotliStream(s, CompressionLevel.Fastest));
        var listing = new UnpackService(_workspace).List(BuildFolder(name, data), AnalysisLimits.Default, default);
        Assert.Equal(WebPlayerData.Kind, listing.Container);
        Assert.Equal(
        [
            "data.unity3d: asset bundle (UnityFS)", "Il2CppData/Metadata/global-metadata.dat: AOT metadata v29",
            "Resources/unity_builtin_extra: serialized asset file", "../evil.txt: text, unsafe name",
        ], listing.Files!.Select(f => $"{f.Path}: {f.Detail}"));
        Assert.Equal($"WebGL data{(compression != null ? $" ({compression} compressed)" : "")}: 4 file(s), engine 2021.3.5f1; AOT metadata " +
                     "Il2CppData/Metadata/global-metadata.dat (AOT metadata v29).", listing.Notes[0]);
        Assert.Equal("Build folder: app.framework.js.br (the JavaScript framework: Emscripten runtime and imports); app.loader.js (the loader); " +
                     "app.wasm.br (the AOT code, WebAssembly).", listing.Notes[1]);
    }

    [Fact]
    public void Unpacks_every_file_but_unsafe_names()
    {
        var path = BuildFolder("app.data", Sample());
        var output = _dir.File("out");
        var report = new UnpackService(_workspace).Unpack(path, output, load: false, AnalysisLimits.Default, default);
        Assert.Equal(Metadata, File.ReadAllBytes(Path.Combine(output, "Il2CppData", "Metadata", "global-metadata.dat")));
        Assert.Equal(3, report.Files.Count);
        Assert.Contains(report.Notes, n => n.Contains("1 entr(ies) with unsafe names not extracted", StringComparison.Ordinal));
        Assert.False(File.Exists(_dir.File("evil.txt")));
    }

    [Fact]
    public void Corrupt_headers_are_reported()
    {
        var data = Sample();
        BitConverter.GetBytes(0xFFFFFFF0u).CopyTo(data, 16);
        Assert.Equal(ErrorCode.MalformedInput, Assert.Throws<ToolError>(() => Containers.Open(data, "x.data", AnalysisLimits.Default, default)).Code);
        var outside = Sample();
        // First entry's offset.
        BitConverter.GetBytes(0x7FFFFFF0u).CopyTo(outside, 20);
        var contents = Containers.Open(outside, "x.data", AnalysisLimits.Default, default);
        Assert.Equal("out of range", contents.Entries![0].Detail);
    }

    private static byte[] Compress(byte[] data, Func<Stream, Stream> wrap)
    {
        var ms = new MemoryStream();
        using (var z = wrap(ms)) z.Write(data);
        return ms.ToArray();
    }
}
