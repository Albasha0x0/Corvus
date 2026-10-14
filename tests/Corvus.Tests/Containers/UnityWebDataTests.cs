using System.IO.Compression;
using System.Text;
using Corvus.Core;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>Unity WebGL data files (plain, gzip, Brotli) built at test time, with the Build folder around them.</summary>
public sealed class UnityWebDataTests : IDisposable
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
        File.WriteAllBytes(Path.Combine(build, "game.wasm.br"), [0]);
        File.WriteAllBytes(Path.Combine(build, "game.framework.js.br"), [0]);
        File.WriteAllText(Path.Combine(build, "game.loader.js"), "");
        var path = Path.Combine(build, dataName);
        File.WriteAllBytes(path, data);
        return path;
    }

    [Theory]
    [InlineData("game.data", null)]
    [InlineData("game.data.gz", "gzip")]
    [InlineData("game.data.br", "Brotli")]
    public void ListsFilesWithRolesAndTheBuildFolder(string name, string? compression)
    {
        var data = Sample();
        if (compression == "gzip") data = Compress(data, s => new GZipStream(s, CompressionLevel.Fastest));
        if (compression == "Brotli") data = Compress(data, s => new BrotliStream(s, CompressionLevel.Fastest));
        var listing = new UnpackService(_workspace).List(BuildFolder(name, data), AnalysisLimits.Default, default);
        Assert.Equal(UnityWebData.Kind, listing.Container);
        Assert.Equal(
        [
            "data.unity3d: Unity asset bundle (UnityFS)", "Il2CppData/Metadata/global-metadata.dat: Il2Cpp metadata v29",
            "Resources/unity_builtin_extra: Unity serialized file", "../evil.txt: text, unsafe name",
        ], listing.Files!.Select(f => $"{f.Path}: {f.Detail}"));
        Assert.Equal($"UnityWebData{(compression != null ? $" ({compression} compressed)" : "")}: 4 file(s), Unity 2021.3.5f1; Il2Cpp metadata " +
                     "Il2CppData/Metadata/global-metadata.dat (Il2Cpp metadata v29).", listing.Notes[0]);
        Assert.Equal("Build folder: game.framework.js.br (the JavaScript framework: Emscripten runtime and imports); game.loader.js (the loader); " +
                     "game.wasm.br (the Il2Cpp code, WebAssembly).", listing.Notes[1]);
    }

    [Fact]
    public void UnpacksEveryFileButUnsafeNames()
    {
        var path = BuildFolder("game.data", Sample());
        var output = _dir.File("out");
        var report = new UnpackService(_workspace).Unpack(path, output, load: false, AnalysisLimits.Default, default);
        Assert.Equal(Metadata, File.ReadAllBytes(Path.Combine(output, "Il2CppData", "Metadata", "global-metadata.dat")));
        Assert.Equal(3, report.Files.Count);
        Assert.Contains(report.Notes, n => n.Contains("1 entr(ies) with unsafe names not extracted", StringComparison.Ordinal));
        Assert.False(File.Exists(_dir.File("evil.txt")));
    }

    [Fact]
    public void CorruptHeadersAreReported()
    {
        var data = Sample();
        BitConverter.GetBytes(0xFFFFFFF0u).CopyTo(data, 16);
        Assert.Equal(ErrorCode.MalformedInput, Assert.Throws<ToolError>(() => Containers.Open(data, "x.data", AnalysisLimits.Default, default)).Code);
        var outside = Sample();
        BitConverter.GetBytes(0x7FFFFFF0u).CopyTo(outside, 20); // first entry's offset
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
