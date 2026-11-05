using System.Text;
using System.Text.Json;
using Corvus.Core;
using Corvus.Services;
using Corvus.Services.Analysis;
using Corvus.Tests.NativeFormats;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>The SBOM of a native image lists the libraries its code names by version string.</summary>
[Collection(ProcessEnvironmentCollection.Name)]
public sealed class NativeSbomTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly AssemblyWorkspace _workspace = new(new ServerOptions());

    public void Dispose()
    {
        _workspace.Dispose();
        _dir.Dispose();
    }

    private static byte[] Image(params string[] strings) => new ElfWriter
    {
        Machine = ElfWriter.EmX64, Is64 = true, Type = 2, Base = 0x400000, Entry = ElfWriter.TextRva, Text = [0xC3],
        Hash = ElfWriter.HashKind.None, DataSectionName = ".rodata",
        Data = Encoding.ASCII.GetBytes(string.Join('\0', strings) + "\0"),
    }.Build();

    private async Task<JsonElement> Sbom(byte[] image)
    {
        var path = _dir.File("lib.so");
        File.WriteAllBytes(path, image);
        var sbom = _dir.File("lib.cdx.json");
        var tools = new InspectionTools(new InspectionService(_workspace), _workspace);
        await tools.SummarizeFile(path: path, view: "dependencies", sbomPath: sbom);
        var bytes = File.ReadAllBytes(sbom);
        DependencyInventoryTests.AssertValid(bytes);
        return JsonDocument.Parse(bytes).RootElement.GetProperty("components").Clone();
    }

    [Fact]
    public async Task A_version_string_in_a_native_image_becomes_a_component_with_evidence()
    {
        var components = await Sbom(Image("OpenSSL 3.0.13  30 Jan 2024", "inflate 1.2.13 Copyright 1995-2022 Mark Adler"));
        var tls = components.EnumerateArray().Single(c => c.GetProperty("name").GetString() == "OpenSSL");
        Assert.Equal("3.0.13", tls.GetProperty("version").GetString());
        var method = tls.GetProperty("evidence").GetProperty("identity")[0].GetProperty("methods")[0];
        Assert.Equal("binary-analysis", method.GetProperty("technique").GetString());
        Assert.Contains("OpenSSL 3.0.13", method.GetProperty("value").GetString());
        Assert.Contains(components.EnumerateArray(), c => c.GetProperty("name").GetString() == "zlib" && c.GetProperty("version").GetString() == "1.2.13");
    }

    [Fact]
    public async Task A_version_string_with_no_digits_after_the_dot_names_the_library_without_a_version()
    {
        var components = await Sbom(Image("wolfSSL 5.x build"));
        var lib = components.EnumerateArray().Single(c => c.GetProperty("name").GetString() == "wolfSSL");
        Assert.False(lib.TryGetProperty("version", out _));
    }
}
