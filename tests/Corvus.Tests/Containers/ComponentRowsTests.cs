using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Corvus.Core;
using Corvus.Services;
using Corvus.Services.Analysis;
using Corvus.Services.Analysis.Dependencies;
using Corvus.Tests.NativeFormats;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>componentsPath writes the compiled-in components of an image as JSON lines for a custom table.</summary>
[Collection(ProcessEnvironmentCollection.Name)]
public sealed class ComponentRowsTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly AssemblyWorkspace _workspace = new(new ServerOptions());
    private readonly EnvironmentScope _env = new EnvironmentScope().Set(OsvAdvisories.DatabaseVariable, null);

    public void Dispose()
    {
        _env.Dispose();
        _workspace.Dispose();
        _dir.Dispose();
    }

    private static byte[] Image(params string[] strings) => new ElfWriter
    {
        Machine = ElfWriter.EmX64, Is64 = true, Type = 2, Base = 0x400000, Entry = ElfWriter.TextRva, Text = [0xC3],
        Hash = ElfWriter.HashKind.None, DataSectionName = ".rodata",
        Data = Encoding.ASCII.GetBytes(string.Join('\0', strings) + "\0"),
    }.Build();

    private static byte[] GoProgram() => new ElfWriter
    {
        Machine = ElfWriter.EmX64, Is64 = true, Type = 2, Base = 0x400000, Entry = ElfWriter.TextRva, Text = [0xC3],
        Hash = ElfWriter.HashKind.None, DataSectionName = ".go.buildinfo", Data = GoBuildInfoTests.Inline(),
    }.Build();

    private async Task<List<JsonElement>> Rows(string path, string name = "rows.jsonl")
    {
        var output = _dir.File(name);
        var tools = new InspectionTools(new InspectionService(_workspace), _workspace);
        await tools.SummarizeFile(path: path, componentsPath: output);
        return [.. File.ReadAllLines(output).Select(l => JsonDocument.Parse(l).RootElement.Clone())];
    }

    private string Write(string name, byte[] bytes)
    {
        var path = _dir.File(name);
        File.WriteAllBytes(path, bytes);
        return path;
    }

    [Fact]
    public async Task An_embedded_zlib_and_OpenSSL_version_string_become_rows_with_CPE_names_and_image_hashes()
    {
        var bytes = Image("OpenSSL 3.0.13  30 Jan 2024", "inflate 1.2.13 Copyright 1995-2022 Mark Adler");
        var rows = await Rows(Write("tool.so", bytes));
        var tls = rows.Single(r => r.GetProperty("Component").GetString() == "OpenSSL");
        Assert.Equal("3.0.13", tls.GetProperty("Version").GetString());
        Assert.Equal("cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*", tls.GetProperty("Cpe").GetString());
        Assert.Equal(Convert.ToHexStringLower(SHA1.HashData(bytes)), tls.GetProperty("ImageSHA1").GetString());
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(bytes)), tls.GetProperty("ImageSHA256").GetString());
        Assert.Equal("tool.so", tls.GetProperty("ImageName").GetString());
        var zlib = rows.Single(r => r.GetProperty("Component").GetString() == "zlib");
        Assert.Equal(("1.2.13", "cpe:2.3:a:zlib:zlib:1.2.13:*:*:*:*:*:*:*"), (zlib.GetProperty("Version").GetString(), zlib.GetProperty("Cpe").GetString()));
    }

    [Fact]
    public async Task A_native_component_no_advisory_source_covers_is_unknown_with_its_reason()
    {
        var rows = await Rows(Write("tool.so", Image("OpenSSL 3.0.13  30 Jan 2024")));
        var row = Assert.Single(rows);
        Assert.StartsWith("unknown: ", row.GetProperty("AdvisoryState").GetString());
        Assert.Contains("C libraries", row.GetProperty("AdvisoryState").GetString());
        Assert.Empty(row.GetProperty("Advisories").EnumerateArray());
    }

    [Fact]
    public async Task A_Go_module_row_keeps_its_purl_and_the_matched_advisory_id()
    {
        using var db = new TempDir();
        Directory.CreateDirectory(Path.Combine(db.Path, "Go"));
        File.WriteAllText(Path.Combine(db.Path, "Go", "GO-1.json"),
            """{"id":"GO-1","aliases":["CVE-2024-0001"],"summary":"s","affected":[{"package":{"ecosystem":"Go","name":"golang.org/x/sys"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"0.21.0"}]}]}]}""");
        using var scope = new EnvironmentScope().Set(OsvAdvisories.DatabaseVariable, db.Path);
        var rows = await Rows(Write("tool", GoProgram()));
        var sys = rows.Single(r => r.GetProperty("Component").GetString() == "golang.org/x/sys");
        Assert.Equal("pkg:golang/golang.org/x/sys@v0.20.0", sys.GetProperty("Purl").GetString());
        Assert.Equal("matched", sys.GetProperty("AdvisoryState").GetString());
        Assert.Equal(["GO-1", "CVE-2024-0001"], sys.GetProperty("Advisories").EnumerateArray().Select(a => a.GetString()));
        Assert.Equal("none", rows.Single(r => r.GetProperty("Component").GetString() == "stdlib").GetProperty("AdvisoryState").GetString());
    }

    [Fact]
    public async Task Every_line_holds_the_declared_columns_and_nothing_else()
    {
        var rows = await Rows(Write("tool.so", Image("OpenSSL 3.0.13", "wolfSSL 5.6.0", "inflate 1.2.13")));
        Assert.Equal(3, rows.Count);
        var declared = ComponentRows.Columns.Select(c => c.Name).ToArray();
        foreach (var row in rows)
        {
            Assert.Equal(declared, row.EnumerateObject().Select(p => p.Name));
            Assert.True(DateTimeOffset.TryParse(row.GetProperty("TimeGenerated").GetString(), out _));
            Assert.Equal(JsonValueKind.Array, row.GetProperty("Advisories").ValueKind);
        }
    }

    [Fact]
    public async Task A_folder_writes_rows_for_each_image_under_its_relative_name()
    {
        var folder = Path.Combine(_dir.Path, "app");
        Directory.CreateDirectory(Path.Combine(folder, "lib"));
        File.WriteAllBytes(Path.Combine(folder, "a.so"), Image("OpenSSL 3.0.13"));
        File.WriteAllBytes(Path.Combine(folder, "lib", "b.so"), Image("inflate 1.2.13"));
        File.WriteAllText(Path.Combine(folder, "notes.txt"), "OpenSSL 3.0.13");
        var rows = await Rows(folder);
        Assert.Equal([("a.so", "OpenSSL"), ("lib/b.so", "zlib")],
            rows.Select(r => (r.GetProperty("ImageName").GetString()!, r.GetProperty("Component").GetString()!)));
    }

    [Fact]
    public async Task An_image_with_no_component_writes_no_file_and_says_it_is_unknown()
    {
        var output = _dir.File("rows.jsonl");
        var tools = new InspectionTools(new InspectionService(_workspace), _workspace);
        await tools.SummarizeFile(path: Write("plain.so", Image("nothing here")), componentsPath: output);
        Assert.False(File.Exists(output));
    }

    [Theory]
    [InlineData("Mbed TLS", "3.4.0", "cpe:2.3:a:trustedfirmware:mbed_tls:3.4.0:*:*:*:*:*:*:*")]
    [InlineData("wolfSSL", "5.6.0", "cpe:2.3:a:wolfssl:wolfssl:5.6.0:*:*:*:*:*:*:*")]
    [InlineData("libsodium", "1.0.19", "")]
    [InlineData("OpenSSL", null, "")]
    public void A_CPE_name_is_given_only_for_a_confirmed_dictionary_entry_with_a_version(string name, string? version, string expected) =>
        Assert.Equal(expected, ComponentRows.Cpe(name, version));
}
