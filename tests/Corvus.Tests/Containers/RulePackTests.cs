using System.Formats.Tar;
using System.IO.Compression;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Corvus.Core;

namespace Corvus.Tests;

/// <summary>corvus rules fetch: a pinned archive is installed only when its SHA-256 matches, never offline; no network is used.</summary>
public sealed class RulePackTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    /// <summary>Answers every request with <paramref name="body"/> and counts the requests.</summary>
    private sealed class FixedResponse(byte[] body) : HttpMessageHandler
    {
        public int Requests { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Requests++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(body) });
        }
    }

    private static readonly (string Name, string Text)[] Entries =
    [
        ("pack-1.0/LICENSE", "fixture license"),
        ("pack-1.0/rules/one.yar", "rule one { condition: true }"),
        ("pack-1.0/rules/sub/two.yara", "rule two { condition: true }"),
        ("pack-1.0/rules/README.md", "not a rule"),
        ("pack-1.0/tests/three.yar", "rule three { condition: true }"),
    ];

    private static byte[] TarGz()
    {
        var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionLevel.Fastest, leaveOpen: true))
        using (var tar = new TarWriter(gz))
            foreach (var (name, text) in Entries)
                tar.WriteEntry(new PaxTarEntry(TarEntryType.RegularFile, name) { DataStream = new MemoryStream(Encoding.UTF8.GetBytes(text)) });
        return ms.ToArray();
    }

    private static byte[] Zip()
    {
        var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
            foreach (var (name, text) in Entries)
                using (var s = zip.CreateEntry(name).Open()) s.Write(Encoding.UTF8.GetBytes(text));
        return ms.ToArray();
    }

    private static RulePack Pack(string extension, byte[] archive) => new("fixture", "1.0", $"https://example.com/pack-1.0{extension}",
        Convert.ToHexStringLower(SHA256.HashData(archive)), "pack-1.0/rules/", "pack-1.0/LICENSE", "fixture", "a test pack");

    [Fact]
    public async Task A_pack_whose_hash_matches_installs_its_rules_and_license()
    {
        foreach (var (extension, archive) in new[] { (".tar.gz", TarGz()), (".zip", Zip()) })
        {
            var root = _dir.File("rules" + extension);
            var (pack, downloaded) = await RulePacks.FetchAsync(Pack(extension, archive), root, new FixedResponse(archive), offline: false, default);
            Assert.True(downloaded);
            Assert.Equal(Path.Combine(root, "fixture", "1.0"), pack.Folder);
            Assert.Equal(["LICENSE", "one.yar", "pack.json", Path.Combine("sub", "two.yara")],
                Directory.EnumerateFiles(pack.Folder, "*", SearchOption.AllDirectories).Select(f => Path.GetRelativePath(pack.Folder, f)).Order(StringComparer.Ordinal));
            Assert.Equal("fixture license", File.ReadAllText(Path.Combine(pack.Folder, "LICENSE")));
            Assert.Equal(2, pack.RuleFiles);
            Assert.Equal(pack.Folder, RulePacks.Folder(root, "fixture"));
        }
    }

    [Fact]
    public async Task A_hash_mismatch_is_refused_and_installs_nothing()
    {
        var archive = TarGz();
        var root = _dir.File("rules");
        var pinned = Pack(".tar.gz", archive) with { Sha256 = new string('0', 64) };
        var e = await Assert.ThrowsAsync<ToolError>(() => RulePacks.FetchAsync(pinned, root, new FixedResponse(archive), offline: false, default));
        Assert.Contains($"differs from the pinned {pinned.Sha256}; nothing was installed", e.Message);
        Assert.Empty(RulePacks.Installed(root));
        Assert.False(Directory.Exists(Path.Combine(root, "fixture")));
    }

    [Fact]
    public async Task Offline_the_download_is_refused_without_a_request()
    {
        var archive = Zip();
        var http = new FixedResponse(archive);
        var e = await Assert.ThrowsAsync<ToolError>(() => RulePacks.FetchAsync(Pack(".zip", archive), _dir.File("rules"), http, offline: true, default));
        Assert.Equal(ErrorCode.Unsupported, e.Code);
        Assert.StartsWith("CORVUS_OFFLINE is set", e.Message, StringComparison.Ordinal);
        Assert.Equal(0, http.Requests);
    }

    [Fact]
    public void A_pack_query_for_a_pack_not_installed_names_the_fetch_command()
    {
        var e = Assert.Throws<ToolError>(() => RulePacks.ResolveQuery("pack:malcontent", _dir.File("empty")));
        Assert.Equal(ErrorCode.NotFound, e.Code);
        Assert.Equal("run: corvus rules fetch malcontent", e.Remediation);
        Assert.Null(RulePacks.ResolveQuery("rule a { condition: true }", _dir.File("empty")));
    }
}
