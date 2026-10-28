using System.Formats.Tar;
using System.IO.Compression;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Corvus.Core;

namespace Corvus.Tests;

/// <summary>
/// corvus rules fetch and import: a pinned archive is installed only when its
/// SHA-256 matches, never offline; no network is used.
/// </summary>
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

    internal static byte[] TarGz()
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

    internal static RulePack Pack(string extension, byte[] archive) => new("fixture", "1.0", $"https://example.com/pack-1.0{extension}",
        Convert.ToHexStringLower(SHA256.HashData(archive)), "pack-1.0/rules/", "pack-1.0/LICENSE", "fixture", "a test pack", new DateOnly(2026, 10, 1));

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
    public void A_local_archive_with_a_pinned_hash_installs_and_lists_its_version_and_date()
    {
        var archive = _dir.File("pack-1.0.tar.gz");
        File.WriteAllBytes(archive, TarGz());
        var root = _dir.File("rules");
        // Import takes no HTTP handler: it has no way to reach the network.
        var (pack, installed) = RulePacks.Import(archive, root, pins: [Pack(".tar.gz", File.ReadAllBytes(archive))]);
        Assert.True(installed);
        Assert.Equal((2, new DateOnly(2026, 10, 1)), (pack.RuleFiles, pack.AsOf));
        var listed = Assert.Single(RulePacks.Installed(root));
        Assert.Equal("fixture 1.0, rules as of 2026-10-01", listed.Label);
        Assert.False(RulePacks.Import(archive, root, "fixture", [Pack(".tar.gz", File.ReadAllBytes(archive))]).Installed);
    }

    [Fact]
    public void A_local_archive_whose_hash_is_not_the_pin_is_refused_naming_both_hashes()
    {
        var archive = _dir.File("pack-1.0.zip");
        File.WriteAllBytes(archive, Zip());
        var actual = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(archive)));
        var pinned = Pack(".zip", Zip()) with { Sha256 = new string('0', 64) };
        var root = _dir.File("rules");
        var named = Assert.Throws<ToolError>(() => RulePacks.Import(archive, root, "fixture", [pinned]));
        Assert.Contains($"SHA-256 {actual} differs from the pinned {pinned.Sha256} of fixture 1.0; nothing was installed", named.Message);
        var unnamed = Assert.Throws<ToolError>(() => RulePacks.Import(archive, root, pins: [pinned]));
        Assert.Contains($"SHA-256 {actual} is not pinned (fixture 1.0: {pinned.Sha256})", unnamed.Message);
        Assert.Empty(RulePacks.Installed(root));
    }

    [Fact]
    public async Task A_fetched_pack_records_its_pinned_date_and_one_without_a_pin_is_unknown()
    {
        var archive = Zip();
        var (dated, _) = await RulePacks.FetchAsync(Pack(".zip", archive), _dir.File("dated"), new FixedResponse(archive), offline: false, default);
        Assert.Equal("fixture 1.0, rules as of 2026-10-01", RulePacks.At(dated.Folder).Label);
        var (undated, _) = await RulePacks.FetchAsync(Pack(".zip", archive) with { AsOf = null }, _dir.File("undated"), new FixedResponse(archive), offline: false, default);
        Assert.Equal("fixture 1.0, rules as of unknown", RulePacks.At(undated.Folder).Label);
    }

    [Fact]
    public void A_pack_installed_without_a_date_lists_it_as_unknown()
    {
        var folder = Path.Combine(_dir.File("rules"), "old", "2.0");
        Directory.CreateDirectory(folder);
        File.WriteAllText(Path.Combine(folder, "pack.json"), "{}");
        Assert.Equal("old 2.0, rules as of unknown", Assert.Single(RulePacks.Installed(_dir.File("rules"))).Label);
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
