using System.Formats.Tar;
using System.IO.Compression;
using System.Text;
using Corvus.Core;
using Corvus.Core.Archives;

namespace Corvus.Tests;

/// <summary>Images saved as a tar: a docker save archive and an OCI layout built here, read for configuration, history and per-layer files.</summary>
public sealed class SavedImageTests
{
    private static byte[] Tar(params (string Name, byte[] Bytes)[] files)
    {
        using var output = new MemoryStream();
        using (var tar = new TarWriter(output, TarEntryFormat.Ustar, leaveOpen: true))
            foreach (var (name, bytes) in files)
                tar.WriteEntry(new UstarTarEntry(TarEntryType.RegularFile, name) { DataStream = new MemoryStream(bytes) });
        return output.ToArray();
    }

    private static byte[] Gzip(byte[] data)
    {
        using var output = new MemoryStream();
        using (var gzip = new GZipStream(output, CompressionLevel.Fastest, leaveOpen: true)) gzip.Write(data);
        return output.ToArray();
    }

    private static byte[] Text(string s) => Encoding.UTF8.GetBytes(s);

    private const string Config = """
        {"architecture":"amd64","os":"linux","created":"2024-01-02T03:04:05Z",
         "config":{"Entrypoint":["/bin/app"],"Cmd":["--serve"],"Env":["PATH=/bin","MODE=prod"],"User":"app","WorkingDir":"/srv","ExposedPorts":{"8080/tcp":{}}},
         "rootfs":{"type":"layers","diff_ids":["sha256:a","sha256:b"]},
         "history":[{"created_by":"ADD base.tar /"},{"created_by":"ENV MODE=prod","empty_layer":true},{"created_by":"RUN rm /etc/secret"}]}
        """;

    private static (byte[] Base, byte[] Top) Layers() =>
    (
        Tar(("etc/secret", Text("key")), ("bin/app", Text("program"))),
        Gzip(Tar(("etc/.wh.secret", []), ("var/cache/.wh..wh..opq", []), ("srv/new.txt", Text("new"))))
    );

    private static byte[] DockerSave()
    {
        var (lower, upper) = Layers();
        return Tar(
            ("manifest.json", Text("""[{"Config":"cfg.json","RepoTags":["app:1"],"Layers":["l1/layer.tar","l2/layer.tar"]}]""")),
            ("cfg.json", Text(Config)), ("l1/layer.tar", lower), ("l2/layer.tar", upper));
    }

    private static byte[] OciLayout()
    {
        var (lower, upper) = Layers();
        return Tar(
            ("oci-layout", Text("""{"imageLayoutVersion":"1.0.0"}""")),
            ("index.json", Text("""{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:m1","platform":{"os":"linux","architecture":"amd64"},"annotations":{"org.opencontainers.image.ref.name":"app:1"}}]}""")),
            ("blobs/sha256/m1", Text("""{"config":{"digest":"sha256:c1"},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"sha256:l1"},{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:l2"}]}""")),
            ("blobs/sha256/c1", Text(Config)), ("blobs/sha256/l1", lower), ("blobs/sha256/l2", upper));
    }

    [Fact]
    public void A_docker_save_archive_lists_its_configuration_layers_and_whiteouts()
    {
        var c = Containers.Open(DockerSave(), "app.tar", AnalysisLimits.Default, default);
        Assert.Equal("docker image archive", c.Kind);
        Assert.Contains("image: app:1", c.Notes);
        Assert.Contains("entrypoint: [\"/bin/app\"]", c.Notes);
        Assert.Contains("cmd: [\"--serve\"]", c.Notes);
        Assert.Contains("env (2): PATH=/bin; MODE=prod", c.Notes);
        Assert.Contains("user: app", c.Notes);
        Assert.Contains("working directory: /srv", c.Notes);
        Assert.Contains("exposed ports: 8080/tcp", c.Notes);
        var paths = c.Entries!.Select(e => e.Path).ToList();
        Assert.Contains("layer 1/bin/app", paths);
        Assert.Contains("layer 2/srv/new.txt", paths);
        Assert.Equal("whiteout: removes /etc/secret of the lower layers", c.Entries!.Single(e => e.Path == "layer 2/etc/.wh.secret").Detail);
        Assert.Equal("opaque directory: hides /var/cache of the lower layers", c.Entries!.Single(e => e.Path == "layer 2/var/cache/.wh..wh..opq").Detail);
        Assert.Equal("ADD base.tar /", c.Entries!.Single(e => e.Path == "history/1").Detail);
        Assert.Equal("ENV MODE=prod; no layer", c.Entries!.Single(e => e.Path == "history/2").Detail);
    }

    [Fact]
    public void An_oci_layout_follows_the_index_to_the_manifest_config_and_gzip_layers()
    {
        var c = Containers.Open(OciLayout(), "app-oci.tar", AnalysisLimits.Default, default);
        Assert.Equal("OCI image layout", c.Kind);
        Assert.Contains("image: app:1 (linux/amd64)", c.Notes);
        Assert.Contains("entrypoint: [\"/bin/app\"]", c.Notes);
        var layer2 = c.Entries!.Single(e => e.Path == "layer 2");
        Assert.Contains("gzip", layer2.Detail);
        Assert.Contains("1 whiteout(s)", layer2.Detail);
        Assert.Contains(c.Entries!, e => e.Path == "layer 2/srv/new.txt" && e.Size == 3);
    }

    [Fact]
    public void A_zstd_layer_is_decompressed_and_listed()
    {
        using var packed = new MemoryStream();
        using (var z = new ZstdSharp.CompressionStream(packed, 1, leaveOpen: true)) z.Write(Tar(("bin/tool", Text("x"))));
        var data = Tar(("manifest.json", Text("""[{"Config":"cfg.json","Layers":["l1/layer.tar.zst"]}]""")), ("cfg.json", Text(Config)), ("l1/layer.tar.zst", packed.ToArray()));
        var c = Containers.Open(data, "zstd.tar", AnalysisLimits.Default, default);
        Assert.Contains("zstd", c.Entries!.Single(e => e.Path == "layer 1").Detail);
        Assert.Contains(c.Entries!, e => e.Path == "layer 1/bin/tool");
    }

    [Fact]
    public void A_layer_blob_missing_from_the_archive_is_listed_as_unknown()
    {
        var (lower, _) = Layers();
        var data = Tar(
            ("manifest.json", Text("""[{"Config":"cfg.json","Layers":["l1/layer.tar","l2/layer.tar"]}]""")),
            ("cfg.json", Text(Config)), ("l1/layer.tar", lower));
        var c = Containers.Open(data, "partial.tar", AnalysisLimits.Default, default);
        Assert.Contains("blob not in the archive; files unknown", c.Entries!.Single(e => e.Path == "layer 2").Detail);
        Assert.Contains(c.Entries!, e => e.Path == "layer 1/bin/app");
    }

    [Fact]
    public void A_missing_configuration_is_reported_unknown_and_the_layers_are_kept()
    {
        var (lower, _) = Layers();
        var data = Tar(("manifest.json", Text("""[{"Config":"cfg.json","Layers":["l1/layer.tar"]}]""")), ("l1/layer.tar", lower));
        var c = Containers.Open(data, "noconfig.tar", AnalysisLimits.Default, default);
        Assert.Contains(c.Notes, n => n.Contains("configuration cfg.json: unknown"));
        Assert.Contains(c.Entries!, e => e.Path == "layer 1/etc/secret");
    }

    [Fact]
    public void Files_past_the_item_limit_are_counted_and_named()
    {
        var c = Containers.Open(DockerSave(), "app.tar", new AnalysisLimits { MaxItems = 2 }, default);
        Assert.Contains(c.Notes, n => n.StartsWith("item count limit: 2-file;", StringComparison.Ordinal));
    }

    [Fact]
    public void A_tar_with_a_manifest_that_lists_no_image_stays_a_plain_tar()
    {
        var c = Containers.Open(Tar(("manifest.json", Text("""{"name":"extension"}""")), ("a.txt", Text("x"))), "ext.tar", AnalysisLimits.Default, default);
        Assert.Equal("tar", c.Kind);
    }

    [Fact]
    public void A_tar_with_an_unparsable_manifest_stays_a_plain_tar()
    {
        var c = Containers.Open(Tar(("manifest.json", Text("{not json")), ("a.txt", Text("x"))), "bad.tar", AnalysisLimits.Default, default);
        Assert.Equal("tar", c.Kind);
    }

    [Fact]
    public void A_tar_with_a_manifest_and_a_corrupt_later_header_stays_a_plain_tar()
    {
        var data = Tar(("manifest.json", Text("{}")), ("a.txt", Text("x")), ("b.txt", Text("y")));
        data[1024 + 148] ^= 0x55;
        var c = Containers.Open(data, "cut.tar", AnalysisLimits.Default, default);
        Assert.Equal("tar", c.Kind);
    }

    private static byte[] Noise(int length)
    {
        var bytes = new byte[length];
        new Random(7).NextBytes(bytes);
        return bytes;
    }

    private static byte[] OneLayerImage(byte[] layer) =>
        Tar(("manifest.json", Text("""[{"Config":"cfg.json","Layers":["l1/layer.tar"]}]""")), ("cfg.json", Text(Config)), ("l1/layer.tar", layer));

    [Fact]
    public void A_truncated_gzip_layer_keeps_its_earlier_entries_and_is_marked_partial()
    {
        var packed = Gzip(Tar(("first.txt", Text("one")), ("big.bin", Noise(40_000))));
        var cut = packed[..(packed.Length - 20_000)];
        var c = Containers.Open(OneLayerImage(cut), "cut.tar", AnalysisLimits.Default, default);
        Assert.Contains(c.Entries!, e => e.Path == "layer 1/first.txt");
        Assert.EndsWith("; partial", c.Entries!.Single(e => e.Path == "layer 1").Detail);
        Assert.Contains(c.Notes, n => n.StartsWith("layer 1: stopped reading after", StringComparison.Ordinal));
    }

    [Fact]
    public void A_layer_past_the_total_limit_is_cut_and_named()
    {
        var packed = Gzip(Tar(("first.txt", Text("one")), ("big.bin", Noise(40_000))));
        var c = Containers.Open(OneLayerImage(packed), "big.tar", new AnalysisLimits { MaxTotalBytes = 4_096 }, default);
        Assert.Contains(c.Entries!, e => e.Path == "layer 1/first.txt");
        Assert.EndsWith("; partial", c.Entries!.Single(e => e.Path == "layer 1").Detail);
        Assert.Contains(c.Notes, n => n.StartsWith("layer 1:", StringComparison.Ordinal) && n.Contains("4,096"));
    }

    [Fact]
    [FuzzEntry(typeof(ContainerImage))]
    public void Fuzzed_image_archives_never_throw_unexpectedly()
    {
        var failures = FormatFuzz.Run(DockerSave(), b => { try { Containers.Open(b, "x.tar", AnalysisLimits.Default, default); } catch (ToolError) { } }, 300);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }
}
