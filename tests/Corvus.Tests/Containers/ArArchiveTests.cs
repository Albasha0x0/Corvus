using System.Formats.Tar;
using System.IO.Compression;
using System.Text;
using Corvus.Core;
using Corvus.Core.Archives;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>ar archives built here: a Debian package (gzip control tar, zstd data tar) and a static library with GNU and BSD member names.</summary>
public sealed class ArArchiveTests
{
    private static readonly byte[] Tool = [0x7F, (byte)'E', (byte)'L', (byte)'F', 2, 1, 1, 0, .. new byte[56]];

    private const string Control = "Package: tool\nVersion: 1.2-3\nArchitecture: amd64\nDepends: libc6 (>= 2.34)\nDescription: a test tool\n more text\n";

    private static byte[] Member(string name, byte[] data)
    {
        var header = Encoding.ASCII.GetBytes($"{name,-16}{0,-12}{0,-6}{0,-6}{"100644",-8}{data.Length,-10}`\n");
        return [.. header, .. data, .. data.Length % 2 == 1 ? "\n"u8.ToArray() : []];
    }

    private static byte[] Ar(params byte[][] members) => [.. "!<arch>\n"u8, .. members.SelectMany(m => m)];

    private static byte[] Tar(params (string Path, byte[] Data)[] files)
    {
        var o = new MemoryStream();
        using (var w = new TarWriter(o, TarEntryFormat.Gnu, leaveOpen: true))
        {
            w.WriteEntry(new GnuTarEntry(TarEntryType.Directory, "./"));
            foreach (var (path, data) in files)
                w.WriteEntry(new GnuTarEntry(TarEntryType.RegularFile, path) { DataStream = new MemoryStream(data) });
        }
        return o.ToArray();
    }

    private static byte[] Deb()
    {
        var gz = new MemoryStream();
        using (var z = new GZipStream(gz, CompressionLevel.Fastest, leaveOpen: true)) z.Write(Tar(("./control", Encoding.ASCII.GetBytes(Control))));
        using var zstd = new ZstdSharp.Compressor();
        var data = zstd.Wrap(Tar(("./usr/bin/tool", Tool), ("./usr/share/doc/tool/README", "readme"u8.ToArray()))).ToArray();
        return Ar(Member("debian-binary", "2.0\n"u8.ToArray()), Member("control.tar.gz", gz.ToArray()), Member("data.tar.zst", data));
    }

    [Fact]
    public void Debian_package_lists_data_and_control_files_and_notes_the_fields()
    {
        var c = Containers.Open(Deb(), "tool.deb", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal("debian package", c.Kind);
        Assert.Equal("debian package tool 1.2-3 (amd64): depends libc6 (>= 2.34); a test tool (format 2.0)", c.Notes[0]);
        Assert.Equal(["DEBIAN/control", "usr/bin/tool", "usr/share/doc/tool/README"], c.Entries!.Select(e => e.Path).Order(StringComparer.Ordinal));
        Assert.Equal(Tool, c.Items.Single(i => i.Name == "usr/bin/tool").Bytes);
    }

    [Fact]
    public void Static_library_lists_members_with_long_names()
    {
        byte[] a = [1, 2, 3], b = [4, 5];
        var names = "a_member_with_a_long_name.o/\n"u8.ToArray();
        var gnu = Ar(Member("/", new byte[8]), Member("//", names), Member("/0", a), Member("short.o/", b));
        var c = Containers.Open(gnu, "libx.a", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal("ar archive", c.Kind);
        Assert.Equal(["a_member_with_a_long_name.o", "short.o"], c.Entries!.Select(e => e.Path));
        Assert.Equal(a, c.Items[0].Bytes);
        Assert.Contains("symbol table (8 bytes)", c.Notes);
        var bsd = Ar(Member("#1/20", [.. "a_bsd_long_name.o\0\0\0"u8, .. b]));
        var d = Containers.Open(bsd, "liby.a", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal("a_bsd_long_name.o", d.Entries!.Single().Path);
        Assert.Equal(b, d.Items.Single().Bytes);
    }

    [Fact]
    public void Unpack_and_summarize_read_a_debian_package()
    {
        using var dir = new TempDir();
        using var workspace = new AssemblyWorkspace(new ServerOptions());
        var path = dir.File("tool.deb");
        File.WriteAllBytes(path, Deb());
        var report = new UnpackService(workspace).Unpack(path, dir.File("out"), load: false, AnalysisLimits.Default, default);
        Assert.Equal("debian package", report.Container);
        Assert.Equal(Tool, File.ReadAllBytes(report.Files.Single(f => f.Path.Replace('\\', '/').EndsWith("usr/bin/tool", StringComparison.Ordinal)).Path));
        var summary = new InspectionService(workspace).Summarize(null, path, default);
        Assert.Equal("debian package", summary.Container);
        Assert.Contains(summary.Notes, n => n.StartsWith("debian package tool 1.2-3 (amd64)", StringComparison.Ordinal));
    }

    [Fact]
    [FuzzEntry(typeof(ArReader))]
    public void Fuzzed_ar_archives_never_throw_unexpectedly()
    {
        var failures = FormatFuzz.Run(Deb(), b => { try { Containers.Open(b, "x.deb", AnalysisLimits.Default, default, allFiles: true); } catch (ToolError) { } }, 300);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }
}
