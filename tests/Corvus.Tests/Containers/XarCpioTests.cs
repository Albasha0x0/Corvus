using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;
using Corvus.Core;

namespace Corvus.Tests;

/// <summary>A macOS .pkg shape: a xar whose Payload is a cpio holding a binary; mutated archives never throw.</summary>
public sealed class XarCpioTests
{
    /// <summary>newc cpio: one regular file, then the trailer.</summary>
    private static byte[] Cpio(string name, byte[] bytes)
    {
        var o = new MemoryStream();
        void Entry(string n, byte[] b, uint mode)
        {
            var header = $"070701{0:X8}{mode:X8}{0:X8}{0:X8}{1:X8}{0:X8}{b.Length:X8}{0:X8}{0:X8}{0:X8}{0:X8}{n.Length + 1:X8}{0:X8}";
            o.Write(Encoding.ASCII.GetBytes(header));
            o.Write(Encoding.ASCII.GetBytes(n + "\0"));
            while (o.Length % 4 != 0) o.WriteByte(0);
            o.Write(b);
            while (o.Length % 4 != 0) o.WriteByte(0);
        }
        Entry("./" + name, bytes, 0x81A4);
        Entry("TRAILER!!!", [], 0);
        return o.ToArray();
    }

    /// <summary>xar: header, zlib table of contents naming one stored file (in <paramref name="folder"/> when given), then the heap.</summary>
    private static byte[] Xar(string name, byte[] bytes, string? folder = null)
    {
        var file = $"<file id=\"1\"><name>{name}</name><type>file</type><data><offset>0</offset><length>{bytes.Length}</length>" +
                   $"<size>{bytes.Length}</size><encoding style=\"application/octet-stream\"/></data></file>";
        if (folder != null) file = $"<file id=\"2\"><name>{folder}</name><type>directory</type>{file}</file>";
        var toc = $"<?xml version=\"1.0\"?><xar><toc>{file}</toc></xar>";
        var compressed = new MemoryStream();
        using (var z = new ZLibStream(compressed, CompressionLevel.Fastest, leaveOpen: true)) z.Write(Encoding.UTF8.GetBytes(toc));
        var header = new byte[28];
        "xar!"u8.CopyTo(header);
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(4), 28);
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(6), 1);
        BinaryPrimitives.WriteUInt64BigEndian(header.AsSpan(8), (ulong)compressed.Length);
        BinaryPrimitives.WriteUInt64BigEndian(header.AsSpan(16), (ulong)toc.Length);
        return [.. header, .. compressed.ToArray(), .. bytes];
    }

    [Fact]
    public void Pkg_payload_opens_down_to_its_binary()
    {
        var binary = File.ReadAllBytes(Env.FixturePath);
        var pkg = Containers.Open(Xar("Payload", Cpio("usr/local/bin/tool.dll", binary)), "app.pkg", AnalysisLimits.Default, default);
        Assert.Equal("xar", pkg.Kind);
        var payload = Assert.Single(pkg.Items);
        Assert.Equal("Payload", payload.Name);
        var cpio = Containers.Open(payload.Bytes, "Payload", AnalysisLimits.Default, default);
        Assert.Equal("cpio", cpio.Kind);
        Assert.Equal(("usr/local/bin/tool.dll", binary.Length), (Assert.Single(cpio.Items).Name, cpio.Items[0].Bytes.Length));
    }

    [Fact]
    [FuzzEntry(typeof(Core.Archives.XarReader), typeof(Core.Archives.CpioReader))]
    public void Fuzzed_archives_never_crash()
    {
        var cpio = Cpio("a.bin", new byte[64]);
        var failures = FormatFuzz.Run(Xar("Payload", cpio, "d"), b => { try { Containers.Open(b, "x.pkg", AnalysisLimits.Default, default, allFiles: true); } catch (ToolError) { } }, 800);
        failures.AddRange(FormatFuzz.Run(cpio, b => { try { Containers.Open(b, "x.cpio", AnalysisLimits.Default, default, allFiles: true); } catch (ToolError) { } }, 800));
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }
}
