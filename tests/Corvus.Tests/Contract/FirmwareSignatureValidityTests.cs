using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;
using Corvus.Core;
using Corvus.Core.Firmware;

namespace Corvus.Tests;

/// <summary>Every registered signature checks more than its magic, and a detector cannot skip the registry.</summary>
public sealed partial class FirmwareSignatureValidityTests
{
    // Sizes avoid multiples of 16, which a 16-byte-block cipher header cannot tell from its own length.
    private static readonly int[] Sizes = [4099, 70_001];
    private static readonly int[] Seeds = [1, 2, 3];
    private static readonly int[] Headers = [0, 1, 7, 100, 2000];

    private static byte[] Gzip(byte[] data)
    {
        var o = new MemoryStream();
        using (var z = new GZipStream(o, CompressionLevel.Optimal, leaveOpen: true)) z.Write(data);
        return o.ToArray();
    }

    private static byte[] Bytes(params object[] parts)
    {
        var o = new MemoryStream();
        foreach (var p in parts)
            switch (p)
            {
                case string s: o.Write(Encoding.Latin1.GetBytes(s)); break;
                case byte[] b: o.Write(b); break;
                case int n: o.WriteByte((byte)n); break;
                case uint u: o.Write(BitConverter.GetBytes(u)); break;
            }
        return o.ToArray();
    }

    private static uint Crc32(ReadOnlySpan<byte> b) => ~Crc.Raw(0xFFFFFFFF, b);

    private static byte[] Pad(byte[] head, int length = 64) => [.. head, .. new byte[Math.Max(0, length - head.Length)]];

    private static byte[] Tiff(bool big)
    {
        var d = new byte[32];
        (big ? "MM\0*"u8 : "II*\0"u8).CopyTo(d);
        if (big)
        {
            BinaryPrimitives.WriteUInt32BigEndian(d.AsSpan(4), 8);
            BinaryPrimitives.WriteUInt16BigEndian(d.AsSpan(8), 1);
            BinaryPrimitives.WriteUInt16BigEndian(d.AsSpan(12), 3);
            BinaryPrimitives.WriteUInt32BigEndian(d.AsSpan(14), 1);
        }
        else
        {
            BinaryPrimitives.WriteUInt32LittleEndian(d.AsSpan(4), 8);
            BinaryPrimitives.WriteUInt16LittleEndian(d.AsSpan(8), 1);
            BinaryPrimitives.WriteUInt16LittleEndian(d.AsSpan(12), 3);
            BinaryPrimitives.WriteUInt32LittleEndian(d.AsSpan(14), 1);
        }
        return d;
    }

    private static byte[] Rar5(int type = 1)
    {
        byte[] body = [3, (byte)type, 0, 0];
        return Bytes("Rar!\u001A\u0007\u0001\0", Crc32(body), body);
    }

    private static byte[] OpenSsh(string kind)
    {
        var blob = Bytes(BitConverter.GetBytes(kind.Length).Reverse().ToArray(), kind, new byte[12]);
        return Encoding.ASCII.GetBytes($"{kind} {Convert.ToBase64String(blob)}\n");
    }

    private static byte[] Lzfse()
    {
        var d = new byte[40];
        "bvx2"u8.CopyTo(d);
        d[4] = 1;
        d[24] = 32;
        return d;
    }

    private static byte[] Jpeg()
    {
        var d = new byte[32];
        d[0] = 0xFF; d[1] = 0xD8; d[2] = 0xFF; d[3] = 0xE0; d[5] = 16;
        "JFIF\0"u8.CopyTo(d.AsSpan(6));
        d[20] = 0xFF; d[21] = 0xDB;
        return d;
    }

    internal static byte[] VhdFooter()
    {
        var d = new byte[512];
        "conectix"u8.CopyTo(d);
        d[13] = 1;
        d[55] = 1;
        d[63] = 3;
        uint sum = 0;
        foreach (byte b in d) sum += b;
        BinaryPrimitives.WriteUInt32BigEndian(d.AsSpan(64), ~sum);
        return d;
    }

    private static byte[] Vhdx()
    {
        var d = new byte[65_540];
        "vhdxfile"u8.CopyTo(d);
        "head"u8.CopyTo(d.AsSpan(65_536));
        return d;
    }

    /// <summary>A minimal instance of a format, by the signature name; the first table wins on a name both build.</summary>
    private static Dictionary<string, Func<byte[]>> Instances()
    {
        var all = InstancesFirst();
        foreach (var (name, build) in InstancesB()) all.TryAdd(name, build);
        return all;
    }

    private static Dictionary<string, Func<byte[]>> InstancesFirst() => new(FirmwareSignatureInstances.All())
    {
        ["gzip compressed data"] = () => Gzip("minimal"u8.ToArray()),
        ["bzip2 compressed data"] = () => Pad(Bytes("BZh9", new byte[] { 0x31, 0x41, 0x59, 0x26, 0x53, 0x59 })),
        ["xz compressed data"] = () => Pad(Bytes(new byte[] { 0xFD, 0x37, 0x7A, 0x58, 0x5A, 0 }, 0, 4, Crc32([0, 4]))),
        ["LZMA compressed data"] = () => Pad(Bytes(new byte[] { 0x5D, 0, 0, 1, 0 }, new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF })),
        ["Zstandard compressed data"] = () => Bytes(new byte[] { 0x28, 0xB5, 0x2F, 0xFD, 0, 0, 16, 0, 0, 1, 2, 9, 0, 0, 3 }),
        ["LZFSE compressed data"] = Lzfse,
        ["RAR archive (v5)"] = () => Rar5(),
        ["JPEG image"] = Jpeg,
        ["TIFF image (little endian)"] = () => Tiff(false),
        ["TIFF image (big endian)"] = () => Tiff(true),
        ["RTF document"] = () => Encoding.ASCII.GetBytes("{\\rtf1\\ansi\\deff0 text}"),
        ["HTML document"] = () => Encoding.ASCII.GetBytes("<!DOCTYPE html>\n<html></html>\n"),
        ["XML document"] = () => Encoding.ASCII.GetBytes("<?xml version=\"1.0\"?>\n<a/>\n"),
        ["PDF document"] = () => Encoding.ASCII.GetBytes("%PDF-1.4\n"),
        ["WebAssembly module"] = () => Bytes(new byte[] { 0, 0x61, 0x73, 0x6D, 1, 0, 0, 0 }),
        ["OpenSSH public key (ssh-rsa)"] = () => OpenSsh("ssh-rsa"),
        ["OpenSSH public key (ssh-ed25519)"] = () => OpenSsh("ssh-ed25519"),
        ["OpenSSH public key (ecdsa-sha2-nistp256)"] = () => OpenSsh("ecdsa-sha2-nistp256"),
        ["OpenSSL encrypted data"] = () => Bytes("Salted__", new byte[24]),
        ["U-Boot uImage"] = () => FirmwareImageTests.UImage(new byte[16]),
        ["VHD disk image"] = VhdFooter,
        ["VHDX disk image"] = Vhdx,
    };

    /// <summary>Signatures that report a magic planted in random data, with the first case that did.</summary>
    internal static SortedDictionary<string, string> PlantedHits()
    {
        var hits = new SortedDictionary<string, string>(StringComparer.Ordinal);
        foreach (var s in FirmwareSignatures.All)
            foreach (int size in Sizes)
                foreach (int seed in Seeds)
                    foreach (int header in Headers)
                    {
                        int at = header + s.MagicAt;
                        if (at + s.Magic.Length > size) continue;
                        var d = new byte[size];
                        new Random(seed * 7919 + header).NextBytes(d);
                        s.Magic.CopyTo(d, at);
                        var found = new List<SignatureHit>();
                        FirmwareSignatures.Scan(new FirmwareSignatures.Window(d, size, 0, size, null), size, 0, found, 8, x => x == s, default);
                        if (found.Count > 0) hits.TryAdd(s.Format, $"size {size}, seed {seed}, header at {header}");
                    }
        return hits;
    }

    [Fact]
    public void A_magic_planted_in_random_data_is_not_reported_by_any_signature()
    {
        var hits = PlantedHits();
        Assert.True(hits.Count == 0, string.Join("\n", hits.Select(h => $"{h.Key}: {h.Value}")));
    }

    [Fact]
    public void A_minimal_instance_of_each_listed_format_is_reported_under_its_name()
    {
        var missed = new List<string>();
        foreach (var (format, build) in Instances())
        {
            Assert.Contains(FirmwareSignatures.All, s => s.Format == format);
            var hits = FirmwareSignatures.Scan(build(), 16, default);
            if (!hits.Any(h => h.Format == format && h.Offset == 0)) missed.Add($"{format}: not reported at offset 0 (got {string.Join(", ", hits.Select(h => h.Format))})");
        }
        Assert.True(missed.Count == 0, string.Join(Environment.NewLine, missed));
    }

    [Fact]
    public void Every_signature_has_a_minimal_instance()
    {
        var instances = Instances();
        var missing = FirmwareSignatures.All.Where(s => !instances.ContainsKey(s.Format)).Select(s => s.Format).ToList();
        Assert.True(missing.Count == 0, "no minimal instance for: " + string.Join(", ", missing));
    }

    /// <summary>Single-byte changes as (offset, value); a negative value inverts the byte.</summary>
    private static Dictionary<string, (int At, int Value)[]> Mutations()
    {
        var all = MutationsFirst();
        foreach (var (name, changes) in MutationsB()) all.TryAdd(name, [.. changes.Select(m => (m.At, (int)m.Value))]);
        return all;
    }

    private static Dictionary<string, (int At, int Value)[]> MutationsFirst() => new(FirmwareSignatureInstances.Changes())
    {
        ["Zstandard compressed data"] = [(4, 0x08), (6, 0x07), (11, 0x21), (12, 0x03)],
        ["LZFSE compressed data"] = [(4, 0), (24, 0)],
        ["RAR archive (v5)"] = [(8, 0), (13, 2), (12, 0)],
        ["JPEG image"] = [(3, 0), (5, 0), (20, 0)],
        ["VHD disk image"] = [(13, 0), (63, 1), (55, 0)],
        ["VHDX disk image"] = [(65_536, 0)],
        ["TIFF image (little endian)"] = [(12, 0xFF), (14, 0), (8, 0)],
        ["TIFF image (big endian)"] = [(13, 0xFF), (17, 0), (9, 0)],
        ["RTF document"] = [(6, (byte)'A'), (10, 1)],
        ["HTML document"] = [(14, (byte)'x'), (20, 1)],
        ["OpenSSH public key (ssh-rsa)"] = [(13, (byte)'/')],
        ["OpenSSH public key (ssh-ed25519)"] = [(19, (byte)'/')],
        ["OpenSSH public key (ecdsa-sha2-nistp256)"] = [(27, (byte)'/')],
    };

    [Fact]
    public void A_changed_header_field_stops_the_format_being_reported()
    {
        var instances = Instances();
        var kept = new List<string>();
        foreach (var (format, changes) in Mutations())
        {
            Assert.Contains(FirmwareSignatures.Scan(instances[format](), 16, default), h => h.Format == format && h.Offset == 0);
            foreach (var (at, value) in changes)
            {
                var d = instances[format]();
                d[at] = value < 0 ? (byte)~d[at] : (byte)value;
                var hits = FirmwareSignatures.Scan(d, 16, default);
                if (hits.Any(h => h.Format == format && h.Offset == 0)) kept.Add($"{format}: still reported with byte {at} changed to {value}");
            }
        }
        Assert.True(kept.Count == 0, string.Join(Environment.NewLine, kept));
    }

    [Fact]
    public void A_rar_5_archive_with_encrypted_headers_is_reported()
    {
        Assert.Contains(FirmwareSignatures.Scan(Rar5(4), 16, default), h => h.Format == "RAR archive (v5)" && h.Offset == 0);
    }

    [Fact]
    public void A_zstandard_frame_with_two_chained_blocks_is_reported()
    {
        var d = Instances()["Zstandard compressed data"]();
        Assert.Contains(FirmwareSignatures.Scan(d, 16, default), h => h.Format == "Zstandard compressed data" && h.Offset == 0);
    }

    [Fact]
    public void A_document_with_non_ascii_text_in_its_first_bytes_is_reported()
    {
        var d = Encoding.UTF8.GetBytes("<!DOCTYPE html>\n<title>éè</title>\n");
        Assert.Contains(FirmwareSignatures.Scan(d, 16, default), h => h.Format == "HTML document" && h.Offset == 0);
    }

    [Fact]
    public void A_truncated_jpeg_with_an_intact_first_segment_is_reported()
    {
        var hits = FirmwareSignatures.Scan(Jpeg()[..16], 16, default);
        Assert.Contains(hits, h => h.Format == "JPEG image" && h.Offset == 0);
    }

    [Fact]
    public void An_openssl_header_after_the_start_of_the_file_is_not_reported()
    {
        var inner = Instances()["OpenSSL encrypted data"]();
        Assert.Contains(FirmwareSignatures.Scan(inner, 16, default), h => h.Format == "OpenSSL encrypted data");
        Assert.DoesNotContain(FirmwareSignatures.Scan([.. new byte[8], .. inner], 16, default), h => h.Format == "OpenSSL encrypted data");
    }

    [Fact]
    [FuzzEntry(typeof(FirmwareSignatures))]
    public void Fuzzed_images_never_throw_from_a_signature_scan()
    {
        foreach (var seed in Instances().Values.Select(b => b()))
        {
            var failures = FormatFuzz.Run(seed, b => FirmwareSignatures.Scan(b, 32, default), 100);
            Assert.True(failures.Count == 0, string.Join("\n", failures.Take(10)));
        }
    }

    private static readonly Regex MagicCompare = new(
        "\\.(SequenceEqual|StartsWith|IndexOf)\\(\\s*(\"[^\"]{1,12}\"u8|\\[\\s*0x[0-9A-Fa-f]{2},|new byte\\[\\]\\s*\\{\\s*0x)",
        RegexOptions.NonBacktracking | RegexOptions.CultureInvariant);

    /// <summary>Sequence comparisons with a literal magic in server source outside the signature registry and the file header checks: file, then the line numbers.</summary>
    internal static SortedDictionary<string, List<int>> ComparisonsOutsideRegistry()
    {
        var src = Path.Combine(DocsTests.RepoRoot(), "src", "Corvus");
        var found = new SortedDictionary<string, List<int>>(StringComparer.Ordinal);
        foreach (var file in Directory.EnumerateFiles(src, "*.cs", SearchOption.AllDirectories))
        {
            var rel = Path.GetRelativePath(src, file).Replace('\\', '/');
            if (rel.StartsWith("bin/", StringComparison.Ordinal) || rel.StartsWith("obj/", StringComparison.Ordinal) || rel is "Core/Firmware/FirmwareSignatures.cs" or "Core/FileHeaders.cs") continue;
            int line = 0;
            foreach (var text in File.ReadLines(file))
            {
                line++;
                var t = text.Trim();
                if (!t.StartsWith("//", StringComparison.Ordinal) && MagicCompare.IsMatch(t)) (found.TryGetValue(rel, out var lines) ? lines : found[rel] = []).Add(line);
            }
        }
        return found;
    }

    [Fact]
    public void A_magic_comparison_outside_the_signature_registry_is_named_by_file_and_line()
    {
        var found = ComparisonsOutsideRegistry();
        var recorded = CountRatchet.Read("detector-registry");
        var added = found.Where(f => f.Value.Count > recorded.GetValueOrDefault("src/Corvus/" + f.Key))
            .Select(f => $"src/Corvus/{f.Key}: lines {string.Join(", ", f.Value)}").ToList();
        Assert.True(added.Count == 0 || recorded.Count == 0 && Environment.GetEnvironmentVariable(Ratchet.UpdateVariable) == "1",
            "a magic comparison outside FirmwareSignatures; register the format there with its validity check:\n" + string.Join("\n", added));
        CountRatchet.Check("detector-registry", "magic comparisons per source file outside the signature registry may only fall",
            found.ToDictionary(f => "src/Corvus/" + f.Key, f => (double)f.Value.Count), floor: false);
    }

    [Fact]
    public void An_empty_bzip2_stream_holds_and_an_empty_gzip_member_holds()
    {
        byte[] bzip2 = [.. "BZh9"u8, 0x17, 0x72, 0x45, 0x38, 0x50, 0x90, 0, 0, 0, 0];
        Assert.True(FirmwareSignatures.Holds(bzip2, bzip2.Length, "bzip2 compressed data"));
        byte[] gzip = [0x1F, 0x8B, 8, 0, 0, 0, 0, 0, 0, 0xFF, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        Assert.True(FirmwareSignatures.Holds(gzip, gzip.Length, "gzip compressed data"));
    }
}
