using System.Text;
using Corvus.Core;
using Corvus.Native.Pe;
using Corvus.Services;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>TLSH digests of inputs built here, against literals computed with the reference implementation (py-tlsh 5.0.0).</summary>
public sealed class TlshTests : IDisposable
{
    private readonly TempDir _dir = new();
    public void Dispose() => _dir.Dispose();

    private static byte[] Lcg(int length, uint seed)
    {
        var bytes = new byte[length];
        for (int i = 0; i < length; i++)
        {
            seed = seed * 1103515245 + 12345;
            bytes[i] = (byte)(seed >> 16);
        }
        return bytes;
    }

    private static byte[] Text(int lines) =>
        Encoding.ASCII.GetBytes(string.Concat(Enumerable.Range(0, lines).Select(i => $"line {i}: the quick brown fox {i * 7 % 13} jumps over the lazy dog\n")));

    private static byte[] Image()
    {
        var pe = new PeBuilder { Is64 = true, EntryPoint = 0x1000 };
        pe.Add(".text", Lcg(4096, 9), 0x60000020);
        return pe.Build();
    }

    [Fact]
    public void A_minimum_length_input_has_the_reference_digest()
    {
        Assert.Equal("T10B900212ED194595D664969614938B85294E7C51545B4195574C61888924816162A210", Tlsh.Of(Lcg(50, 50)).Digest);
    }

    [Fact]
    public void A_4_KB_input_has_the_reference_digest()
    {
        Assert.Equal("T1DE813B6999CC368098713C9C1F7A92D9C2310A8FE75856DC411356D4EAB771673634D0", Tlsh.Of(Lcg(4096, 4096)).Digest);
    }

    [Fact]
    public void A_1_MB_input_has_the_reference_digest()
    {
        Assert.Equal("T15F253393205E819F39F7FA46E3CE772F6D864767403D5C26E8C72406F48260F96DA491", Tlsh.Of(Lcg(1 << 20, 1 << 20)).Digest);
    }

    [Fact]
    public void A_text_input_has_the_reference_digest()
    {
        Assert.Equal("T17611964B26581369B5DF148953CEE4F6C3DCC513A6722521B83270116814531BCFC496", Tlsh.Of(Text(20)).Digest);
    }

    [Fact]
    public void A_PE_image_has_the_reference_digest()
    {
        Assert.Equal("T10D918D89876E7C60F16C427E23A204DC85F5328CA7C42EBA6A06D2A5292FD45D71ED9C", Tlsh.Of(Image()).Digest);
    }

    [Fact]
    public void Blocks_of_any_size_give_the_digest_of_the_whole_input()
    {
        var data = Lcg(100_000, 100_000);
        var tlsh = new Tlsh();
        for (int at = 0; at < data.Length; at += 777) tlsh.Append(data.AsSpan(at, Math.Min(777, data.Length - at)));
        Assert.Equal(Tlsh.Of(data), tlsh.Final());
    }

    [Fact]
    public void An_input_under_50_bytes_has_no_digest_and_names_the_length()
    {
        Assert.Equal((null, "input under 50 bytes"), Tlsh.Of(Lcg(49, 49)));
    }

    [Fact]
    public void An_input_of_one_repeated_byte_has_no_digest_and_names_the_variation()
    {
        Assert.Equal((null, "too little variation"), Tlsh.Of(new byte[1000]));
    }

    [Fact]
    public void The_file_summary_carries_the_digest_or_the_reason_it_is_absent()
    {
        var path = _dir.File("a.bin");
        File.WriteAllBytes(path, Lcg(4096, 4096));
        var short_ = _dir.File("b.bin");
        File.WriteAllBytes(short_, Lcg(10, 10));
        using var workspace = new AssemblyWorkspace();
        var service = new InspectionService(workspace);
        var summary = service.Summarize(null, path, default, FileViewOptions.None);
        Assert.Equal(Tlsh.Of(Lcg(4096, 4096)).Digest, summary.File.Tlsh);
        Assert.Null(summary.File.TlshAbsent);
        var absent = service.Summarize(null, short_, default, FileViewOptions.None);
        Assert.Null(absent.File.Tlsh);
        Assert.Equal("input under 50 bytes", absent.File.TlshAbsent);
    }

    [Fact]
    public void The_bundle_lists_the_digest_without_its_version_prefix_with_the_file_hashes()
    {
        var path = _dir.File("a.bin");
        File.WriteAllBytes(path, Lcg(4096, 4096));
        using var workspace = new AssemblyWorkspace();
        var summary = new InspectionService(workspace).Summarize(null, path, default, new FileViewOptions { Stix = true });
        var bundle = System.Text.Json.JsonDocument.Parse(StixBundle.Write(summary, "1.0.0", DateTimeOffset.UnixEpoch, Guid.NewGuid(), Guid.NewGuid()));
        var file = bundle.RootElement.GetProperty("objects").EnumerateArray().First(o => o.GetProperty("type").GetString() == "file");
        Assert.Equal(summary.File.Tlsh![2..], file.GetProperty("hashes").GetProperty("TLSH").GetString());
    }
}
