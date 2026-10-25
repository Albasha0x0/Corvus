using System.Security.Cryptography;
using System.Text;
using Corvus.Core.Firmware;
using Corvus.Native.Providers;

namespace Corvus.Tests;

/// <summary>The LZFSE and LZVN decoder against streams Apple's reference encoder wrote (LzfseFixtures/build.ps1).</summary>
public sealed class LzfseTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    internal static byte[] Fixture(string name) => File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Containers", "LzfseFixtures", name));

    /// <summary>The first <paramref name="n"/> bytes of the text build.ps1 generates.</summary>
    internal static byte[] LedgerText(int n)
    {
        var sb = new StringBuilder();
        for (int i = 0; sb.Length < n; i++) sb.Append($"entry {i}: ledger record {i * 7 % 1000} balance {i * 13 % 9973}\n");
        return Encoding.ASCII.GetBytes(sb.ToString(0, n));
    }

    private static int Blocks(byte[] stream, string magic) =>
        Enumerable.Range(0, stream.Length - 3).Count(i => stream.AsSpan(i, 4).SequenceEqual(Encoding.ASCII.GetBytes(magic)));

    [Theory]
    [InlineData("text.lzfse", 300014, "eacf3ee9602cb74720d36e2514c35c0eb0bb3506e00b6b2216acaea85dfc8e40", "bvx2")]
    [InlineData("small.lzfse", 2000, "02649aa4c9a7dc1bae116893fe52678e68522c0b56bdf3d5d7bafa43ca3fa160", "bvxn")]
    [InlineData("random.lzfse", 20000, "1e0f4b402be70a21b4011329c282412f58bb24eb271654fbf00a94dd4721dac4", "bvx2")]
    public void Streams_from_the_reference_encoder_decode_to_their_inputs(string name, int size, string sha256, string block)
    {
        var stream = Fixture(name);
        Assert.True(Blocks(stream, block) > 0);
        var output = new byte[size + 100];
        Assert.Equal(size, Lzfse.Decode(stream, output));
        Assert.Equal(sha256, Convert.ToHexStringLower(SHA256.HashData(output.AsSpan(0, size))));
    }

    [Fact]
    public void A_stream_of_several_FSE_blocks_matches_back_across_blocks()
    {
        var stream = Fixture("text.lzfse");
        Assert.Equal(2, Blocks(stream, "bvx2"));
        Assert.Equal(LedgerText(300014), Decode(stream, 300014));
    }

    private static byte[] Decode(byte[] stream, int size)
    {
        var output = new byte[size];
        Assert.Equal(size, Lzfse.Decode(stream, output));
        return output;
    }

    [Fact]
    public void An_output_shorter_than_the_stream_keeps_its_first_bytes()
    {
        var output = new byte[1000];
        Assert.Equal(1000, Lzfse.Decode(Fixture("text.lzfse"), output));
        Assert.Equal(LedgerText(1000), output);
        var raw = HfsPlusWriter.LzfseRaw([1, 2, 3, 4, 5]);
        var three = new byte[3];
        Assert.Equal(3, Lzfse.Decode(raw, three));
        Assert.Equal([1, 2, 3], three);
        Assert.Equal(0, Lzfse.Decode("bvx$"u8, new byte[8]));
    }

    [Fact]
    public void LZVN_matches_copy_earlier_output_including_overlapping_runs()
    {
        // "hello", a match of 5 at distance 5, "a", a match of 4 at distance 1, then the end-of-stream opcode.
        byte[] stream = [0xE5, .. "hello"u8, 0x10, 5, 0xE1, (byte)'a', 0x08, 1, 6, 0, 0, 0, 0, 0, 0, 0];
        var output = new byte[32];
        int n = Lzfse.DecodeLzvn(stream, output);
        Assert.Equal("hellohelloaaaaa", Encoding.ASCII.GetString(output, 0, n));
    }

    [Fact]
    public void A_match_before_the_start_of_the_output_is_refused()
    {
        byte[] stream = [0xE1, (byte)'a', 0x10, 5, 6, 0, 0, 0, 0, 0, 0, 0];
        Assert.Throws<InvalidDataException>(() => Lzfse.DecodeLzvn(stream, new byte[32]));
        Assert.Throws<InvalidDataException>(() => Lzfse.Decode([.. "bvx2"u8, 0, 0, 0], new byte[8]));
    }

    [Fact]
    [FuzzEntry(typeof(Lzfse))]
    public void Fuzzed_streams_never_throw_past_an_invalid_data_error()
    {
        var output = new byte[400_000];
        foreach (var name in new[] { "small.lzfse", "random.lzfse", "text.lzfse" })
        {
            var failures = FormatFuzz.Run(Fixture(name), b =>
            {
                try { Lzfse.Decode(b, output); } catch (InvalidDataException) { }
                try { Lzfse.DecodeLzvn(b.AsSpan(Math.Min(12, b.Length)), output); } catch (InvalidDataException) { }
            }, 150);
            Assert.True(failures.Count == 0, name + ": " + string.Join("\n", failures.Take(10)));
        }
    }

    // Sizes around the encoder's LZVN threshold (4 KiB) and its block limits, text and incompressible bytes. The CLI
    // sizes its output buffer from the input and refuses an empty one.
    [Trait("Speed", "Slow")]
    [RequiresRealDataFact("CORVUS_LZFSE")]
    public void Inputs_round_trip_through_the_reference_encoder()
    {
        var tool = ExternalTools.Locate(ExternalTools.LzfseTool)!.Value.Path;
        var random = new byte[3 << 20];
        new Random(7).NextBytes(random);
        var inputs = new List<byte[]> { new byte[] { 42 }, LedgerText(4095), LedgerText(4096), random[..65536], LedgerText(1 << 20), random,
            LedgerText(500_000).Concat(random[..500_000]).Concat(new byte[300_000]).ToArray(), File.ReadAllBytes(typeof(Lzfse).Assembly.Location) };
        foreach (var input in inputs)
        {
            var plain = _dir.File("plain");
            var packed = _dir.File("packed");
            File.WriteAllBytes(plain, input);
            var run = ExternalTools.Run(tool, ExternalTools.Arguments(ExternalTools.LzfseTool, "encode", ("file", plain), ("output", packed)), TimeSpan.FromMinutes(2), 1 << 16, default);
            Assert.True(run.ExitCode == 0, run.Stderr);
            Assert.Equal(input, Decode(File.ReadAllBytes(packed), input.Length));
        }
    }
}
