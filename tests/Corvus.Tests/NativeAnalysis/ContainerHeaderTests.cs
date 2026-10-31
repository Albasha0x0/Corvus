using ModelContextProtocol.Protocol;

namespace Corvus.Tests;

/// <summary>survey_features container:header over raw images.</summary>
public sealed class ContainerHeaderTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private async Task<string> Survey(byte[] image)
    {
        await using var server = await InProcessServer.StartAsync();
        var fixture = _dir.File($"blob{Guid.NewGuid():N}.bin");
        File.WriteAllBytes(fixture, image);
        var load = await server.Client.CallToolAsync("load_assembly", new Dictionary<string, object?> { ["path"] = fixture, ["format"] = "raw", ["arch"] = "x64" });
        var r = await server.Client.CallToolAsync("survey_features", new Dictionary<string, object?>
        {
            ["assembly"] = load.StructuredContent!.Value.GetProperty("ids")[0].GetString(),
            ["category"] = "crypto",
        });
        return string.Concat(r.Content.OfType<TextContentBlock>().Select(b => b.Text));
    }

    private static byte[] Random(int n, int seed)
    {
        var bytes = new byte[n];
        new Random(seed).NextBytes(bytes);
        return bytes;
    }

    // Header with caller-chosen entry words, then a random body.
    private static byte[] Table(uint count, params uint[] offsets) =>
        [.. "XCNT"u8, .. U32(2000, count), .. U32(offsets), .. Random(1024, 7)];

    private static byte[] U32(params uint[] words) => [.. words.SelectMany(BitConverter.GetBytes)];

    // Magic, declared length (bytes after the first 8), two entries, then the body.
    private static byte[] Container(string magic, int bodyLength, uint declaredExtra = 0)
    {
        uint declared = (uint)(4 + 8 + bodyLength) + declaredExtra;
        return [.. System.Text.Encoding.ASCII.GetBytes(magic), .. U32(declared, 2, 20, 20 + (uint)bodyLength / 2), .. Random(bodyLength, 7)];
    }

    [Fact]
    public async Task A_container_header_reports_its_magic_length_entropy_and_entry_offsets()
    {
        var text = await Survey([.. new byte[0x40], .. Container("XCNT", 1024), .. new byte[0x40]]);
        Assert.Contains("container 'XCNT' @0x40", text);
        Assert.Contains("declared length 1036", text);
        Assert.Matches(@"body entropy 7\.\d\d", text);
        Assert.Contains("entries at +0x14, +0x214", text);
        Assert.DoesNotContain("partial", text);
    }

    [Fact]
    public async Task A_loader_comparing_the_magic_is_named_as_a_reference()
    {
        // A cmp eax, imm32 of the magic ahead of the container.
        var loader = new byte[] { 0x3D, (byte)'X', (byte)'C', (byte)'N', (byte)'T', 0xC3 };
        var text = await Survey([.. loader, .. new byte[0x1A], .. Container("XCNT", 1024)]);
        Assert.Contains("magic referenced at", text);
        Assert.DoesNotContain("loader references unknown", text);
    }

    [Fact]
    public async Task A_container_cut_by_the_end_of_the_image_is_reported_as_partial()
    {
        var text = await Survey(Container("XCNT", 1024, declaredExtra: 4096));
        Assert.Contains("partial: 1036 of 5132 declared bytes", text);
    }

    [Fact]
    public async Task A_low_entropy_body_after_a_valid_header_is_not_a_container()
    {
        var text = await Survey([.. Container("XCNT", 1024)[..20], .. new byte[1024]]);
        Assert.DoesNotContain("container 'XCNT'", text);
    }

    [Theory]
    [InlineData(40u, 30u)]
    [InlineData(20u, 4u)]
    [InlineData(20u, 5000u)]
    public async Task An_entry_offset_that_descends_or_leaves_the_container_is_rejected(uint first, uint second)
    {
        var text = await Survey(Table(2, first, second));
        Assert.DoesNotContain("container 'XCNT'", text);
    }

    [Theory]
    [InlineData(0u)]
    [InlineData(257u)]
    public async Task An_entry_count_outside_1_to_256_is_rejected(uint count)
    {
        var text = await Survey(Table(count, 20, 40));
        Assert.DoesNotContain("container 'XCNT'", text);
    }

    [Fact]
    public async Task A_body_under_the_minimum_length_is_not_a_container()
    {
        var text = await Survey(Container("XCNT", 300));
        Assert.DoesNotContain("container 'XCNT'", text);
    }

    [Fact]
    public async Task A_declared_length_near_the_u32_limit_is_reported_as_partial()
    {
        var text = await Survey(Container("XCNT", 1024, declaredExtra: uint.MaxValue - 1100));
        Assert.Contains("partial:", text);
    }

    [Fact]
    public async Task A_reversed_magic_in_code_is_named_as_a_reference()
    {
        // A cmp eax, imm32 of the magic in reversed byte order.
        var loader = new byte[] { 0x3D, (byte)'T', (byte)'N', (byte)'C', (byte)'X', 0xC3 };
        var text = await Survey([.. loader, .. new byte[0x1A], .. Container("XCNT", 1024)]);
        Assert.Contains("magic referenced at", text);
    }

    [Fact]
    public async Task References_beyond_the_cap_are_counted()
    {
        // Six cmp eax, imm32 of the magic, 8 bytes apart.
        var loader = Enumerable.Repeat(new byte[] { 0x3D, (byte)'X', (byte)'C', (byte)'N', (byte)'T', 0x90, 0x90, 0x90 }, 6).SelectMany(b => b).ToArray();
        var text = await Survey([.. loader, .. Container("XCNT", 1024)]);
        Assert.Contains("and 3 more", text);
    }

    [Fact]
    public async Task A_second_container_is_not_a_loader_reference_of_the_first()
    {
        var text = await Survey([.. Container("XCNT", 1024), .. new byte[4], .. Container("XCNT", 1024)]);
        Assert.Contains("loader references unknown", text);
    }
}
