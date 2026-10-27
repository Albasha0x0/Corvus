using Corvus.Core;
using Corvus.Native.Annotations;
using Corvus.Services;
using Corvus.Tools;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>search_instructions over the built-in index of a tiny image: mov eax, 1; ret at the entry point and mov eax, 2; ret at +0x40.</summary>
public sealed class InstructionSearchTests : IDisposable
{
    private readonly ITestOutputHelper _output;
    private readonly TempDir _dir = new();
    private readonly Env _env = new();
    private readonly NativeCodeTools _tools;
    private readonly string _image;

    public InstructionSearchTests(ITestOutputHelper output)
    {
        _output = output;
        var code = new NativeCodeService(_env.Workspace, _env.Options, null, new AnnotationStore(_dir.File("ann")));
        _tools = new NativeCodeTools(_env.Workspace, code, _env.Pager);
        _image = _dir.File("tiny.dll");
        File.WriteAllBytes(_image, PdbTests.TinyImage(Guid.NewGuid(), 1));
    }

    public void Dispose()
    {
        _env.Dispose();
        _dir.Dispose();
    }

    private async Task<string> Search(string? mnemonic = null, string? operands = null, string? text = null, string? value = null, string? function = null,
        string? start = null, string? end = null, int offset = 0, int limit = 100, int maxInstructions = 500_000)
    {
        var result = await _tools.SearchInstructions(_image, mnemonic, operands, text, value, function, start, end, offset, limit, maxInstructions);
        _output.WriteLine(result);
        return result;
    }

    [Fact]
    public async Task Filters_scopes_paging_and_budget()
    {
        var ret = await Search(mnemonic: "^ret$");
        Assert.Contains("Engine: ours", ret);
        Assert.Matches(@"\n  0x140001005  \S+\+0x5  ret", ret);
        Assert.Contains("1 matching instruction ", await Search(mnemonic: "mov", value: "1"));
        Assert.Contains("0 matching instructions", await Search(mnemonic: "mov", value: "2"));
        // A range outside any function, value in hex.
        var range = await Search(operands: "eax", value: "0x2", start: "rva:0x1040", end: "rva:0x1046");
        Assert.Matches(@"0x140001040  -  mov\s+eax,\s*2", range);
        Assert.Contains("1 matching instruction ", await Search(text: @"^mov\s+eax", start: "rva:0x1000", end: "rva:0x1006"));

        // Paging and the scan budget.
        var all = await Search(text: ".", start: "rva:0x1040", end: "rva:0x1046", limit: 1);
        Assert.Contains("≥2 matching instructions", all);
        Assert.Contains("More: offset=1", all);
        Assert.Contains("ret", await Search(text: ".", start: "rva:0x1040", end: "rva:0x1046", offset: 1, limit: 1));
        var budget = await Search(text: ".", start: "rva:0x1040", end: "rva:0x1046", maxInstructions: 1);
        Assert.Contains("Scan budget of 1 instruction reached at 0x140001045: the next page goes on from there", budget);
        Assert.Contains("[More: offset=1]", budget);
        Assert.Contains("ret", await Search(text: ".", start: "rva:0x1040", end: "rva:0x1046", offset: 1, maxInstructions: 1));
        // No match within the budget: the page scans on to one.
        Assert.Contains("1 matching instruction ", await Search(mnemonic: "^ret$", start: "rva:0x1040", end: "rva:0x1046", maxInstructions: 1));

        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => Search())).Code);
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => Search(mnemonic: "(unclosed"))).Code);
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => Search(mnemonic: "mov", value: "zz"))).Code);
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => Search(mnemonic: "mov", function: "rva:0x1000", start: "rva:0x1000"))).Code);
    }

    /// <summary>G2-B5: pages a scan budget stops continue at the record's nextOffset, as the text footer says, to every match once.</summary>
    [Theory, Trait("Speed", "Slow")]
    [InlineData(null)]
    [InlineData("rva:0x1000")]
    public async Task Budget_stopped_pages_walk_to_every_match_once(string? from)
    {
        const int Functions = 24;
        byte[] Code(Dictionary<string, uint> _)
        {
            var bytes = new List<byte>();
            for (int i = 0; i < Functions; i++) bytes.AddRange([0xB8, (byte)i, 0, 0, 0, 0xC3, .. Enumerable.Repeat((byte)0xCC, 10)]); // mov eax, i; ret
            return [.. bytes];
        }
        var path = _dir.File("rets.dll");
        File.WriteAllBytes(path, LinkedImages.Build("rets.dll", [.. Enumerable.Range(0, Functions).Select(i => ($"F{i}", (object)(16 * i)))], [], Code));
        await using var server = await InProcessServer.StartAsync();
        Dictionary<string, object?> Args(int offset) => new()
        {
            ["image"] = path, ["mnemonic"] = "^ret$", ["maxInstructions"] = 3, ["limit"] = 4, ["offset"] = offset,
            ["from"] = from, ["to"] = from == null ? null : $"rva:0x{0x1000 + 16 * Functions:X}",
        };
        var seen = new List<string>();
        int pages = 0, scanned = 0;
        for (int offset = 0; ; pages++)
        {
            Assert.True(pages < 3 * Functions, "the walk does not end");
            var r = await server.Client.CallToolAsync("search_instructions", Args(offset));
            var text = string.Concat(r.Content.OfType<ModelContextProtocol.Protocol.TextContentBlock>().Select(b => b.Text));
            Assert.True(r.IsError != true, text);
            var record = r.StructuredContent!.Value;
            seen.AddRange(record.GetProperty("items").EnumerateArray().Select(i => i.GetProperty("address").GetString()!));
            scanned += record.GetProperty("scanned").GetInt32();
            bool more = record.GetProperty("hasMore").GetBoolean();
            var footer = System.Text.RegularExpressions.Regex.Match(text, @"\[More: offset=(\d+)\]");
            Assert.Equal(more, footer.Success);
            if (!more)
            {
                Assert.False(record.TryGetProperty("nextOffset", out _));
                Assert.True(record.GetProperty("totalExact").GetBoolean(), text);
                break;
            }
            Assert.False(record.GetProperty("totalExact").GetBoolean());
            int next = record.GetProperty("nextOffset").GetInt32();
            Assert.Equal(next, int.Parse(footer.Groups[1].Value));
            Assert.Equal(offset + record.GetProperty("items").GetArrayLength(), next);
            offset = next;
        }
        Assert.True(pages > 2, $"{pages} pages: the budget should stop the scan");
        // Each page goes on where the last stopped: the walk scans each instruction about once (mov, ret; the range adds 10 int3 each).
        Assert.InRange(scanned, 1, (from == null ? 2 : 12) * Functions + pages);
        Assert.Equal(Functions, seen.Count);
        Assert.Equal(Enumerable.Range(0, Functions).Select(i => $"0x{0x180001005L + 16 * i:X}"), seen);
    }
}
