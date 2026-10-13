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
        Assert.Contains("1 match(es)", await Search(mnemonic: "mov", value: "1"));
        Assert.Contains("0 match(es)", await Search(mnemonic: "mov", value: "2"));
        // a range outside any function, value in hex
        var range = await Search(operands: "eax", value: "0x2", start: "rva:0x1040", end: "rva:0x1046");
        Assert.Matches(@"0x140001040  -  mov\s+eax,\s*2", range);
        Assert.Contains("1 match(es)", await Search(text: @"^mov\s+eax", start: "rva:0x1000", end: "rva:0x1006"));

        // paging and the scan budget
        var all = await Search(text: ".", start: "rva:0x1040", end: "rva:0x1046", limit: 1);
        Assert.Contains("More than 1 match(es)", all);
        Assert.Contains("More: offset=1", all);
        Assert.Contains("ret", await Search(text: ".", start: "rva:0x1040", end: "rva:0x1046", offset: 1, limit: 1));
        var budget = await Search(text: ".", start: "rva:0x1040", end: "rva:0x1046", maxInstructions: 1);
        Assert.Contains("Scan budget of 1 instruction reached at 0x140001045: continue with from=0x140001045 to=0x140001046", budget);

        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => Search())).Code);
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => Search(mnemonic: "(unclosed"))).Code);
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => Search(mnemonic: "mov", value: "zz"))).Code);
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => Search(mnemonic: "mov", function: "rva:0x1000", start: "rva:0x1000"))).Code);
    }
}
