using System.Text.Json;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;
using Corvus.Core;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>Native tools on real libraries (the e_sqlite3 package): block paging of a large function, and the policy for undecoded architectures.</summary>
public class NativeRealPagingTests
{
    private static string Sqlite(string rid, string file) => RealPackages.File("SQLitePCLRaw.lib.e_sqlite3", "2.1.11", "runtimes", rid, "native", file);

    [Fact, Trait("Data", "Real"), Trait("Speed", "Slow")]
    public async Task Get_cfg_pages_cover_every_block_of_the_largest_function()
    {
        var path = Sqlite("win-x64", "e_sqlite3.dll");
        await using var server = await InProcessServer.StartAsync();
        var largest = await LargestFunction(path);
        var starts = new List<string>();
        int offset = 0, total = -1, pages = 0;
        while (true)
        {
            var result = await server.Client.CallToolAsync("get_cfg", new Dictionary<string, object?> { ["image"] = path, ["address"] = largest, ["offset"] = offset });
            Assert.True(result.IsError != true, string.Concat(result.Content.OfType<TextContentBlock>().Select(b => b.Text)));
            var text = string.Concat(result.Content.OfType<TextContentBlock>().Select(b => b.Text));
            Assert.True(TokenEstimate.Of(text) <= 6300, $"page {pages}: {TokenEstimate.Of(text)} tokens");
            var record = JsonDocument.Parse(result.StructuredContent!.Value.GetRawText()).RootElement;
            total = record.GetProperty("total").GetInt32();
            starts.AddRange(record.GetProperty("items").EnumerateArray().Select(b => b.GetProperty("start").GetString()!));
            pages++;
            if (!record.TryGetProperty("nextOffset", out var next)) break;
            offset = next.GetInt32();
        }
        Assert.True(total > 1000, $"{total} blocks");
        Assert.Equal(total, starts.Count);
        Assert.Equal(total, starts.Distinct().Count());
        Assert.True(pages > 1);
    }

    /// <summary>The function with the most blocks, as an address.</summary>
    private static async Task<string> LargestFunction(string path)
    {
        using var env = new Env();
        var code = new NativeCodeService(env.Workspace, env.Options);
        var native = env.Workspace.LoadAny(path).Native!;
        var index = await code.Index(native, null, default);
        var f = index.Functions.MaxBy(f => f.BlockCount)!;
        return $"rva:0x{f.Start:X}";
    }

    [Theory, Trait("Data", "Real")]
    [InlineData("linux-mips64", "EM_MIPS")]
    [InlineData("linux-s390x", "EM_S390")]
    [InlineData("linux-ppc64le", "EM_PPC64")]
    [InlineData("linux-riscv64", "EM_RISCV")]
    public async Task Undecoded_architectures_refuse_code_tools_with_the_machine_name(string rid, string machine)
    {
        var path = Sqlite(rid, "libe_sqlite3.so");
        var options = new ServerOptions { BackgroundIndexing = false };
        using var workspace = new AssemblyWorkspace(options);
        var code = new NativeCodeService(workspace, options);
        var pager = new OutputPager(options);
        var tools = new NativeCodeTools(workspace, code, pager);
        foreach (var call in new Func<Task>[] { () => tools.FindXrefs(path, "sqlite3_free"), () => tools.NativeCallTree(path, "sqlite3_free"),
                     () => tools.Disassemble(path, "sqlite3_free"), () => tools.GetCfg(path, "sqlite3_free") })
        {
            var e = await Assert.ThrowsAsync<ToolError>(call);
            Assert.Equal(ErrorCode.Unsupported, e.Code);
            Assert.Contains(machine, e.Message);
            Assert.False(string.IsNullOrWhiteSpace(e.Remediation));
        }
        var dossier = await new NativeFunctionTools(workspace, code, pager).AnalyzeNativeFunction(path, "sqlite3_free");
        Assert.DoesNotContain("0 blocks", dossier);
        Assert.Contains("not decoded", dossier);
    }
}
