using System.Diagnostics;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>
/// Real .NET applications whose references are missing, so their first resolutions build stubs (a re-entrant stub build
/// raised dnlib's LockException on LINQPad 5.52.01 and Codist 9.0). CORVUS_STUB_APPS: <c>;</c>-separated entries
/// <c>assembly path|member token|method token|type token</c>, e.g. <c>LINQPad.exe|0x06000413|0x06001AFA|0x020001FF</c>.
/// </summary>
[Collection(SweepCollection.Name)]
public class StubAppsRealDataTests(ITestOutputHelper output)
{
    private const string Variable = "CORVUS_STUB_APPS";

    /// <summary>A warm call on the same server; verify_native_imports used to hold the lock for minutes, chaining timeouts.</summary>
    private static readonly TimeSpan WarmBudget = TimeSpan.FromSeconds(10);

    [Fact]
    [Trait("Speed", "Slow")]
    public async Task FirstResolutionsAndEditsSucceed_AndVerifyDoesNotChainTimeouts()
    {
        if (Environment.GetEnvironmentVariable(Variable) is not { Length: > 0 } list) return;
        foreach (var entry in list.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var parts = entry.Split('|');
            var (path, member, method, type) = (parts[0], parts[1], parts[2], parts[3]);
            var assembly = Path.GetFileNameWithoutExtension(path);
            await using var client = await McpProtocolTests.StartServerAsync("--load", path);
            async Task<TimeSpan> Call(string tool, Dictionary<string, object?> args)
            {
                var watch = Stopwatch.StartNew();
                var result = await client.CallToolAsync(tool, args);
                var text = string.Join("\n", result.Content.OfType<TextContentBlock>().Select(c => c.Text));
                Assert.True(result.IsError != true, $"{assembly} {tool}: {text}");
                output.WriteLine($"{assembly} {tool}: {watch.Elapsed.TotalSeconds:0.00} s");
                return watch.Elapsed;
            }

            await Call("get_assembly_info", new() { ["assembly"] = assembly });
            await Call("decompile_assembly_attributes", new() { ["assembly"] = assembly });
            await Call("decompile_member", new() { ["member"] = member, ["assembly"] = assembly });
            await Call("patch_method_csharp", new() { ["method"] = method, ["code"] = "throw null;", ["assembly"] = assembly, ["dryRun"] = true });
            Assert.True(await Call("verify_native_imports", new() { ["assembly"] = assembly }) < WarmBudget);
            Assert.True(await Call("find_references", new() { ["symbol"] = type, ["assembly"] = assembly, ["kind"] = "type" }) < WarmBudget);
            Assert.True(await Call("decompile_type", new() { ["type"] = type, ["assembly"] = assembly }) < WarmBudget);
            await Call("add_types_csharp", new() { ["assembly"] = assembly, ["code"] = "namespace Probe { public static class Added { public static int Answer() { return 42; } } }" });
            await Call("add_members_csharp", new() { ["type"] = type, ["assembly"] = assembly, ["code"] = "public static int ProbeMember() { return 7; }" });
            await Call("diff_edits", new() { ["assembly"] = assembly });
        }
    }
}
