using Corvus.Core;
using Corvus.Mcp;
using Corvus.Native.Calls;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>get_pe_info: capability groups from imports; the answer is the same whether or not the code index is built.</summary>
public sealed class PeInfoCodeTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    [Fact]
    public async Task The_answer_does_not_depend_on_the_code_index()
    {
        var options = new ServerOptions { BackgroundIndexing = false };
        using var workspace = new AssemblyWorkspace(options);
        var code = new NativeCodeService(workspace, options, null, new Native.Annotations.AnnotationStore(_dir.File("annotations")));
        var tools = new NativeTools(workspace, new OutputPager(options), code);
        var path = McpProtocolTests.NativeSample(_dir);
        var collector = ToolOutput.Collect();
        var before = await tools.GetPeInfo(path);
        var beforeRecord = System.Text.Json.JsonSerializer.Serialize(collector.Value);
        Assert.Contains("Capabilities (from static imports):", before);
        Assert.Matches(@"  ui +1  MessageBox", before); // delay-loaded USER32!MessageBoxW
        Assert.Contains("Code: view=code gives the function statistics", before);

        var native = workspace.Read(() => workspace.Natives[0]);
        await code.Index(native, null, default);
        collector = ToolOutput.Collect();
        Assert.Equal(before, await tools.GetPeInfo(native.Id));
        Assert.Equal(beforeRecord, System.Text.Json.JsonSerializer.Serialize(collector.Value));
        // the record (section entropy reads the whole file) is computed once per image
        Assert.Contains(native.Analysis.Keys, t => t.Name == "SummaryCache");
    }

    [Fact]
    public async Task View_code_waits_for_the_index_and_gives_its_statistics()
    {
        var options = new ServerOptions { BackgroundIndexing = false };
        using var workspace = new AssemblyWorkspace(options);
        var code = new NativeCodeService(workspace, options, null, new Native.Annotations.AnnotationStore(_dir.File("annotations")));
        var tools = new NativeTools(workspace, new OutputPager(options), code);
        var path = McpProtocolTests.NativeSample(_dir);
        var collector = ToolOutput.Collect();
        var text = await tools.GetPeInfo(path, view: "code");
        Assert.Matches(@"Code: \d+ functions \(\d+ thunks, \d+ noreturn\), [\d,]+ instructions", text);
        Assert.Contains("entry points: entry, 2 exports, 1 TLS callback", text);
        Assert.Contains("Capabilities (from static and late-bound imports):", text);
        var record = Assert.IsType<PeSummary>(collector.Value);
        Assert.Equal(2, record.Code!.Exports);
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => tools.GetPeInfo(path, view: "all"))).Code);
    }

    [Fact]
    public void Capability_groups_match_without_suffixes_and_by_module()
    {
        var groups = ApiCapabilities.Classify([
            ("KERNEL32.dll", "CreateFileW"), ("KERNEL32.dll", "ReadFile"), ("ADVAPI32.dll", "RegOpenKeyExW"), ("WS2_32.dll", "#23"),
            ("WININET.dll", "InternetOpenUrlA"), ("KERNEL32.dll", "IsDebuggerPresent"), ("KERNEL32.dll", "GetProcAddress"), ("libc.so.6", "socket"),
            ("KERNEL32.dll", "CreateRemoteThread"), ("bcrypt.dll", "BCryptEncrypt"), ("KERNEL32.dll", "Sleep")]);
        var byName = groups.ToDictionary(g => g.Group);
        Assert.Equal(["CreateFile", "ReadFile"], byName["files"].Apis);
        Assert.Equal(["RegOpenKey"], byName["registry"].Apis);
        Assert.Equal(3, byName["network"].Count); // a ws2_32 ordinal, InternetOpenUrl, socket
        Assert.Contains("IsDebuggerPresent", byName["debug"].Apis);
        Assert.Contains("CreateRemoteThread", byName["process_thread"].Apis);
        Assert.Contains("BCryptEncrypt", byName["crypto"].Apis);
        Assert.Contains("GetProcAddress", byName["dynamic_loading"].Apis);
        Assert.DoesNotContain(groups, g => g.Apis.Contains("Sleep"));
        Assert.True(groups.Zip(groups.Skip(1)).All(p => p.First.Count >= p.Second.Count));
    }
}
