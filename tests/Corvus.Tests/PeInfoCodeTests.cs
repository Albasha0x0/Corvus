using Corvus.Core;
using Corvus.Native.Calls;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>get_pe_info: capability groups from imports, and the code section once the index is built (never waited for).</summary>
public sealed class PeInfoCodeTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    [Fact]
    public async Task Code_section_appears_once_the_index_is_ready()
    {
        var options = new ServerOptions { BackgroundIndexing = false };
        using var workspace = new AssemblyWorkspace(options);
        var code = new NativeCodeService(workspace, options, null, new Native.Annotations.AnnotationStore(_dir.File("annotations")));
        var tools = new NativeTools(workspace, new OutputPager(options), code);
        var path = McpProtocolTests.NativeSample(_dir);
        var before = await tools.GetPeInfo(path);
        Assert.Contains("Code: the code index is still building", before);
        Assert.Contains("Capabilities (from static imports):", before);
        Assert.Matches(@"  ui +1  MessageBox", before); // delay-loaded USER32!MessageBoxW

        var native = workspace.Read(() => workspace.Natives[0]);
        await code.Index(native, null, default);
        var after = await tools.GetPeInfo(native.Id);
        Assert.Matches(@"Code: \d+ functions \(\d+ thunks, \d+ noreturn\), [\d,]+ instructions", after);
        Assert.Contains("% of executable bytes in functions", after);
        Assert.Contains("entry points: entry, 2 exports, 1 TLS callback", after);
        Assert.Contains("largest: ", after);
        var overview = NativeTools.Overview(code.Ready(native)!);
        Assert.Equal(2, overview.Exports);
        Assert.Same(overview, NativeTools.Overview(code.Ready(native)!)); // computed once per name version
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
