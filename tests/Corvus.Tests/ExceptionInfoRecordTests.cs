using Corvus.Core;
using Corvus.Mcp;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>get_exception_info's record on MSVC metadata: the scheme, handlers and protected ranges of one function, and the image counts.</summary>
public class ExceptionInfoRecordTests
{
    private static readonly string Kernel32 = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "kernel32.dll");

    [WindowsFact]
    public async Task Msvc_frames_give_handlers_ranges_and_counts()
    {
        using var env = new Env();
        var code = new NativeCodeService(env.Workspace, env.Options);
        var tools = new NativeExceptionTools(env.Workspace, code, env.Pager);
        var collector = ToolOutput.Collect();
        await tools.GetExceptionInfo(Kernel32);
        var summary = Assert.IsType<ExceptionReport>(collector.Value);
        Assert.True(summary.Counts!["frames"] > 0);

        var native = env.Workspace.Read(() => env.Workspace.GetNative("kernel32.dll"));
        var index = await code.Index(native, null, default);
        var frame = index.ExceptionInfo.Frames.First(f => f.Scopes.Any(s => s.BeginRva != null));
        await tools.GetExceptionInfo("kernel32.dll", $"rva:0x{frame.FunctionRva:X}");
        var one = Assert.IsType<ExceptionReport>(collector.Value);
        Assert.Equal("msvc", one.Format);
        Assert.Contains("__C_specific_handler", one.Scheme);
        Assert.Contains(one.Ranges, r => r.Kind is "except" or "finally");
    }
}
