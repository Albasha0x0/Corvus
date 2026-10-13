using Corvus.Core;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>ida_python arguments without IDA: code or file, output limit, missing file (NativeIdaTypeTests runs scripts in IDA).</summary>
public sealed class EngineScriptToolTests
{
    [Fact]
    public async Task Arguments_are_checked_before_any_engine_starts()
    {
        using var dir = new TempDir();
        var options = new ServerOptions { IdaScripting = true };
        using var workspace = new AssemblyWorkspace(options);
        using var engines = new NativeEngineService();
        var tools = new EngineScriptTools(workspace, engines, options);
        Task<string> Run(string? code = null, string? file = null) => tools.IdaPython("x.dll", code, file: file);
        Assert.Equal("Pass code or file.", (await Assert.ThrowsAsync<ToolError>(() => Run())).Message);
        Assert.Equal("Pass code or file, not both.", (await Assert.ThrowsAsync<ToolError>(() => Run("1", "a.py"))).Message);
        Assert.Equal(ErrorCode.NotFound, (await Assert.ThrowsAsync<ToolError>(() => Run(file: dir.File("missing.py")))).Code);
        var off = new EngineScriptTools(workspace, engines, new ServerOptions());
        Assert.Equal(ErrorCode.Unsupported, (await Assert.ThrowsAsync<ToolError>(() => off.IdaPython("x.dll", "1"))).Code);
    }
}
