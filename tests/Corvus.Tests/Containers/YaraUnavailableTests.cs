using Corvus.Core;
using Corvus.Native.Providers.Worker;
using Corvus.Native.Providers.Worker.Yara;
using Corvus.Services.Analysis;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>The error and the server_status row when the YARA-X library is missing.</summary>
public sealed class YaraUnavailableTests : IDisposable
{
    private readonly TempDir _dir = new();
    public void Dispose() => _dir.Dispose();

    [Fact]
    public async Task A_missing_library_keeps_its_next_step_and_is_not_retryable()
    {
        using var pool = new WorkerPool(new WorkerPoolOptions
        {
            Enabled = true,
            MemoryLimitBytes = 0,
            Start = WorkerPool.OwnCommand() with { Environment = new Dictionary<string, string?> { [YaraX.LibraryVariable] = _dir.File("absent.dll") } },
        });

        var e = await Assert.ThrowsAsync<ToolError>(() => Task.Run(() => YaraSearchKind.Compile("rule a { condition: true }", CancellationToken.None, pool)));

        Assert.Equal(ErrorCode.ProviderUnavailable, e.Code);
        Assert.False(e.Retryable);
        Assert.Contains(YaraX.LibraryVariable, e.NextFor("search_container"));
    }

    [Fact]
    public void Another_unavailable_error_is_not_remapped()
    {
        Assert.Null(YaraX.Remap(new ToolError(ErrorCode.ProviderUnavailable, "The worker host is off.")));
    }

    [Fact]
    public void Server_status_names_the_rule_scanner_with_its_remedy_when_the_library_is_absent()
    {
        var saved = Environment.GetEnvironmentVariable(YaraX.LibraryVariable);
        try
        {
            Environment.SetEnvironmentVariable(YaraX.LibraryVariable, _dir.File("absent.dll"));
            var row = SessionTools.RuleScannerCapability();
            Assert.False(row.Available);
            Assert.Equal("YARA-X", row.Name);
            Assert.Contains(YaraX.LibraryVariable, row.Remediation);
        }
        finally { Environment.SetEnvironmentVariable(YaraX.LibraryVariable, saved); }
    }

    [Fact]
    public void Server_status_reports_the_rule_scanner_version_when_the_library_is_set()
    {
        var saved = Environment.GetEnvironmentVariable(YaraX.LibraryVariable);
        try
        {
            var lib = _dir.File("lib.bin");
            File.WriteAllBytes(lib, [1]);
            Environment.SetEnvironmentVariable(YaraX.LibraryVariable, lib);
            var row = SessionTools.RuleScannerCapability();
            Assert.True(row.Available);
            Assert.Contains(YaraX.Version, row.Detail);
        }
        finally { Environment.SetEnvironmentVariable(YaraX.LibraryVariable, saved); }
    }
}
