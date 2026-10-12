using dnlib.DotNet;
using Corvus.Core;

namespace Corvus.Tests;

public class DecompilerTests : IDisposable
{
    private readonly Env _env = new();
    public void Dispose() => _env.Dispose();

    [Fact]
    public void DecompilesTypeWithNestedTypes()
    {
        var code = _env.Decompiler.DecompileType(_env.Fixture, _env.Def<TypeDef>("Account"), default);
        Assert.Contains("public class Account : Entity, IChargeable", code);
        Assert.Contains("Charge(int amount, string source)", code);
        Assert.Contains("class Inventory", code);
        Assert.Contains("public const int MaxBalance = 100;", code);
    }

    [Theory]
    [InlineData("Account::LoadAsync", "await Task.Delay(1)")]
    [InlineData("Account::Range", "yield return 1")]
    [InlineData("Account::SumPositive", "v > 0")]
    [InlineData("Account::Balance", "get")]
    [InlineData("Account::get_Balance", "public int Balance")] // an accessor alone was a bare block
    [InlineData("Account::add_Closed", "event EventHandler")]
    [InlineData("Account::Closed", "event EventHandler")]
    [InlineData("Account::_balance", "private int _balance")]
    [InlineData("Account::.ctor", "AccountCount++")]
    [InlineData("Vec2::Length", "MathF.Sqrt")]
    public void DecompilesMembersBackToSource(string symbol, string expected) =>
        Assert.Contains(expected, _env.Decompile(symbol));

    [Theory]
    [InlineData("Team", "Red = 1")]
    [InlineData("IChargeable", "interface IChargeable")]
    [InlineData("Vec2", "struct Vec2")]
    [InlineData("Container", "where T : class")]
    public void DecompilesEveryTypeKind(string type, string expected) =>
        Assert.Contains(expected, _env.Decompiler.DecompileType(_env.Fixture, _env.Def<TypeDef>(type, SymbolKind.Type), default));

    [Fact]
    public void DisassemblesWithTokensAndOffsets()
    {
        var il = _env.Decompiler.Disassemble(_env.Fixture, _env.One("Account::CheckLicense").Member, default);
        Assert.Contains("ldstr \"LICENSE-KEY-123\"", il);
        Assert.Contains("IL_0000", il);
        Assert.Matches(@"/\* 06[0-9A-F]{6} \*/", il);
    }

    [Fact]
    public void DisassemblesTypesFieldsPropertiesEvents()
    {
        foreach (var (symbol, directive) in new[] { ("Account", ".class"), ("Account::_balance", ".field"), ("Account::Balance", ".property"), ("Account::Closed", ".event") })
            Assert.Contains(directive, _env.Decompiler.Disassemble(_env.Fixture, _env.One(symbol).Member, default));
    }

    [Fact]
    public void ExportsProjectWithProgressAndRefusesNonEmptyDirectory()
    {
        using var dir = new TempDir();
        var progress = new List<string>();
        var result = _env.Decompiler.ExportProject(_env.Fixture, dir.Path, (_, _, s) => progress.Add(s), default);
        Assert.NotNull(result.ProjectFile);
        Assert.True(result.FileCount > 3);
        Assert.Empty(result.FailedTypes);
        Assert.Contains(Directory.EnumerateFiles(dir.Path, "*.cs", SearchOption.AllDirectories), f => f.EndsWith("Account.cs"));
        Assert.Throws<ToolError>(() => _env.Decompiler.ExportProject(_env.Fixture, dir.Path, null, default));
    }

    [Fact]
    public async Task ExportRunningThroughTheTool_DoesNotHoldUpWriters()
    {
        using var env = new Env(typeof(AssemblyWorkspace).Assembly.Location); // large enough to be mid-export
        using var dir = new TempDir();
        using var cts = new CancellationTokenSource();
        var export = new Corvus.Tools.DecompileTools(env.Workspace, env.Decompiler, env.Pager).ExportProject(env.Fixture.Id, dir.Path, null!, cts.Token);
        var waited = System.Diagnostics.Stopwatch.StartNew();
        while (!Directory.EnumerateFiles(dir.Path, "*.cs", SearchOption.AllDirectories).Any() && !export.IsCompleted && waited.Elapsed < TimeSpan.FromSeconds(60))
            await Task.Delay(20);
        Assert.False(export.IsCompleted, "the export finished before a writer could be queued");
        var write = System.Diagnostics.Stopwatch.StartNew();
        await Task.Run(() => env.Workspace.Write(() => 0));
        Assert.True(write.Elapsed < TimeSpan.FromSeconds(1), $"the write waited {write.Elapsed}");
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => export);
    }

    [Fact]
    public void AssemblyAttributes() =>
        Assert.Contains("TargetFramework", _env.Decompiler.DecompileAssemblyAttributes(_env.Fixture, default));

    [Fact]
    public void CallerCancellation_IsNotAToolError()
    {
        using var env = new Env();
        var decompiler = new Services.DecompilerService(env.Workspace, new ServerOptions());
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        // Caller cancellation is not converted to a ToolError.
        Assert.ThrowsAny<OperationCanceledException>(() => decompiler.DecompileType(env.Fixture, env.Def<TypeDef>("Account"), cts.Token));
    }

    [Fact]
    public void AssemblyReportCoversIdentityPeAndReferences()
    {
        var report = _env.Report.Build(_env.Fixture);
        foreach (var expected in new[] { "Id: TestFixture", "Target framework", "PE32", "Sections:", ".text", "Metadata streams", "References:", "System.Runtime", "Il2Cpp metadata: 2 methods" })
            Assert.Contains(expected, report);
    }
}
