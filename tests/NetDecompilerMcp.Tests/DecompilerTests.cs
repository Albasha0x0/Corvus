using dnlib.DotNet;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Tests;

public class DecompilerTests : IDisposable
{
    private readonly Env _env = new();
    public void Dispose() => _env.Dispose();

    [Fact]
    public void DecompilesTypeWithNestedTypes()
    {
        var code = _env.Decompiler.DecompileType(_env.Fixture, _env.Def<TypeDef>("Player"), default);
        Assert.Contains("public class Player : Entity, IDamageable", code);
        Assert.Contains("TakeDamage(int amount, string source)", code);
        Assert.Contains("class Inventory", code);
        Assert.Contains("public const int MaxHealth = 100;", code);
    }

    [Theory]
    [InlineData("Player::LoadAsync", "await Task.Delay(1)")]
    [InlineData("Player::Range", "yield return 1")]
    [InlineData("Player::SumPositive", "v > 0")]
    [InlineData("Player::Health", "get")]
    [InlineData("Player::Died", "event EventHandler")]
    [InlineData("Player::_health", "private int _health")]
    [InlineData("Player::.ctor", "PlayerCount++")]
    [InlineData("Vec2::Length", "MathF.Sqrt")]
    public void DecompilesMembersBackToSource(string symbol, string expected) =>
        Assert.Contains(expected, _env.Decompile(symbol));

    [Theory]
    [InlineData("Team", "Red = 1")]
    [InlineData("IDamageable", "interface IDamageable")]
    [InlineData("Vec2", "struct Vec2")]
    [InlineData("Container", "where T : class")]
    public void DecompilesEveryTypeKind(string type, string expected) =>
        Assert.Contains(expected, _env.Decompiler.DecompileType(_env.Fixture, _env.Def<TypeDef>(type, SymbolKind.Type), default));

    [Fact]
    public void DisassemblesWithTokensAndOffsets()
    {
        var il = _env.Decompiler.Disassemble(_env.Fixture, _env.One("Player::CheckLicense").Member, default);
        Assert.Contains("ldstr \"LICENSE-KEY-123\"", il);
        Assert.Contains("IL_0000", il);
        Assert.Matches(@"/\* 06[0-9A-F]{6} \*/", il);
    }

    [Fact]
    public void DisassemblesTypesFieldsPropertiesEvents()
    {
        foreach (var symbol in new[] { "Player", "Player::_health", "Player::Health", "Player::Died" })
            Assert.False(string.IsNullOrWhiteSpace(_env.Decompiler.Disassemble(_env.Fixture, _env.One(symbol).Member, default)));
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
        Assert.Contains(Directory.EnumerateFiles(dir.Path, "*.cs", SearchOption.AllDirectories), f => f.EndsWith("Player.cs"));
        Assert.Throws<ToolError>(() => _env.Decompiler.ExportProject(_env.Fixture, dir.Path, null, default));
    }

    [Fact]
    public void AssemblyAttributes() =>
        Assert.Contains("TargetFramework", _env.Decompiler.DecompileAssemblyAttributes(_env.Fixture, default));

    [Fact]
    public void TimeoutProducesClearError()
    {
        using var env = new Env();
        var options = new ServerOptions { TimeoutSeconds = 5 };
        var decompiler = new Services.DecompilerService(env.Workspace, options);
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        // Caller cancellation propagates as cancellation (not a tool error).
        Assert.ThrowsAny<OperationCanceledException>(() => decompiler.DecompileType(env.Fixture, env.Def<TypeDef>("Player"), cts.Token));
    }

    [Fact]
    public void AssemblyReportCoversIdentityPeAndReferences()
    {
        var report = _env.Report.Build(_env.Fixture);
        foreach (var expected in new[] { "Id: TestFixture", "Target framework", "PE32", "Sections:", ".text", "Metadata streams", "References:", "System.Runtime", "Il2Cpp metadata: 2 methods" })
            Assert.Contains(expected, report);
    }
}
