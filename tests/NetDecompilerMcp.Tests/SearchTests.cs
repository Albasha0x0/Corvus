using NetDecompilerMcp.Core;
using NetDecompilerMcp.Services;

namespace NetDecompilerMcp.Tests;

public class SearchTests : IDisposable
{
    private readonly Env _env = new(withConsumer: true);
    public void Dispose() => _env.Dispose();

    private IReadOnlyList<LoadedAssembly> All => _env.Workspace.Assemblies;

    [Fact]
    public void SymbolsBySubstringWildcardRegexAndRanking()
    {
        var r = _env.Search.SearchSymbols("damage", false, SymbolKind.Any, All, null, 100, default);
        Assert.Contains(r.Items, s => s.Member.Name == "TakeDamage");
        Assert.Contains(r.Items, s => s.Member.Name == "IDamageable");

        var wildcard = _env.Search.SearchSymbols("Take*", false, SymbolKind.Method, All, null, 100, default);
        Assert.All(wildcard.Items, s => Assert.StartsWith("Take", s.Member.Name));

        var regex = _env.Search.SearchSymbols("^Check.*e$", true, SymbolKind.Method, All, null, 100, default);
        Assert.Equal("CheckLicense", Assert.Single(regex.Items).Member.Name);

        var exactFirst = _env.Search.SearchSymbols("Player", false, SymbolKind.Any, All, null, 100, default);
        Assert.Equal("Player", exactFirst.Items[0].Member.Name);

        Assert.Throws<ToolError>(() => _env.Search.SearchSymbols("(", true, SymbolKind.Any, All, null, 10, default));
        Assert.Throws<ToolError>(() => _env.Search.SearchSymbols("", false, SymbolKind.Any, All, null, 10, default));
    }

    [Fact]
    public void SymbolsByFullNameNamespaceFilterAndLimit()
    {
        var full = _env.Search.SearchSymbols("Game.Player::Take", false, SymbolKind.Method, All, null, 100, default);
        Assert.Equal(2, full.Total);
        var ns = _env.Search.SearchSymbols("a", false, SymbolKind.Type, All, "Consumer", 100, default);
        Assert.All(ns.Items, s => Assert.Equal("TestFixture.Consumer", s.Assembly.Id));
        var limited = _env.Search.SearchSymbols("e", false, SymbolKind.Any, All, null, 3, default);
        Assert.Equal(3, limited.Items.Count);
        Assert.True(limited.Total > limited.Items.Count);
    }

    [Fact]
    public void StringsInBodiesAndConstants()
    {
        var r = _env.Search.SearchStrings("license-", false, All, 50, default);
        Assert.Contains(r.Items, h => h.Owner.Name == "CheckLicense" && h.ILOffset != null);
        Assert.Contains(r.Items, h => h.Owner.Name == "Validate");
        var re = _env.Search.SearchStrings(@"^\[Player\]", true, All, 50, default);
        Assert.Contains(re.Items, h => h.Owner.Name == "Log");
    }

    [Theory]
    [InlineData("100", "MaxHealth")]     // const field
    [InlineData("0x3E8", "Score")]       // ldc.i4 1000 in Boss.Score
    [InlineData("2", "Blue")]            // enum member
    [InlineData("30", ".ctor")]          // dictionary initializer in Shop
    [InlineData("1_000", "Score")]
    public void Constants(string value, string owner) =>
        Assert.Contains(_env.Search.SearchConstants(value, All, 100, default).Items, h => h.Owner.Name == owner);

    [Fact]
    public void ConstantsRejectText() =>
        Assert.Throws<ToolError>(() => _env.Search.SearchConstants("hello", All, 10, default));

    [Theory]
    [InlineData("ldstr *LICENSE*; call *Validate*", "CheckLicense")]
    [InlineData("ldstr \"hit by \"; ...; call *::Log*", "TakeDamage")]
    [InlineData("ldc.i4 0x3E8; ret", "Score")]
    [InlineData("callvirt *IDamageable::TakeDamage*", "Hit")]
    [InlineData("newobj *Player::.ctor*", "Spawn")]
    [InlineData("ldfld *_health; ldc.i4.2; mul", "Score")]
    public void IlPatterns(string pattern, string method)
    {
        var r = _env.Search.SearchIL(pattern, All, 50, default);
        var match = Assert.Single(r.Items, m => m.Method.Name == method);
        Assert.NotEmpty(match.Instructions);
    }

    [Fact]
    public void IlPatternErrors()
    {
        Assert.Throws<ToolError>(() => _env.Search.SearchIL("", All, 10, default));
        Assert.Throws<ToolError>(() => _env.Search.SearchIL("...", All, 10, default));
        Assert.Empty(_env.Search.SearchIL("ldstr *does-not-exist*", All, 10, default).Items);
    }
}
