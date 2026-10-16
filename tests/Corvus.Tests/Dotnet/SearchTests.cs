using Corvus.Core;

namespace Corvus.Tests;

public class SearchTests : IDisposable
{
    private readonly Env _env = new(withConsumer: true);
    public void Dispose() => _env.Dispose();

    private IReadOnlyList<LoadedAssembly> All => _env.Workspace.Assemblies;

    [Fact]
    public void SymbolsBySubstringWildcardRegexAndRanking()
    {
        var r = _env.Search.SearchSymbols("charge", false, SymbolKind.Any, All, null, 100, default);
        Assert.Contains(r.Items, s => s.Member.Name == "Charge");
        Assert.Contains(r.Items, s => s.Member.Name == "IChargeable");

        var wildcard = _env.Search.SearchSymbols("Charg*", false, SymbolKind.Method, All, null, 100, default);
        Assert.All(wildcard.Items, s => Assert.StartsWith("Charg", s.Member.Name));

        var regex = _env.Search.SearchSymbols("^Check.*w$", true, SymbolKind.Method, All, null, 100, default);
        Assert.Equal("CheckPreview", Assert.Single(regex.Items).Member.Name);

        var exactFirst = _env.Search.SearchSymbols("Account", false, SymbolKind.Any, All, null, 100, default);
        Assert.Equal("Account", exactFirst.Items[0].Member.Name);

        Assert.Throws<ToolError>(() => _env.Search.SearchSymbols("(", true, SymbolKind.Any, All, null, 10, default));
        Assert.Throws<ToolError>(() => _env.Search.SearchSymbols("", false, SymbolKind.Any, All, null, 10, default));
    }

    /// <summary>A calli printed its signature operand as the reader's type name ("dnlib.DotNet.StandAloneSigMD"; C++/CLI code).</summary>
    [Fact]
    public void CalliShowsAndMatchesItsSignature()
    {
        using var dir = new TempDir();
        File.WriteAllBytes(dir.File("Pointers.dll"), Roslyn.Compile("Pointers",
            "public static unsafe class P { public static int Call(delegate* unmanaged[Cdecl]<int, int> f) => f(2); }",
            new Microsoft.CodeAnalysis.CSharp.CSharpCompilationOptions(Microsoft.CodeAnalysis.OutputKind.DynamicallyLinkedLibrary, allowUnsafe: true)));
        using var env = new Env(dir.File("Pointers.dll"));
        var match = Assert.Single(env.Search.SearchIL("calli *int(int)", [env.Fixture], 10, default).Items);
        Assert.Contains("calli unmanaged cdecl int(int)", Assert.Single(match.Instructions));
    }

    [Fact]
    public void TimeLimitFailsWithWhatWasFound()
    {
        var search = new Corvus.Services.SearchService { TimeLimit = TimeSpan.Zero };
        var error = Assert.Throws<ToolError>(() => search.SearchStrings("a", false, All, 10, default));
        Assert.Equal(ErrorCode.Timeout, error.Code);
        var json = System.Text.Json.JsonDocument.Parse(error.ToJson()).RootElement;
        Assert.True(json.GetProperty("retryable").GetBoolean());
        Assert.Equal(0, json.GetProperty("partial").GetProperty("typesSearched").GetInt32());
        Assert.True(json.GetProperty("partial").GetProperty("typesTotal").GetInt32() > 0);
        Assert.Equal(0, json.GetProperty("partial").GetProperty("results").GetArrayLength());

        // A partial result too large to send with an error is dropped and its size reported.
        var big = System.Text.Json.JsonDocument.Parse(ToolError.ErrorJson("timeout", true, "m", null, new { text = string.Concat(Enumerable.Repeat("a,", 3 * ToolError.MaxPartialTokens)) }, new { a = 1 })).RootElement;
        Assert.Equal(System.Text.Json.JsonValueKind.Null, big.GetProperty("partial").ValueKind);
        Assert.Equal(1, big.GetProperty("details").GetProperty("a").GetInt32());
        Assert.True(big.GetProperty("details").GetProperty("partialOmittedChars").GetInt32() > 3 * ToolError.MaxPartialTokens);
    }

    [Fact]
    public void SymbolsByFullNameNamespaceFilterAndLimit()
    {
        var full = _env.Search.SearchSymbols("Model.Account::Charg", false, SymbolKind.Method, All, null, 100, default);
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
        var r = _env.Search.SearchStrings("preview-", false, All, 50, default);
        Assert.Contains(r.Items, h => h.Owner.Name == "CheckPreview" && h.ILOffset != null);
        Assert.Contains(r.Items, h => h.Owner.Name == "Validate");
        var re = _env.Search.SearchStrings(@"^\[Account\]", true, All, 50, default);
        Assert.Contains(re.Items, h => h.Owner.Name == "Log");
    }

    [Theory]
    [InlineData("100", "MaxBalance")]     // const field
    [InlineData("0x3E8", "Score")]       // ldc.i4 1000 in PremiumAccount.Score
    [InlineData("2", "Blue")]            // enum member
    [InlineData("30", ".ctor")]          // dictionary initializer in Shop
    [InlineData("1_000", "Score")]
    public void Constants(string value, string owner) =>
        Assert.Contains(_env.Search.SearchConstants(value, All, 100, default).Items, h => h.Owner.Name == owner);

    [Fact]
    public void AttributeArgumentsOfEveryKind_AreFormattedAndSearchable()
    {
        var tagged = _env.Def<dnlib.DotNet.TypeDef>("Fixture.Model.Tagged", SymbolKind.Type);
        Assert.Equal("[Tags(new int[] { 1, 2, 3 }, 5, typeof(Vec2), Team.Blue, Names = new string[] { \"a\", \"b\" })]",
            Format.Attribute(tagged.CustomAttributes.Single()));
        var marked = _env.Def<dnlib.DotNet.MethodDef>("Tagged::Marked");
        Assert.Equal("[Tags(null, new int[] { 935 }, typeof(int), (Team)7)]", Format.Attribute(marked.CustomAttributes.Single()));
        // a number inside an attribute's array argument is found
        Assert.Contains(_env.Search.SearchConstants("0x3A7", All, 100, default).Items, h => h.Owner.Name == "Marked" && h.Kind == "attribute [TagsAttribute]");
    }

    [Fact]
    public void ConstantsRejectText() =>
        Assert.Throws<ToolError>(() => _env.Search.SearchConstants("hello", All, 10, default));

    [Theory]
    [InlineData("ldstr *PREVIEW*; call *Validate*", "CheckPreview")]
    [InlineData("ldstr \"charged by \"; ...; call *::Log*", "Charge")]
    [InlineData("ldc.i4 0x3E8; ret", "Score")]
    [InlineData("callvirt *IChargeable::Charge*", "Bill")]
    [InlineData("newobj *Account::.ctor*", "Open")]
    [InlineData("ldfld *_balance; ldc.i4.2; mul", "Score")]
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
