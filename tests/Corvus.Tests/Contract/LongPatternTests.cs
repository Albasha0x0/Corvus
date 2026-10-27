using Corvus.Core;
using Corvus.Services;
using Corvus.Services.Mobile;
using static Corvus.Tests.AndroidSamples;

namespace Corvus.Tests;

/// <summary>Patterns of 100k characters match without an internal error; a regex too large for NonBacktracking falls back to a time-limited one.</summary>
public sealed class LongPatternTests : IDisposable
{
    private static readonly string Long = new('a', 100_000);
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    [Fact]
    public void A_long_resource_name_wildcard_matches_nothing()
    {
        var res = new ArscWriter(0x7f, "com.example.app");
        res.String("string", "app_name", "Example");
        var apk = Save(_dir, "res.apk", ContainerFixtures.Zip([("AndroidManifest.xml", Manifest()), ("resources.arsc", res.Build())]));
        var service = new AndroidPackageService();

        Assert.Empty(service.Resources(apk, null, Long + "*", null, 0, 10).Items);
        Assert.Single(service.Resources(apk, null, "app*", null, 0, 10).Items);
    }

    [Theory]
    [InlineData("")]
    [InlineData("*")]
    public void A_long_dex_query_matches_nothing(string suffix)
    {
        var apk = Save(_dir, "app.apk", Apk(30, ("classes.dex", Dex())));
        var service = new DexService();

        Assert.Equal(0, service.ListClasses(apk, Long + suffix, null, 0, 10, default).Total);
        Assert.Empty(service.Search(apk, "string", Long + suffix, 0, 10, default).Items);
        Assert.Equal(3, service.ListClasses(apk, "com.example*", null, 0, 10, default).Total);
    }

    [Fact]
    public void A_long_il_operand_wildcard_matches_nothing()
    {
        var search = new SearchService();
        Assert.Empty(search.SearchIL("ldstr *" + Long + "*", [], 10, default).Items);
        Assert.False(SearchService.CreateMatcher(Long + "*", regex: false)("aaa"));
    }

    [Fact]
    public void A_long_user_regex_falls_back_to_a_time_limited_one()
    {
        var regex = RegexTimeouts.Create(Long);
        Assert.Equal(RegexTimeouts.Limit, regex.MatchTimeout);
        Assert.False(SearchService.CreateMatcher(Long, regex: true)("aaa"));
    }
}
