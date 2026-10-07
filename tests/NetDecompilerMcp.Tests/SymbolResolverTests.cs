using dnlib.DotNet;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Tests;

public class SymbolResolverTests : IDisposable
{
    private readonly Env _env = new();
    public void Dispose() => _env.Dispose();

    [Theory]
    [InlineData("Fixture.Game.Player", "Fixture.Game.Player")]
    [InlineData("Player", "Fixture.Game.Player")]
    [InlineData("player", "Fixture.Game.Player")]
    [InlineData("  Fixture.Game.Player  ", "Fixture.Game.Player")]
    [InlineData("Fixture.Game.Player+Inventory", "Fixture.Game.Player/Inventory")]
    [InlineData("Fixture.Game.Player/Inventory", "Fixture.Game.Player/Inventory")]
    [InlineData("Fixture.Game.Player.Inventory", "Fixture.Game.Player/Inventory")]
    [InlineData("Player.Inventory", "Fixture.Game.Player/Inventory")]
    [InlineData("Player+Inventory", "Fixture.Game.Player/Inventory")]
    [InlineData("Container<T>", "Fixture.Game.Container`1")]
    [InlineData("Fixture.Game.Container`1", "Fixture.Game.Container`1")]
    [InlineData("Container", "Fixture.Game.Container`1")]
    [InlineData("Il2CppDummyDll.AddressAttribute", "Il2CppDummyDll.AddressAttribute")]
    public void ResolvesTypeForms(string query, string expected) =>
        Assert.Equal(expected, _env.Def<TypeDef>(query, SymbolKind.Type).FullName);

    [Theory]
    [InlineData("Fixture.Game.Player::CheckLicense")]
    [InlineData("Fixture.Game.Player.CheckLicense")]
    [InlineData("Player::CheckLicense")]
    [InlineData("Player.CheckLicense()")]
    [InlineData("player::checklicense")]
    public void ResolvesMethodForms(string query) => Assert.Equal("CheckLicense", _env.One(query).Member.Name);

    [Fact]
    public void OverloadsAreAllReturnedAndSignatureNarrows()
    {
        Assert.Equal(2, SymbolResolver.Resolve(_env.Workspace, null, "Player::TakeDamage").Count);
        Assert.Equal(2, _env.Def<MethodDef>("Player::TakeDamage(int, string)").MethodSig.Params.Count);
        Assert.Single(_env.Def<MethodDef>("Player::TakeDamage(System.Int32)").MethodSig.Params);
        Assert.Single(_env.Def<MethodDef>("Player::TakeDamage(int amount)").MethodSig.Params);
        var ex = Assert.Throws<ToolError>(() => _env.One("Player::TakeDamage"));
        Assert.Contains("ambiguous", ex.Message);
        Assert.Contains("0x06", ex.Message); // candidates come with tokens
    }

    [Theory]
    [InlineData("Player::.ctor")]
    [InlineData("Player::ctor")]
    [InlineData("Player::#ctor")]
    [InlineData("Fixture.Game.Player..ctor")]
    public void ResolvesConstructors(string query) => Assert.True(_env.Def<MethodDef>(query).IsConstructor);

    [Fact]
    public void ResolvesTokensWithAndWithoutPrefix()
    {
        var player = _env.Def<TypeDef>("Player");
        Assert.Same(player, _env.One($"0x{player.MDToken.Raw:X8}").Member);
        var method = player.FindMethod("CheckLicense");
        Assert.Same(method, _env.One($"{method.MDToken.Raw:X8}").Member);
        Assert.Same(method, _env.One($"0x{method.MDToken.Raw:x8}").Member);
        Assert.Throws<ToolError>(() => _env.One("0x06FFFFFF"));
        Assert.Throws<ToolError>(() => _env.One("0x0600FFFF", SymbolKind.Type));
    }

    [Fact]
    public void PropertiesFieldsEventsAndNestedTypesAsMembers()
    {
        Assert.IsAssignableFrom<PropertyDef>(_env.One("Player::Health").Member);
        Assert.IsAssignableFrom<FieldDef>(_env.One("Player::_health").Member);
        Assert.IsAssignableFrom<EventDef>(_env.One("Player::Died").Member); // event preferred over its backing field
        Assert.IsAssignableFrom<FieldDef>(_env.One("Player::Died", SymbolKind.Field).Member);
        Assert.IsAssignableFrom<TypeDef>(_env.One("Player::Inventory").Member);
        Assert.IsAssignableFrom<PropertyDef>(_env.One("Shop::Item").Member); // indexer
    }

    [Fact]
    public void GenericMethodNameWithTypeArguments() =>
        Assert.Equal("Pick", _env.One("Shop::Pick<T>").Member.Name);

    [Fact]
    public void NotFoundGivesSuggestions()
    {
        var member = Assert.Throws<ToolError>(() => _env.One("Player::TakeDmg"));
        Assert.Contains("TakeDamage", member.Message);
        var type = Assert.Throws<ToolError>(() => _env.One("Fixture.Game.Playr"));
        Assert.Contains("not found", type.Message);
        Assert.Throws<ToolError>(() => _env.One(""));
        Assert.Throws<ToolError>(() => _env.One("Player::"));
    }

    [Fact]
    public void BareMemberNames_AreSearchedInEveryType()
    {
        Assert.Equal("Fixture.Game.Player::CheckLicense()", _env.One("CheckLicense").Label);
        Assert.Equal("Fixture.Game.Player::CheckLicense()", _env.One("checklicense").Label); // case-insensitive when nothing matches exactly
        Assert.Equal("_health", _env.One("_health", SymbolKind.Field).Member.Name);
        // the same name on several types: all of them, and the ambiguity error lists them
        var score = SymbolResolver.Resolve(_env.Workspace, null, "Score");
        Assert.Contains(score, s => s.Label == "Fixture.Game.Entity::Score()");
        Assert.Contains(score, s => s.Label == "Fixture.Game.Boss::Score()");
        Assert.Contains("Fixture.Game.Boss::Score()", Assert.Throws<ToolError>(() => _env.One("Score")).Message);
        // a signature narrows overloads; a type name still resolves to the type first
        Assert.Equal(2, _env.One("TakeDamage(int, string)").Member is MethodDef m ? m.Parameters.Count - 1 : 0);
        Assert.IsAssignableFrom<TypeDef>(_env.One("Player").Member);
        Assert.Contains("not found", Assert.Throws<ToolError>(() => _env.One("NoSuchMemberAnywhere")).Message);
    }

    [Fact]
    public void KindFilterAndParsing()
    {
        Assert.Equal(SymbolKind.Method, SymbolResolver.ParseKind("Methods"));
        Assert.Equal(SymbolKind.Any, SymbolResolver.ParseKind(null));
        Assert.Throws<ToolError>(() => SymbolResolver.ParseKind("banana"));
        Assert.Throws<ToolError>(() => _env.One("Player::Health", SymbolKind.Method));
    }

    [Fact]
    public void UnknownAssemblyListsLoaded()
    {
        var ex = Assert.Throws<ToolError>(() => SymbolResolver.Resolve(_env.Workspace, "Nope", "Player"));
        Assert.Contains("TestFixture", ex.Message);
    }

    [Theory]
    [InlineData("Dictionary<TKey, TValue>", "Dictionary`2")]
    [InlineData("List<Dictionary<int,string>>", "List`1")]
    [InlineData("Outer+Inner<T>", "Outer/Inner`1")]
    public void NormalizesGenericSyntax(string input, string expected) =>
        Assert.Equal(expected, SymbolResolver.NormalizeTypeName(input));
}
