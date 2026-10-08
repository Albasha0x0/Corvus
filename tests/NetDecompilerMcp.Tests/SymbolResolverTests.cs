using dnlib.DotNet;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Tests;

public class SymbolResolverTests : IDisposable
{
    private readonly Env _env = new();
    public void Dispose() => _env.Dispose();

    [Theory]
    [InlineData("Fixture.Model.Account", "Fixture.Model.Account")]
    [InlineData("Account", "Fixture.Model.Account")]
    [InlineData("account", "Fixture.Model.Account")]
    [InlineData("  Fixture.Model.Account  ", "Fixture.Model.Account")]
    [InlineData("Fixture.Model.Account+Inventory", "Fixture.Model.Account/Inventory")]
    [InlineData("Fixture.Model.Account/Inventory", "Fixture.Model.Account/Inventory")]
    [InlineData("Fixture.Model.Account.Inventory", "Fixture.Model.Account/Inventory")]
    [InlineData("Account.Inventory", "Fixture.Model.Account/Inventory")]
    [InlineData("Account+Inventory", "Fixture.Model.Account/Inventory")]
    [InlineData("Container<T>", "Fixture.Model.Container`1")]
    [InlineData("Fixture.Model.Container`1", "Fixture.Model.Container`1")]
    [InlineData("Container", "Fixture.Model.Container`1")]
    [InlineData("Il2CppDummyDll.AddressAttribute", "Il2CppDummyDll.AddressAttribute")]
    public void ResolvesTypeForms(string query, string expected) =>
        Assert.Equal(expected, _env.Def<TypeDef>(query, SymbolKind.Type).FullName);

    [Theory]
    [InlineData("Fixture.Model.Account::CheckLicense")]
    [InlineData("Fixture.Model.Account.CheckLicense")]
    [InlineData("Account::CheckLicense")]
    [InlineData("Account.CheckLicense()")]
    [InlineData("account::checklicense")]
    public void ResolvesMethodForms(string query) => Assert.Equal("CheckLicense", _env.One(query).Member.Name);

    [Fact]
    public void OverloadsAreAllReturnedAndSignatureNarrows()
    {
        Assert.Equal(2, SymbolResolver.Resolve(_env.Workspace, null, "Account::Charge").Count);
        Assert.Equal(2, _env.Def<MethodDef>("Account::Charge(int, string)").MethodSig.Params.Count);
        Assert.Single(_env.Def<MethodDef>("Account::Charge(System.Int32)").MethodSig.Params);
        Assert.Single(_env.Def<MethodDef>("Account::Charge(int amount)").MethodSig.Params);
        var ex = Assert.Throws<ToolError>(() => _env.One("Account::Charge"));
        Assert.Contains("ambiguous", ex.Message);
        Assert.Contains("0x06", ex.Message); // candidates come with tokens
    }

    [Theory]
    [InlineData("Account::.ctor")]
    [InlineData("Account::ctor")]
    [InlineData("Account::#ctor")]
    [InlineData("Fixture.Model.Account..ctor")]
    public void ResolvesConstructors(string query) => Assert.True(_env.Def<MethodDef>(query).IsConstructor);

    [Fact]
    public void ResolvesTokensWithAndWithoutPrefix()
    {
        var account = _env.Def<TypeDef>("Account");
        Assert.Same(account, _env.One($"0x{account.MDToken.Raw:X8}").Member);
        var method = account.FindMethod("CheckLicense");
        Assert.Same(method, _env.One($"{method.MDToken.Raw:X8}").Member);
        Assert.Same(method, _env.One($"0x{method.MDToken.Raw:x8}").Member);
        Assert.Throws<ToolError>(() => _env.One("0x06FFFFFF"));
        Assert.Throws<ToolError>(() => _env.One("0x0600FFFF", SymbolKind.Type));
    }

    [Fact]
    public void PropertiesFieldsEventsAndNestedTypesAsMembers()
    {
        Assert.IsAssignableFrom<PropertyDef>(_env.One("Account::Balance").Member);
        Assert.IsAssignableFrom<FieldDef>(_env.One("Account::_balance").Member);
        Assert.IsAssignableFrom<EventDef>(_env.One("Account::Closed").Member); // event preferred over its backing field
        Assert.IsAssignableFrom<FieldDef>(_env.One("Account::Closed", SymbolKind.Field).Member);
        Assert.IsAssignableFrom<TypeDef>(_env.One("Account::Inventory").Member);
        Assert.IsAssignableFrom<PropertyDef>(_env.One("Shop::Item").Member); // indexer
    }

    [Fact]
    public void GenericMethodNameWithTypeArguments() =>
        Assert.Equal("Pick", _env.One("Shop::Pick<T>").Member.Name);

    [Fact]
    public void NotFoundGivesSuggestions()
    {
        var member = Assert.Throws<ToolError>(() => _env.One("Account::Chrge"));
        Assert.Contains("Charge", member.Message);
        var type = Assert.Throws<ToolError>(() => _env.One("Fixture.Model.Acount"));
        Assert.Contains("not found", type.Message);
        Assert.Throws<ToolError>(() => _env.One(""));
        Assert.Throws<ToolError>(() => _env.One("Account::"));
    }

    [Fact]
    public void BareMemberNames_AreSearchedInEveryType()
    {
        Assert.Equal("Fixture.Model.Account::CheckLicense()", _env.One("CheckLicense").Label);
        Assert.Equal("Fixture.Model.Account::CheckLicense()", _env.One("checklicense").Label); // case-insensitive when nothing matches exactly
        Assert.Equal("_balance", _env.One("_balance", SymbolKind.Field).Member.Name);
        // the same name on several types: all of them, and the ambiguity error lists them
        var score = SymbolResolver.Resolve(_env.Workspace, null, "Score");
        Assert.Contains(score, s => s.Label == "Fixture.Model.Entity::Score()");
        Assert.Contains(score, s => s.Label == "Fixture.Model.PremiumAccount::Score()");
        Assert.Contains("Fixture.Model.PremiumAccount::Score()", Assert.Throws<ToolError>(() => _env.One("Score")).Message);
        // a signature narrows overloads; a type name still resolves to the type first
        Assert.Equal(2, _env.One("Charge(int, string)").Member is MethodDef m ? m.Parameters.Count - 1 : 0);
        Assert.IsAssignableFrom<TypeDef>(_env.One("Account").Member);
        Assert.Contains("not found", Assert.Throws<ToolError>(() => _env.One("NoSuchMemberAnywhere")).Message);
    }

    [Fact]
    public void KindFilterAndParsing()
    {
        Assert.Equal(SymbolKind.Method, SymbolResolver.ParseKind("Methods"));
        Assert.Equal(SymbolKind.Any, SymbolResolver.ParseKind(null));
        Assert.Throws<ToolError>(() => SymbolResolver.ParseKind("banana"));
        Assert.Throws<ToolError>(() => _env.One("Account::Balance", SymbolKind.Method));
    }

    [Fact]
    public void UnknownAssemblyListsLoaded()
    {
        var ex = Assert.Throws<ToolError>(() => SymbolResolver.Resolve(_env.Workspace, "Nope", "Account"));
        Assert.Contains("TestFixture", ex.Message);
    }

    [Theory]
    [InlineData("Dictionary<TKey, TValue>", "Dictionary`2")]
    [InlineData("List<Dictionary<int,string>>", "List`1")]
    [InlineData("Outer+Inner<T>", "Outer/Inner`1")]
    public void NormalizesGenericSyntax(string input, string expected) =>
        Assert.Equal(expected, SymbolResolver.NormalizeTypeName(input));
}
