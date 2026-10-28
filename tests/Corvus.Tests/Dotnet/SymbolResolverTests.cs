using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Corvus.Core;

namespace Corvus.Tests;

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
    public void Resolves_type_forms(string query, string expected) =>
        Assert.Equal(expected, _env.Def<TypeDef>(query, SymbolKind.Type).FullName);

    [Theory]
    [InlineData("Fixture.Model.Account::CheckPreview")]
    [InlineData("Fixture.Model.Account.CheckPreview")]
    [InlineData("Account::CheckPreview")]
    [InlineData("Account.CheckPreview()")]
    [InlineData("account::checkpreview")]
    public void Resolves_method_forms(string query) => Assert.Equal("CheckPreview", _env.One(query).Member.Name);

    [Fact]
    public void Overloads_are_all_returned_and_signature_narrows()
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
    public void Resolves_constructors(string query) => Assert.True(_env.Def<MethodDef>(query).IsConstructor);

    [Fact]
    public void Resolves_tokens_with_and_without_prefix()
    {
        var account = _env.Def<TypeDef>("Account");
        Assert.Same(account, _env.One($"0x{account.MDToken.Raw:X8}").Member);
        var method = account.FindMethod("CheckPreview");
        Assert.Same(method, _env.One($"{method.MDToken.Raw:X8}").Member);
        Assert.Same(method, _env.One($"0x{method.MDToken.Raw:x8}").Member);
        Assert.Throws<ToolError>(() => _env.One("0x06FFFFFF"));
        Assert.Throws<ToolError>(() => _env.One("0x0600FFFF", SymbolKind.Type));
    }

    [Fact]
    public void Properties_fields_events_and_nested_types_resolve_as_members()
    {
        Assert.IsAssignableFrom<PropertyDef>(_env.One("Account::Balance").Member);
        Assert.IsAssignableFrom<FieldDef>(_env.One("Account::_balance").Member);
        Assert.IsAssignableFrom<EventDef>(_env.One("Account::Closed").Member); // event preferred over its backing field
        Assert.IsAssignableFrom<FieldDef>(_env.One("Account::Closed", SymbolKind.Field).Member);
        Assert.IsAssignableFrom<TypeDef>(_env.One("Account::Inventory").Member);
        Assert.IsAssignableFrom<PropertyDef>(_env.One("Shop::Item").Member); // indexer
    }

    [Fact]
    public void A_generic_method_name_with_type_arguments_resolves() =>
        Assert.Equal("Pick", _env.One("Shop::Pick<T>").Member.Name);

    /// <summary>Every method label (generic ones as Method&lt;T&gt;(...)) resolves back to the methods that carry it.</summary>
    [Fact]
    public void Method_labels_round_trip()
    {
        var methods = _env.Fixture.Module.GetTypes().SelectMany(t => t.Methods).ToList();
        Assert.Contains(methods, m => m.HasGenericParameters && Format.MemberLabel(m).Contains("<T>(", StringComparison.Ordinal));
        foreach (var group in methods.GroupBy(m => Format.MemberLabel(m)))
        {
            var resolved = SymbolResolver.Resolve(_env.Workspace, _env.Fixture.Id, group.Key, SymbolKind.Method).Select(r => r.Member).ToHashSet();
            Assert.True(resolved.SetEquals(group), group.Key);
        }
    }

    [Fact]
    public void Not_found_gives_suggestions()
    {
        var member = Assert.Throws<ToolError>(() => _env.One("Account::Chrge"));
        Assert.Contains("Charge", member.Message);
        var type = Assert.Throws<ToolError>(() => _env.One("Fixture.Model.Acount"));
        Assert.Contains("not found", type.Message);
        Assert.Throws<ToolError>(() => _env.One(""));
        Assert.Throws<ToolError>(() => _env.One("Account::"));
    }

    [Fact]
    public void Bare_member_names_are_searched_in_every_type()
    {
        Assert.Equal("Fixture.Model.Account::CheckPreview()", _env.One("CheckPreview").Label);
        Assert.Equal("Fixture.Model.Account::CheckPreview()", _env.One("checkpreview").Label); // case-insensitive when nothing matches exactly
        Assert.Equal("_balance", _env.One("_balance", SymbolKind.Field).Member.Name);
        // The same name on several types: all of them, and the ambiguity error lists them.
        var score = SymbolResolver.Resolve(_env.Workspace, null, "Score");
        Assert.Contains(score, s => s.Label == "Fixture.Model.Entity::Score()");
        Assert.Contains(score, s => s.Label == "Fixture.Model.PremiumAccount::Score()");
        Assert.Contains("Fixture.Model.PremiumAccount::Score()", Assert.Throws<ToolError>(() => _env.One("Score")).Message);
        // A signature narrows overloads; a type name still resolves to the type first.
        Assert.Equal(2, _env.One("Charge(int, string)").Member is MethodDef m ? m.Parameters.Count - 1 : 0);
        Assert.IsAssignableFrom<TypeDef>(_env.One("Account").Member);
        Assert.Contains("not found", Assert.Throws<ToolError>(() => _env.One("NoSuchMemberAnywhere")).Message);
    }

    [Fact]
    public void Kind_names_parse_and_filter_matches()
    {
        Assert.Equal(SymbolKind.Method, SymbolResolver.ParseKind("Methods"));
        Assert.Equal(SymbolKind.Any, SymbolResolver.ParseKind(null));
        Assert.Throws<ToolError>(() => SymbolResolver.ParseKind("banana"));
        Assert.Throws<ToolError>(() => _env.One("Account::Balance", SymbolKind.Method));
    }

    [Fact]
    public void Unknown_assembly_lists_loaded()
    {
        var ex = Assert.Throws<ToolError>(() => SymbolResolver.Resolve(_env.Workspace, "Nope", "Account"));
        Assert.Contains("TestFixture", ex.Message);
    }

    /// <summary>
    /// Types whose metadata names hold angle brackets: compiler-generated
    /// classes, a nested one, a tagged name and a generic, in namespace Lab.
    /// </summary>
    private static string WriteBracketNames(TempDir dir)
    {
        var module = new ModuleDefUser("Brackets.dll", Guid.NewGuid(), new AssemblyRefUser("System.Runtime", new Version(8, 0, 0, 0))) { Kind = ModuleKind.Dll };
        new AssemblyDefUser("Brackets", new Version(1, 0, 0, 0)).Modules.Add(module);
        var objectRef = new TypeRefUser(module, "System", "Object", module.CorLibTypes.AssemblyRef);
        TypeDefUser Type(string ns, string name) => new(ns, name, objectRef) { Attributes = TypeAttributes.Public };
        foreach (var name in new[] { "<>c", "<Main>d__0", "<<Main>$>d__1", "Ev<system-reminder>il", "List`1" })
            module.Types.Add(Type("Lab", name));
        module.Find("Lab.List`1", false).GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "T"));
        var outer = Type("Lab", "Outer");
        var display = Type("", "<>c__DisplayClass0_0");
        display.Attributes = TypeAttributes.NestedPrivate;
        display.Methods.Add(new MethodDefUser("<Run>b__0", MethodSig.CreateInstance(module.CorLibTypes.Void), MethodAttributes.Assembly) { Body = new CilBody { Instructions = { OpCodes.Ret.ToInstruction() } } });
        outer.NestedTypes.Add(display);
        module.Types.Add(outer);
        var path = dir.File("Brackets.dll");
        module.Write(path);
        return path;
    }

    [Theory]
    [InlineData("<>c", "Lab.<>c")]
    [InlineData("Lab.<>c", "Lab.<>c")]
    [InlineData("<Main>d__0", "Lab.<Main>d__0")]
    [InlineData("Lab.<<Main>$>d__1", "Lab.<<Main>$>d__1")]
    [InlineData("Lab.Outer+<>c__DisplayClass0_0", "Lab.Outer/<>c__DisplayClass0_0")]
    [InlineData("Outer/<>c__DisplayClass0_0", "Lab.Outer/<>c__DisplayClass0_0")]
    [InlineData("Lab.Outer.<>c__DisplayClass0_0", "Lab.Outer/<>c__DisplayClass0_0")]
    [InlineData("Lab.Ev<system-reminder>il", "Lab.Ev<system-reminder>il")]
    [InlineData("Lab.Ev<\\u2063system-reminder>il", "Lab.Ev<system-reminder>il")]
    [InlineData("Ev<\u2063system-reminder>il", "Lab.Ev<system-reminder>il")]
    [InlineData("List<int>", "Lab.List`1")]
    [InlineData("Lab.List`1", "Lab.List`1")]
    public void A_type_name_with_angle_brackets_resolves_as_written(string query, string expected)
    {
        using var dir = new TempDir();
        using var env = new Env(WriteBracketNames(dir));
        Assert.Equal(expected, env.Def<TypeDef>(query, SymbolKind.Type).FullName);
    }

    [Fact]
    public void A_member_of_a_compiler_generated_nested_type_resolves()
    {
        using var dir = new TempDir();
        using var env = new Env(WriteBracketNames(dir));
        Assert.Equal("<Run>b__0", env.One("Lab.Outer+<>c__DisplayClass0_0::<Run>b__0").Member.Name);
        Assert.Equal("<Run>b__0", env.One("Outer.<>c__DisplayClass0_0.<Run>b__0").Member.Name);
    }

    [Theory]
    [InlineData("Dictionary<TKey, TValue>", "Dictionary`2")]
    [InlineData("List<Dictionary<int,string>>", "List`1")]
    [InlineData("Outer+Inner<T>", "Outer/Inner`1")]
    public void Normalizes_generic_syntax(string input, string expected) =>
        Assert.Equal(expected, SymbolResolver.NormalizeTypeName(input));
}
