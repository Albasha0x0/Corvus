using dnlib.DotNet;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Services;

namespace NetDecompilerMcp.Tests;

public class ReferenceTests : IDisposable
{
    private readonly Env _env = new(withConsumer: true);
    public void Dispose() => _env.Dispose();

    private List<ReferenceService.Reference> Refs(string symbol, bool virtualCalls = true, SymbolKind kind = SymbolKind.Any) =>
        _env.References.FindReferences(_env.One(symbol, kind), virtualCalls, 1000, default).Items;

    [Fact]
    public void MethodCallSites()
    {
        var r = Assert.Single(Refs("Secret::Validate"));
        Assert.Equal("CheckLicense", r.Where.Name);
        Assert.Equal("call", r.Kind);
        Assert.NotNull(r.ILOffset);
    }

    [Fact]
    public void CrossAssemblyReferences()
    {
        Assert.Contains(Refs("Player::.ctor"), r => r.Where.Name == "Spawn" && r.Assembly.Id == "TestFixture.Consumer");
        Assert.Contains(Refs("Shop::Buy"), r => r.Where.Name == "TryBuy");
        Assert.Contains(Refs("Entity", kind: SymbolKind.Type), r => r.Kind == "base type" && r.Where.Name == "Minion");
    }

    [Fact]
    public void VirtualAndInterfaceDispatch()
    {
        // Arena.Hit calls IDamageable.TakeDamage, Arena.Total calls Entity.Score: both dispatch to Player.
        var takeDamage = Refs("Player::TakeDamage(int)");
        Assert.Contains(takeDamage, r => r.Where.Name == "Hit" && r.Detail.Contains("IDamageable::TakeDamage"));
        Assert.Contains(Refs("Player::Score"), r => r.Where.Name == "Total" && r.Detail.Contains("Entity::Score"));
        Assert.DoesNotContain(Refs("Player::TakeDamage(int)", virtualCalls: false), r => r.Where.Name == "Hit");

        var bases = ReferenceService.BaseDeclarations(_env.Def<MethodDef>("Boss::Score"));
        Assert.Contains(bases, m => m.DeclaringType.Name == "Player");
        Assert.Contains(bases, m => m.DeclaringType.Name == "Entity");
    }

    [Fact]
    public void CrossAssemblyFieldReferencesAreFieldsNotMethods()
    {
        // A MemberRef to a field in another assembly is both IMethod and IField in dnlib; it must be treated as a field.
        Assert.Contains(Refs("Entity::Name"), r => r.Where.Name == "NameOf" && r.Kind == "read");
        var callees = _env.References.FindCallees(_env.Def<MethodDef>("Consumer.Arena::NameOf"));
        var field = Assert.Single(callees);
        Assert.Equal("field read", field.Kind);
        Assert.Equal("Fixture.Game.Entity::Name", field.Target);
        Assert.Single(_env.Search.SearchIL("ldfld *Entity::Name", _env.Workspace.Assemblies, 10, default).Items);
    }

    [Fact]
    public void FieldReadsWritesAndAddresses()
    {
        var r = Refs("Player::_health");
        Assert.Contains(r, i => i.Kind == "write" && i.Where.Name == "set_Health");
        Assert.Contains(r, i => i.Kind == "read" && i.Where.Name == "get_IsAlive");
        Assert.Contains(r, i => i.Kind == "write" && i.Where.Name == ".ctor");
        Assert.Contains(Refs("Player::PlayerCount"), i => i.Kind == "write" && i.Where.Name == ".ctor");
    }

    [Fact]
    public void PropertyAndEventAccessors()
    {
        Assert.Contains(Refs("Player::Health"), i => i.Kind == "get" && i.Where.Name == "MoveNext"); // inside LoadAsync's state machine
        Assert.Empty(Refs("Fixture.Game.Player::Died", kind: SymbolKind.Event)); // raised through the backing field
    }

    [Fact]
    public void TypeUsagesInEveryPosition()
    {
        var damageable = Refs("IDamageable", kind: SymbolKind.Type);
        Assert.Contains(damageable, i => i.Kind == "implements" && i.Where.Name == "Player");
        Assert.Contains(damageable, i => i.Kind == "parameter type" && i.Where.Name == "Hit");
        var player = Refs("Player", kind: SymbolKind.Type);
        Assert.Contains(player, i => i.Kind == "base type" && i.Where.Name == "Boss");
        Assert.Contains(player, i => i.Kind == "return type" && i.Where.Name == "Spawn");
        Assert.Contains(player, i => i.Kind == "newobj");
        var address = Refs("Il2CppDummyDll.AddressAttribute", kind: SymbolKind.Type);
        Assert.Contains(address, i => i.Kind == "attribute" && i.Where.Name == "First");
    }

    [Fact]
    public void LimitKeepsTotal()
    {
        var r = _env.References.FindReferences(_env.One("Player::_health"), true, 2, default);
        Assert.Equal(2, r.Items.Count);
        Assert.True(r.Total > 2);
    }

    [Fact]
    public void Callees()
    {
        var list = _env.References.FindCallees(_env.Def<MethodDef>("Player::TakeDamage(int, string)"));
        Assert.Contains(list, c => c.Target.Contains("::Log("));
        Assert.Contains(list, c => c.Target.Contains("::TakeDamage(int)") && c.TargetAssembly?.Id == "TestFixture");
        Assert.Contains(list, c => c.Kind == "string" && c.Target.Contains("hit by"));
        Assert.Throws<ToolError>(() => _env.References.FindCallees(_env.Def<MethodDef>("Entity::Tick")));
    }

    [Fact]
    public void OverridesAndImplementationsAcrossAssemblies()
    {
        var tick = _env.References.FindOverrides(_env.Def<MethodDef>("Entity::Tick"), default);
        Assert.Contains(tick, s => ((MethodDef)s.Member).DeclaringType.Name == "Minion");
        var score = _env.References.FindOverrides(_env.Def<MethodDef>("Entity::Score"), default);
        Assert.Equal(["Boss", "Player"], score.Select(s => ((MethodDef)s.Member).DeclaringType.Name.String).Order());
        Assert.Contains(_env.References.FindOverrides(_env.Def<MethodDef>("IDamageable::TakeDamage"), default),
            s => ((MethodDef)s.Member).DeclaringType.Name == "Player");
        Assert.Throws<ToolError>(() => _env.References.FindOverrides(_env.Def<MethodDef>("Player::CheckLicense"), default));
    }

    [Fact]
    public void Hierarchy()
    {
        var h = _env.References.GetHierarchy(_env.Def<TypeDef>("Player", SymbolKind.Type), 100, default);
        Assert.StartsWith("Fixture.Game.Entity", h.BaseChain[0]);
        Assert.Contains("Fixture.Game.IDamageable", h.Interfaces);
        Assert.Single(h.Derived);
        var entity = _env.References.GetHierarchy(_env.Def<TypeDef>("Entity", SymbolKind.Type), 100, default);
        Assert.Equal(2, entity.DerivedTotal); // Player + Minion (other assembly)
        var iface = _env.References.GetHierarchy(_env.Def<TypeDef>("IDamageable", SymbolKind.Type), 100, default);
        Assert.Contains(iface.Derived, d => d.Member.Name == "Player");
    }
}
