using dnlib.DotNet;
using Corvus.Core;
using Corvus.Services;

namespace Corvus.Tests;

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
        Assert.Equal("CheckPreview", r.Where.Name);
        Assert.Equal("call", r.Kind);
        Assert.NotNull(r.ILOffset);
    }

    [Fact]
    public void CrossAssemblyReferences()
    {
        Assert.Contains(Refs("Account::.ctor"), r => r.Where.Name == "Open" && r.Assembly.Id == "TestFixture.Consumer");
        Assert.Contains(Refs("Shop::Buy"), r => r.Where.Name == "TryBuy");
        Assert.Contains(Refs("Entity", kind: SymbolKind.Type), r => r.Kind == "base type" && r.Where.Name == "Archive");
    }

    [Fact]
    public void Rows_of_one_owner_are_distinct()
    {
        // a comparer over the target implements two generic interfaces, and carries an attribute twice
        var module = _env.Fixture.Module;
        var account = _env.Def<TypeDef>("Account", SymbolKind.Type);
        var accountSig = new ClassSig(account);
        TypeSpec Over(string ns, string name) =>
            new TypeSpecUser(new GenericInstSig(new ClassSig(new TypeRefUser(module, ns, name, module.CorLibTypes.AssemblyRef)), accountSig));
        var comparer = new TypeDefUser("Fixture.Model", "AccountComparer", module.CorLibTypes.Object.TypeDefOrRef);
        comparer.Interfaces.Add(new InterfaceImplUser(Over("System.Collections.Generic", "IComparer`1")));
        comparer.Interfaces.Add(new InterfaceImplUser(Over("System.Collections.Generic", "IEqualityComparer`1")));
        module.Types.Add(comparer);
        var marker = _env.Def<TypeDef>("Entity", SymbolKind.Type);
        var holder = new TypeDefUser("Fixture.Model", "MarkedTwice", module.CorLibTypes.Object.TypeDefOrRef);
        var ctor = new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void), marker);
        holder.CustomAttributes.Add(new CustomAttribute(ctor));
        holder.CustomAttributes.Add(new CustomAttribute(ctor));
        module.Types.Add(holder);

        var rows = Refs("Account", kind: SymbolKind.Type).Where(r => r.Where.Name == "AccountComparer").ToList();
        Assert.Equal(2, rows.Count);
        Assert.Equal(rows.Count, rows.Select(r => (r.Kind, r.Detail)).Distinct().Count());
        Assert.Contains(rows, r => r.Detail.Contains("IEqualityComparer"));
        Assert.Single(Refs("Entity", kind: SymbolKind.Type), r => r.Where.Name == "MarkedTwice" && r.Kind == "attribute");
    }

    [Fact]
    public void VirtualAndInterfaceDispatch()
    {
        // Branch.Bill calls IChargeable.Charge, Branch.Total calls Entity.Score: both dispatch to Account.
        var charge = Refs("Account::Charge(int)");
        Assert.Contains(charge, r => r.Where.Name == "Bill" && r.Detail.Contains("IChargeable::Charge"));
        Assert.Contains(Refs("Account::Score"), r => r.Where.Name == "Total" && r.Detail.Contains("Entity::Score"));
        Assert.DoesNotContain(Refs("Account::Charge(int)", virtualCalls: false), r => r.Where.Name == "Bill");

        var bases = ReferenceService.BaseDeclarations(_env.Def<MethodDef>("PremiumAccount::Score"));
        Assert.Contains(bases, m => m.DeclaringType.Name == "Account");
        Assert.Contains(bases, m => m.DeclaringType.Name == "Entity");
    }

    [Fact]
    public void CrossAssemblyFieldReferencesAreFieldsNotMethods()
    {
        // A MemberRef to a field in another assembly is both IMethod and IField in dnlib; it must be treated as a field.
        Assert.Contains(Refs("Entity::Name"), r => r.Where.Name == "NameOf" && r.Kind == "read");
        var callees = _env.References.FindCallees(_env.Def<MethodDef>("Consumer.Branch::NameOf"));
        var field = Assert.Single(callees);
        Assert.Equal("field read", field.Kind);
        Assert.Equal("Fixture.Model.Entity::Name", field.Target);
        Assert.Single(_env.Search.SearchIL("ldfld *Entity::Name", _env.Workspace.Assemblies, 10, default).Items);
    }

    [Fact]
    public void FieldReadsWritesAndAddresses()
    {
        var r = Refs("Account::_balance");
        Assert.Contains(r, i => i.Kind == "write" && i.Where.Name == "set_Balance");
        Assert.Contains(r, i => i.Kind == "read" && i.Where.Name == "get_IsActive");
        Assert.Contains(r, i => i.Kind == "write" && i.Where.Name == ".ctor");
        Assert.Contains(Refs("Account::AccountCount"), i => i.Kind == "write" && i.Where.Name == ".ctor");
    }

    [Fact]
    public void PropertyAndEventAccessors()
    {
        Assert.Contains(Refs("Account::Balance"), i => i.Kind == "get" && i.Where.Name == "MoveNext"); // inside LoadAsync's state machine
        Assert.Empty(Refs("Fixture.Model.Account::Closed", kind: SymbolKind.Event)); // raised through the backing field
    }

    [Fact]
    public void TypeUsagesInEveryPosition()
    {
        var chargeable = Refs("IChargeable", kind: SymbolKind.Type);
        Assert.Contains(chargeable, i => i.Kind == "implements" && i.Where.Name == "Account");
        Assert.Contains(chargeable, i => i.Kind == "parameter type" && i.Where.Name == "Bill");
        var account = Refs("Account", kind: SymbolKind.Type);
        Assert.Contains(account, i => i.Kind == "base type" && i.Where.Name == "PremiumAccount");
        Assert.Contains(account, i => i.Kind == "return type" && i.Where.Name == "Open");
        Assert.Contains(account, i => i.Kind == "newobj");
        var address = Refs("Il2CppDummyDll.AddressAttribute", kind: SymbolKind.Type);
        Assert.Contains(address, i => i.Kind == "attribute" && i.Where.Name == "First");
    }

    [Fact]
    public void LimitKeepsTotal()
    {
        var r = _env.References.FindReferences(_env.One("Account::_balance"), true, 2, default);
        Assert.Equal(2, r.Items.Count);
        Assert.True(r.Total > 2);
    }

    [Fact]
    public void Callees()
    {
        var list = _env.References.FindCallees(_env.Def<MethodDef>("Account::Charge(int, string)"));
        Assert.Contains(list, c => c.Target.Contains("::Log("));
        Assert.Contains(list, c => c.Target.Contains("::Charge(int)") && c.TargetAssembly?.Id == "TestFixture");
        Assert.Contains(list, c => c.Kind == "string" && c.Target.Contains("charged by"));
        Assert.Throws<ToolError>(() => _env.References.FindCallees(_env.Def<MethodDef>("Entity::Tick")));
    }

    [Fact]
    public void OverridesAndImplementationsAcrossAssemblies()
    {
        var tick = _env.References.FindOverrides(_env.Def<MethodDef>("Entity::Tick"), default);
        Assert.Contains(tick, s => ((MethodDef)s.Member).DeclaringType.Name == "Archive");
        var score = _env.References.FindOverrides(_env.Def<MethodDef>("Entity::Score"), default);
        Assert.Equal(["Account", "PremiumAccount"], score.Select(s => ((MethodDef)s.Member).DeclaringType.Name.String).Order());
        Assert.Contains(_env.References.FindOverrides(_env.Def<MethodDef>("IChargeable::Charge"), default),
            s => ((MethodDef)s.Member).DeclaringType.Name == "Account");
        Assert.Throws<ToolError>(() => _env.References.FindOverrides(_env.Def<MethodDef>("Account::CheckPreview"), default));
    }

    [Fact]
    public void Hierarchy()
    {
        var h = _env.References.GetHierarchy(_env.Def<TypeDef>("Account", SymbolKind.Type), 100, default);
        Assert.StartsWith("Fixture.Model.Entity", h.BaseChain[0]);
        Assert.Contains("Fixture.Model.IChargeable", h.Interfaces);
        Assert.Single(h.Derived);
        var entity = _env.References.GetHierarchy(_env.Def<TypeDef>("Entity", SymbolKind.Type), 100, default);
        Assert.Equal(2, entity.DerivedTotal); // Account + Archive (other assembly)
        var iface = _env.References.GetHierarchy(_env.Def<TypeDef>("IChargeable", SymbolKind.Type), 100, default);
        Assert.Contains(iface.Derived, d => d.Member.Name == "Account");
    }
}
