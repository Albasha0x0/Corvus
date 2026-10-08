using dnlib.DotNet;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Services;

namespace NetDecompilerMcp.Tests;

public class CallGraphTests : IDisposable
{
    private readonly Env _env = new(withConsumer: true);
    private readonly CallGraphService _graph;

    public CallGraphTests() => _graph = new CallGraphService(_env.Workspace);

    public void Dispose() => _env.Dispose();

    private string Tree(string method, bool callers, int depth = 3, bool external = false) =>
        _env.Workspace.Read(() => _graph.Tree(_env.Fixture, _env.Def<MethodDef>(method), callers, depth, 300, external, default));

    [Fact]
    public void CallerAndCalleeTrees()
    {
        Assert.Contains("Fixture.Model.Account::CheckLicense()", Tree("Secret::Validate", callers: true));
        var callees = Tree("Account::Charge(int, string)", callers: false);
        Assert.Contains("Fixture.Model.Account::Log(string)", callees);
        Assert.Contains("Fixture.Model.Account::Charge(int)", callees);
        Assert.Contains("String::Concat", Tree("Account::Charge(int, string)", callers: false, external: true));
        Assert.Contains("no callers", Tree("Account::CheckLicense", callers: true));
    }

    [Fact]
    public void VirtualDispatchAndCrossAssembly()
    {
        var callers = Tree("Account::Charge(int)", callers: true);
        Assert.Contains("Consumer.Branch::Bill(IChargeable)", callers);
        Assert.Contains("via Fixture.Model.IChargeable::Charge(int)", callers);
        Assert.Contains("[TestFixture.Consumer]", callers);
    }

    [Fact]
    public void PathsFromStartAndFromEntryPoints()
    {
        var hit = _env.Def<MethodDef>("Consumer.Branch::Bill");
        var target = _env.Def<MethodDef>("Account::Charge(int)");
        var fromHit = _env.Workspace.Read(() => _graph.Paths(hit, target, 8, 10, default));
        Assert.Contains(fromHit, p => p.First() == hit && p.Last() == target);

        var validate = _env.Def<MethodDef>("Secret::Validate");
        var fromRoots = _env.Workspace.Read(() => _graph.Paths(null, validate, 8, 10, default));
        Assert.Contains(fromRoots, p => p.First().Name == "CheckLicense" && p.Last() == validate);
    }

    [Fact]
    public void VirtualHopsAreMarkedAndCanBeExcluded()
    {
        // Account.Charge(int) is reached from Branch.Bill only through IChargeable.Charge.
        var hit = _env.Def<MethodDef>("Consumer.Branch::Bill");
        var target = _env.Def<MethodDef>("Account::Charge(int)");
        var path = Assert.Single(_env.Workspace.Read(() => _graph.PathSteps(hit, target, 8, 10, includeVirtual: true, default)));
        Assert.Equal([hit, target], path.Select(s => s.Method));
        Assert.Null(path[0].Via);
        Assert.Equal("Fixture.Model.IChargeable::Charge(int)", Format.MemberLabel(path[1].Via!));
        Assert.Empty(_env.Workspace.Read(() => _graph.PathSteps(hit, target, 8, 10, includeVirtual: false, default)));

        // The direct caller Charge(int, string) is still found.
        var direct = _env.Workspace.Read(() => _graph.PathSteps(null, target, 8, 10, includeVirtual: false, default));
        Assert.Contains(direct, p => p[^2].Method.Name == "Charge" && p[^2].Method.Parameters.Count == 3);
        Assert.All(direct, p => Assert.All(p, s => Assert.Null(s.Via)));
    }

    [Fact]
    public void DirectPathsAreNotHiddenByVirtualDispatch()
    {
        // Impl.Run has no direct callers but is reached virtually from Kick; it must still be a path root.
        using var dir = new TempDir();
        var path = dir.File("Dispatch.dll");
        File.WriteAllBytes(path, ReferenceResolutionTests.Compile("Dispatch", """
            public abstract class Base { public abstract void Run(); }
            public class Impl : Base { public override void Run() { G.Target(); } }
            public static class G { public static void Target() { } }
            public static class Driver { public static void Kick(Base b) { b.Run(); } public static void Start() { Kick(null); } }
            """));
        using var env = new Env(path);
        var graph = new CallGraphService(env.Workspace);
        var paths = env.Workspace.Read(() => graph.PathSteps(null, env.Def<MethodDef>("G::Target"), 8, 10, includeVirtual: true, default));
        Assert.Equal(["Impl::Run()", "G::Target()"], paths[0].Select(s => Format.MemberLabel(s.Method)));
        Assert.All(paths[0], s => Assert.Null(s.Via));
        Assert.Contains(paths, p => p.Select(s => s.Method.Name.String).SequenceEqual(["Start", "Kick", "Run", "Target"]) && p[2].Via != null);
    }

    [Fact]
    public void TreesExpandBreadthFirst()
    {
        // A heads a long caller chain; depth-first with a small node budget would never reach Z.
        using var dir = new TempDir();
        var path = dir.File("Chain.dll");
        File.WriteAllBytes(path, ReferenceResolutionTests.Compile("Chain", """
            public static class G
            {
                public static void Root() { }
                public static void A() { Root(); Shared(); }
                public static void B() { A(); }
                public static void C() { B(); Shared(); }
                public static void D() { C(); }
                public static void Z() { Root(); }
                public static void Shared() { Root(); }
            }
            """));
        using var env = new Env(path);
        var graph = new CallGraphService(env.Workspace);
        string Callers(int depth, int maxNodes) =>
            env.Workspace.Read(() => graph.Tree(env.Fixture, env.Def<MethodDef>("G::Root"), true, depth, maxNodes, false, default));

        var small = Callers(5, 3);
        Assert.Contains("  G::Z()", small);        // level 1 complete before anything deeper
        Assert.Contains("  G::Shared()", small);
        Assert.DoesNotContain("G::B()", small);
        Assert.Contains("[Stopped after 3 nodes", small);

        // A node reachable at several depths is expanded once, at the shallowest.
        var full = Callers(5, 300);
        Assert.Equal("""
            Callers of G::Root()  [Chain]  (depth 5)
              G::A()
                G::B()
                  G::C()  (expanded under G::Shared())
              G::Shared()
                G::A()  (expanded under the root)
                G::C()
                  G::D()
              G::Z()

            """.ReplaceLineEndings("\n"), full.ReplaceLineEndings("\n"));
    }

    [Fact]
    public void GraphIsRebuiltAfterEdits()
    {
        _env.Workspace.Read(() => { _graph.EnsureBuilt(default); return 0; });
        Assert.True(_graph.IsBuilt);
        _env.Edit(() => _env.Edits.StubMethod(_env.One("Account::CheckLicense"), "true")); // drops the call to Validate
        Assert.False(_graph.IsBuilt);
        Assert.Contains("no callers", Tree("Secret::Validate", callers: true));
    }
}
