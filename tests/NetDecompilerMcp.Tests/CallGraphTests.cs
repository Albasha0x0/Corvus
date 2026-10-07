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
        Assert.Contains("Fixture.Game.Player::CheckLicense()", Tree("Secret::Validate", callers: true));
        var callees = Tree("Player::TakeDamage(int, string)", callers: false);
        Assert.Contains("Fixture.Game.Player::Log(string)", callees);
        Assert.Contains("Fixture.Game.Player::TakeDamage(int)", callees);
        Assert.Contains("String::Concat", Tree("Player::TakeDamage(int, string)", callers: false, external: true));
        Assert.Contains("no callers", Tree("Player::CheckLicense", callers: true));
    }

    [Fact]
    public void VirtualDispatchAndCrossAssembly()
    {
        var callers = Tree("Player::TakeDamage(int)", callers: true);
        Assert.Contains("Consumer.Arena::Hit(IDamageable)", callers);
        Assert.Contains("via Fixture.Game.IDamageable::TakeDamage(int)", callers);
        Assert.Contains("[TestFixture.Consumer]", callers);
    }

    [Fact]
    public void RecursionAndRepeatsAreMarked()
    {
        // TakeDamage(int, string) calls TakeDamage(int); Shop.PriceOf(string, int) calls PriceOf(string).
        var tree = Tree("Shop::PriceOf(string)", callers: true, depth: 5);
        Assert.Contains("Fixture.Game.Shop::PriceOf(string, int)", tree);
    }

    [Fact]
    public void PathsFromStartAndFromEntryPoints()
    {
        var hit = _env.Def<MethodDef>("Consumer.Arena::Hit");
        var target = _env.Def<MethodDef>("Player::TakeDamage(int)");
        var fromHit = _env.Workspace.Read(() => _graph.Paths(hit, target, 8, 10, default));
        Assert.Contains(fromHit, p => p.First() == hit && p.Last() == target);

        var validate = _env.Def<MethodDef>("Secret::Validate");
        var fromRoots = _env.Workspace.Read(() => _graph.Paths(null, validate, 8, 10, default));
        Assert.Contains(fromRoots, p => p.First().Name == "CheckLicense" && p.Last() == validate);
    }

    [Fact]
    public void VirtualHopsAreMarkedAndCanBeExcluded()
    {
        // Arena.Hit calls IDamageable.TakeDamage; Player.TakeDamage(int) is reached only through that interface call
        var hit = _env.Def<MethodDef>("Consumer.Arena::Hit");
        var target = _env.Def<MethodDef>("Player::TakeDamage(int)");
        var path = Assert.Single(_env.Workspace.Read(() => _graph.PathSteps(hit, target, 8, 10, includeVirtual: true, default)));
        Assert.Equal([hit, target], path.Select(s => s.Method));
        Assert.Null(path[0].Via);
        Assert.Equal("Fixture.Game.IDamageable::TakeDamage(int)", Format.MemberLabel(path[1].Via!));
        Assert.Empty(_env.Workspace.Read(() => _graph.PathSteps(hit, target, 8, 10, includeVirtual: false, default)));

        // the direct caller TakeDamage(int, string) is still found without virtual dispatch
        var direct = _env.Workspace.Read(() => _graph.PathSteps(null, target, 8, 10, includeVirtual: false, default));
        Assert.Contains(direct, p => p[^2].Method.Name == "TakeDamage" && p[^2].Method.Parameters.Count == 3);
        Assert.All(direct, p => Assert.All(p, s => Assert.Null(s.Via)));
    }

    [Fact]
    public void DirectPathsAreNotHiddenByVirtualDispatch()
    {
        // Impl.Run calls Target directly; nothing calls Impl.Run directly, but Driver.Kick reaches it through Base.Run.
        // With virtual edges Impl.Run is no entry point, so only the longer Start -> Kick -> Run -> Target chain would show.
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
        // Root's callers: A (at the end of a long chain: A <- B <- C <- D) and Z (direct, nothing else).
        // Depth-first with a small node budget would follow A's chain and never list Z.
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
        Assert.Contains("  G::Z()", small);        // all of level 1 (A, Shared, Z) before anything deeper
        Assert.Contains("  G::Shared()", small);
        Assert.DoesNotContain("G::B()", small);
        Assert.Contains("[Stopped after 3 nodes", small);

        // Shared is a caller of Root (level 1) and of A (level 2): expanded once, at level 1, referenced under A
        var full = Callers(5, 300);
        // C calls B (level 3 under A) and Shared (level 2): expanded at level 2
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
        _env.Edit(() => _env.Edits.StubMethod(_env.One("Player::CheckLicense"), "true")); // removes the call to Validate
        Assert.False(_graph.IsBuilt);
        Assert.Contains("no callers", Tree("Secret::Validate", callers: true));
    }
}
