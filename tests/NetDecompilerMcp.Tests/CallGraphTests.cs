using dnlib.DotNet;
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
    public void GraphIsRebuiltAfterEdits()
    {
        _env.Workspace.Read(() => { _graph.EnsureBuilt(default); return 0; });
        Assert.True(_graph.IsBuilt);
        _env.Edit(() => _env.Edits.StubMethod(_env.One("Player::CheckLicense"), "true")); // removes the call to Validate
        Assert.False(_graph.IsBuilt);
        Assert.Contains("no callers", Tree("Secret::Validate", callers: true));
    }
}
