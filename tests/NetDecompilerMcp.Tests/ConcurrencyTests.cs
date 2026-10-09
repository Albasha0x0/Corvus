using System.Collections.Concurrent;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Tests;

/// <summary>Readers and writers hammer one workspace at the same time; nothing may throw or observe a half-applied edit.</summary>
public class ConcurrencyTests
{
    [Trait("Speed", "Slow")]
    [Fact]
    public async Task ReadersAndWritersInterleaveSafely()
    {
        using var env = new Env(withConsumer: true);
        var errors = new ConcurrentBag<Exception>();
        // A clock deadline and dedicated threads: a timer callback can starve on a busy thread pool.
        var deadline = System.Diagnostics.Stopwatch.StartNew();
        bool Running() => (deadline.Elapsed < TimeSpan.FromSeconds(5) || env.Fixture.Edits.Count <= 10)
                         && deadline.Elapsed < TimeSpan.FromSeconds(60) && env.Fixture.Edits.Count < 2_000;

        Task Loop(Action body) => Task.Factory.StartNew(() =>
        {
            while (Running())
            {
                try { body(); }
                catch (Exception ex) { errors.Add(ex); }
            }
        }, TaskCreationOptions.LongRunning);

        var readers = new[]
        {
            Loop(() => env.Workspace.Read(() => env.Decompiler.DecompileType(env.Fixture, env.Def<dnlib.DotNet.TypeDef>("Shop", SymbolKind.Type), default))),
            Loop(() => env.Workspace.Read(() => env.References.FindReferences(env.One("Account::_balance"), true, 100, default).Total)),
            Loop(() => env.Workspace.Read(() => env.Search.SearchStrings("LICENSE", false, env.Workspace.Assemblies, 10, default).Total)),
            Loop(() => env.Workspace.Read(() => env.Decompiler.Disassemble(env.Fixture, env.One("Account::Score").Member, default))),
        };
        int i = 0;
        string current = "Describe";
        var writer = Loop(() =>
        {
            var next = ++i % 2 == 0 ? "DescribeA" : "DescribeB";
            env.Edit(() => env.Edits.Rename(env.One("Shop::" + current), next));
            current = next;
            env.Edit(() => env.Edits.StubMethod(env.One("Account::Score"), (i % 100).ToString()));
        });

        await Task.WhenAll(readers.Append(writer));
        Assert.Empty(errors);
        Assert.True(env.Fixture.Edits.Count > 10);
    }
}
