using System.Collections.Concurrent;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Tests;

/// <summary>Readers and writers hammer one workspace at the same time; nothing may throw or observe a half-applied edit.</summary>
public class ConcurrencyTests
{
    [Fact]
    public async Task ReadersAndWritersInterleaveSafely()
    {
        using var env = new Env(withConsumer: true);
        var errors = new ConcurrentBag<Exception>();
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(8));

        async Task Loop(Action body) => await Task.Run(() =>
        {
            while (!stop.IsCancellationRequested)
            {
                try { body(); }
                catch (Exception ex) { errors.Add(ex); }
            }
        });

        var readers = new[]
        {
            Loop(() => env.Workspace.Read(() => env.Decompiler.DecompileType(env.Fixture, env.Def<dnlib.DotNet.TypeDef>("Shop", SymbolKind.Type), default))),
            Loop(() => env.Workspace.Read(() => env.References.FindReferences(env.One("Player::_health"), true, 100, default).Total)),
            Loop(() => env.Workspace.Read(() => env.Search.SearchStrings("LICENSE", false, env.Workspace.Assemblies, 10, default).Total)),
            Loop(() => env.Workspace.Read(() => env.Decompiler.Disassemble(env.Fixture, env.One("Player::Score").Member, default))),
        };
        int i = 0;
        string current = "Describe";
        var writer = Loop(() =>
        {
            var next = ++i % 2 == 0 ? "DescribeA" : "DescribeB";
            env.Edit(() => env.Edits.Rename(env.One("Shop::" + current), next));
            current = next;
            env.Edit(() => env.Edits.StubMethod(env.One("Player::Score"), (i % 100).ToString()));
        });

        await Task.WhenAll(readers.Append(writer));
        Assert.Empty(errors);
        Assert.True(env.Fixture.Edits.Count > 10);
    }
}
