using Microsoft.Extensions.DependencyInjection;
using ModelContextProtocol.Protocol;
using Corvus.Core;
using Corvus.Mcp;

namespace Corvus.Tests;

/// <summary>The default leftover cap (STANDARDS S9.3): two calls may run on past their deadline, a third waits.</summary>
public sealed class LeftoverCapTests
{
    [Fact]
    public async Task DefaultCap_IsTwo()
    {
        Assert.Equal(2, LeftoverWork.DefaultMax);
        using var services = new ServiceCollection().AddSingleton(new ServerOptions { TimeoutSeconds = 3600 }).AddSingleton<ResultStore>().BuildServiceProvider();
        var leftovers = LeftoverWork.For(services.GetRequiredService<ServerOptions>());
        if (Environment.GetEnvironmentVariable(LeftoverWork.MaxVariable) is null) Assert.Equal(2, leftovers.Max);
        leftovers.Max = LeftoverWork.DefaultMax;

        var release = new TaskCompletionSource();
        CallToolResult Done() => new() { Content = [new TextContentBlock { Text = "done" }] };
        async Task Abandon(string tool)
        {
            using var cts = new CancellationTokenSource();
            var call = CallFilter.Run(new CallToolRequestParams { Name = tool }, null, services, async _ => { await release.Task; return Done(); }, cts.Token).AsTask();
            await cts.CancelAsync();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => call.WaitAsync(TimeSpan.FromMinutes(1)));
        }
        await Abandon("rename_symbol");
        Assert.Equal(1, leftovers.Running);
        Assert.True(await leftovers.WaitForRoom(new CancellationTokenSource(TimeSpan.FromMilliseconds(50)).Token));
        await Abandon("rename_namespace");
        Assert.Equal(2, leftovers.Running);
        Assert.False(await leftovers.WaitForRoom(new CancellationTokenSource(TimeSpan.FromMilliseconds(50)).Token));
        release.SetResult();
        Assert.True(await leftovers.WaitForRoom(new CancellationTokenSource(TimeSpan.FromMinutes(1)).Token));
    }
}
