using System.Runtime.CompilerServices;
using Microsoft.Extensions.Logging;
using Corvus.Core;

namespace Corvus.Services;

/// <summary>
/// Background indexing after assemblies load: decodes every method body once (warming the operand caches the
/// fast IL reader uses) and builds the call graph, so the first search / cross-reference / call tree is as fast as the
/// following ones. Work is done in small chunks under the shared lock, so edits are never blocked for long.
/// </summary>
public sealed class IndexingService : IDisposable
{
    private const int ChunkSize = 200;

    private readonly AssemblyWorkspace _workspace;
    private readonly CallGraphService _graph;
    private readonly ILogger<IndexingService>? _logger;
    private readonly ConditionalWeakTable<dnlib.DotNet.ModuleDef, object> _indexed = new();
    private readonly object _sync = new();
    private CancellationTokenSource? _run;
    private Task _task = Task.CompletedTask;
    private volatile string _status = "idle";

    public IndexingService(AssemblyWorkspace workspace, CallGraphService graph, ServerOptions options, ILogger<IndexingService>? logger = null)
    {
        _workspace = workspace;
        _graph = graph;
        _logger = logger;
        if (options.BackgroundIndexing)
        {
            workspace.AssembliesLoaded += _ => Start();
            workspace.AssemblyUnloaded += _ => Start();
        }
    }

    /// <summary>"idle", "indexing X (n/m types)", "building call graph", "done", "superseded", "stopped" (workspace disposed), "failed: ...".</summary>
    public string Status => _status;

    /// <summary>Restarts indexing for everything not indexed yet (a newer load supersedes a running pass).</summary>
    public void Start()
    {
        lock (_sync)
        {
            _run?.Cancel();
            var cts = _run = new CancellationTokenSource();
            var previous = _task;
            _task = Task.Run(async () =>
            {
                try { await previous.ConfigureAwait(false); } catch { /* superseded */ }
                Run(cts.Token);
            });
        }
    }

    /// <summary>Waits until the current indexing pass finishes (tests, and callers that want warm caches).</summary>
    public bool WaitForIdle(TimeSpan timeout)
    {
        Task task;
        lock (_sync) task = _task;
        try { return task.Wait(timeout); }
        catch (AggregateException) { return true; }
    }

    private void Run(CancellationToken ct)
    {
        using var scope = AssemblyWorkspace.CancelWaitsWith(ct, "background indexing");
        try
        {
            var pending = _workspace.Read(() => _workspace.Assemblies.Where(a => !a.IsDirty && !_indexed.TryGetValue(a.Module, out _)).ToList());
            foreach (var asm in pending)
            {
                var types = _workspace.Read(() => asm.Module.GetTypes().ToList());
                for (int i = 0; i < types.Count; i += ChunkSize)
                {
                    ct.ThrowIfCancellationRequested();
                    _status = $"indexing {asm.Id} ({i}/{types.Count} types)";
                    int start = i;
                    _workspace.Read(() =>
                    {
                        if (!_workspace.Assemblies.Contains(asm)) return 0; // unloaded meanwhile
                        foreach (var t in types.Skip(start).Take(ChunkSize))
                            foreach (var m in t.Methods)
                                FastIlReader.Read(asm, m);
                        return 0;
                    });
                }
                _workspace.Read(() => { _indexed.AddOrUpdate(asm.Module, true); return 0; });
            }
            ct.ThrowIfCancellationRequested();
            _status = "building call graph";
            _graph.EnsureBuilt(ct);
            _status = "done";
            _logger?.LogInformation("Background indexing done ({Count} assemblies)", pending.Count);
        }
        catch (OperationCanceledException)
        {
            _status = "superseded";
        }
        catch (ObjectDisposedException)
        {
            _status = "stopped";
        }
        catch (Exception ex)
        {
            _status = $"failed: {ex.Message}";
            _logger?.LogWarning(ex, "Background indexing failed");
        }
    }

    public void Dispose()
    {
        lock (_sync) _run?.Cancel();
    }
}
