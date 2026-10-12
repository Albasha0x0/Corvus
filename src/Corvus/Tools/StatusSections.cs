using System.Globalization;
using Microsoft.Extensions.DependencyInjection;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Services;

namespace Corvus.Tools;

/// <summary>The budget a call gets: tool profile, page ceiling, deadline and delivery, each with its source.</summary>
internal sealed class BudgetStatus : IStatusSection
{
    public string Name => "budget";
    public int Order => 10;

    public IEnumerable<StatusField> Fields(IServiceProvider services)
    {
        if (services.GetService<ServerOptions>() is not { } o) yield break;
        var defaults = new ServerOptions();
        yield return new("profile", o.Toolsets.SetEquals(Core.Toolsets.All) ? "all" : string.Join(",", o.Toolsets.Order(StringComparer.Ordinal)),
            o.Toolsets.SetEquals(Core.Toolsets.Default) ? "default" : $"{Core.Toolsets.Option} or {Core.Toolsets.Variable}");
        yield return new("ceiling", $"{o.MaxOutputChars.ToString("N0", CultureInfo.InvariantCulture)} characters per page",
            o.MaxOutputChars == defaults.MaxOutputChars ? "default" : "--max-output");
        yield return new("deadline", $"{o.TimeoutSeconds * CallFilter.DeadlineFactor} s per call ({CallFilter.DeadlineFactor}x --timeout {o.TimeoutSeconds} s); long-running tools keep their own limits",
            o.TimeoutSeconds == defaults.TimeoutSeconds ? "default" : "--timeout");
        yield return new("delivery", "text blocks, plus structuredContent for tools with an output schema; a result over the ceiling is kept (results section)");
    }
}

/// <summary>The kept-result store (S3.5).</summary>
internal sealed class ResultsStatus : IStatusSection
{
    public string Name => "results";
    public int Order => 20;

    public IEnumerable<StatusField> Fields(IServiceProvider services)
    {
        if (services.GetService<ResultStore>() is not { } store) yield break;
        var s = store.Status();
        var source = Environment.GetEnvironmentVariable(ResultCacheOptions.RootVariable) is { Length: > 0 } ? ResultCacheOptions.RootVariable : "default";
        yield return new("mode", s.Mode == "disk" ? "disk and memory" : "memory only", source);
        if (s.Root != null)
        {
            yield return new("folder", s.Root, source);
            yield return new("disk", $"{s.Entries} results, {Megabytes(s.Bytes)} of {s.MaxBytes >> 20} MB, unused results kept {s.MaxAge.TotalDays:0} days",
                $"{ResultCacheOptions.MaxMegabytesVariable}, {ResultCacheOptions.MaxDaysVariable}");
        }
        yield return new("memory", $"{s.MemoryEntries} results, {s.MemoryChars.ToString("N0", CultureInfo.InvariantCulture)} of {s.MaxMemoryChars.ToString("N0", CultureInfo.InvariantCulture)} characters");
        yield return new("perResult", $"{s.MaxResultChars.ToString("N0", CultureInfo.InvariantCulture)} characters at most on disk");
        yield return new("session", $"{s.Kept} kept, {s.Reads} read, {s.Evicted} evicted" + (s.LastError != null ? $"; last problem: {s.LastError}" : ""));
    }

    internal static string Megabytes(long bytes) => (bytes / (1024.0 * 1024)).ToString("0.#", CultureInfo.InvariantCulture) + " MB";
}

/// <summary>Saved and in-memory caches: engine databases, native code indexes, imported names and the page cache.</summary>
internal sealed class CachesStatus : IStatusSection
{
    public string Name => "caches";
    public int Order => 30;

    public IEnumerable<StatusField> Fields(IServiceProvider services)
    {
        var engines = services.GetService<NativeEngineService>();
        var code = services.GetService<NativeCodeService>();
        if (engines?.CacheStatus() is { } db)
            yield return new("engineDatabases", $"{db.Root}: {db.Entries} entries, {ResultsStatus.Megabytes(db.Bytes)} of {db.MaxBytes >> 20} MB, unused entries kept {db.MaxAge.TotalDays:0} days; " +
                $"this session {db.Evicted} evicted" + (db.LastError != null ? $"; last problem: {db.LastError}" : ""),
                $"{Native.Providers.AnalysisCache.RootVariable}, {Native.Providers.AnalysisCache.MaxMegabytesVariable}, _DAYS");
        if (code != null)
        {
            yield return code.IndexCache?.Status() is { } c
                ? new("codeIndex", $"{c.Root}: {c.Entries} entries, {ResultsStatus.Megabytes(c.Bytes)} of {c.MaxBytes >> 20} MB, unused entries kept {c.MaxAge.TotalDays:0} days; " +
                    $"this session {c.Hits} loaded, {c.Misses} not found, {c.Rejected} unusable (rebuilt), {c.Writes} saved, {c.Evicted} evicted" +
                    (c.LastError != null ? $"; last problem: {c.LastError}" : ""), "--index-cache")
                : new("codeIndex", "off: every image's code index is built when it is opened", "--index-cache off or CORVUS_CODE_INDEX_CACHE=off");
            var s = code.ImportStats;
            yield return new("importedNames", $"{code.AnnotationRoot}; this session {s.LayersRestored} layer(s) restored on load ({s.NamesRestored} names), {s.LayersSaved} saved" +
                (s.LastProblem != null ? $"; last problem: {s.LastProblem}" : ""));
        }
        if (services.GetService<OutputPager>() is { } pager)
            yield return new("decompile", $"{pager.CachedTexts} texts kept for later pages");
    }
}

/// <summary>Calls still running after cancellation or their deadline, and the workspace lock holders.</summary>
internal sealed class CallsStatus : IStatusSection
{
    public string Name => "calls";
    public int Order => 40;

    public IEnumerable<StatusField> Fields(IServiceProvider services)
    {
        if (services.GetService<ServerOptions>() is { } options)
        {
            var leftovers = LeftoverWork.For(options);
            yield return new("leftover", $"{leftovers.Running} of at most {leftovers.Max} cancelled or timed-out calls still finishing; {leftovers.Total} since start" +
                (leftovers.Running < leftovers.Max ? "" : "; new calls wait, then are refused as busy"), LeftoverWork.MaxVariable);
        }
        // This call holds no lock, so every holder is another call or background work.
        if (services.GetService<AssemblyWorkspace>() is { } workspace)
        {
            var users = workspace.LockUsers();
            yield return new("workspaceLock", users.Count == 0 ? "free" : string.Join("; ", users.Select(u => u.ToString())));
        }
    }
}

/// <summary>Child processes of this server (engine workers, helpers, external tools) with their start times.</summary>
internal sealed class WorkersStatus : IStatusSection
{
    public string Name => "workers";
    public int Order => 50;

    public IEnumerable<StatusField> Fields(IServiceProvider services) =>
        Native.Providers.ChildProcess.Live().Select(w => new StatusField(w.Program, $"pid {w.Id}, started {w.Started:yyyy-MM-ddTHH:mm:ssZ}"));
}

/// <summary>This server process: run id (also in each trace line), process id and start time.</summary>
internal sealed class RunStatus : IStatusSection
{
    public string Name => "run";
    public int Order => 60;

    public IEnumerable<StatusField> Fields(IServiceProvider services) =>
    [
        new("runId", CallLog.RunId),
        new("pid", Environment.ProcessId.ToString(CultureInfo.InvariantCulture)),
        new("started", ServerIdentity.StartedAt.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture)),
    ];
}
