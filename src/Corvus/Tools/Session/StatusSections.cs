using System.Globalization;
using Microsoft.Extensions.DependencyInjection;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Services;

namespace Corvus.Tools;

/// <summary>The budget a call gets: client, tool profile, output ceiling, page size, deadline and delivery, each with its source.</summary>
internal sealed class BudgetStatus : IStatusSection
{
    public string Name => "budget";
    public int Order => 10;

    public IEnumerable<StatusField> Fields(IServiceProvider services)
    {
        if (services.GetService<ServerOptions>() is not { } o) yield break;
        var defaults = new ServerOptions();
        var c = ClientProfiles.Resolve(o, ClientName(services));
        static string N(int n) => n.ToString("N0", CultureInfo.InvariantCulture);
        yield return new("client", $"{c.Profile.Name} ({c.Profile.Id})", c.Source);
        yield return new("profile", c.Toolsets, o.ToolsetsText != null ? $"{Core.Toolsets.Option} or {Core.Toolsets.Variable}" : c.Source);
        yield return new("ceiling", $"{N(c.MaxTokens)} tokens per result" + (c.MaxChars is { } chars ? $", at most {N(chars)} characters" : ""), c.MaxTokensSource);
        yield return new("page", "estimated tokens per part: list 6,000, code 8,000, bytes 6,000, report 4,000, edit 3,000; a call's maxTokens up to the ceiling");
        var server = Deadlines.Server(o).TotalSeconds;
        yield return c.DeadlineSeconds is { } waits && Deadlines.Effective(false, o, c) is { } answer
            ? new("deadline", $"{answer.TotalSeconds:0} s per call: {c.Profile.Id} waits {waits} s, so calls answer {Deadlines.ClientMargin.TotalSeconds:0} s before " +
                $"(server limit {server:0} s); long-running tools stop then too, and the same call made again picks up their work", c.DeadlineSource)
            : new("deadline", $"{server:0} s per call ({Deadlines.ServerFactor}x --timeout {o.TimeoutSeconds} s); long-running tools keep their own limits",
                o.TimeoutSeconds == defaults.TimeoutSeconds ? "default" : "--timeout");
        bool json = string.Equals(Environment.GetEnvironmentVariable(CallFilter.ResultModeVariable), "json", StringComparison.OrdinalIgnoreCase);
        yield return new("delivery", json ? "text block = the structured JSON, plus structuredContent"
            : "text, plus structuredContent where a tool has an output schema; each part fitted alone: lists continue at nextOffset, " +
              "other results keep their head and a resultId", json ? CallFilter.ResultModeVariable : "default");
    }

    /// <summary>The connected client's clientInfo.name, when the server is in this provider.</summary>
    private static string? ClientName(IServiceProvider services)
    {
        try { return services.GetService<ModelContextProtocol.Server.McpServer>()?.ClientInfo?.Name; }
        catch (InvalidOperationException) { return null; }
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
            yield return new("folder", StatusPaths.Short(s.Root), source);
            yield return new("disk", $"{Core.FolderTally.Text(s.Entries, s.Bytes, Megabytes, "results")} of {s.MaxBytes >> 20} MB, unused results kept {s.MaxAge.TotalDays:0} days",
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
            yield return new("engineDatabases", $"{StatusPaths.Short(db.Root)}: {Core.FolderTally.Text(db.Entries, db.Bytes, ResultsStatus.Megabytes)} of {db.MaxBytes >> 20} MB, unused entries kept {db.MaxAge.TotalDays:0} days; " +
                $"this session {db.Evicted} evicted" + (db.LastError != null ? $"; last problem: {db.LastError}" : ""),
                $"{Native.Providers.AnalysisCache.RootVariable}, {Native.Providers.AnalysisCache.MaxMegabytesVariable}, _DAYS");
        if (code != null)
        {
            yield return code.IndexCache?.Status() is { } c
                ? new("codeIndex", $"{StatusPaths.Short(c.Root)}: {Core.FolderTally.Text(c.Entries, c.Bytes, ResultsStatus.Megabytes)} of {c.MaxBytes >> 20} MB, unused entries kept {c.MaxAge.TotalDays:0} days; " +
                    $"this session {c.Hits} loaded, {c.Misses} not found, {c.Rejected} unusable (rebuilt), {c.Writes} saved, {c.Evicted} evicted" +
                    (c.LastError != null ? $"; last problem: {c.LastError}" : ""), "--index-cache")
                : new("codeIndex", "off: every image's code index is built when it is opened", "--index-cache off or CORVUS_CODE_INDEX_CACHE=off");
            var s = code.ImportStats;
            yield return new("importedNames", $"{StatusPaths.Short(code.AnnotationRoot)}; this session {s.LayersRestored} layer(s) restored on load ({s.NamesRestored} names), {s.LayersSaved} saved" +
                (s.LastProblem != null ? $"; last problem: {s.LastProblem}" : ""));
        }
        if (services.GetService<OutputPager>() is { } pager)
            yield return new("decompile", $"{pager.CacheSize.Count} texts kept for later pages, {pager.CacheSize.Chars.ToString("N0", CultureInfo.InvariantCulture)} of " +
                $"{OutputPager.CacheMaxChars.ToString("N0", CultureInfo.InvariantCulture)} characters");
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
            yield return new("joined", $"{CallJoin.For(options).Running} read-only runs shared by identical calls");
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

    // Programs are few; their instances are not, so each program is one field naming at most this many.
    internal const int PidsPerProgram = 3;

    public IEnumerable<StatusField> Fields(IServiceProvider services) =>
        Native.Providers.ChildProcess.Live().GroupBy(w => w.Program, StringComparer.Ordinal).Select(g => new StatusField(g.Key, Describe([.. g])));

    /// <summary>One program's running children, oldest first: pid and start of each up to <see cref="PidsPerProgram"/>, then a count.</summary>
    internal static string Describe(IReadOnlyList<(int Id, string Program, DateTimeOffset Started)> children) =>
        string.Join("; ", children.Take(PidsPerProgram).Select(w => $"pid {w.Id}, started {w.Started:yyyy-MM-ddTHH:mm:ssZ}")) +
        (children.Count > PidsPerProgram ? $"; {children.Count - PidsPerProgram} more" : "");
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
        new("dataDir", Native.Providers.DataFolder.Root,
            Environment.GetEnvironmentVariable(Native.Providers.DataFolder.RootVariable) is { Length: > 0 } ? Native.Providers.DataFolder.RootVariable : "default"),
    ];
}

/// <summary>Status paths under the data folder name it once (run.dataDir), so a long folder does not repeat in every section.</summary>
internal static class StatusPaths
{
    public const string DataDir = "<dataDir>";

    public static string Short(string path)
    {
        var root = Path.TrimEndingDirectorySeparator(Native.Providers.DataFolder.Root);
        return path.StartsWith(root, StringComparison.OrdinalIgnoreCase) && (path.Length == root.Length || path[root.Length] is '/' or '\\')
            ? DataDir + path[root.Length..] : path;
    }
}
