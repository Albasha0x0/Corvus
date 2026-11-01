using System.ComponentModel;
using System.Text;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Native;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Ghidra;
using Corvus.Native.Providers.Ida;
using Corvus.Services;
using ModelContextProtocol.Server;

namespace Corvus.Tools;

/// <summary>get_engine_status: what each engine session of a native image holds, without starting one.</summary>
[McpServerToolType]
public sealed class NativeEngineStatusTools(AssemblyWorkspace workspace, NativeEngineService? engines = null)
{
    public sealed record EngineBlock(string Name, [property: Description("VA.")] string Start, ulong Size, string Permissions, bool Initialized);

    public sealed record EngineStatus(
        [property: Description("ida or ghidra.")] string Engine,
        [property: Description("not_started, opening, open, failed or closed.")] string State,
        [property: Description("While opening (or where a failed open stopped): start, load, analysis, save, ready.")] string? Stage,
        [property: Description("Seconds since the open started.")] double Seconds,
        [property: Description("Whether the engine's cache holds a saved analysis of these bytes (an open loads it without analyzing).")] bool SavedAnalysis,
        string? Error)
    {
        public string? Version { get; init; }
        [Description("Expected open seconds: earlier opens or a default rate.")] public double? ExpectedSeconds { get; init; }
        [Description("Expected seconds left.")] public double? RemainingSeconds { get; init; }
        [Description("The running or ended job: an open, or a background run such as reanalyze_native.")] public EngineJob? Job { get; init; }
        [Description("The analysis profile: full or none (IDA); standard, full, minimal or none (Ghidra).")] public string? Profile { get; init; }
        [Description("Known limits of this engine's analysis (engine-profile-standard: about 2% fewer references than the full profile).")]
        public IReadOnlyList<string>? Limitations { get; init; }
        public string? Processor { get; init; }
        public string? Language { get; init; }
        public string? Compiler { get; init; }
        [Description("load_assembly's import overrides this database was made with (a database of its own).")] public string? ImportOverrides { get; init; }
        public string? Format { get; init; }
        [Description("VA.")] public string? ImageBase { get; init; }
        public int? PointerSize { get; init; }
        public string? Endian { get; init; }
        [Description("complete, partial (stopped early; the database keeps what was analyzed) or running.")]
        public string? Analysis { get; init; }
        public IReadOnlyList<string>? Warnings { get; init; }
        [Description("Ghidra: the analysis's Error and Warning bookmark counts.")] public string? AnalysisProblems { get; init; }
        [Description("Ghidra: the first bookmarks (all with bookmarks=true).")] public IReadOnlyList<string>? Bookmarks { get; init; }
        public int? Functions { get; init; }
        public int? ExternalFunctions { get; init; }
        [Description("VAs, at most 64.")] public IReadOnlyList<string>? EntryPoints { get; init; }
        public string? Md5 { get; init; }
        public string? Sha256 { get; init; }
        public IReadOnlyList<EngineBlock>? Blocks { get; init; }
        [Description("Whether the open loaded a saved database instead of analyzing.")] public bool? ReusedDatabase { get; init; }
        [Description("Seconds the open took.")] public double? OpenSeconds { get; init; }
        [Description("The project directory (Ghidra) or database file (IDA).")] public string? Database { get; init; }
        public int? WorkerPid { get; init; }
        public bool? Decompiler { get; init; }
        [Description("Edits a worker restart would replay (made since the last save).")] public int? UnsavedEdits { get; init; }
        [Description("Whether the database has changes not yet saved, when the engine says.")] public bool? Changed { get; init; }
        [Description("Seconds per open stage.")]
        public IReadOnlyList<EngineOpenStage>? OpenStages { get; init; }
    }

    /// <summary>A job of an engine session: what ran, whether it is running or ended, its budget and, once ended, its outcome.</summary>
    public sealed record EngineJob(
        [property: Description("open or the background run's name.")] string What,
        [property: Description("running or ended.")] string State,
        string StartedAt,
        [property: Description("Seconds the job may run; null: no limit.")] double? BudgetSeconds,
        [property: Description("The result once ended; null while running.")] string? Outcome)
    {
        [Description("complete, partial, failed or cancelled; null while running.")] public string? Result { get; init; }
    }

    public sealed record EngineStatusReport(string Image, IReadOnlyList<EngineStatus> Engines);

    [McpServerTool(Name = "get_engine_status", Title = "Engine status of a native image", UseStructuredContent = true, OutputSchemaType = typeof(EngineStatusReport))]
    [Description("IDA and Ghidra sessions of a native image: state, running job, engine view. Starts no engine.")]
    public async Task<string> GetEngineStatus(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("Default auto: both.")] string? engine = null,
        [Description("Ghidra: all Error and Warning bookmarks (default 5).")] bool bookmarks = false,
        [Description("Seconds to wait, 0-600; returns at the first state change, at once if settled.")] int waitSeconds = 0,
        CancellationToken cancellationToken = default)
    {
        if (engines == null) throw new ToolError(ErrorCode.ProviderUnavailable, "No analysis engine is set up in this server.");
        var wanted = string.IsNullOrWhiteSpace(engine) || engine.Trim().Equals("auto", StringComparison.OrdinalIgnoreCase) ? null : engine.Trim().ToLowerInvariant();
        if (wanted != null && !engines.ProviderIds.Contains(wanted))
            throw new ToolError(ErrorCode.InvalidArgument, $"Unknown engine '{engine!.Trim()}'.", "use auto, ida or ghidra");
        if (waitSeconds is < 0 or > 600) throw new ToolError(ErrorCode.InvalidArgument, $"waitSeconds {waitSeconds} is outside 0-600.", "waitSeconds=60");
        var native = await Task.Run(() => NativeAnalysisTools.ResolveImage(workspace, image), cancellationToken);
        var states = engines.ImageSessions(native);
        string? waited = null;
        if (waitSeconds > 0 && !Settled(states))
        {
            // The wait ends at the first change of an engine's state, and
            // before the call's deadline.
            var before = Signature(states);
            var wait = TimeSpan.FromSeconds(waitSeconds);
            if (Deadlines.Left is { } left && left - DeadlineMargin < wait) wait = left > DeadlineMargin ? left - DeadlineMargin : TimeSpan.Zero;
            var clock = System.Diagnostics.Stopwatch.StartNew();
            while (Signature(states) == before && clock.Elapsed < wait)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(Math.Min(200, Math.Max(1, (wait - clock.Elapsed).TotalMilliseconds))), cancellationToken);
                states = engines.ImageSessions(native);
            }
            if (Signature(states) == before)
                waited = $"no change in {clock.Elapsed.TotalSeconds:0} s" + (clock.Elapsed < TimeSpan.FromSeconds(waitSeconds) ? " (the call's deadline ended the wait)" : "");
        }
        var list = new List<EngineStatus>();
        foreach (var id in engines.ProviderIds.Where(i => wanted == null || i == wanted))
        {
            bool saved = engines.HasSavedAnalysis(native, id);
            var identity = engines.Identity(id);
            // Describe leaves only the completion pass's suffix in Profile.
            EngineStatus Known(EngineStatus s) => s with
            {
                Profile = identity.Profile + s.Profile, Version = s.Version ?? identity.Version,
                Limitations = identity.Profile == "standard" && s.Profile != "→full" ? [Limitations.Id(Limitation.EngineProfileStandard)] : null,
            };
            if (states.FirstOrDefault(s => s.Engine == id) is not { } state)
            {
                if (wanted != null || saved || engines.UnavailabilityOf(id) == null)
                    list.Add(Known(new EngineStatus(id, "not_started", null, 0, saved, engines.UnavailabilityOf(id)?.Reason)));
                continue;
            }
            var status = new EngineStatus(id, state.State, state.Stage, state.Seconds, saved, state.Error)
            {
                OpenStages = state.OpenStages.Count > 0 ? state.OpenStages : null,
                ExpectedSeconds = state.State == "opening" ? state.ExpectedSeconds : null,
                RemainingSeconds = state.State == "opening" ? Math.Max(0, Math.Round(state.ExpectedSeconds - state.Seconds)) : null,
                Job = state.State switch
                {
                    "opening" => new EngineJob("open", "running", state.OpenStarted.ToString("o"), engines.OpenLimitSeconds, null),
                    "failed" => new EngineJob("open", "ended", state.OpenStarted.ToString("o"), engines.OpenLimitSeconds, state.Error)
                        { Result = state.Cancelled ? "cancelled" : "failed" },
                    _ => null,
                },
            };
            if (state.Session is { IsOpen: true } session) status = await Describe(native, session, status, bookmarks, cancellationToken);
            status = Known(status);
            if (status.Analysis == "partial") status = status with { Limitations = [.. status.Limitations ?? [], Limitations.Id(Limitation.AnalysisPartial)] };
            list.Add(status);
        }
        return ToolOutput.With(Render(native, list, states, waited), new EngineStatusReport(native.Id, list));
    }

    /// <summary>Time kept back from the call's deadline so the answer arrives in time.</summary>
    private static readonly TimeSpan DeadlineMargin = TimeSpan.FromSeconds(1);

    /// <summary>True when no engine is opening and no background run is going: there is nothing to wait for.</summary>
    private static bool Settled(IReadOnlyList<NativeEngineService.ImageEngineStatus> states) =>
        states.All(s => s.State != "opening" && (s.Session as WorkerSessionBase)?.BackgroundRunning != true);

    private static string Signature(IReadOnlyList<NativeEngineService.ImageEngineStatus> states) =>
        string.Join('|', states.Select(s => $"{s.Engine}:{s.State}:{(s.Session as WorkerSessionBase)?.BackgroundRunning}"));

    private static async Task<EngineStatus> Describe(LoadedNative native, INativeDecompilerSession session, EngineStatus status, bool allBookmarks, CancellationToken ct)
    {
        string Va(ulong rva) => $"0x{session.ImageBase + rva:X}";
        status = status with
        {
            ImageBase = $"0x{session.ImageBase:X}",
            ReusedDatabase = session.ReusedDatabase,
            OpenSeconds = Math.Round(session.OpenTime.TotalSeconds, 1),
            Decompiler = session.DecompilerAvailable,
            Analysis = session.AnalysisComplete ? "complete" : "partial",
        };
        if (session is WorkerSessionBase worker)
        {
            status = status with { WorkerPid = worker.WorkerProcessId, UnsavedEdits = worker.UnsavedCount, ImportOverrides = worker.Overrides?.Text };
            if (worker.Background is { } job)
                status = status with
                {
                    Job = new EngineJob(job.What, worker.BackgroundRunning ? "running" : "ended", job.Started.ToString("o"), job.Budget?.TotalSeconds, worker.BackgroundResult) { Result = worker.BackgroundKind },
                    RemainingSeconds = worker.BackgroundRunning && job.Remaining(DateTime.UtcNow) is { } left ? Math.Round(left.TotalSeconds) : null,
                    Stage = worker.BackgroundRunning
                        ? $"background {job.What}: running {(DateTime.UtcNow - job.Started).TotalSeconds:0} s" +
                          (job.Budget is { } budget
                              ? $" of {budget.TotalSeconds:0} s, {job.Percent(DateTime.UtcNow)}% of the budget, at most {job.Remaining(DateTime.UtcNow)!.Value.TotalSeconds:0} s left"
                              : ", no time limit; it ends when the analysis finishes, stalls or is cancelled")
                        : $"background {worker.BackgroundResult}",
                };
            // A running job holds the engine; ask it nothing more.
            if (worker.BackgroundRunning) return status;
        }
        if (session is GhidraSession g)
        {
            status = status with { Database = g.ProjectDirectory, Warnings = g.Warnings, Language = g.Language, Functions = g.FunctionCount };
            status = status with { Profile = await g.CompletionAsync(ct) };
            var (errors, warnings, rows) = await g.BookmarksAsync(allBookmarks ? 2000 : 5, rva => Va(rva), ct);
            if (errors + warnings > 0) status = status with { AnalysisProblems = $"{errors} error(s), {warnings} warning(s)", Bookmarks = rows };
        }
        if (session is IdaSession i) status = status with { Database = i.DatabasePath, Warnings = i.Warnings.Count > 0 ? i.Warnings : null };
        try
        {
            var info = await session.GetEngineInfoAsync(ct);
            status = status with
            {
                Version = info.Version, Processor = info.Processor, Language = info.Language, Compiler = info.Compiler, Format = info.Format,
                PointerSize = info.PointerSize, Endian = info.Endian, Functions = info.Functions, ExternalFunctions = info.ExternalFunctions,
                EntryPoints = info.EntryPoints.Select(e => Va(e)).ToList(), Md5 = info.Md5, Sha256 = info.Sha256, Changed = info.Changed,
                Blocks = info.Blocks.Select(b => new EngineBlock(b.Name, $"0x{b.Start:X}", b.Size, b.Permissions, b.Initialized)).ToList(),
                Analysis = info.Analysis == "running" ? "running" : status.Analysis,
            };
        }
        catch (ToolError e)
        {
            status = status with { Error = $"{ToolError.CodeName(e.Code)}: {e.Message}" };
        }
        return status;
    }

    private static string Render(LoadedNative native, List<EngineStatus> list, IReadOnlyList<NativeEngineService.ImageEngineStatus> states, string? waited)
    {
        var sb = new StringBuilder($"Engine sessions of {native.Id}:\n");
        if (waited != null) sb.AppendLine(waited + "; call again to keep waiting");
        if (list.Count == 0) sb.AppendLine("  none: no engine is available");
        foreach (var s in list)
        {
            var name = NativeEngineService.DisplayName(s.Engine);
            switch (s.State)
            {
                case "not_started":
                    sb.AppendLine($"{name}: not started" + (s.SavedAnalysis ? "; a saved analysis exists (engine=" + s.Engine + " loads it without analyzing)" : "") +
                                  (s.Error != null ? $"; not available: {s.Error}" : ""));
                    continue;
                case "opening":
                    sb.AppendLine($"{name}: opening ({s.Stage ?? "start"}, {s.Seconds:0.#} s" +
                                  (s.ExpectedSeconds > 0 ? $", expected {s.ExpectedSeconds:0} s ({states.FirstOrDefault(e => e.Engine == s.Engine)?.ExpectedBasis ?? "default rate"}), about {s.RemainingSeconds:0} s left" : "") + ")");
                    sb.AppendLine($"  next: get_engine_status image={native.Id} waitSeconds=60 waits for the end; engine=ours answers now");
                    if (s.OpenStages != null) sb.AppendLine($"  stages so far: {EngineOpenProfile.Describe(s.OpenStages)}");
                    continue;
                case "failed":
                    sb.AppendLine($"{name}: failed after {s.Seconds:0.#} s ({s.Stage}): {s.Error}");
                    if (s.OpenStages != null) sb.AppendLine($"  open stages: {EngineOpenProfile.Describe(s.OpenStages)}");
                    continue;
                case "closed":
                    sb.AppendLine($"{name}: closed (the next engine call opens it again)");
                    continue;
            }
            sb.AppendLine($"{name} {s.Version}: open, analysis {s.Analysis}" + (s.ReusedDatabase == true ? ", reused saved database" : ", analyzed in this session") +
                          $", opened in {s.OpenSeconds:0.#} s; profile {s.Profile}");
            if (s.OpenStages != null) sb.AppendLine($"  open stages: {EngineOpenProfile.Describe(s.OpenStages)}");
            if (s.Stage?.StartsWith("background", StringComparison.Ordinal) == true) sb.AppendLine("  " + s.Stage);
            if (s.AnalysisProblems != null)
            {
                sb.AppendLine($"  analysis problems (bookmarks): {s.AnalysisProblems}");
                foreach (var b in s.Bookmarks ?? []) sb.AppendLine("    " + b);
            }
            if (s.Analysis == "partial")
                sb.AppendLine($"  the analysis budget ran out; reanalyze_native image={native.Id} engine={s.Engine} completes it");
            sb.AppendLine($"  {s.Processor} {s.Language}" + (s.Compiler != null ? $", compiler {s.Compiler}" : "") + $", {s.Format}, {s.PointerSize * 8}-bit {s.Endian}, base {s.ImageBase}");
            if (s.ImportOverrides != null) sb.AppendLine($"  import overrides: {s.ImportOverrides}");
            sb.AppendLine($"  {s.Functions} functions, {s.ExternalFunctions} external; decompiler {(s.Decompiler == true ? "available" : "not available")}");
            if (s.EntryPoints is { Count: > 0 } ep) sb.AppendLine($"  entry points: {string.Join(", ", ep.Take(8))}{(ep.Count > 8 ? $" (+{ep.Count - 8})" : "")}");
            if (s.Sha256 != null || s.Md5 != null) sb.AppendLine($"  input: sha256 {s.Sha256 ?? "-"}, md5 {s.Md5 ?? "-"}");
            sb.AppendLine($"  database {s.Database}; worker pid {s.WorkerPid?.ToString() ?? "none"}; {s.UnsavedEdits} unsaved edit(s)" +
                          (s.Changed == true ? ", changes not yet saved" : ""));
            foreach (var w in s.Warnings ?? []) sb.AppendLine($"  warning: {w}");
            if (s.Blocks is { Count: > 0 } blocks)
            {
                sb.AppendLine($"  {blocks.Count} memory blocks:");
                foreach (var b in blocks.Take(40)) sb.AppendLine($"    {b.Name,-12} {b.Start}  {b.Size,10:N0}  {b.Permissions}{(b.Initialized ? "" : "  uninitialized")}");
                if (blocks.Count > 40) sb.AppendLine($"    ... {blocks.Count - 40} more (structured output)");
            }
            if (s.Error != null) sb.AppendLine($"  error: {s.Error}");
        }
        return sb.ToString();
    }
}
