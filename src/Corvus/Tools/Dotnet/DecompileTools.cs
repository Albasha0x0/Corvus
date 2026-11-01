using System.ComponentModel;
using System.Text;
using dnlib.DotNet;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Services;
using Corvus.Services.Simplify;
using static Corvus.Tools.ToolSupport;

namespace Corvus.Tools;

[McpServerToolType]
public sealed class DecompileTools(AssemblyWorkspace workspace, DecompilerService decompiler, OutputPager pager, NotesService? notes = null,
    Services.Mobile.AndroidProjectExport? android = null, ServerOptions? options = null,
    Native.Providers.Worker.WorkerPool? workers = null)
{
    private const int MaxMembersPerCall = 25;

    [McpServerTool(Name = "decompile_member", Title = "Decompile to C#", UseStructuredContent = true, OutputSchemaType = typeof(CodePage))]
    [Description("Decompile a member or a whole type to C#; every overload unless a parameter list picks one. " +
                 "Code the decompiler fails on shows as IL.")]
    public Task<string> DecompileMember(
        [Description(SymbolDescription)] string member,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description("Restrict to this kind (default any).")] string? kind = null,
        [Description(SimplifiedDescription)] bool simplified = false,
        [Description("Start with build-pinning comments: SHA-256, MVID, tokens, IL hashes.")] bool provenance = false,
        [Description(CharOffsetDescription)] int offset = 0,
        [Description(MaxTokensDescription)] int? maxTokens = null,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var all = SymbolResolver.Resolve(workspace, assembly, member, SymbolResolver.ParseKind(kind));
        var header = offset == 0 ? NotesHeader(all) : "";
        if (all.Count == 1 && all[0].Member is TypeDef)
        {
            var banner = PlaceholderBanner(all[0].Assembly, [all[0].Member]);
            var source = banner + (provenance ? Provenance(all[0].Assembly, [all[0].Member]) : "") + TypeSource(all[0], simplified, cancellationToken);
            return header + ToolOutput.Text(pager, source, offset, Page("csharp", all), maxTokens);
        }
        RequireFew(all, member);

        var text = pager.GetOrCreate(CacheKey((simplified ? "member-simplified" : "member") + (provenance ? "-provenance" : ""), all), () =>
            string.Join("\n", all.GroupBy(a => a.Assembly).Select(g =>
                $"// [{g.Key.Id}]\n" + PlaceholderBanner(g.Key, g.Select(s => s.Member)) + (provenance ? Provenance(g.Key, g.Select(s => s.Member)) : "") + (simplified
                    ? decompiler.DecompileSimplified(g.Key, g.Select(s => s.Member).ToList(), new SimplifyOptions(), cancellationToken)
                    : decompiler.DecompileMembers(g.Key, g.Select(s => s.Member), cancellationToken)))));
        return header + ToolOutput.Text(pager, text, offset, Page("csharp", all), maxTokens);
    }, cancellationToken);

    /// <summary>
    /// Comment lines naming methods whose bodies are generated placeholders and the
    /// native address to read instead; empty when every method has a recovered body.
    /// </summary>
    private static string PlaceholderBanner(LoadedAssembly asm, IEnumerable<IMemberDef> members)
    {
        var rows = new List<string>();
        var total = 0;
        foreach (var m in members)
        {
            var methods = m switch
            {
                MethodDef md => [md],
                TypeDef t => t.Methods.ToList(),
                PropertyDef p => p.GetMethods.Concat(p.SetMethods).Concat(p.OtherMethods).ToList(),
                EventDef e => new[] { e.AddMethod, e.RemoveMethod, e.InvokeMethod }.OfType<MethodDef>().ToList(),
                _ => new List<MethodDef>(),
            };
            foreach (var method in methods)
            {
                var address = AotMetadataService.GetAttributes(method)
                    .FirstOrDefault(a => a.Name == "AddressAttribute" && !a.InvalidAddress);
                if (address == null) continue;
                total++;
                if (rows.Count >= 20) continue;
                // Address values are kept as written; an attribute with no location is reported as unknown.
                var location = new[] { "RVA", "VA", "Offset" }
                    .Select(k => (Key: k, Value: address.Values.GetValueOrDefault(k)))
                    .FirstOrDefault(x => AotMetadataService.ParseNumber(x.Value) != null);
                rows.Add(location.Value == null
                    ? $"//   {Format.MemberLabel(method)}  address unknown"
                    : $"//   {Format.MemberLabel(method)}  {location.Key} {location.Value}");
            }
        }
        if (total == 0) return "";
        return $"// Placeholder bodies in [{asm.Id}]: {total} methods, not recovered code. " +
               "Next: decompile_native at each address in the native image.\n" + string.Join("\n", rows) +
               (total > rows.Count ? $"\n//   ... {total - rows.Count} more" : "") + "\n";
    }

    /// <summary>The record of a code page; the call filter fills in the page.</summary>
    private static CodePage Page(string language, IReadOnlyList<ResolvedSymbol> symbols, IReadOnlyList<IlMethodHash>? methods = null) =>
        new(language, "", 0, null, 0) { Symbols = symbols.Select(SymbolRef.Of).ToList(), Methods = methods };

    /// <summary>One line when the members (a type: and its members) have open notes; empty otherwise, so it costs nothing without notes.</summary>
    private string NotesHeader(IReadOnlyList<ResolvedSymbol> symbols)
    {
        if (notes == null) return "";
        int open = 0;
        foreach (var g in symbols.GroupBy(s => s.Assembly))
        {
            if (g.Key.Module.Mvid is not { } mvid) continue;
            var tokens = g.SelectMany(s => s.Member is TypeDef t
                ? t.Methods.Cast<IMemberDef>().Concat(t.Fields).Concat(t.Properties).Concat(t.Events).Append(t)
                : [s.Member]).Select(m => m.MDToken.Raw).ToHashSet();
            open += notes.OpenCount(new NoteAnchor(NoteAnchor.DotNet, Mvid: mvid.ToString()).StoreKey, a => a.Token is { } token && tokens.Contains(token));
        }
        var first = symbols.Count > 0 ? symbols[0] : null;
        return first == null ? "" : NotesService.Header(open, symbols.Count == 1 ? $"{first.Assembly.Id}:{Format.Token(first.Member)}" : first.Assembly.Id);
    }

    /// <summary>Comment lines tying decompiled output to its build; hashes in full (docs/il-hash.md).</summary>
    private static string Provenance(LoadedAssembly asm, IEnumerable<IMemberDef> members)
    {
        var sb = new StringBuilder($"// Provenance: {asm.BuildIdentity}{(asm.IsDirty ? " (file as loaded; unsaved edits not included)" : "")}\n");
        using var raw = IlHash.RawReader(asm);
        foreach (var m in members)
        {
            sb.Append("//   ").Append(Format.MemberLabel(m)).Append("  token ").Append(Format.Token(m)).Append('\n');
            IEnumerable<MethodDef> methods = m switch
            {
                MethodDef md => [md],
                PropertyDef p => p.GetMethods.Concat(p.SetMethods).Concat(p.OtherMethods),
                EventDef e => new[] { e.AddMethod, e.RemoveMethod, e.InvokeMethod }.Where(x => x != null).Concat(e.OtherMethods),
                _ => [],
            };
            foreach (var method in methods)
                sb.Append("//     ").Append(m is MethodDef ? "" : $"{method.Name} {Format.Token(method)}: ").Append("IL hash ").Append(IlHash.Of(asm, method) ?? "none")
                  .Append("  raw IL SHA-256 ").Append(IlHash.RawSha256(raw, method) ?? "none").Append('\n');
        }
        return sb.ToString();
    }

    [McpServerTool(Name = "get_il", Title = "IL disassembly", UseStructuredContent = true, OutputSchemaType = typeof(CodePage))]
    [Description("IL disassembly of a member or type (tokens, offsets, try blocks); each method starts with its normalized IL hash " +
                 "(stable across rebuilds) and raw IL SHA-256. Input for patch_method_il.")]
    public Task<string> GetIL(
        [Description(SymbolDescription)] string symbol,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description("Portable PDB source lines at IL offsets, local names, SourceLink URLs.")] bool source = false,
        [Description(CharOffsetDescription)] int offset = 0,
        [Description(MaxTokensDescription)] int? maxTokens = null,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var all = SymbolResolver.Resolve(workspace, assembly, symbol);
        RequireFew(all, symbol);
        var text = pager.GetOrCreate(CacheKey(source ? "il-source" : "il", all), () => string.Join("\n", all.Select(s =>
        {
            var (pdb, status) = source ? PortablePdb.For(s.Assembly) : (null, "");
            var pdbLine = !source ? "" : pdb == null ? $"// {status}\n"
                : $"// {status}{(pdb.SourceLinkDocuments > 0 ? $"; SourceLink maps {Plural(pdb.SourceLinkDocuments, "document")}" : "")}\n";
            return $"// [{s.Assembly.Id}] {s.Label}\n{pdbLine}{HashLines(s)}{decompiler.Disassemble(s.Assembly, s.Member, cancellationToken, pdb)}";
        })));
        var hashes = all.SelectMany(s =>
        {
            using var raw = IlHash.RawReader(s.Assembly);
            return MethodsOf(s.Member).Select(m => new IlMethodHash(Format.Token(m), IlHash.Of(s.Assembly, m), IlHash.RawSha256(raw, m))).ToList();
        }).Take(200).ToList();
        return ToolOutput.Text(pager, text, offset, Page("il", all, hashes), maxTokens);
    }, cancellationToken);

    private static IEnumerable<MethodDef> MethodsOf(IMemberDef member) => member switch
    {
        MethodDef m => [m],
        PropertyDef p => p.GetMethods.Concat(p.SetMethods).Concat(p.OtherMethods),
        EventDef e => new[] { e.AddMethod, e.RemoveMethod, e.InvokeMethod }.Where(m => m != null).Concat(e.OtherMethods),
        TypeDef t => t.Methods,
        _ => [],
    };

    /// <summary>One "// IL hash:" line per method of the symbol with its raw IL SHA-256 (docs/il-hash.md), and the method's name unless the symbol is that method.</summary>
    private static string HashLines(ResolvedSymbol s)
    {
        var methods = MethodsOf(s.Member);
        var sb = new StringBuilder();
        using var raw = IlHash.RawReader(s.Assembly);
        foreach (var m in methods)
        {
            var hash = IlHash.Of(s.Assembly, m);
            var value = hash != null ? IlHash.Short(hash)
                : m.RVA == 0 && MetadataUtil.SafeBody(m) == null ? "none (no body)" : "none (body not valid IL)";
            sb.Append("// IL hash: ").Append(value);
            if (IlHash.RawSha256(raw, m) is { } bytes)
                sb.Append("  raw IL SHA-256: ").Append(IlHash.Short(bytes)).Append(s.Assembly.IsDirty ? " (file as loaded)" : "");
            if (s.Member is not MethodDef) sb.Append("  ").Append(m.Name).Append('(').Append(Format.ParameterTypes(m.MethodSig)).Append(')');
            sb.Append('\n');
            if (!s.Assembly.IsDirty)
                foreach (var issue in s.Assembly.BodyHealth.ClauseIssues(m))
                    sb.Append("// invalid exception clause: ").Append(issue).Append('\n');
        }
        return sb.ToString();
    }

    [McpServerTool(Name = "export_project", Title = "Export C# project", UseStructuredContent = true, OutputSchemaType = typeof(ExportOutcome))]
    [Description("Decompile an assembly into a C# project on disk; an .apk or .aab gives a Gradle project. " +
                 "Written whole or not at all; a repeat joins a running export.")]
    public Task<string> ExportProject(
        [Description(AssemblyDescription)] string assembly,
        [Description("Empty or new output directory.")] string outputDirectory,
        [Description("Replace a previous export in outputDirectory.")] bool overwrite = false,
        RequestContext<CallToolRequestParams> context = null!, // bound by the SDK
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        // The call's token also ends at its deadline, which ends this wait only.
        // The export stops when the client cancels, it ends or it stalls.
        var stop = OutputCall.Current is { } call ? call.ClientCancel : cancellationToken;
        var key = ExportKey(assembly, outputDirectory);
        var joins = CallJoin.For(options ?? Detached);
        var runs = RunsOf(joins);
        var started = new ExportRun();
        int answered = 0;
        void Progress(int d, int t, string status)
        {
            started.Rule?.Progress($"{d} of {t} units ({status})");
            (started.Done, started.Total) = (d, t);
            if (Volatile.Read(ref answered) == 0) Report(progress, d, t, status);
        }
        bool package = android != null && Services.Mobile.AndroidProjectExport.IsPackagePath(assembly) && File.Exists(assembly.Trim());
        var joined = joins.Run(key, token =>
        {
            runs[key] = started;
            return Job(runs, key, started, package, assembly, outputDirectory, overwrite, Progress, token);
        }, stop, r => r);
        var run = joined.WasRunning && runs.TryGetValue(key, out var existing) ? existing : started;
        Interlocked.Increment(ref run.Waiting);
        bool left = false, delivered = false;
        try
        {
            var deadline = new TaskCompletionSource();
            using (cancellationToken.Register(() => deadline.TrySetResult()))
                if (await Task.WhenAny(joined.Result, deadline.Task) == joined.Result || stop.IsCancellationRequested)
                {
                    delivered = true;
                    // A caller that takes the end is its report: mark it before
                    // leaving the wait, so no notice follows.
                    if (joined.Result.IsCompleted) Interlocked.Exchange(ref run.Notified, 1);
                    return Render(await joined.Result);
                }
            Volatile.Write(ref answered, 1);
            // Leave the wait first, then register, so an end in between still finds this caller gone.
            left = true;
            Interlocked.Decrement(ref run.Waiting);
            _ = joined.Work.ContinueWith(t => NotifyEnd(run, assembly, outputDirectory, (Task<ExportOutcome>)t),
                CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            var (done, total) = (run.Done, run.Total);
            throw new ToolError(ErrorCode.Timeout, $"The export of {assembly} is still running ({done} of {total} units done); " +
                $"it continues in the background and {SafeFile.FullPath(outputDirectory)} appears only when complete.",
                "repeat the same call to wait; a [workspace] notice reports its end")
            {
                Partial = new { done, total, outputDirectory = SafeFile.FullPath(outputDirectory) },
                Details = new { stillRunning = true, partial = true },
                RetryAfter = LeftoverWork.RetryAfter,
                Retryable = true,
            };
        }
        finally
        {
            if (!left)
            {
                Interlocked.Decrement(ref run.Waiting);
                // A caller that detached without a result leaves an ended run unannounced otherwise.
                if (!delivered && joined.Work.IsCompleted) NotifyEnd(run, assembly, outputDirectory, (Task<ExportOutcome>)joined.Work);
            }
        }
    });

    private static readonly ServerOptions Detached = new();

    private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<CallJoin, System.Collections.Concurrent.ConcurrentDictionary<string, ExportRun>> RunTables = new();

    private static string ExportKey(string assembly, string outputDirectory) => $"export_project:{assembly.Trim()}|{SafeFile.FullPath(outputDirectory)}";

    /// <summary>Callers waiting on the running export of the assembly to the folder; 0 when none runs.</summary>
    internal int WaitingOn(string assembly, string outputDirectory) =>
        RunsOf(CallJoin.For(options ?? Detached)).TryGetValue(ExportKey(assembly, outputDirectory), out var run) ? Volatile.Read(ref run.Waiting) : 0;

    /// <summary>Running exports by join key for one join table, for the units done and the waiting callers.</summary>
    private static System.Collections.Concurrent.ConcurrentDictionary<string, ExportRun> RunsOf(CallJoin joins) =>
        RunTables.GetValue(joins, _ => new(StringComparer.Ordinal));

    /// <summary>The clock of the stall check.</summary>
    internal TimeProvider Clock { get; init; } = TimeProvider.System;

    /// <summary>The server's processor time; null when unreadable.</summary>
    internal Func<TimeSpan?> ProcessCpu { get; init; } = () =>
    {
        try { using var self = System.Diagnostics.Process.GetCurrentProcess(); return self.TotalProcessorTime; }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception) { return null; }
    };

    private sealed class ExportRun
    {
        public StallRule? Rule;
        public int Done, Total, Waiting, Notified;
    }

    // An export in this process ends on completion, cancel, error or a stall;
    // one in a file worker is watched by the worker's own stall rule.
    private async Task<ExportOutcome> Job(System.Collections.Concurrent.ConcurrentDictionary<string, ExportRun> runs, string key, ExportRun run, bool package, string assembly, string outputDirectory, bool overwrite,
        Action<int, int, string> progress, CancellationToken token)
    {
        var inWorker = package && FileIsolation.PoolFor(options, workers) is { Sandboxed: false };
        using var halt = CancellationTokenSource.CreateLinkedTokenSource(token);
        StallRule? rule = null;
        ITimer? timer = null;
        if (!inWorker)
        {
            var window = options is { } o ? TimeSpan.FromSeconds(o.StallSeconds) : ServerOptions.StallWindow();
            var watched = rule = run.Rule = new StallRule(window, Clock);
            var poll = window / 8;
            timer = Clock.CreateTimer(_ => { if (watched.Stalled(ProcessCpu())) halt.Cancel(); }, null, poll, poll);
        }
        try
        {
            var stopToken = halt.Token;
            return await Task.Run(() => package ? ExportPackage(assembly.Trim(), outputDirectory, overwrite, progress, stopToken)
                : Task.FromResult(ExportAssembly(assembly, outputDirectory, overwrite, progress, stopToken)), CancellationToken.None).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (rule != null && !token.IsCancellationRequested)
        {
            throw new ToolError(ErrorCode.Timeout,
                $"{StallRule.MessagePrefix}export_project': no progress and under 1% of the server's processor time for {rule.Window.TotalSeconds:0.###} s ({rule.LastUnitText}); nothing was kept.",
                $"repeat the same call to export again, or raise {ServerOptions.StallWindowVariable} (seconds without progress)")
            { Partial = new { done = run.Done, total = run.Total }, Retryable = true };
        }
        finally
        {
            // DisposeAsync waits for a running stall check, so it cannot cancel
            // halt after halt is disposed.
            if (timer != null) await timer.DisposeAsync().ConfigureAwait(false);
            runs.TryRemove(new KeyValuePair<string, ExportRun>(key, run));
        }
    }

    /// <summary>The first line of a failed job's message, or a fixed text when it reported none.</summary>
    private static string Reason(Task job) => (job.Exception?.GetBaseException().Message ?? "no reason reported").Split('\n')[0].Trim();

    /// <summary>Queues the end of an export once; none while a caller still waits and gets the result.</summary>
    private void NotifyEnd(ExportRun run, string assembly, string outputDirectory, Task<ExportOutcome> job)
    {
        if (Volatile.Read(ref run.Waiting) > 0 || Interlocked.Exchange(ref run.Notified, 1) != 0) return;
        var dir = SafeFile.FullPath(outputDirectory);
        workspace.Notify(job.Status switch
        {
            TaskStatus.RanToCompletion => $"export_project of {assembly} finished: {job.Result.Files} files in {dir}. Next: build {job.Result.ProjectFile ?? dir}, or repeat the call with overwrite=true to export again.",
            TaskStatus.Canceled => $"export_project of {assembly} was cancelled; nothing was kept. Next: repeat the same call to export again.",
            _ => $"export_project of {assembly} failed ({Format.Clip(Reason(job), 200)}). Next: fix the cause and repeat the same call (overwrite=true replaces a finished export).",
        });
    }

    private ExportOutcome ExportAssembly(string assembly, string outputDirectory, bool overwrite, Action<int, int, string> progress, CancellationToken ct)
    {
        var asm = workspace.Read(() => workspace.Get(assembly), ct);
        var r = decompiler.ExportProject(asm, outputDirectory, progress, ct, overwrite);
        return new ExportOutcome(true, asm.Id, r.Directory, r.FileCount, r.ProjectFile, r.FailedTypes) { Replaced = r.Replaced, Notes = r.Renamed.Count > 0 ? r.Renamed : null, RenamedFiles = r.RenamedFiles.Count > 0 ? r.RenamedFiles : null };
    }

    private Task<ExportOutcome> ExportPackage(string path, string outputDirectory, bool overwrite, Action<int, int, string> progress, CancellationToken ct)
    {
        var args = new FileWork.ExportPackageArgs(path, outputDirectory, overwrite);
        // A sandboxed worker cannot write the named folder, so the export stays in the server.
        if (FileIsolation.PoolFor(options, workers) is { Sandboxed: true }) return FileWork.ExportPackageWith(android!, args, progress, ct);
        return FileIsolation.RunAsync(options, workers, FileWork.ExportPackage, args, path,
            () => FileWork.ExportPackageWith(android!, args, progress, ct).GetAwaiter().GetResult(), ct);
    }

    private static string Render(ExportOutcome r)
    {
        var text = $"Exported {r.Source} to {r.OutputDirectory}: {r.Files} files.{(r.ProjectFile != null ? $" Project: {r.ProjectFile}" : "")}{(r.Replaced ? " (replaced the previous export)" : "")}";
        if (r.Notes is { Count: > 0 } notes) text += "\n" + string.Join("\n", notes);
        if (r.RenamedFiles is { Count: > 0 } renamed) text += $"\nWritten with .bin appended: {string.Join(", ", renamed.Take(20))}";
        if (r.FailedTypes.Count > 0)
            text += $"\n{Plural(r.FailedTypes.Count, "type")} failed to decompile (their files contain the error):\n  " + string.Join("\n  ", r.FailedTypes.Take(20));
        return ToolOutput.With(text, r);
    }

    private const string SimplifiedDescription =
        "Show the code as simplify_methods would leave it, assembly unchanged.";

    private string TypeSource(ResolvedSymbol sym, bool simplified, CancellationToken ct) =>
        pager.GetOrCreate(CacheKey(simplified ? "type-simplified" : "type", [sym]), () => $"// [{sym.Assembly.Id}] {sym.Label}\n" + (simplified
            ? decompiler.DecompileSimplified(sym.Assembly, [sym.Member], new SimplifyOptions(), ct)
            : decompiler.DecompileType(sym.Assembly, (TypeDef)sym.Member, ct)));

    private string CacheKey(string kind, IEnumerable<ResolvedSymbol> symbols) =>
        $"{decompiler.TypeSystemKey()}|{kind}|{string.Join(",", symbols.Select(s => s.Assembly.Id + (s.Member.MDToken.Rid != 0 ? Format.Token(s.Member) : Format.MemberLabel(s.Member))))}"; // added members share token (new)

    /// <summary>More than 25 matches: ambiguous, naming up to 25 in details.matches and as many as fit the error budget in the text.</summary>
    private static void RequireFew(IReadOnlyList<ResolvedSymbol> all, string query)
    {
        if (all.Count <= MaxMembersPerCall) return;
        var first = all.Take(MaxMembersPerCall).ToList();
        var lines = new List<string>();
        int chars = 0;
        foreach (var a in first)
        {
            var line = "  " + a;
            if (chars + line.Length > 2_000) break;
            lines.Add(line);
            chars += line.Length + 1;
        }
        throw new ToolError(ErrorCode.Ambiguous, $"'{query}' matches {all.Count} symbols. First matches:\n" + string.Join("\n", lines) +
                            (lines.Count < all.Count ? $"\n  ... {all.Count - lines.Count} more" : ""),
            "narrow it with a type name, a parameter list (Method(int, string)) or a token from details.matches")
        { Details = new { matches = first.Select(SymbolRef.Of).ToList(), total = all.Count } };
    }
}
