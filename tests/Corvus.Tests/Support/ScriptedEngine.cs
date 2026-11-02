using System.Text.Json;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Ida;

namespace Corvus.Tests;

/// <summary>
/// An engine whose functions, pseudocode, references, analysis control and marks are scripted: search_decompiled,
/// reanalyze_native, list_functions view=candidates, decompile_native callersOf and note marks run against it in the quick set.
/// </summary>
internal sealed class ScriptedEngine : INativeDecompilerProvider
{
    public string Id { get; init; } = IdaProvider.ProviderId;
    public string DisplayName => "scripted engine";
    public List<(uint Start, uint End, string Name, NativeFunctionFlags Flags)> Functions { get; } = [];
    public Dictionary<uint, string> Texts { get; } = [];
    public HashSet<uint> Failing { get; } = [];
    /// <summary>Seconds each decompilation of these functions takes.</summary>
    public Dictionary<uint, double> Slow { get; } = [];
    /// <summary>When set, slow functions advance this clock instead of waiting, and batches time out against it.</summary>
    public ManualClock? Clock { get; set; }
    public List<NativeXref> Xrefs { get; } = [];
    public List<EngineString> Strings { get; } = [];
    public int Lanes { get; set; } = 1;
    public int Decompiles;
    /// <summary>Functions asked per batch request, in order.</summary>
    public List<int> Batches { get; } = [];
    public List<NativeAnalyzerOption> Analyzers { get; } = [];
    public List<(IReadOnlyList<KeyValuePair<string, string>> Options, uint? Start, uint? End, double? Seconds)> Reanalyses { get; } = [];
    /// <summary>When set, a reanalysis runs until it completes or is cancelled.</summary>
    public TaskCompletionSource? ReanalysisGate { get; set; }
    public Func<NativeReanalysis> ReanalysisResult { get; set; } = () => new NativeReanalysis(true, 2, 3, TimeSpan.FromSeconds(1), []);
    public List<NativeFunctionCandidate> Candidates { get; } = [];
    /// <summary>Request limits seen by each script run; null when the call set none.</summary>
    public List<TimeSpan?> ScriptLimits { get; } = [];
    /// <summary>Seconds a script takes; a run whose request limit (default 120 s) is shorter times out.</summary>
    public double ScriptSeconds { get; set; }
    /// <summary>When set, a script runs until it completes or is cancelled.</summary>
    public TaskCompletionSource? ScriptGate { get; set; }
    public NativeScriptResult ScriptResult { get; set; } = new("1", "", "", null);
    public List<(IReadOnlyList<NativeMark> Marks, string Stamp)> MarkPushes { get; } = [];
    /// <summary>Name batches the session received, with the stamp each carried.</summary>
    public List<(IReadOnlyList<NativeNameItem> Items, string? Stamp)> NamePushes { get; } = [];
    /// <summary>When set, a pushed name replaces the function's name in its pseudocode.</summary>
    public bool NamesShowInText { get; set; }
    /// <summary>When set, a session keeps names, comments, types and analysis state in a database file of this cache, as a real engine does.</summary>
    public AnalysisCache? Cache { get; set; }

    public ProviderAvailability CheckAvailability() => ProviderAvailability.Ok(Id, new Dictionary<string, string>());
    public Task<ProviderAvailability> ProbeAsync(CancellationToken cancellationToken = default) => Task.FromResult(CheckAvailability());

    /// <summary>Stages the open reports, each lasting the given milliseconds.</summary>
    public List<(string Stage, int Milliseconds)> OpenStages { get; } = [];
    /// <summary>Stages that last until their source completes, in place of their milliseconds.</summary>
    public Dictionary<string, TaskCompletionSource> StageGates { get; } = [];
    public int Opens;
    /// <summary>Types the session lists.</summary>
    public List<NativeTypeEntry> Types { get; } = [];
    /// <summary>When set, listing types waits for it.</summary>
    public TaskCompletionSource? TypeGate { get; set; }
    /// <summary>When set, the open fails with it.</summary>
    public Exception? OpenFailure { get; set; }
    /// <summary>When set, the session reports a partial analysis.</summary>
    public bool PartialAnalysis { get; set; }
    /// <summary>When set, the session reports every patch as missing, so the patched bytes open as their own image.</summary>
    public bool RefusePatches { get; set; }
    /// <summary>When set, the open fails with it after its stages.</summary>
    public Exception? LateOpenFailure { get; set; }

    /// <summary>Set when an open observed its cancellation token.</summary>
    public TaskCompletionSource OpenCancelled { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    /// <summary>Set when the provider was disposed, which ends a real engine's workers.</summary>
    public TaskCompletionSource Disposed { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

    public async Task<INativeDecompilerSession> OpenAsync(string imagePath, string? sha256 = null, NativeOpenOptions? options = null, CancellationToken cancellationToken = default)
    {
        Interlocked.Increment(ref Opens);
        if (OpenFailure != null) throw OpenFailure;
        var clock = System.Diagnostics.Stopwatch.StartNew();
        foreach (var (stage, ms) in OpenStages)
        {
            options?.Progress?.Report(new NativeProviderProgress(stage, clock.Elapsed));
            try
            {
                if (StageGates.TryGetValue(stage, out var gate)) await gate.Task.WaitAsync(cancellationToken);
                else await Task.Delay(ms, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                OpenCancelled.TrySetResult();
                throw;
            }
        }
        if (LateOpenFailure != null) throw LateOpenFailure;
        if (Cache == null) return new Session(this, null, new Database());
        var entry = Cache.Acquire(Id, imagePath, sha256);
        var file = Path.Combine(entry.Directory, Database.FileName);
        bool reused = File.Exists(file);
        return new Session(this, entry, reused ? JsonSerializer.Deserialize<Database>(File.ReadAllText(file))! : new Database()) { Reused = reused };
    }

    /// <summary>What the scripted engine keeps in its database file.</summary>
    internal sealed class Database
    {
        public const string FileName = "scripted.json";
        public Dictionary<uint, string> Names { get; set; } = [];
        public Dictionary<uint, string> Comments { get; set; } = [];
        public List<NativeTypeEntry> Types { get; set; } = [];
        public Dictionary<string, string> Options { get; set; } = [];
        public int Reanalyses { get; set; }
    }

    public void Dispose() => Disposed.TrySetResult();

    /// <summary>Adds a function of <paramref name="size"/> bytes with pseudocode lines.</summary>
    public void Add(uint start, string name, params string[] lines) => Add(start, 0x10, name, NativeFunctionFlags.None, lines);

    public void Add(uint start, uint size, string name, NativeFunctionFlags flags, params string[] lines)
    {
        Functions.Add((start, start + size, name, flags));
        Texts[start] = string.Join("\n", lines);
    }

    private sealed class Session(ScriptedEngine e, CacheEntry? entry, Database db) : INativeDecompilerSession, INativeEngineControl, IBackgroundJobs, IEngineDatabase
    {
        public BackgroundRunner Jobs { get; } = new(() => "image.bin");
        private string? _marksStamp;
        public string ProviderId => e.Id;
        public string ImagePath => "";
        public string Sha256 => "";
        public NativeArch Arch => NativeArch.X64;
        public ulong ImageBase => 0x140000000;
        public bool Reused { get; init; } = true;
        public bool ReusedDatabase => Reused;
        public TimeSpan OpenTime => TimeSpan.Zero;
        public bool DecompilerAvailable => true;
        public bool IsOpen => true;
        public string DatabasePath => entry == null ? "" : Path.Combine(entry.Directory, Database.FileName);

        private string NameOf((uint Start, uint End, string Name, NativeFunctionFlags Flags) f) => db.Names.GetValueOrDefault(f.Start, f.Name);

        // The file is replaced whole, so a reader never sees a partial write.
        private void Persist()
        {
            if (entry == null) return;
            lock (db)
            {
                var temp = DatabasePath + ".tmp";
                File.WriteAllText(temp, JsonSerializer.Serialize(db));
                File.Move(temp, DatabasePath, true);
            }
        }

        public string ExportNote => "the scripted database; the session's own copy stays in its analysis cache";

        public Task<long> SaveAsAsync(string path, CancellationToken cancellationToken)
        {
            if (entry == null) throw new ToolError(ErrorCode.Unsupported, "The scripted engine keeps no database file.");
            Persist();
            lock (db) File.Copy(DatabasePath, path, true);
            return Task.FromResult(new FileInfo(path).Length);
        }

        public bool AnalysisComplete => !e.PartialAnalysis;
        public int DecompileLanes => e.Lanes;

        public async Task<DecompiledFunction> DecompileAsync(uint rva, CancellationToken cancellationToken = default)
        {
            var f = e.Functions.FirstOrDefault(x => rva >= x.Start && rva < x.End);
            if (f.Name == null) throw new ToolError(ErrorCode.NotFound, $"no function contains rva 0x{rva:X}");
            if (e.Clock == null && e.Slow.TryGetValue(f.Start, out var s)) await Task.Delay(TimeSpan.FromSeconds(s), cancellationToken);
            if (e.Failing.Contains(f.Start)) throw new ToolError(ErrorCode.Failed, $"decompilation failed at 0x{f.Start:X}: scripted");
            Interlocked.Increment(ref e.Decompiles);
            string comment, name;
            lock (db)
            {
                comment = db.Comments.TryGetValue(f.Start, out var c) ? $"// {c}\n" : "";
                name = NameOf(f);
            }
            return new DecompiledFunction(f.Start, name, comment + e.Texts.GetValueOrDefault(f.Start, ""), []);
        }

        public Task<IReadOnlyList<DecompileOutcome>> DecompileManyAsync(IReadOnlyList<uint> rvas, double secondsPerItem, double budgetSeconds,
            CancellationToken cancellationToken = default)
        {
            lock (e) e.Batches.Add(rvas.Count);
            if (e.Clock is { } clock) return DecompileOnClockAsync(clock, rvas, secondsPerItem, budgetSeconds, cancellationToken);
            return ((INativeDecompilerSession)new Plain(this)).DecompileManyAsync(rvas, secondsPerItem, budgetSeconds, cancellationToken);
        }

        private async Task<IReadOnlyList<DecompileOutcome>> DecompileOnClockAsync(ManualClock clock, IReadOnlyList<uint> rvas, double secondsPerItem,
            double budgetSeconds, CancellationToken cancellationToken)
        {
            var results = new List<DecompileOutcome>(rvas.Count);
            long started = clock.GetTimestamp();
            foreach (var rva in rvas)
            {
                double left = budgetSeconds - clock.GetElapsedTime(started).TotalSeconds;
                if (left <= 0) { results.Add(new DecompileOutcome(rva, DecompileStatus.Skipped, null, null, null)); continue; }
                double limit = Math.Min(secondsPerItem, Math.Max(1, left));
                if (e.Slow.TryGetValue(rva, out var s) && s > limit)
                {
                    clock.Advance(TimeSpan.FromSeconds(limit));
                    results.Add(new DecompileOutcome(rva, DecompileStatus.Error, null, "timeout", $"not decompiled within {secondsPerItem:0.#} s"));
                    continue;
                }
                if (e.Slow.TryGetValue(rva, out s)) clock.Advance(TimeSpan.FromSeconds(s));
                try { results.Add(new DecompileOutcome(rva, DecompileStatus.Ok, await DecompileAsync(rva, cancellationToken), null, null)); }
                catch (ToolError x) { results.Add(new DecompileOutcome(rva, DecompileStatus.Error, null, ToolError.CodeName(x.Code), x.Message)); }
            }
            return results;
        }

        public async Task<NativeTypeList> ListTypesAsync(string? filter, string? kind, int offset, int limit, CancellationToken cancellationToken = default)
        {
            if (e.TypeGate != null) await e.TypeGate.Task.WaitAsync(cancellationToken);
            List<NativeTypeEntry> own;
            lock (db) own = [.. db.Types];
            var types = own.Concat(e.Types.Where(t => own.All(o => o.Name != t.Name)))
                .Where(t => kind == null || t.Kind == kind)
                .Where(t => string.IsNullOrEmpty(filter) || t.Name.Contains(filter, StringComparison.OrdinalIgnoreCase))
                .ToList();
            return new NativeTypeList(types.Count, types.Skip(Math.Max(0, offset)).Take(limit > 0 ? limit : int.MaxValue).ToList());
        }

        public Task<IReadOnlyList<NativeFunctionInfo>> ListFunctionsAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<NativeFunctionInfo>>(e.Functions.Select(f => new NativeFunctionInfo(f.Start, f.End, NameOf(f), f.Flags)).ToList());

        public Task<FunctionDisassembly> DisassembleAsync(uint rva, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<PatchSyncResult> SyncPatchesAsync(IReadOnlyList<NativeByteRange> wanted, CancellationToken cancellationToken = default) =>
            Task.FromResult(new PatchSyncResult(wanted.Count, 0, 0, 0, e.RefusePatches ? wanted.Count : 0, 0, [], TimeSpan.Zero));
        public Task<IReadOnlyList<NativeXref>> GetXrefsToAsync(uint rva, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<NativeXref>>(e.Xrefs.Where(x => x.ToRva == rva).ToList());
        public Task<IReadOnlyList<EngineString>> ListStringsAsync(int max, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<EngineString>>(e.Strings.Take(max).ToList());
        public Task<IReadOnlyList<NativeXref>> GetXrefsFromAsync(uint rva, bool wholeFunction = false, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<NativeXref>>([]);
        public Task<string> SetNameAsync(uint rva, string name, CancellationToken cancellationToken = default)
        {
            lock (db)
            {
                db.Names[rva] = name;
                Persist();
            }
            return Task.FromResult(name);
        }

        public Task<string> SetCommentAsync(uint rva, string text, bool repeatable = false, CancellationToken cancellationToken = default)
        {
            lock (db)
            {
                db.Comments[rva] = text;
                Persist();
            }
            return Task.FromResult(text);
        }
        public Task<NameBatchResult> ApplyNamesAsync(IReadOnlyList<NativeNameItem> items, string? stampKey = null, string? stamp = null, bool save = false,
            CancellationToken cancellationToken = default)
        {
            lock (e)
            {
                e.NamePushes.Add((items, stamp));
                lock (db)
                {
                    foreach (var item in items)
                    {
                        if (item.Name != null) db.Names[item.Rva] = item.Name;
                        if (!string.IsNullOrEmpty(item.Comment)) db.Comments[item.Rva] = item.Comment;
                    }
                    Persist();
                }
                if (e.NamesShowInText)
                    foreach (var item in items)
                        if (e.Functions.FirstOrDefault(f => f.Start == item.Rva) is { Name: not null } f && e.Texts.TryGetValue(f.Start, out var text))
                            e.Texts[f.Start] = text.Replace(f.Name, item.Name);
            }
            return Task.FromResult(new NameBatchResult(items.Count, 0, 0, 0, TimeSpan.Zero, []));
        }
        public Task<string?> GetStampAsync(string key, CancellationToken cancellationToken = default) =>
            Task.FromResult(key == EngineControl.MarksStampKey ? _marksStamp : null);
        public Task SaveAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task CloseAsync(bool save = true, CancellationToken cancellationToken = default) => Task.CompletedTask;
        public ValueTask DisposeAsync() { entry?.Dispose(); return ValueTask.CompletedTask; }
        public void Dispose() => entry?.Dispose();

        public Task<IReadOnlyList<NativeAnalyzerOption>> AnalyzersAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<NativeAnalyzerOption>>(e.Analyzers.Select(a =>
            {
                lock (db) return db.Options.TryGetValue(a.Name, out var v) ? a with { Value = v } : a;
            }).ToList());

        public Task<NativeReanalysis> ReanalyzeAsync(IReadOnlyList<KeyValuePair<string, string>> options, uint? start, uint? end, double? seconds,
            CancellationToken cancellationToken = default)
        {
            e.Reanalyses.Add((options, start, end, seconds));
            return e.ReanalysisGate is { } gate ? Wait(gate.Task, options, cancellationToken) : Task.FromResult(Reanalyzed(options));
        }

        /// <summary>Keeps the one-run options and the run count, as an engine keeps its analysis state.</summary>
        private NativeReanalysis Reanalyzed(IReadOnlyList<KeyValuePair<string, string>> options)
        {
            lock (db)
            {
                foreach (var (name, value) in options) db.Options[name] = value;
                db.Reanalyses++;
                Persist();
            }
            return e.ReanalysisResult();
        }

        private async Task<NativeReanalysis> Wait(Task gate, IReadOnlyList<KeyValuePair<string, string>> options, CancellationToken cancellationToken)
        {
            await gate.WaitAsync(cancellationToken);
            return Reanalyzed(options);
        }

        public async Task<NativeScriptResult> RunScriptAsync(string code, bool reset = false, CancellationToken cancellationToken = default)
        {
            e.ScriptLimits.Add(EngineRequestLimit.Current);
            if (e.ScriptGate is { } gate) await gate.Task.WaitAsync(cancellationToken);
            else if (EngineRequestLimit.Current != Timeout.InfiniteTimeSpan && e.ScriptSeconds > (EngineRequestLimit.Current ?? TimeSpan.FromSeconds(120)).TotalSeconds)
                throw new ToolError(ErrorCode.Timeout, "ida did not answer python within the limit.");
            return Scripted(code) ?? e.ScriptResult;
        }

        /// <summary>Runs the script lines "name RVA NAME", "comment RVA TEXT" and "type NAME KIND SIZE MEMBERS"; null when the code has none.</summary>
        private NativeScriptResult? Scripted(string code)
        {
            int applied = 0;
            foreach (var line in code.Split('\n', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
            lock (db)
            {
                var part = line.Split(' ', 3, StringSplitOptions.TrimEntries);
                if (part.Length < 3) continue;
                if (part[0] == "name" && uint.TryParse(part[1].AsSpan(2), System.Globalization.NumberStyles.HexNumber, null, out var named)) db.Names[named] = part[2];
                else if (part[0] == "comment" && uint.TryParse(part[1].AsSpan(2), System.Globalization.NumberStyles.HexNumber, null, out var noted)) db.Comments[noted] = part[2];
                else if (part[0] == "type" && part[2].Split(' ') is [var kind, var size, var members]
                    && long.TryParse(size, out var bytes) && int.TryParse(members, out var count))
                {
                    db.Types.RemoveAll(t => t.Name == part[1]);
                    db.Types.Add(new NativeTypeEntry(part[1], kind, bytes, count));
                }
                else continue;
                applied++;
            }
            if (applied == 0) return null;
            Persist();
            return new NativeScriptResult(applied.ToString(System.Globalization.CultureInfo.InvariantCulture), "", "", null);
        }

        public Task<NativeCandidateScan> FunctionCandidatesAsync(int maxInstructions, CancellationToken cancellationToken = default) =>
            Task.FromResult(new NativeCandidateScan(e.Candidates, e.Candidates.Sum(c => c.Instructions), false));

        public Task<NativeMarkResult> SetMarksAsync(IReadOnlyList<NativeMark> marks, string stamp, CancellationToken cancellationToken = default)
        {
            e.MarkPushes.Add((marks, stamp));
            _marksStamp = stamp;
            return Task.FromResult(new NativeMarkResult(marks.Count, 0, 0, []));
        }
    }

    /// <summary>The interface's default batch loop over the scripted session's DecompileAsync.</summary>
    private sealed class Plain(INativeDecompilerSession inner) : INativeDecompilerSession
    {
        public string ProviderId => inner.ProviderId;
        public string ImagePath => inner.ImagePath;
        public string Sha256 => inner.Sha256;
        public NativeArch Arch => inner.Arch;
        public ulong ImageBase => inner.ImageBase;
        public bool ReusedDatabase => true;
        public TimeSpan OpenTime => TimeSpan.Zero;
        public bool DecompilerAvailable => true;
        public bool IsOpen => true;
        public Task<DecompiledFunction> DecompileAsync(uint rva, CancellationToken cancellationToken = default) => inner.DecompileAsync(rva, cancellationToken);
        public Task<IReadOnlyList<NativeFunctionInfo>> ListFunctionsAsync(CancellationToken cancellationToken = default) => inner.ListFunctionsAsync(cancellationToken);
        public Task<FunctionDisassembly> DisassembleAsync(uint rva, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<IReadOnlyList<NativeXref>> GetXrefsToAsync(uint rva, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<IReadOnlyList<NativeXref>> GetXrefsFromAsync(uint rva, bool wholeFunction = false, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<string> SetNameAsync(uint rva, string name, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<string> SetCommentAsync(uint rva, string text, bool repeatable = false, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<NameBatchResult> ApplyNamesAsync(IReadOnlyList<NativeNameItem> items, string? stampKey = null, string? stamp = null, bool save = false,
            CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<string?> GetStampAsync(string key, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task SaveAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task CloseAsync(bool save = true, CancellationToken cancellationToken = default) => Task.CompletedTask;
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
        public void Dispose() { }
    }
}

/// <summary>A clock that moves only when told to, so time budgets are deterministic.</summary>
internal sealed class ManualClock : TimeProvider
{
    private long _ticks = TimeSpan.TicksPerDay;
    public override long TimestampFrequency => TimeSpan.TicksPerSecond;
    public override long GetTimestamp() => Interlocked.Read(ref _ticks);
    public override DateTimeOffset GetUtcNow() => new(Interlocked.Read(ref _ticks), TimeSpan.Zero);
    public void Advance(TimeSpan by) => Interlocked.Add(ref _ticks, by.Ticks);
}
