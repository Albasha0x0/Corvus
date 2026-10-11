using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Providers;
using NetDecompilerMcp.Native.Providers.Ida;

namespace NetDecompilerMcp.Tests;

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
    public List<NativeXref> Xrefs { get; } = [];
    public int Lanes { get; set; } = 1;
    public int Decompiles;
    /// <summary>Functions asked per batch request, in order.</summary>
    public List<int> Batches { get; } = [];
    public List<NativeAnalyzerOption> Analyzers { get; } = [];
    public List<(IReadOnlyList<KeyValuePair<string, string>> Options, uint? Start, uint? End, double Seconds)> Reanalyses { get; } = [];
    public Func<NativeReanalysis> ReanalysisResult { get; set; } = () => new NativeReanalysis(true, 2, 3, TimeSpan.FromSeconds(1), []);
    public List<NativeFunctionCandidate> Candidates { get; } = [];
    public List<(IReadOnlyList<NativeMark> Marks, string Stamp)> MarkPushes { get; } = [];

    public ProviderAvailability CheckAvailability() => ProviderAvailability.Ok(Id, new Dictionary<string, string>());
    public Task<ProviderAvailability> ProbeAsync(CancellationToken cancellationToken = default) => Task.FromResult(CheckAvailability());

    /// <summary>Stages the open reports, each lasting the given milliseconds.</summary>
    public List<(string Stage, int Milliseconds)> OpenStages { get; } = [];

    public async Task<INativeDecompilerSession> OpenAsync(string imagePath, string? sha256 = null, NativeOpenOptions? options = null, CancellationToken cancellationToken = default)
    {
        var clock = System.Diagnostics.Stopwatch.StartNew();
        foreach (var (stage, ms) in OpenStages)
        {
            options?.Progress?.Report(new NativeProviderProgress(stage, clock.Elapsed));
            await Task.Delay(ms, cancellationToken);
        }
        return new Session(this);
    }

    public void Dispose() { }

    /// <summary>Adds a function of <paramref name="size"/> bytes with pseudocode lines.</summary>
    public void Add(uint start, string name, params string[] lines) => Add(start, 0x10, name, NativeFunctionFlags.None, lines);

    public void Add(uint start, uint size, string name, NativeFunctionFlags flags, params string[] lines)
    {
        Functions.Add((start, start + size, name, flags));
        Texts[start] = string.Join("\n", lines);
    }

    private sealed class Session(ScriptedEngine e) : INativeDecompilerSession, INativeEngineControl
    {
        private string? _marksStamp;
        public string ProviderId => e.Id;
        public string ImagePath => "";
        public string Sha256 => "";
        public NativeArch Arch => NativeArch.X64;
        public ulong ImageBase => 0x140000000;
        public bool ReusedDatabase => true;
        public TimeSpan OpenTime => TimeSpan.Zero;
        public bool DecompilerAvailable => true;
        public bool IsOpen => true;
        public int DecompileLanes => e.Lanes;

        public async Task<DecompiledFunction> DecompileAsync(uint rva, CancellationToken cancellationToken = default)
        {
            var f = e.Functions.FirstOrDefault(x => rva >= x.Start && rva < x.End);
            if (f.Name == null) throw new ToolError(ErrorCode.NotFound, $"no function contains rva 0x{rva:X}");
            if (e.Slow.TryGetValue(f.Start, out var s)) await Task.Delay(TimeSpan.FromSeconds(s), cancellationToken);
            if (e.Failing.Contains(f.Start)) throw new ToolError(ErrorCode.Failed, $"decompilation failed at 0x{f.Start:X}: scripted");
            Interlocked.Increment(ref e.Decompiles);
            return new DecompiledFunction(f.Start, f.Name, e.Texts.GetValueOrDefault(f.Start, ""), []);
        }

        public Task<IReadOnlyList<DecompileOutcome>> DecompileManyAsync(IReadOnlyList<uint> rvas, double secondsPerItem, double budgetSeconds,
            CancellationToken cancellationToken = default)
        {
            lock (e) e.Batches.Add(rvas.Count);
            return ((INativeDecompilerSession)new Plain(this)).DecompileManyAsync(rvas, secondsPerItem, budgetSeconds, cancellationToken);
        }

        public Task<IReadOnlyList<NativeFunctionInfo>> ListFunctionsAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<NativeFunctionInfo>>(e.Functions.Select(f => new NativeFunctionInfo(f.Start, f.End, f.Name, f.Flags)).ToList());

        public Task<FunctionDisassembly> DisassembleAsync(uint rva, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<PatchSyncResult> SyncPatchesAsync(IReadOnlyList<NativeByteRange> wanted, CancellationToken cancellationToken = default) =>
            Task.FromResult(new PatchSyncResult(wanted.Count, 0, 0, 0, 0, 0, [], TimeSpan.Zero));
        public Task<IReadOnlyList<NativeXref>> GetXrefsToAsync(uint rva, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<NativeXref>>(e.Xrefs.Where(x => x.ToRva == rva).ToList());
        public Task<IReadOnlyList<NativeXref>> GetXrefsFromAsync(uint rva, bool wholeFunction = false, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<NativeXref>>([]);
        public Task<string> SetNameAsync(uint rva, string name, CancellationToken cancellationToken = default) => Task.FromResult(name);
        public Task<string> SetCommentAsync(uint rva, string text, bool repeatable = false, CancellationToken cancellationToken = default) => Task.FromResult(text);
        public Task<NameBatchResult> ApplyNamesAsync(IReadOnlyList<NativeNameItem> items, string? stampKey = null, string? stamp = null, bool save = false,
            CancellationToken cancellationToken = default) => Task.FromResult(new NameBatchResult(items.Count, 0, 0, 0, TimeSpan.Zero, []));
        public Task<string?> GetStampAsync(string key, CancellationToken cancellationToken = default) =>
            Task.FromResult(key == EngineControl.MarksStampKey ? _marksStamp : null);
        public Task SaveAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task CloseAsync(bool save = true, CancellationToken cancellationToken = default) => Task.CompletedTask;
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
        public void Dispose() { }

        public Task<IReadOnlyList<NativeAnalyzerOption>> AnalyzersAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<NativeAnalyzerOption>>(e.Analyzers);

        public Task<NativeReanalysis> ReanalyzeAsync(IReadOnlyList<KeyValuePair<string, string>> options, uint? start, uint? end, double seconds,
            CancellationToken cancellationToken = default)
        {
            e.Reanalyses.Add((options, start, end, seconds));
            return Task.FromResult(e.ReanalysisResult());
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
