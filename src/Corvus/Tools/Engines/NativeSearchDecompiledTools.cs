using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.RegularExpressions;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Native;
using Corvus.Native.Providers;
using Corvus.Services;
using static Corvus.Tools.ToolSupport;

namespace Corvus.Tools;

/// <summary>A regular expression over the engine's pseudocode of many functions, budgeted, in parallel where the engine allows, resumable by cursor.</summary>
[McpServerToolType]
public sealed class NativeSearchDecompiledTools(AssemblyWorkspace workspace, NativeEngineService engines, OutputPager pager, NativeCodeService? code = null,
    NativeNamePush? names = null, NativeTypePush? types = null, NativeUserTypePush? userTypes = null, TimeProvider? time = null)
{
    private readonly TimeProvider _time = time ?? TimeProvider.System;

    public sealed record DecompiledHit(
        [property: Description("Start VA of the function.")] string Function,
        string Name,
        [property: Description("1-based line of the pseudocode.")] int Line,
        string Text);

    public sealed record SearchDecompiledReport(
        string Image,
        [property: Description("ida or ghidra.")] string Engine,
        string Pattern,
        IReadOnlyList<DecompiledHit> Items,
        [property: Description("Functions in scope (after filter; thunks left out).")] int FunctionsTotal,
        [property: Description("Index of the first function searched (offset counts functions, not hits).")] int Offset,
        [property: Description("Functions searched by this call.")] int FunctionsSearched,
        [property: Description("Functions that did not decompile (their error and the rest in the text).")] int Failed,
        [property: Description("offset= for the next call; absent when every function in scope was searched.")] int? NextOffset,
        bool HasMore,
        [property: Description("False when functions were left: the hits are those of the functions searched.")] bool TotalExact,
        [property: Description("Why the call stopped before the end: hits (limit), functions (maxFunctions) or time (timeoutSeconds).")] string? StoppedBy)
    {
        [Description("Seconds the search took (moved to _meta).")] public double? ElapsedSeconds { get; init; }
        [Description("Why this engine answered.")] public string? EngineNote { get; init; }
    }

    /// <summary>Functions asked of the engine per request: small enough to stop near the budget, large enough to amortize the round trip.</summary>
    private const int Chunk = 8;

    [McpServerTool(Name = "search_decompiled", Title = "Search native pseudocode", UseStructuredContent = true, OutputSchemaType = typeof(SearchDecompiledReport))]
    [Description("Regex (case-insensitive; (?-i) for exact case) per line of the IDA or Ghidra pseudocode of every function (or filtered ones), in " +
                 "address order; parallel where the engine allows, cached. Stops at maxFunctions, timeoutSeconds or limit hits.")]
    public Task<string> SearchDecompiled(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("Regex.")] string pattern,
        [Description(EngineChoice.EngineOnlyDescription)] string? engine = null,
        [Description(NameFilter.Description + ".")] string? filter = null,
        [Description("Max 20000.")] int maxFunctions = 500,
        [Description("Max 600.")] int timeoutSeconds = 60,
        [Description("First function (nextOffset).")] int offset = 0,
        [Description("Max hits (max 2000).")] int limit = 100,
        [Description(ToolSupport.MaxTokensDescription)] int? maxTokens = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        if (string.IsNullOrWhiteSpace(pattern)) throw new ToolError(ErrorCode.InvalidArgument, "pattern is empty.", "pass a regular expression, e.g. 'memcpy|strcpy'");
        Regex regex;
        try { regex = new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(200)); }
        catch (ArgumentException e) { throw new ToolError(ErrorCode.InvalidArgument, $"pattern is not a valid regular expression: {e.Message}"); }
        var nameFilter = NameFilter.Parse(filter);
        int cursor = offset;
        if (cursor < 0) throw new ToolError(ErrorCode.InvalidArgument, $"offset must be 0 or more, not {cursor}.");
        int max = Math.Clamp(maxFunctions, 1, 20_000), hitLimit = Math.Clamp(limit, 1, 2000);
        var budget = TimeSpan.FromSeconds(Math.Clamp(timeoutSeconds, 1, 600));
        long started = _time.GetTimestamp();

        EngineChoice.Mode(engine, engines);
        var native = await Task.Run(() => NativeAnalysisTools.ResolveImage(workspace, image), cancellationToken);
        var choice = EngineChoice.EngineOnly(engine, engines, native);
        var session = await engines.Session(native, choice.Engine, new Progress<NativeProviderProgress>(p =>
            progress.Report(new ProgressNotificationValue { Progress = (float)p.Elapsed.TotalSeconds, Message = p.Stage })), cancellationToken);
        EngineReport.Answered(choice, engines, session);
        if (!session.DecompilerAvailable)
            throw new ToolError(ErrorCode.Unsupported, $"The {session.ProviderId} decompiler is not available for {session.Arch} code here.",
                "search_instructions searches the disassembly instead");
        if (names != null) await names.EnsureAsync(native, session, cancellationToken);
        if (types != null) await types.EnsureAsync(native, session, cancellationToken);
        if (userTypes != null) await userTypes.EnsureAsync(native, session, cancellationToken);

        var index = code?.Ready(native);
        var pe = native.Image;
        string Display(NativeFunctionInfo f) => NativeTools.DisplayName(index?.NameAt(f.StartRva) ?? f.Name, pe.Format);
        var scope = (await session.ListFunctionsAsync(cancellationToken)).Where(f => (f.Flags & NativeFunctionFlags.Thunk) == 0)
            .GroupBy(f => f.StartRva).Select(g => g.First()).OrderBy(f => f.StartRva)
            .Where(f => nameFilter == null || nameFilter.IsMatch(Display(f)) || nameFilter.IsMatch(f.Name)).ToList();
        if (cursor > scope.Count) throw new ToolError(ErrorCode.InvalidArgument, $"offset {cursor} is past the {scope.Count} functions in scope.", "start again with offset=0");
        var window = scope.Skip(cursor).Take(max).ToList();

        var texts = new string?[window.Count];
        var errors = new string?[window.Count];
        var stamp = Stamp(session);
        int hitsSoFar = 0;
        var lanes = Math.Clamp(EngineControl.Of(session)?.DecompileLanes ?? 1, 1, 16);
        int chunk = Chunk * lanes; // one request at a time; the engine spreads it over its decompiler pool
        for (int first = 0; first < window.Count && hitsSoFar < hitLimit; first += chunk)
        {
            var left = budget - _time.GetElapsedTime(started);
            if (left <= TimeSpan.Zero) break;
            int last = Math.Min(first + chunk, window.Count);
            var asked = new List<int>();
            for (int i = first; i < last; i++)
            {
                if (Cached(native, session, stamp, window[i].StartRva) is { } cached) texts[i] = cached;
                else asked.Add(i);
            }
            if (asked.Count > 0)
            {
                IReadOnlyList<DecompileOutcome> outcomes;
                try
                {
                    outcomes = await session.DecompileManyAsync(asked.Select(i => window[i].StartRva).ToList(), Math.Min(60, left.TotalSeconds),
                        Math.Max(1, left.TotalSeconds), cancellationToken);
                }
                catch (ToolError e) when (e.Code is not ErrorCode.NotLoaded)
                {
                    // the request failed as a whole (a worker restart): its functions are failures, the search goes on
                    outcomes = asked.Select(i => new DecompileOutcome(window[i].StartRva, DecompileStatus.Error, null, ToolError.CodeName(e.Code), e.Message)).ToList();
                }
                for (int k = 0; k < asked.Count && k < outcomes.Count; k++)
                {
                    int i = asked[k];
                    var o = outcomes[k];
                    if (o.Function is { } f) texts[i] = Remember(session, stamp, window[i].StartRva, f.Text);
                    else if (o.Status == DecompileStatus.Error) errors[i] = $"{o.ErrorCode}: {o.Error}";
                }
            }
            for (int i = first; i < last; i++)
                if (texts[i] is { } t) hitsSoFar += CountHits(regex, t, hitLimit);
            progress.Report(new ProgressNotificationValue { Progress = last, Total = window.Count, Message = $"searching pseudocode: {last}/{window.Count}" });
        }

        // results in address order: stop at the first function not reached, or after the one that reaches the hit limit
        var hits = new List<DecompiledHit>();
        var failures = new List<string>();
        int searched = 0;
        string? stoppedBy = null;
        for (int i = 0; i < window.Count; i++)
        {
            if (texts[i] == null && errors[i] == null) { stoppedBy = hitsSoFar >= hitLimit ? "hits" : "time"; break; }
            searched++;
            if (errors[i] is { } error) { failures.Add($"{NativeAddress.Va(pe, window[i].StartRva)} {Display(window[i])}: {error}"); continue; }
            var lines = texts[i]!.Split('\n');
            for (int l = 0; l < lines.Length; l++)
            {
                var line = lines[l].TrimEnd('\r');
                bool match;
                try { match = regex.IsMatch(line); }
                catch (RegexMatchTimeoutException) { match = false; }
                if (match) hits.Add(new DecompiledHit(NativeAddress.Va(pe, window[i].StartRva), Display(window[i]), l + 1, Format.Clip(line.Trim(), 240)));
            }
            if (hits.Count >= hitLimit && i + 1 < window.Count) { stoppedBy = "hits"; break; }
        }
        int end = cursor + searched;
        if (stoppedBy == null && end < scope.Count) stoppedBy = "functions";
        int? nextCursor = end < scope.Count ? end : null;

        // the time taken is in _meta: the text is the same in every run that searched the same functions
        var sb = new StringBuilder($"// {native.Id}: /{pattern}/ over the {session.ProviderId} pseudocode of {Plural(scope.Count, "function")}" +
                                   (nameFilter != null ? $" matching '{nameFilter.Text}'" : "") + $"; searched {cursor + (searched > 0 ? 1 : 0)}-{end} " +
                                   $"(requests of {chunk} over a decompiler pool of {lanes})\n");
        sb.Append($"{Plural(hits.Count, "hit")} in {Plural(hits.Select(h => h.Function).Distinct().Count(), "function")}:\n");
        var rows = hits.Select(h => $"  {h.Function}  {h.Name}:{h.Line}  {h.Text}").ToList();
        int fit = pager.FitRows(rows, 2_000);
        foreach (var row in rows.Take(fit)) sb.Append(row).Append('\n');
        if (fit < rows.Count) sb.Append($"[{fit} of {rows.Count} hits fit in the output limit; the structured result has all]\n");
        if (failures.Count > 0)
        {
            sb.Append($"{Plural(failures.Count, "function")} did not decompile:\n");
            foreach (var f in failures.Take(10)) sb.Append("  " + f + "\n");
            if (failures.Count > 10) sb.Append($"  ... {failures.Count - 10} more\n");
        }
        if (nextCursor is { } nc)
            sb.Append($"Stopped ({stoppedBy switch { "hits" => $"limit={hitLimit} hits", "time" => $"timeoutSeconds={(int)budget.TotalSeconds} used", _ => $"maxFunctions={max}" }}); " +
                      $"[More: offset={nc}]\n");
        else sb.Append("Every function in scope was searched.\n");
        if (nextCursor != null) ToolOutput.Coverage("partial", $"{end - cursor} of the {scope.Count - cursor} functions from offset {cursor} were searched", Limitations.Id(stoppedBy == "time" ? Limitation.TimeLimit : Limitation.RowCap));
        return ToolOutput.With(sb.ToString(), new SearchDecompiledReport(native.Id, session.ProviderId, pattern, hits, scope.Count, cursor, searched,
            failures.Count, nextCursor, nextCursor != null, nextCursor == null, nextCursor != null ? stoppedBy : null)
            { ElapsedSeconds = Math.Round(_time.GetElapsedTime(started).TotalSeconds, 1), EngineNote = choice.Note });
    });

    private static int CountHits(Regex regex, string text, int cap)
    {
        int n = 0;
        foreach (var line in text.Split('\n'))
        {
            try { if (regex.IsMatch(line) && ++n >= cap) break; }
            catch (RegexMatchTimeoutException) { }
        }
        return n;
    }

    /// <summary>The pushed state the pseudocode depends on: names, types, PDB types, user types, analysis generation.</summary>
    private static string Stamp(INativeDecompilerSession session) =>
        $"{NativeNamePush.CurrentStamp(session)}|{NativeTypePush.CurrentStamp(session)}|{NativePdbTypes.CurrentStamp(session)}|" +
        $"{NativeUserTypePush.CurrentStamp(session)}|{EngineControl.Generation(session)}";

    /// <summary>Pseudocode of the function at <paramref name="start"/> from an earlier search or decompile_native, under the same stamp.</summary>
    private string? Cached(LoadedNative native, INativeDecompilerSession session, string stamp, uint start)
    {
        var cache = Texts.GetOrCreateValue(session);
        lock (cache)
            if (cache.Stamp == stamp && cache.Texts.TryGetValue(start, out var text)) return text;
        // decompile_native's text: a header line, then the pseudocode
        if (pager.TryGet(NativeAnalysisTools.TextKey(native, session, start, false), out var page) && page.IndexOf('\n') is var nl and >= 0)
            return page[(nl + 1)..];
        return null;
    }

    private static string Remember(INativeDecompilerSession session, string stamp, uint start, string text)
    {
        var cache = Texts.GetOrCreateValue(session);
        lock (cache)
        {
            if (cache.Stamp != stamp || cache.Chars + text.Length > MaxCachedChars)
            {
                cache.Texts.Clear();
                cache.Chars = 0;
                cache.Stamp = stamp;
            }
            if (cache.Texts.TryAdd(start, text)) cache.Chars += text.Length;
        }
        return text;
    }

    /// <summary>Pseudocode kept per session for later searches (about 64 MB of text at most).</summary>
    private const long MaxCachedChars = 32_000_000;

    private sealed class SessionTexts
    {
        public string Stamp = "";
        public long Chars;
        public readonly Dictionary<uint, string> Texts = [];
    }

    private static readonly ConditionalWeakTable<INativeDecompilerSession, SessionTexts> Texts = new();
}
