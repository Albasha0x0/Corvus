using System.Text;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Native;
using Corvus.Native.Providers;
using static Corvus.Tools.ToolSupport;

namespace Corvus.Tools;

public sealed partial class NativeCodeTools
{
    /// <summary>Code items the engine is asked to scan for candidates.</summary>
    private const int CandidateScan = 5_000_000;

    private static bool Candidates(string? view) => view?.Trim().ToLowerInvariant() switch
    {
        null or "" or "functions" => false,
        "candidates" => true,
        _ => throw new ToolError(ErrorCode.InvalidArgument, $"Unknown view '{view}'.", "use functions or candidates"),
    };

    /// <summary>
    /// list_functions view=candidates: runs of code the engine decoded that no function holds, ranked by the calls, then the
    /// jumps and data references, to their start; define_native kind=function makes one a function.
    /// </summary>
    private async Task<string> FunctionCandidates(string image, (EngineMode Mode, bool Named) mode, int offset, int limit,
        RequestContext<CallToolRequestParams>? context, IProgress<ProgressNotificationValue> progress, CancellationToken ct)
    {
        if (engines == null) throw new ToolError(ErrorCode.Unsupported, "view=candidates needs IDA or Ghidra; no engine is configured.");
        string? engine = mode.Mode switch
        {
            EngineMode.Ida => "ida",
            EngineMode.Ghidra => "ghidra",
            EngineMode.Ours when mode.Named => throw new ToolError(ErrorCode.InvalidArgument, "view=candidates reads the code IDA or Ghidra decoded outside functions; the built-in index has none.",
                "pass engine=ida or engine=ghidra"),
            _ => null,
        };
        var native = await Task.Run(() => NativeAnalysisTools.ResolveImage(workspace, image), ct);
        var session = await engines.Session(native, engine, new Progress<NativeProviderProgress>(p =>
            progress.Report(new ProgressNotificationValue { Progress = (float)p.Elapsed.TotalSeconds, Message = p.Stage })), ct);
        var scan = await EngineControl.Require(session, "function candidates").FunctionCandidatesAsync(CandidateScan, ct);
        var ranked = scan.Items.OrderByDescending(c => c.Calls).ThenByDescending(c => c.Jumps + c.DataRefs).ThenBy(c => c.Start).ToList();
        var pe = native.Image;
        string Va(uint rva) => NativeAddress.Va(pe, rva);
        var rows = ranked.Select(c => $"{Va(c.Start)}  {c.End - c.Start,7}  {Plural(c.Instructions, "instruction")}; refs to start: {c.Calls} call, {c.Jumps} jump, {c.DataRefs} data").ToList();
        var engineLine = $"Engine: {session.ProviderId} (code outside functions)";
        var sb = new StringBuilder($"{native.Id}: {Plural(ranked.Count, "run")} of code in no function ({session.ProviderId}; {scan.Scanned:N0} code items scanned" +
                                   (scan.Truncated ? $", stopped at {CandidateScan:N0}" : "") + ")\n" + engineLine + "\n");
        sb.Append(pager.PageRows(rows, offset, limit, "candidate"));
        if (ranked.Count > 0) sb.AppendLine($"Next: define_native image={native.Id} address={Va(ranked[0].Start)} kind=function");
        var result = Paged(ranked, offset, limit, (page, o, total, more) => new FunctionList(native.Id, ranked.Count,
            page.Select(c => new FunctionEntry(Va(c.Start), (int)(c.End - c.Start), $"candidate_{pe.ImageBase + c.Start:X}",
                ["candidate", Plural(c.Instructions, "instruction")], session.ProviderId, c.Calls + c.Jumps + c.DataRefs)).ToList(),
            o, total, more, scan.Truncated ? $"scan stopped at {CandidateScan:N0} code items" : null, session.ProviderId, "code outside functions"));
        return ToolOutput.With(sb.ToString(), result);
    }
}
