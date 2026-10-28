using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Worker;
using Corvus.Services.Analysis;

namespace Corvus.Tools;

public sealed partial class NativeEmulationTools
{
    internal const string SpeakeasyEngine = "speakeasy";

    /// <summary>API calls a speakeasy run may make before it stops.</summary>
    internal const int MaxApiCalls = 10_000;

    /// <summary>Saved runs kept per image; older run folders are deleted when a new run starts.</summary>
    internal const int KeptRuns = 8;

    /// <summary>The folder that holds the saved emulator runs; tests point it elsewhere.</summary>
    internal static string RunsRoot { get => _runsRoot ?? DataFolder.Combine("emulation"); set => _runsRoot = value; }

    private static string? _runsRoot;

    private static void RefuseGhidraOnly(params (string Name, string? Value)[] given)
    {
        var used = given.Where(g => !string.IsNullOrWhiteSpace(g.Value)).Select(g => g.Name).ToList();
        if (used.Count > 0)
            throw new ToolError(ErrorCode.InvalidArgument, $"engine=speakeasy runs the whole program from address and takes no {string.Join(", ", used)}.",
                "omit them, or pass engine=ghidra to emulate one function with them");
    }

    /// <summary>Runs the image in speakeasy in the worker host: from its entry point (or address), or as raw code at address.</summary>
    private async Task<string> EmulateProgramAsync(string image, string address, int maxInstructions, int seconds, CancellationToken cancellationToken)
    {
        var emulator = ExternalTools.Locate(ExternalTools.Emulator)?.Path
            ?? throw new ToolError(ErrorCode.ProviderUnavailable, $"engine=speakeasy needs {ExternalTools.Emulator.Name}, which was not found ({ExternalTools.Emulator.Variable} or PATH).",
                ExternalTools.Remediation(ExternalTools.Emulator));
        var (native, rva) = await Task.Run(() => NativeAnalysisTools.Resolve(workspace, nativeCode, image, address), cancellationToken);
        var arch = native.Image.Arch switch
        {
            NativeArch.X86 => "x86",
            NativeArch.X64 => "amd64",
            var other => throw new ToolError(ErrorCode.Unsupported, $"speakeasy emulates x86 and x64 code; {native.Id} is {other}.", "pass engine=ghidra"),
        };
        var request = new JsonObject
        {
            ["emulator"] = emulator, ["input"] = native.FilePath, ["seconds"] = seconds, ["apis"] = MaxApiCalls, ["instructions"] = maxInstructions,
        };
        switch (native.Image)
        {
            case RawCodeImage:
                request["raw"] = true;
                request["offset"] = rva;
                request["arch"] = arch;
                break;
            case Native.Pe.PeFile pe:
                if (rva != pe.EntryPointRva) request["entry"] = rva;
                break;
            default:
                throw new ToolError(ErrorCode.Unsupported, $"speakeasy runs Windows PE images and raw code; {native.Id} is {native.Image.Format}.", "pass engine=ghidra");
        }
        var output = NewRunFolder(native.OriginalSha256);
        request["output"] = output;
        // The worker op waits seconds + 60 for the emulator; 30 s more covers the worker's start and its reply.
        var answer = await WorkerPool.Shared.RunAsync("emulator", ProgramEmulationOps.EmulateOp, request, TimeSpan.FromSeconds(seconds + 90), cancellationToken,
            native.FilePath);
        var run = answer.Deserialize<ProgramEmulation>(ProgramEmulationOps.Json) ?? throw new ToolError(ErrorCode.Failed, "The emulator worker answered without a result.");
        var notes = run.Notes.ToList();
        if (native.HasPatches) notes.Add("The emulator ran the file on disk: patches made in this session are not in it (save_native writes them).");
        run = run with { Notes = notes };
        var text = FormatProgram(native.Id, run, output);
        var report = ProgramReport(native.Id, run);
        var where = run.StoppedAt ?? "?";
        ToolError? error = run.Stop switch
        {
            "complete" => null,
            "unsupported_api" => new ToolError(ErrorCode.Unsupported, $"Emulation stopped at {where}: the emulator does not model {run.Detail ?? "an API"}.",
                "the calls before it are in the partial result; engine=ghidra with stubs= answers that call in one function") { Partial = text },
            "timeout" or "max_total_time" => new ToolError(ErrorCode.Timeout, $"Emulation reached its time budget ({seconds} s) at {where}.",
                "raise timeoutSeconds; the calls so far are in the partial result") { Partial = text },
            "max_api_count" => new ToolError(ErrorCode.LimitExceeded, $"Emulation reached {MaxApiCalls:N0} API calls at {where}.",
                "the calls so far are in the partial result") { Partial = text },
            "max_instructions" or "max_instruction_count" => new ToolError(ErrorCode.LimitExceeded, $"Emulation reached its instruction budget ({maxInstructions:N0}) at {where}.",
                "raise maxInstructions; the calls so far are in the partial result") { Partial = text },
            _ => new ToolError(ErrorCode.Failed, $"Emulation stopped at {where}: {run.Stop}{(run.Detail != null ? $" ({run.Detail})" : "")}.",
                "the calls before it are in the partial result; disassemble shows the code there") { Partial = text },
        };
        return error != null ? throw error : Mcp.ToolOutput.Report(text, report);
    }

    private static long _lastRunTicks;

    /// <summary>A new run folder for the image with <paramref name="sha256"/>; the oldest runs past <see cref="KeptRuns"/> are deleted.</summary>
    internal static string NewRunFolder(string sha256)
    {
        var parent = Path.Combine(RunsRoot, sha256[..Math.Min(16, sha256.Length)]);
        Directory.CreateDirectory(parent);
        foreach (var old in Directory.GetDirectories(parent).Order(StringComparer.Ordinal).SkipLast(KeptRuns - 1))
            try { Directory.Delete(old, recursive: true); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        // Names sort in start order, also for runs started within one clock tick.
        long ticks, last;
        do
        {
            last = Interlocked.Read(ref _lastRunTicks);
            ticks = Math.Max(DateTime.UtcNow.Ticks, last + 1);
        }
        while (Interlocked.CompareExchange(ref _lastRunTicks, ticks, last) != last);
        var folder = Path.Combine(parent, new DateTime(ticks, DateTimeKind.Utc).ToString("yyyyMMdd-HHmmss-fffffff", CultureInfo.InvariantCulture));
        Directory.CreateDirectory(folder);
        return folder;
    }

    internal static EmulationReport ProgramReport(string imageId, ProgramEmulation run) =>
        new(imageId, SpeakeasyEngine, 0, run.Stop, run.StoppedAt, null, run.ReturnValue, [], run.ApiCalls.Count, [], [], [], [])
        {
            ElapsedSeconds = run.ElapsedSeconds,
            ApiCalls = run.ApiCalls,
            FilesWritten = run.FilesWritten,
            RegionSet = run.RegionSet,
            Notes = run.Notes,
        };

    internal static string FormatProgram(string imageId, ProgramEmulation run, string output)
    {
        var sb = new StringBuilder();
        sb.Append(CultureInfo.InvariantCulture, $"{imageId}: speakeasy emulation ({run.Arch}), ");
        sb.Append(run.Stop == "complete" ? "ran to its end" : $"stopped at {run.StoppedAt ?? "?"}: {run.Stop}{(run.Detail != null ? $" ({run.Detail})" : "")}");
        if (run.ReturnValue != null) sb.Append(", returned ").Append(run.ReturnValue);
        sb.Append(CultureInfo.InvariantCulture, $", {ToolSupport.Plural(run.ApiCalls.Count, "API call")}, {run.ElapsedSeconds:0.###} s\n");
        foreach (var c in run.ApiCalls.Take(200))
            sb.Append(CultureInfo.InvariantCulture, $"  {c.Site} {c.Api}({string.Join(", ", c.Arguments)}){(c.Returned != null ? " -> " + c.Returned : "")}\n");
        if (run.ApiCalls.Count > 200) sb.Append(CultureInfo.InvariantCulture, $"  ... {run.ApiCalls.Count - 200} more in the structured result\n");
        foreach (var f in run.FilesWritten)
            sb.Append(CultureInfo.InvariantCulture, $"wrote {f.Path} ({f.Size:N0} bytes){(f.SavedAs != null ? ", saved as " + f.SavedAs : "")}\n");
        if (run.RegionSet != null)
            sb.Append(CultureInfo.InvariantCulture, $"memory: {run.Regions} region(s), {run.RegionBytes:N0} bytes, in {run.RegionSet} (open_minidump reads it)\n");
        foreach (var n in run.Notes) sb.Append("note: ").Append(n).Append('\n');
        sb.Append("run folder: ").Append(output).Append('\n');
        return sb.ToString();
    }
}
