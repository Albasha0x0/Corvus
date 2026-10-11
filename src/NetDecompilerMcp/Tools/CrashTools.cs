using System.ComponentModel;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Services;

namespace NetDecompilerMcp.Tools;

/// <summary>Crash analysis beyond one dump: crash text without a dump.</summary>
[McpServerToolType]
public sealed class CrashTools(StackTextService stacks)
{
    [McpServerTool(Name = "symbolize_stack_text", Title = "Symbolize crash text", UseStructuredContent = true)]
    [Description("Resolves the frames of crash text against the loaded build: Unity Player.log / error.log native backtraces (with the log's module " +
                 "list for load addresses), Mono managed frames (matched by their module MVID) and Il2Cpp/Unity managed lines, .NET exception text " +
                 "(the inner chain, NativeAOT frames), WER Report.wer and Event Log 1000/1026 text (faulting module, offset, time stamp, code), and " +
                 "debugger stacks (module!function+0x.., module+0x..). Native frames are named through the loaded images (code index, PDB, Il2Cpp " +
                 "names); every frame says whether it is the same build (buildCheck: time stamps, MVIDs, the text's own names), and modules the " +
                 "text needs that are not loaded are listed. Lines no format recognizes are counted, with a sample.")]
    public Task<StackTextService.SymbolizedStack> SymbolizeStackText(
        [Description("The crash text (up to 1 MiB). Pass this or path.")] string? text = null,
        [Description("A log or report file (Player.log, error.log, Report.wer, saved event text); its last 8 MiB are read.")] string? path = null,
        [Description("auto (default), unity, dotnet, wer, eventlog or windbg.")] string? format = "auto",
        [Description("Native image ids or paths to resolve against (';'-separated); default every loaded native image.")] string? images = null,
        [Description("Module load addresses for absolute addresses, 'name=0xBASE;...' (the crash's module list in the text is used too).")] string? moduleBases = null,
        [Description("Index of the first frame returned.")] int offset = 0,
        [Description("Max frames returned (default 200).")] int limit = StackTextService.DefaultLimit,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => stacks.Symbolize(text, path, format, images, moduleBases, offset, limit, cancellationToken), cancellationToken);
}
