using System.ComponentModel;
using System.Text;
using System.Text.RegularExpressions;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Code;
using NetDecompilerMcp.Services;
using static NetDecompilerMcp.Tools.ToolSupport;

namespace NetDecompilerMcp.Tools;

/// <summary>Native code: functions, disassembly, control flow, cross-references, call trees and strings (x86 / x64).</summary>
[McpServerToolType]
public sealed class NativeCodeTools(AssemblyWorkspace workspace, NativeCodeService code, OutputPager pager)
{
    private const string IndexNote = "The first call on an image waits for its code index (built in the background after loading; seconds for a typical DLL, " +
                                     "under a minute for a 300 MB executable; progress is reported).";

    /// <summary>Loads the image if given by path, waits for its index, and resolves the address (names include functions).</summary>
    private async Task<(LoadedNative Native, NativeCodeIndex Index)> Open(string image, RequestContext<CallToolRequestParams>? context,
        IProgress<ProgressNotificationValue> progress, CancellationToken ct)
    {
        var native = await Task.Run(() =>
        {
            var id = workspace.Read(() => workspace.FindNative(image)?.Id);
            if (id == null && !string.IsNullOrWhiteSpace(image) && Path.IsPathFullyQualified(image.Trim()) && File.Exists(image.Trim()))
                id = workspace.LoadAny(image.Trim()).Native?.Id ?? throw new ToolError(ErrorCode.Unsupported, $"{image} is a .NET assembly, not a native image.",
                    "use the .NET tools for it");
            return workspace.Read(() => workspace.GetNative(id ?? image));
        }, ct);
        // Progress is the seconds waited: phase counts restart at zero, and progress that goes backwards is not sent.
        var waited = System.Diagnostics.Stopwatch.StartNew();
        var index = await code.Index(native, new Progress<CodeIndexProgress>(p =>
            progress.Report(new ProgressNotificationValue
            {
                Progress = (float)waited.Elapsed.TotalSeconds,
                Message = $"indexing {native.Id}: {p.Phase}" + (p.Total > 0 ? $" {p.Done:N0}/{p.Total:N0}" : p.Done > 0 ? $" ({p.Done:N0} instructions)" : ""),
            })), ct);
        if (index.Support == CodeSupport.DeclaredFunctionsOnly && index.SupportNote != null)
            workspace.Notify($"{native.Id}: {index.SupportNote}");
        return (native, index);
    }

    private static uint Address(NativeCodeIndex index, string text) => NativeAddress.Parse(index.Image, text, name =>
    {
        if (name.StartsWith("sub_", StringComparison.OrdinalIgnoreCase) && NativeAddress.Number(name[4..]) is { } n)
        {
            if (n < index.Image.SizeOfImage && index.FunctionByStart((uint)n) != null) return (uint)n;
            if (n >= index.Image.ImageBase && n - index.Image.ImageBase < index.Image.SizeOfImage) return (uint)(n - index.Image.ImageBase);
        }
        return index.Functions.FirstOrDefault(f => f.KnownName == name)?.Start;
    });

    private static NativeFunction FunctionAt(NativeCodeIndex index, uint rva) =>
        index.FunctionAt(rva) ?? throw new ToolError(ErrorCode.NotFound, $"No function contains {NativeAddress.Va(index.Image, rva)}.",
            "list_functions shows the functions; disassemble shows raw instructions at any address");

    private static string Flags(NativeFunction f)
    {
        var flags = new List<string>();
        if (f.Flags.HasFlag(FunctionFlags.Thunk)) flags.Add("thunk");
        if (f.Flags.HasFlag(FunctionFlags.NoReturn)) flags.Add("noreturn");
        if (f.Flags.HasFlag(FunctionFlags.UnresolvedJumps)) flags.Add("unresolved jumps");
        if (f.Flags.HasFlag(FunctionFlags.InvalidCode)) flags.Add("invalid code");
        if (f.Flags.HasFlag(FunctionFlags.Truncated)) flags.Add("truncated");
        if (f.Flags.HasFlag(FunctionFlags.Funclet)) flags.Add("funclet");
        return flags.Count > 0 ? $"  [{string.Join(", ", flags)}]" : "";
    }

    private static string Coverage(NativeCodeIndex index)
    {
        var notes = new List<string>();
        if (index.Support == CodeSupport.DeclaredFunctionsOnly) notes.Add(index.SupportNote ?? "instructions are not decoded for this architecture");
        if (index.AbsoluteRefsUnconfirmed) notes.Add("no relocations: absolute data references are accepted by address range alone");
        notes.AddRange(index.Truncations);
        return notes.Count > 0 ? "Note: " + string.Join("; ", notes) + "\n" : "";
    }

    [McpServerTool(Name = "list_functions", Title = "List native functions", ReadOnly = true, Idempotent = true, OpenWorld = false)]
    [Description("Functions of a native image (x86 / x64): address, size, name (export name, module!import for thunks, or sub_<rva>), flags " +
                 "(thunk, noreturn, unresolved jumps, invalid code, funclet), how it was found and how many call sites reach it. " + IndexNote)]
    public Task<string> ListFunctions(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("Only functions whose name contains this text (case-insensitive).")] string? filter = null,
        [Description("Order: address (default), size (largest first) or callers (most called first).")] string? sort = null,
        [Description("Index of the first row.")] int offset = 0,
        [Description("Max rows (default 300).")] int limit = 300,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var (native, index) = await Open(image, context, progress, cancellationToken);
        IEnumerable<NativeFunction> list = index.Functions.Where(f => filter == null || f.Name.Contains(filter, StringComparison.OrdinalIgnoreCase));
        list = (sort?.Trim().ToLowerInvariant()) switch
        {
            null or "" or "address" => list,
            "size" => list.OrderByDescending(f => f.Size),
            "callers" => list.OrderByDescending(f => index.CountRefsTo(f.Start)),
            _ => throw new ToolError(ErrorCode.InvalidArgument, $"Unknown sort '{sort}'.", "use address, size or callers"),
        };
        var rows = list.Select(f => $"{NativeAddress.Va(index.Image, f.Start)}  {f.Size,7}  {f.Name}{Flags(f)}  ({f.Sources}; {index.CountRefsTo(f.Start)} refs)").ToList();
        var s = index.Stats;
        return $"{native.Id}: {Plural(s.Functions, "function")} ({s.Thunks} thunks, {s.NoReturnFunctions} noreturn), {s.Instructions:N0} instructions, " +
               $"{s.Xrefs:N0} references, {Plural(s.Strings, "string")}\n" + Coverage(index) + pager.PageRows(rows, offset, limit, "function");
    });

    [McpServerTool(Name = "disassemble", Title = "Disassemble native code", ReadOnly = true, Idempotent = true, OpenWorld = false)]
    [Description("MASM-syntax disassembly of the native function containing an address (with block labels), or of maxInstructions from the address " +
                 "when it is in no function or function=false. Calls and data references are named (module!import, exports, sub_<rva>, loc_<rva>) " +
                 "and string references shown as comments. " + IndexNote)]
    public Task<string> Disassemble(
        [Description(NativeTools.ImageDescription)] string image,
        [Description(NativeTools.AddressDescription)] string address,
        [Description("Disassemble the whole containing function (default true); false: maxInstructions from the address.")] bool function = true,
        [Description("Max instructions (default 2000).")] int maxInstructions = 2000,
        [Description(OffsetDescription)] int offset = 0,
        [Description(MaxCharsDescription)] int? maxChars = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var (_, index) = await Open(image, context, progress, cancellationToken);
        if (index.Support == CodeSupport.DeclaredFunctionsOnly)
            throw new ToolError(ErrorCode.Unsupported, $"Instructions are not decoded for {index.Image.Arch} images.", "decompile_native disassembles through IDA");
        var rva = Address(index, address);
        int max = Math.Clamp(maxInstructions, 1, 200_000);
        var fn = function ? index.FunctionAt(rva) : null;
        var text = pager.GetOrCreate($"disasm|{index.Image.Sha256}|{(fn != null ? "f" + fn.Start : "r" + rva)}|{max}", () =>
        {
            var sb = new StringBuilder();
            if (fn != null)
            {
                sb.AppendLine($"; {fn.Name} at {NativeAddress.Va(index.Image, fn.Start)}, {fn.Size} bytes, {Plural(fn.BlockCount, "block")}{Flags(fn)}");
                foreach (var (label, line) in index.DisassembleFunction(fn, max, out bool truncated, cancellationToken))
                {
                    if (label != null) sb.AppendLine($"{label}:");
                    if (line != null) sb.AppendLine(Line(line));
                    if (truncated && label == null && line == null) break;
                }
            }
            else
            {
                sb.AppendLine($"; {Plural(max, "instruction")} from {NativeAddress.Va(index.Image, rva)}" + (function ? " (no function contains it)" : ""));
                foreach (var line in index.Disassemble(rva, max)) sb.AppendLine(Line(line));
            }
            return sb.ToString();
        });
        return Coverage(index) + pager.Page(text, offset, maxChars);
    });

    private static string Line(DisasmLine l) => $"  {l.Address:X}  {l.Bytes,-24} {l.Text}{(l.Comment != null ? "  ; " + l.Comment : "")}";

    [McpServerTool(Name = "get_cfg", Title = "Native control-flow graph", ReadOnly = true, Idempotent = true, OpenWorld = false)]
    [Description("Basic blocks of the native function containing an address: each block's range, instruction count, how it ends (return, jump, " +
                 "switch, tail call, noreturn call...) and its successors; resolved switch tables with their cases; indirect jumps whose targets are unknown. " + IndexNote)]
    public Task<string> GetCfg(
        [Description(NativeTools.ImageDescription)] string image,
        [Description(NativeTools.AddressDescription)] string address,
        [Description(OffsetDescription)] int offset = 0,
        [Description(MaxCharsDescription)] int? maxChars = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var (_, index) = await Open(image, context, progress, cancellationToken);
        if (index.Support == CodeSupport.DeclaredFunctionsOnly)
            throw new ToolError(ErrorCode.Unsupported, $"Instructions are not decoded for {index.Image.Arch} images.", "decompile_native analyzes them through IDA");
        var fn = FunctionAt(index, Address(index, address));
        var graph = index.GetGraph(fn, cancellationToken);
        string Va(uint rva) => NativeAddress.Va(index.Image, rva);
        var sb = new StringBuilder($"{fn.Name} at {Va(fn.Start)}: {Plural(graph.Blocks.Count, "block")}{(graph.Truncated ? " (truncated)" : "")}\n");
        foreach (var b in graph.Blocks)
            sb.AppendLine($"  {Va(b.Start)}-{Va(b.End)}  {b.InstructionCount,4} insn  {b.EndKind}" +
                          (b.Successors.Count > 0 ? "  -> " + string.Join(", ", b.Successors.Select(e => $"{Va(e.To)}{(e.Kind is EdgeKind.FallThrough or EdgeKind.Jump ? "" : " " + e.Kind)}")) : ""));
        foreach (var sw in graph.Switches)
            sb.AppendLine($"  switch at {Va(sw.JumpRva)}: table {Va(sw.TableRva)}, {sw.EntryCount} entries, {Plural(sw.Targets.Count, "distinct target")}: " +
                          string.Join(", ", sw.Targets.Take(64).Select(Va)) + (sw.Targets.Count > 64 ? ", ..." : ""));
        foreach (var j in graph.UnresolvedJumps) sb.AppendLine($"  unresolved indirect jump at {Va(j)}");
        foreach (var t in graph.TailCalls) sb.AppendLine($"  tail call to {index.NameAt(t) ?? Va(t)}");
        return pager.Page(sb.ToString(), offset, maxChars);
    });

    [McpServerTool(Name = "find_xrefs", Title = "Native cross-references", ReadOnly = true, Idempotent = true, OpenWorld = false)]
    [Description("Everything in a native image that references an address: calls (direct and through import slots and thunks), jumps, data reads " +
                 "and writes, address-taken uses, switch tables and relocated data pointers, each with the function it is in. For an import " +
                 "(module!name) lists the call sites of that API. " + IndexNote)]
    public Task<string> FindXrefs(
        [Description(NativeTools.ImageDescription)] string image,
        [Description(NativeTools.AddressDescription)] string address,
        [Description("Index of the first row.")] int offset = 0,
        [Description("Max rows (default 500).")] int limit = 500,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var (_, index) = await Open(image, context, progress, cancellationToken);
        var rva = Address(index, address);
        string Va(uint r) => NativeAddress.Va(index.Image, r);
        string Where(uint from) => index.FunctionAt(from) is { } f ? $"{f.Name}+0x{from - f.Start:X}" : "(no function)";
        var rows = new List<string>();
        var import = index.Image.Imports.FirstOrDefault(i => i.SlotRva == rva);
        if (import != null)
            rows.AddRange(index.Callers(import).Select(c => $"{Va(c.From)}  {c.Kind,-10} {Where(c.From)}"));
        else
            rows.AddRange(index.RefsTo(rva).Select(x => $"{Va(x.From)}  {x.Kind,-10} {Where(x.From)}"));
        var target = index.NameAt(rva) ?? (index.StringAt(rva) is { } s ? index.CommentFor(rva) : null);
        return $"References to {Va(rva)}{(target != null ? $" ({target})" : "")}:\n" + Coverage(index) + pager.PageRows(rows, offset, limit, "reference");
    });

    [McpServerTool(Name = "native_call_tree", Title = "Native call tree", ReadOnly = true, Idempotent = true, OpenWorld = false)]
    [Description("Callers or callees of a native function, several levels deep (calls through thunks and import slots included; imports are leaves). " +
                 "Repeated subtrees and recursion are marked instead of expanded. " + IndexNote)]
    public Task<string> NativeCallTree(
        [Description(NativeTools.ImageDescription)] string image,
        [Description(NativeTools.AddressDescription)] string function,
        [Description("callers or callees (default callees).")] string direction = "callees",
        [Description("Levels (1-8, default 3).")] int depth = 3,
        [Description("Max nodes (default 500).")] int maxNodes = 500,
        [Description(OffsetDescription)] int offset = 0,
        [Description(MaxCharsDescription)] int? maxChars = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        bool callers = direction?.Trim().ToLowerInvariant() switch
        {
            "callers" => true,
            "callees" or null or "" => false,
            _ => throw new ToolError(ErrorCode.InvalidArgument, $"Unknown direction '{direction}'.", "use callers or callees"),
        };
        var (_, index) = await Open(image, context, progress, cancellationToken);
        var fn = FunctionAt(index, Address(index, function));
        var root = index.CallTree(fn, Math.Clamp(depth, 1, 8), callers, ClampLimit(maxNodes, 20_000));
        var sb = new StringBuilder();
        void Walk(CallTreeNode node, int level)
        {
            var name = node.Function?.Name ?? (node.Import != null ? NativeCodeIndex.ImportName(node.Import) : NativeAddress.Va(index.Image, node.Address));
            sb.Append(new string(' ', level * 2)).Append(name)
              .Append(node.Function != null ? $"  {NativeAddress.Va(index.Image, node.Function.Start)}" : "")
              .Append(node.Repeated ? "  (repeated)" : "").Append(node.Truncated ? "  (more not shown)" : "").AppendLine();
            foreach (var child in node.Children) Walk(child, level + 1);
        }
        Walk(root, 0);
        return pager.Page(sb.ToString(), offset, maxChars);
    });

    [McpServerTool(Name = "search_native_strings", Title = "Search native strings", ReadOnly = true, Idempotent = true, OpenWorld = false)]
    [Description("Strings (ASCII and UTF-16) a native image's code or data references, with the address, the number of references and the first " +
                 "referencing function; filter by substring or regex. " + IndexNote)]
    public Task<string> SearchNativeStrings(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("Text to find (case-insensitive substring), or a regex with regex=true; omit to list all.")] string? query = null,
        [Description("Treat query as a regular expression.")] bool regex = false,
        [Description("Index of the first row.")] int offset = 0,
        [Description("Max rows (default 300).")] int limit = 300,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        Regex? pattern = null;
        if (regex && !string.IsNullOrEmpty(query))
        {
            try { pattern = new Regex(query, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1)); }
            catch (ArgumentException ex) { throw new ToolError(ErrorCode.InvalidArgument, $"Invalid regex: {ex.Message}"); }
        }
        var (_, index) = await Open(image, context, progress, cancellationToken);
        var rows = new List<string>();
        foreach (var s in index.Strings)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var text = index.ReadString(s, 400);
            bool match = query == null || (pattern != null ? SafeMatch(pattern, text) : text.Contains(query, StringComparison.OrdinalIgnoreCase));
            if (!match) continue;
            var refs = index.RefsTo(s.Rva, 1);
            var first = refs.Count > 0 && index.FunctionAt(refs[0].From) is { } f ? f.Name : null;
            rows.Add($"{NativeAddress.Va(index.Image, s.Rva)}  {(s.Encoding == StringEncoding.Utf16 ? "L" : " ")}\"{Format.Clip(Escape(text), 200)}\"  " +
                     $"{index.CountRefsTo(s.Rva)} refs{(first != null ? $", first in {first}" : "")}");
        }
        return pager.PageRows(rows, offset, limit, "string");
    });

    private static bool SafeMatch(Regex r, string text)
    {
        try { return r.IsMatch(text); }
        catch (RegexMatchTimeoutException) { return false; }
    }

    private static string Escape(string s) => s.Replace("\\", "\\\\").Replace("\r", "\\r").Replace("\n", "\\n").Replace("\t", "\\t").Replace("\"", "\\\"");
}
