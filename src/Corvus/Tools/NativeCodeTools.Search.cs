using System.ComponentModel;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Code;
using static Corvus.Tools.ToolSupport;

namespace Corvus.Tools;

// The query shape (mnemonic / operand filters, scoped scans with a scan budget and paging) follows mrexodia/ida-pro-mcp's
// insn_query and search_text (MIT); see THIRD-PARTY-NOTICES.md.
public sealed partial class NativeCodeTools
{
    [McpServerTool(Name = "search_instructions", Title = "Search native instructions")]
    [Description("Find instructions by mnemonic, operand or whole-line regex (case-insensitive) and an operand value (immediate, displacement or " +
                 "target) in every function, one function, or an address range; a scan budget's end is named in the result (continue with start=).")]
    public Task<string> SearchInstructions(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("Mnemonic regex, e.g. '^(call|jmp)$'.")] string? mnemonic = null,
        [Description("Operand text regex, e.g. 'rsp\\+|fs:'.")] string? operands = null,
        [Description("Regex over the whole instruction text.")] string? text = null,
        [Description("An operand value: 0x10B, 267, or an address.")] string? value = null,
        [Description("Only this function: " + NativeTools.AddressDescription)] string? function = null,
        [Description("Range start (with end, or alone: to the end of its section).")] string? start = null,
        [Description("Range end (exclusive).")] string? end = null,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description("Max matches (max 2000).")] int limit = 100,
        [Description("Max instructions scanned (max 5000000).")] int maxInstructions = 500_000,
        [Description(EngineDescription)] string? engine = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var mode = Mode(engine);
        var query = new InstructionQuery(Pattern(mnemonic, "mnemonic"), Pattern(operands, "operands"), Pattern(text, "text"), Value(value));
        if (query.IsEmpty) throw new ToolError(ErrorCode.InvalidArgument, "Nothing to search for.", "pass mnemonic, operands, text or value");
        if (!string.IsNullOrWhiteSpace(function) && (!string.IsNullOrWhiteSpace(start) || !string.IsNullOrWhiteSpace(end)))
            throw new ToolError(ErrorCode.InvalidArgument, "Pass function or a range, not both.");
        offset = Math.Max(0, offset);
        limit = Math.Clamp(limit, 1, 2000);
        int budget = Math.Clamp(maxInstructions, 1, 5_000_000);
        var (native, index) = await Open(image, context, progress, cancellationToken);
        var choice = Choose(mode, native, index);
        if (!choice.External && index.Support == CodeSupport.DeclaredFunctionsOnly) throw NativeEngineCode.Unsupported(index, engines);

        // the ranges to scan, each with its function when known; an engine scans its own function at the address
        var ranges = new List<(uint Start, uint End, NativeFunction? Function)>();
        uint? functionRva = null;
        if (!string.IsNullOrWhiteSpace(function))
        {
            functionRva = Address(index, function);
            if (!choice.External)
            {
                var f = FunctionAt(index, functionRva.Value);
                ranges.AddRange(index.Ranges(f).Select(r => (r.Start, r.End, (NativeFunction?)f)));
            }
        }
        else if (!string.IsNullOrWhiteSpace(start))
        {
            uint from = Address(index, start);
            uint to = !string.IsNullOrWhiteSpace(end) ? Address(index, end)
                : index.Image.SectionAt(from) is { } s ? s.Rva + s.VirtualSize : throw new ToolError(ErrorCode.InvalidArgument, "start is in no section.", "pass end too");
            if (to <= from) throw new ToolError(ErrorCode.InvalidArgument, "end is not after start.");
            ranges.Add((from, to, null));
        }
        else if (!string.IsNullOrWhiteSpace(end)) throw new ToolError(ErrorCode.InvalidArgument, "end needs start.");
        else if (!choice.External) foreach (var f in index.Functions.OrderBy(f => f.Start)) ranges.AddRange(index.Ranges(f).Select(r => (r.Start, r.End, (NativeFunction?)f)));

        var scan = choice.External
            ? await ScanEngine(native, index, ranges, functionRva, query, offset + limit + 1, budget, choice, progress, cancellationToken)
            : await Task.Run(() => ScanIndex(index, ranges, query, offset + limit + 1, budget, cancellationToken), cancellationToken);

        var sb = new StringBuilder($"; {choice.Line}\n");
        var lines = scan.Matches.Skip(offset).Take(limit).Select(m => $"  {NativeAddress.Va(index.Image, m.Rva)}  {m.Where}  {m.Text}").ToList();
        int fit = pager.FitRows(lines, 600);
        sb.AppendLine($"{(scan.Matches.Count > offset + limit ? "More than " + (offset + limit) : scan.Matches.Count.ToString(CultureInfo.InvariantCulture))} match(es) " +
                      $"in {Plural(scan.Scanned, "instruction")} scanned" + (fit > 0 ? $"; showing {offset + 1}-{offset + fit}" : ""));
        foreach (var line in lines.Take(fit)) sb.AppendLine(line);
        if (fit < lines.Count) sb.AppendLine(OutputPager.CapNote(fit, lines.Count, offset + fit));
        else if (scan.Matches.Count > offset + limit) sb.AppendLine($"More: offset={offset + limit}");
        if (scan.StoppedAt is { } stop)
            sb.AppendLine($"Scan budget of {Plural(budget, "instruction")} reached at {NativeAddress.Va(index.Image, stop)}: continue with start=0x{index.Image.ImageBase + stop:X}" +
                          (ranges.Count > 0 && ranges[^1].End > stop ? $" end=0x{index.Image.ImageBase + ranges[^1].End:X}" : "") + ", or raise maxInstructions");
        return pager.Page(sb.ToString(), 0, null);
    });

    private sealed record InstructionMatch(uint Rva, string Where, string Text);

    private sealed record InstructionScan(List<InstructionMatch> Matches, int Scanned, uint? StoppedAt);

    private static Regex? Pattern(string? text, string name)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        try
        {
            return new Regex(text.Trim(), RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
        }
        catch (ArgumentException e)
        {
            throw new ToolError(ErrorCode.InvalidArgument, $"{name} is not a valid regular expression: {e.Message}");
        }
    }

    private static ulong? Value(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        var t = text.Trim();
        bool negative = t.StartsWith('-');
        var digits = negative ? t[1..] : t;
        ulong n = ulong.TryParse(digits, NumberStyles.None, CultureInfo.InvariantCulture, out var d) ? d
            : NativeAddress.Number(digits) ?? throw new ToolError(ErrorCode.InvalidArgument, $"value '{t}' is not a number.", "use hex (0x10B) or decimal");
        return negative ? unchecked((ulong)-(long)n) : n;
    }

    /// <summary>Filters over an instruction's text: mnemonic (prefixes skipped), operands, the whole line, and an operand value.</summary>
    private sealed partial class InstructionQuery(Regex? mnemonic, Regex? operands, Regex? text, ulong? value)
    {
        private static readonly HashSet<string> Prefixes = new(StringComparer.OrdinalIgnoreCase) { "lock", "rep", "repe", "repz", "repne", "repnz", "bnd", "notrack", "xacquire", "xrelease" };

        public bool IsEmpty => mnemonic == null && operands == null && text == null && value == null;

        /// <param name="targets">Addresses the instruction refers to (VA and RVA are both accepted as the value).</param>
        public bool Matches(string line, ulong imageBase, params uint?[] targets)
        {
            var words = line.TrimStart().Split((char[]?)null, 2, StringSplitOptions.RemoveEmptyEntries);
            int at = 0;
            while (at < words.Length && Prefixes.Contains(words[at]) && words.Length > 1)
            {
                words = words[1].Split((char[]?)null, 2, StringSplitOptions.RemoveEmptyEntries);
                at = 0;
            }
            var mnem = words.Length > 0 ? words[0] : "";
            var ops = words.Length > 1 ? words[1].Trim() : "";
            // ARM width qualifiers (b.w, IDA's TBB.W) do not change the instruction: tbb matches TBB.W
            if (mnemonic != null && !mnemonic.IsMatch(mnem)
                && !(mnem.Length > 2 && mnem[^2] == '.' && mnem[^1] is 'w' or 'W' or 'n' or 'N' && mnemonic.IsMatch(mnem[..^2]))) return false;
            if (operands != null && !operands.IsMatch(ops)) return false;
            if (text != null && !text.IsMatch(line)) return false;
            if (value is { } v)
            {
                bool found = targets.Any(t => t is { } r && (r == v || imageBase + r == v));
                foreach (Match m in Literal().Matches(ops))
                {
                    if (found) break;
                    ulong n = m.Groups[1].Success ? ulong.Parse(m.Groups[1].Value, NumberStyles.HexNumber, CultureInfo.InvariantCulture)
                        : m.Groups[2].Success ? ulong.Parse(m.Groups[2].Value, NumberStyles.HexNumber, CultureInfo.InvariantCulture)
                        : ulong.TryParse(m.Groups[3].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var d) ? d : ulong.MaxValue;
                    bool negative = m.Index > 0 && ops[m.Index - 1] == '-';
                    found = n == v || negative && unchecked((ulong)-(long)n) == v || (n > uint.MaxValue ? false : imageBase + n == v);
                }
                if (!found) return false;
            }
            return true;
        }

        // 0x1F, 1Fh (MASM: a leading digit), 31
        [GeneratedRegex(@"\b(?:0x([0-9a-f]+)|([0-9][0-9a-f]*)h|([0-9]+))\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
        private static partial Regex Literal();
    }

    private static string Where(NativeFunction? f, uint rva) => f != null ? $"{f.Name}+0x{rva - f.Start:X}" : "-";

    private static InstructionScan ScanIndex(NativeCodeIndex index, List<(uint Start, uint End, NativeFunction? Function)> ranges, InstructionQuery query,
        int wanted, int budget, CancellationToken ct)
    {
        var dis = index.CreateDisassembler();
        var matches = new List<InstructionMatch>();
        int scanned = 0;
        foreach (var (start, end, fn) in ranges)
        {
            uint at = start;
            while (at < end)
            {
                ct.ThrowIfCancellationRequested();
                if (scanned >= budget) return new(matches, scanned, at);
                var lines = dis.Disassemble(at, Math.Min(4096, budget - scanned), end);
                if (lines.Count == 0) break;
                foreach (var l in lines)
                {
                    scanned++;
                    var f = fn ?? index.FunctionAt(l.Rva);
                    if (query.Matches(l.Text, index.Image.ImageBase, l.Facts.BranchTarget, l.Facts.MemoryTarget, l.Facts.ImmediateTarget))
                    {
                        matches.Add(new(l.Rva, Where(f, l.Rva), l.Text));
                        if (matches.Count >= wanted) return new(matches, scanned, null);
                    }
                }
                var last = lines[^1];
                at = Math.Max(at + 1, last.Rva + (uint)Math.Max(1, last.Facts.Length));
            }
        }
        return new(matches, scanned, null);
    }

    /// <summary>The engine's instructions: of each function for a function scan or a whole-image scan (the engine's functions), else of the range.</summary>
    private async Task<InstructionScan> ScanEngine(LoadedNative native, NativeCodeIndex index, List<(uint Start, uint End, NativeFunction? Function)> ranges, uint? function,
        InstructionQuery query, int wanted, int budget, EngineChoice choice, IProgress<ProgressNotificationValue> progress, CancellationToken ct)
    {
        var session = await _engine!.Session(native, choice, progress, ct);
        var matches = new List<InstructionMatch>();
        int scanned = 0;
        // true when the scan is done: enough matches, or the budget ran out (stop: the first instruction not scanned)
        bool Take(IEnumerable<Native.Providers.DisassembledInstruction> instructions, Func<uint, string> where, out uint? stop)
        {
            stop = null;
            foreach (var i in instructions)
            {
                if (scanned >= budget) { stop = i.Rva; return true; }
                scanned++;
                if (!query.Matches(i.Text, index.Image.ImageBase)) continue;
                matches.Add(new(i.Rva, where(i.Rva), i.Text));
                if (matches.Count >= wanted) return true;
            }
            return false;
        }
        if (function == null && ranges.Count == 1)
        {
            var (start, end, _) = ranges[0];
            var d = await session.DisassembleRangeAsync(start, Math.Min(budget, (int)Math.Min(int.MaxValue, end - start)), ct);
            Take(d.Instructions.Where(i => i.Rva < end), r => Where(index.FunctionAt(r), r), out var stop);
            return new(matches, scanned, stop);
        }
        var functions = function is { } one ? [one] : (await session.ListFunctionsAsync(ct)).Select(f => f.StartRva).Order().ToList();
        foreach (var f in functions)
        {
            ct.ThrowIfCancellationRequested();
            var d = await session.DisassembleAsync(f, ct);
            var name = index.FunctionByStart(d.StartRva)?.Name ?? d.Name;
            if (Take(d.Instructions, r => $"{name}+0x{r - d.StartRva:X}", out var stop)) return new(matches, scanned, stop);
        }
        return new(matches, scanned, null);
    }
}
