using System.ComponentModel;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Native;
using Corvus.Native.Code;
using static Corvus.Tools.ToolSupport;

namespace Corvus.Tools;

// The query shape (mnemonic / operand filters, scoped scans with a scan budget and paging) follows mrexodia/ida-pro-mcp's
// insn_query and search_text (MIT); see THIRD-PARTY-NOTICES.md.
public sealed partial class NativeCodeTools
{
    [McpServerTool(Name = "search_instructions", Title = "Search native instructions", UseStructuredContent = true, OutputSchemaType = typeof(InstructionMatchList))]
    [Description("Find instructions by mnemonic, operand or whole-line regex (case-insensitive) and an operand value (immediate, displacement or " +
                 "target) in every function, one function or an address range; a page the scan budget stopped goes on at nextOffset.")]
    public Task<string> SearchInstructions(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("Mnemonic regex, e.g. ^(call|jmp)$")] string? mnemonic = null,
        [Description("Operand text regex, e.g. rsp\\+|fs:")] string? operands = null,
        [Description("Regex over the whole instruction text.")] string? text = null,
        [Description("Operand value: 0x10B, 267, an address, or range 0x100..0x1FF.")] string? value = null,
        [Description("Only this function: " + NativeTools.AddressDescription)] string? function = null,
        [Description("Range start (with to, or alone: to the end of its section).")] string? from = null,
        [Description("Range end (exclusive).")] string? to = null,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description("Max matches (max 2000).")] int limit = 100,
        [Description("Instructions scanned per page (max 5000000).")] int maxInstructions = 500_000,
        [Description(EngineDescription)] string? engine = null,
        [Description(MaxTokensDescription)] int? maxTokens = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var mode = Mode(engine);
        var query = new InstructionQuery(Pattern(mnemonic, "mnemonic"), Pattern(operands, "operands"), Pattern(text, "text"), Value(value));
        if (query.IsEmpty) throw new ToolError(ErrorCode.InvalidArgument, "Nothing to search for.", "pass mnemonic, operands, text or value");
        if (!string.IsNullOrWhiteSpace(function) && (!string.IsNullOrWhiteSpace(from) || !string.IsNullOrWhiteSpace(to)))
            throw new ToolError(ErrorCode.InvalidArgument, "Pass function or a range, not both.");
        offset = Math.Max(0, offset);
        limit = Math.Clamp(limit, 1, 2000);
        int budget = Math.Clamp(maxInstructions, 1, ScanState.MaxBudget);
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
        else if (!string.IsNullOrWhiteSpace(from))
        {
            uint first = Address(index, from);
            uint last = !string.IsNullOrWhiteSpace(to) ? Address(index, to)
                : index.Image.SectionAt(first) is { } s ? s.Rva + s.VirtualSize : throw new ToolError(ErrorCode.InvalidArgument, "from is in no section.", "pass to too");
            if (last <= first) throw new ToolError(ErrorCode.InvalidArgument, "to is not after from.");
            ranges.Add((first, last, null));
        }
        else if (!string.IsNullOrWhiteSpace(to)) throw new ToolError(ErrorCode.InvalidArgument, "to needs from.");
        else if (!choice.External) foreach (var f in index.Functions.OrderBy(f => f.Start)) ranges.AddRange(index.Ranges(f).Select(r => (r.Start, r.End, (NativeFunction?)f)));

        // a later page of the same built-in scan starts where an earlier one recorded its position, not from the first range
        string key = $"{mnemonic}|{operands}|{text}|{value}|{function}|{from}|{to}";
        var resume = choice.External ? default : Resumes(index, key).Before(offset);
        int based = resume.Matches;
        var state = new ScanState(query, index.Image.ImageBase, offset - based, offset - based + limit + 1, budget);
        var scan = choice.External
            ? await ScanEngine(native, index, ranges, functionRva, state, choice, progress, cancellationToken)
            : await Task.Run(() => ScanIndex(index, ranges, state, resume.Range, resume.Rva, cancellationToken), cancellationToken);
        if (!choice.External)
        {
            if (scan.Matches.Count > offset - based + limit && scan.Matches[offset - based + limit] is var first)
                Resumes(index, key).Record(offset + limit, first.Range, first.Rva);
            if (scan.StoppedAt is { } at && scan.StoppedRange is { } atRange) Resumes(index, key).Record(based + scan.Matches.Count, atRange, at);
        }

        var head = new StringBuilder($"; {choice.Line}\n{Plural(scan.Scanned, "instruction")} scanned\n");
        // a budget stop after a match past offset continues at nextOffset (the next page rescans to there); without one, at from=
        int total = based + scan.Matches.Count;
        bool resumable = total > offset;
        if (scan.StoppedAt is { } stop)
        {
            var at = NativeAddress.Va(index.Image, stop);
            if (resumable)
            {
                head.AppendLine($"Scan budget of {Plural(budget, "instruction")} reached at {at}: the next page goes on from there");
                ToolOutput.Coverage("partial", $"the scan budget stopped at {at}; total is a lower bound", "row-cap");
            }
            else
            {
                var next = $"from=0x{index.Image.ImageBase + stop:X}" + (ranges.Count > 0 && ranges[^1].End > stop ? $" to=0x{index.Image.ImageBase + ranges[^1].End:X}" : "");
                head.AppendLine($"No match in {Plural(scan.Scanned, "instruction")} up to {at}: continue with {next}");
                ToolOutput.Coverage("partial", $"the scan stopped at {at} without a match; continue with {next}", "row-cap");
            }
        }
        // the scan stops one match past the page: more matches make the total a lower bound
        bool exact = total <= offset + limit && scan.StoppedAt == null;
        bool more = !exact && resumable;
        var page = scan.Matches.Skip(offset - based).Take(limit).Select(m => new InstructionMatch(NativeAddress.Va(index.Image, m.Rva), m.Where, m.Text)).ToList();
        return ToolOutput.List(page, offset, limit, total, m => $"{m.Address}  {m.Function}  {m.Text}",
            rows => new InstructionMatchList(native.Id, rows.ToList(), offset, total, scan.Scanned, choice.Engine, choice.Note)
                { TotalExact = exact ? null : false, Truncated = more ? true : null }, "matching instruction",
            head.ToString(), exact);
    });

    /// <summary>One search_instructions match.</summary>
    public sealed record InstructionMatch(string Address, [property: Description("function+offset, or - outside functions.")] string Function, string Text);

    /// <summary>search_instructions' record.</summary>
    public sealed record InstructionMatchList(string Image, IReadOnlyList<InstructionMatch> Items, int Offset, int Total,
        [property: Description("Instructions scanned.")] int Scanned,
        [property: Description(EngineDoc.Engine)] string Engine,
        [property: Description(EngineDoc.Note)] string? EngineNote)
    {
        public bool? TotalExact { get; init; }

        public bool? Truncated { get; init; }
    }

    private sealed record InstructionScan(List<ScanMatch> Matches, int Scanned, uint? StoppedAt, int? StoppedRange);

    /// <summary>A match and the index of the scanned range it is in.</summary>
    private sealed record ScanMatch(uint Rva, string Where, string Text, int Range);

    /// <summary>Where earlier pages of one built-in scan stopped: the number of matches before a position, by range and address.</summary>
    private sealed class ScanResumes
    {
        private readonly SortedList<int, (int Range, uint Rva)> _at = [];

        public (int Matches, int Range, uint Rva) Before(int offset)
        {
            lock (_at)
            {
                int best = -1;
                foreach (var k in _at.Keys) if (k <= offset) best = k; else break;
                return best < 0 ? default : (best, _at[best].Range, _at[best].Rva);
            }
        }

        public void Record(int matches, int range, uint rva)
        {
            lock (_at)
            {
                if (_at.Count >= 256) _at.RemoveAt(0);
                _at[matches] = (range, rva);
            }
        }
    }

    // per index, so a rebuilt index (patches, a reload) starts over
    private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<NativeCodeIndex, Dictionary<string, ScanResumes>> _resumes = [];

    private static ScanResumes Resumes(NativeCodeIndex index, string key)
    {
        var byKey = _resumes.GetOrCreateValue(index);
        lock (byKey)
        {
            if (!byKey.TryGetValue(key, out var r))
            {
                if (byKey.Count >= 64) byKey.Clear();
                byKey[key] = r = new ScanResumes();
            }
            return r;
        }
    }

    /// <summary>
    /// One page's scan: the first <paramref name="skip"/> matches (the earlier pages) are found again outside the budget, so
    /// a page resumes where the last one stopped; after them the budget counts, and a page scans on to one match past them
    /// unless <see cref="MaxBudget"/> instructions find none.
    /// </summary>
    private sealed class ScanState(InstructionQuery query, ulong imageBase, int skip, int wanted, int budget)
    {
        public const int MaxBudget = 5_000_000;
        public readonly List<ScanMatch> Matches = [];
        public int Scanned;
        /// <summary>The index of the range being scanned.</summary>
        public int Range;
        private int _past;

        /// <summary>The budget is spent before the next instruction.</summary>
        public bool Spent => Matches.Count >= skip && _past >= budget && (Matches.Count > skip || _past >= MaxBudget);

        /// <summary>Scans one instruction; true when the page has enough matches.</summary>
        public bool Take(uint rva, string text, Func<string> where, params uint?[] targets)
        {
            Scanned++;
            if (Matches.Count >= skip) _past++;
            if (!query.Matches(text, imageBase, targets)) return false;
            Matches.Add(new(rva, where(), text, Range));
            return Matches.Count >= wanted;
        }

        public InstructionScan Done(uint? stoppedAt = null) => new(Matches, Scanned, stoppedAt, stoppedAt != null ? Range : null);
    }

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

    /// <summary>One value, or an inclusive range "min..max" (a constant range: crypto rounds, error codes, table sizes).</summary>
    private static (ulong Lo, ulong Hi)? Value(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        int dots = text.IndexOf("..", StringComparison.Ordinal);
        if (dots < 0) return Number(text) is var one ? (one, one) : null;
        var (lo, hi) = (Number(text[..dots]), Number(text[(dots + 2)..]));
        if (hi < lo) throw new ToolError(ErrorCode.InvalidArgument, $"value range '{text.Trim()}' ends before it starts.", "value=0x100..0x1FF");
        return (lo, hi);
    }

    private static ulong Number(string text)
    {
        var t = text.Trim();
        bool negative = t.StartsWith('-');
        var digits = negative ? t[1..] : t;
        ulong n = ulong.TryParse(digits, NumberStyles.None, CultureInfo.InvariantCulture, out var d) ? d
            : NativeAddress.Number(digits) ?? throw new ToolError(ErrorCode.InvalidArgument, $"value '{t}' is not a number.", "use hex (0x10B) or decimal");
        return negative ? unchecked((ulong)-(long)n) : n;
    }

    /// <summary>Filters over an instruction's text: mnemonic (prefixes skipped), operands, the whole line, and an operand value.</summary>
    private sealed partial class InstructionQuery(Regex? mnemonic, Regex? operands, Regex? text, (ulong Lo, ulong Hi)? value)
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
                bool In(ulong x) => x >= v.Lo && x <= v.Hi;
                bool found = targets.Any(t => t is { } r && (In(r) || In(imageBase + r)));
                foreach (Match m in Literal().Matches(ops))
                {
                    if (found) break;
                    ulong n = m.Groups[1].Success ? ulong.Parse(m.Groups[1].Value, NumberStyles.HexNumber, CultureInfo.InvariantCulture)
                        : m.Groups[2].Success ? ulong.Parse(m.Groups[2].Value, NumberStyles.HexNumber, CultureInfo.InvariantCulture)
                        : ulong.TryParse(m.Groups[3].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var d) ? d : ulong.MaxValue;
                    bool negative = m.Index > 0 && ops[m.Index - 1] == '-';
                    found = In(n) || negative && In(unchecked((ulong)-(long)n)) || (n <= uint.MaxValue && In(imageBase + n));
                }
                if (!found) return false;
            }
            return true;
        }

        // 0x1F, 1Fh (MASM: a leading digit), 31
        [GeneratedRegex(@"\b(?:0x([0-9a-f]+)|([0-9][0-9a-f]*)h|([0-9]+))\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
        private static partial Regex Literal();
    }

    private static string Where(NativeFunction? f, uint rva) => f != null ? Format.Within(f.Name, f.Start, rva) : "-";

    private static InstructionScan ScanIndex(NativeCodeIndex index, List<(uint Start, uint End, NativeFunction? Function)> ranges, ScanState state,
        int fromRange, uint fromRva, CancellationToken ct)
    {
        var dis = index.CreateDisassembler();
        for (int r = fromRange; r < ranges.Count; r++)
        {
            var (start, end, fn) = ranges[r];
            state.Range = r;
            uint at = r == fromRange && fromRva > start ? fromRva : start;
            while (at < end)
            {
                ct.ThrowIfCancellationRequested();
                var lines = dis.Disassemble(at, 4096, end);
                if (lines.Count == 0) break;
                foreach (var l in lines)
                {
                    if (state.Spent) return state.Done(l.Rva);
                    if (state.Take(l.Rva, l.Text, () => Where(fn ?? index.FunctionAt(l.Rva), l.Rva), l.Facts.BranchTarget, l.Facts.MemoryTarget, l.Facts.ImmediateTarget))
                        return state.Done();
                }
                var last = lines[^1];
                at = Math.Max(at + 1, last.Rva + (uint)Math.Max(1, last.Facts.Length));
            }
        }
        return state.Done();
    }

    /// <summary>The engine's instructions: of each function for a function scan or a whole-image scan (the engine's functions), else of the range.</summary>
    private async Task<InstructionScan> ScanEngine(LoadedNative native, NativeCodeIndex index, List<(uint Start, uint End, NativeFunction? Function)> ranges, uint? function,
        ScanState state, EngineChoice choice, IProgress<ProgressNotificationValue> progress, CancellationToken ct)
    {
        var session = await _engine!.Session(native, choice, progress, ct);
        // true when the scan is done: enough matches, or the budget ran out (stop: the first instruction not scanned)
        bool Take(IEnumerable<Native.Providers.DisassembledInstruction> instructions, Func<uint, string> where, out uint? stop)
        {
            stop = null;
            foreach (var i in instructions)
            {
                if (state.Spent) { stop = i.Rva; return true; }
                if (state.Take(i.Rva, i.Text, () => where(i.Rva))) return true;
            }
            return false;
        }
        if (function == null && ranges.Count == 1)
        {
            var (start, end, _) = ranges[0];
            for (uint at = start; at < end;)
            {
                ct.ThrowIfCancellationRequested();
                var d = await session.DisassembleRangeAsync(at, (int)Math.Min(4096, end - at), ct);
                var lines = d.Instructions.Where(i => i.Rva >= at && i.Rva < end).ToList();
                if (lines.Count == 0) break;
                if (Take(lines, r => Where(index.FunctionAt(r), r), out var stop)) return state.Done(stop);
                at = Math.Max(at + 1, lines[^1].Rva + (uint)Math.Max(1, lines[^1].Bytes.Length));
            }
            return state.Done();
        }
        var functions = function is { } one ? [one] : (await session.ListFunctionsAsync(ct)).Select(f => f.StartRva).Order().ToList();
        foreach (var f in functions)
        {
            ct.ThrowIfCancellationRequested();
            var d = await session.DisassembleAsync(f, ct);
            var name = index.FunctionByStart(d.StartRva)?.Name ?? d.Name;
            if (Take(d.Instructions, r => $"{name}+0x{r - d.StartRva:X}", out var stop)) return state.Done(stop);
        }
        return state.Done();
    }
}
