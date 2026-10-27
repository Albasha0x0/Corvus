using System.Text.RegularExpressions;
using Corvus.Native.Code;

namespace Corvus.Native.Diff;

/// <summary>One row of an aligned instruction diff: = same, ~ same shape with other operands, - only old, + only new, … skipped unchanged rows.</summary>
public sealed record DiffRow(string Op, uint? OldRva, uint? NewRva, string? OldText, string? NewText);

/// <summary>An aligned diff of a matched function pair, bounded to the changed regions and their context.</summary>
public sealed record FunctionDiffResult(IReadOnlyList<DiffRow> Rows, int Same, int Changed, int Removed, int Added, int OldInstructions, int NewInstructions,
    bool Truncated, IReadOnlyList<string> Notes);

/// <summary>Diffs a matched function pair with build-independent operands, so only logic changes show; not thread-safe.</summary>
public sealed class FunctionDiff(MatchResult match)
{
    public const int MaxInstructions = 50_000;
    private const int MaxDataMaps = 512;

    private readonly AddressMapper _mapper = new(match);
    private readonly Dictionary<uint, string> _dataLabels = [];

    public FunctionDiffResult Diff(FunctionMatch pair, int context, int maxRows, CancellationToken ct)
    {
        var notes = new List<string>();
        var oldIndex = match.Old.Index;
        var newIndex = match.New.Index;
        var oldFn = match.Old.Functions[pair.Old].Function;
        var newFn = match.New.Functions[pair.New].Function;
        var olds = FunctionCode.Instructions(oldIndex, new MaskedDecoder(oldIndex.Image, oldIndex), oldFn, ct, out _);
        var news = FunctionCode.Instructions(newIndex, new MaskedDecoder(newIndex.Image, newIndex), newFn, ct, out _);
        foreach (var (list, side) in new[] { (olds, "old"), (news, "new") })
            if (list.Count > MaxInstructions)
            {
                notes.Add($"the {side} function has {list.Count:N0} instructions; the first {MaxInstructions:N0} are compared");
                list.RemoveRange(MaxInstructions, list.Count - MaxInstructions);
            }
        // Shapes alone mispair identical calls: align shapes, then rendered text, then fill gaps by shape and render again.
        var oldTokens = olds.Select(i => i.Token).ToArray();
        var newTokens = news.Select(i => i.Token).ToArray();
        var map = InstructionAlignment.Align(oldTokens, newTokens, ct);
        var oldText = Render(oldIndex, olds, i => $"L{i}", true, ct);
        var newText = Render(newIndex, news, Labels(map, news.Count), false, ct);
        map = Fill(InstructionAlignment.Align(Hashes(oldText), Hashes(newText), ct), oldTokens, newTokens, ct);
        newText = Render(newIndex, news, Labels(map, news.Count), false, ct);

        var rows = new List<DiffRow>(olds.Count + news.Count);
        int next = 0;
        for (int i = 0; i < olds.Count; i++)
        {
            if (map[i] < 0)
            {
                rows.Add(new("-", olds[i].Rva, null, oldText[i], null));
                continue;
            }
            for (; next < map[i]; next++) rows.Add(new("+", null, news[next].Rva, null, newText[next]));
            rows.Add(new(oldText[i] == newText[next] ? "=" : "~", olds[i].Rva, news[next].Rva, oldText[i], newText[next]));
            next++;
        }
        for (; next < news.Count; next++) rows.Add(new("+", null, news[next].Rva, null, newText[next]));

        var (shown, truncated) = Window(rows, Math.Max(0, context), Math.Max(1, maxRows));
        return new FunctionDiffResult(shown, rows.Count(r => r.Op == "="), rows.Count(r => r.Op == "~"), rows.Count(r => r.Op == "-"), rows.Count(r => r.Op == "+"),
            olds.Count, news.Count, truncated, notes);
    }

    private static int[] Hashes(string[] text) => text.Select(t => StringComparer.Ordinal.GetHashCode(t)).ToArray();

    /// <summary>New-side labels: the old instruction a new one aligns with, else N plus its own index.</summary>
    private static Func<int, string> Labels(int[] map, int count)
    {
        var inverse = new int[count];
        Array.Fill(inverse, -1);
        for (int i = 0; i < map.Length; i++) if (map[i] >= 0) inverse[map[i]] = i;
        return j => inverse[j] >= 0 ? $"L{inverse[j]}" : $"N{j}";
    }

    /// <summary>Pairs the instructions left between aligned ones by shape, so a changed operand shows as ~ rather than - and +.</summary>
    private static int[] Fill(int[] map, int[] oldTokens, int[] newTokens, CancellationToken ct)
    {
        int prevI = -1, prevJ = -1;
        for (int i = 0; i <= map.Length; i++)
        {
            if (i < map.Length && map[i] < 0) continue;
            int j = i < map.Length ? map[i] : newTokens.Length;
            int oldFrom = prevI + 1, newFrom = prevJ + 1;
            if (i > oldFrom && j > newFrom)
            {
                var sub = InstructionAlignment.Align(oldTokens[oldFrom..i], newTokens[newFrom..j], ct);
                for (int k = 0; k < sub.Length; k++) if (sub[k] >= 0) map[oldFrom + k] = newFrom + sub[k];
            }
            prevI = i;
            prevJ = j;
        }
        return map;
    }

    /// <summary>The changed rows with <paramref name="context"/> unchanged rows around each run; longer unchanged runs become one … row.</summary>
    private static (List<DiffRow> Rows, bool Truncated) Window(List<DiffRow> rows, int context, int maxRows)
    {
        var keep = new bool[rows.Count];
        for (int k = 0; k < rows.Count; k++)
            if (rows[k].Op != "=")
                for (int c = Math.Max(0, k - context); c <= Math.Min(rows.Count - 1, k + context); c++) keep[c] = true;
        var result = new List<DiffRow>();
        for (int k = 0; k < rows.Count;)
        {
            if (keep[k]) { result.Add(rows[k++]); continue; }
            int start = k;
            while (k < rows.Count && !keep[k]) k++;
            result.Add(new("…", rows[start].OldRva, rows[start].NewRva, $"{k - start} unchanged instruction(s)", null));
        }
        if (result.Count <= maxRows) return (result, false);
        return (result.Take(maxRows).ToList(), true);
    }

    /// <summary>Each instruction's text with its operand targets named build-independently.</summary>
    private string[] Render(NativeCodeIndex index, List<MaskedInsn> code, Func<int, string> label, bool old, CancellationToken ct)
    {
        var disassembler = new NativeDisassembler(index.Image);
        var at = new Dictionary<uint, int>(code.Count);
        for (int k = 0; k < code.Count; k++) at.TryAdd(code[k].Rva, k);
        var lines = code.Select(i => disassembler.DecodeOne(i.Rva)).ToList();
        var labels = new Dictionary<uint, string>();
        foreach (var line in lines)
        {
            ct.ThrowIfCancellationRequested();
            if (line == null) continue;
            foreach (var target in new[] { line.Facts.BranchTarget, line.Facts.MemoryTarget, line.Facts.ImmediateTarget })
                if (target is { } t && !labels.ContainsKey(t))
                    labels[t] = at.TryGetValue(t, out var k) ? label(k) : Name(index, t, old, ct);
        }
        return code.Select(i => disassembler.DecodeOne(i.Rva, labels)?.Text ?? "(bad)").ToArray();
    }

    /// <summary>A build-independent name for an address outside the function.</summary>
    public string Name(NativeCodeIndex index, uint rva, bool old, CancellationToken ct)
    {
        var prints = old ? match.Old : match.New;
        if (prints.ByStart.TryGetValue(rva, out var fi))
        {
            var pair = old ? match.ByOld[fi] : match.ByNew[fi];
            if (pair != null)
            {
                var fn = match.New.Functions[pair.New].Function;
                return match.New.Index.NameAt(fn.Start) ?? fn.Name;
            }
            return (old ? "old:" : "new:") + (index.NameAt(rva) ?? $"sub_{rva:X}");
        }
        if (index.StringAt(rva) is { } s)
        {
            var text = index.ReadString(s, 48);
            return "\"" + Regex.Replace(text.Length > 40 ? text[..40] + "…" : text, @"[\x00-\x1F\""]", m => $"\\x{(int)m.Value[0]:X2}") + "\"";
        }
        if (index.NameAt(rva) is { } named) return named;
        // Switch tables address their entries from the image base.
        if (rva == 0) return "__ImageBase";
        if (!old) return $"data_{rva:X}";
        if (_dataLabels.TryGetValue(rva, out var known)) return known;
        string labelText = _dataLabels.Count < MaxDataMaps && _mapper.Map(rva, ct).NewRva is { } mapped ? $"data_{mapped:X}" : $"old:data_{rva:X}";
        return _dataLabels[rva] = labelText;
    }

    private static readonly Regex Address = new(@"\b(?:sub|loc|off|unk|byte|word|dword|qword|stru|asc|j_sub|nullsub)_([0-9A-Fa-f]{4,16})\b|\b0x([0-9A-Fa-f]{6,16})\b",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);

    /// <summary>Pseudocode with in-image addresses (sub_X, loc_X, 0x...) replaced by the names <see cref="Name"/> gives, so both builds read alike.</summary>
    public string NormalizePseudocode(string text, bool old, CancellationToken ct)
    {
        var index = old ? match.Old.Index : match.New.Index;
        var image = index.Image;
        return Address.Replace(text, m =>
        {
            var hex = m.Groups[1].Success ? m.Groups[1].Value : m.Groups[2].Value;
            if (!ulong.TryParse(hex, System.Globalization.NumberStyles.HexNumber, null, out var va) || va < image.ImageBase || va - image.ImageBase >= image.SizeOfImage)
                return m.Value;
            return Name(index, (uint)(va - image.ImageBase), old, ct);
        });
    }
}
