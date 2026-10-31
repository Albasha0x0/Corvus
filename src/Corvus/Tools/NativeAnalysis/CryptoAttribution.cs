using System.Text.RegularExpressions;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Code;
using Corvus.Services.Analysis;

namespace Corvus.Tools;

/// <summary>
/// Function notes for block cipher routines: algorithm, mode, key size,
/// padding, wrappers, callers and the local record path.
/// </summary>
internal static partial class CryptoAttribution
{
    // Levels searched for storage strings: the function, its callers and theirs.
    private const int MaxDepth = 3;
    private const int MaxLines = 4096;

    [GeneratedRegex(@"(?<![A-Za-z])(local|session)Storage(?![a-z])|(?<![A-Za-z])IndexedDB(?![a-z])|document\.cookie")]
    private static partial Regex StoragePath();

    [GeneratedRegex(@"\band\b.*[, ](0Fh|0x0?f|15)\b", RegexOptions.IgnoreCase)]
    private static partial Regex Mask15();

    [GeneratedRegex(@"\bcmp\b.*[, ](0Ah|0Ch|0Eh)\b", RegexOptions.IgnoreCase)]
    private static partial Regex Rounds();

    /// <summary>
    /// Adds the cipher notes of <paramref name="f"/> through <paramref name="add"/>
    /// (address, text, kind); adds none when the image has no cipher table or
    /// the function neither reads nor reaches one.
    /// </summary>
    internal static void Notes(
        NativeCodeIndex index, NativeFunction f,
        Action<string?, string, string> add, CancellationToken ct, long scanLimit = CryptoConstantRules.ScanLimit)
    {
        var image = index.Image;
        var facts = CryptoConstantRules.Facts(index, ct, scanLimit);
        var tables = facts.Tables.Where(t => t.Cipher).ToList();
        if (tables.Count == 0)
        {
            if (facts.Extent.Note is { } note) add(null, $"crypto: tables unknown ({note})", "crypto");
            return;
        }
        string Va(uint r) => NativeAddress.Va(image, r);
        string Name(NativeFunction fn) => index.NameAt(fn.Start) ?? fn.Name;

        Dictionary<uint, List<string>> memo = [];
        List<string> Uses(NativeFunction fn)
        {
            if (memo.TryGetValue(fn.Start, out var hit)) return hit;
            var found = new SortedSet<string>(StringComparer.Ordinal);
            foreach (var r in index.RefsFrom(fn))
                if (r.Kind is XrefKind.Read or XrefKind.Address
                    && tables.LastOrDefault(t => r.To >= t.Start && r.To < t.End) is { } table)
                    found.Add(table.Algorithm);
            return memo[fn.Start] = [.. found];
        }

        // Cipher routines the function reaches through calls, nearest first.
        var reached = new List<(NativeFunction Callee, List<string> Algorithms, uint Site, int Depth)>();
        var seen = new HashSet<uint> { f.Start };
        var queue = new Queue<(NativeFunction Fn, uint Site, int Depth)>();
        foreach (var c in index.Callees(f))
            if (c.Function is { } g && seen.Add(g.Start)) queue.Enqueue((g, c.From, 1));
        while (queue.Count > 0)
        {
            var (g, site, depth) = queue.Dequeue();
            if (Uses(g) is { Count: > 0 } algorithms)
            {
                reached.Add((g, algorithms, site, depth));
                continue;
            }
            if (depth >= 2) continue;
            foreach (var c in index.Callees(g))
                if (c.Function is { } h && seen.Add(h.Start)) queue.Enqueue((h, site, depth + 1));
        }

        var own = Uses(f);
        if (own.Count == 0 && reached.Count == 0) return;
        var algorithmNames = string.Join(", ", own.Concat(reached.SelectMany(r => r.Algorithms)).Distinct());

        if (own.Count > 0)
            add(Va(f.Start), $"crypto: reads {string.Join(", ", own)} tables", "crypto");
        foreach (var (callee, algorithms, site, depth) in reached)
            add(Va(site),
                $"crypto: {(depth == 1 ? "calls" : "reaches")} {Name(callee)} "
                + $"({string.Join(", ", algorithms)}) at {Va(callee.Start)}", "crypto");

        var lines = Lines(index, f);
        if (reached.Count > 0)
        {
            if (index.Image.Arch is not (NativeArch.X86 or NativeArch.X64))
                add(Va(f.Start), "crypto: mode not determined (loop shapes are read on x86 and x64 only)", "crypto");
            else if (BlockLoop(index, f, facts, [.. reached.Select(r => r.Site)]) is { } loop)
                add(Va(loop.Start),
                    $"crypto: mode {loop.Mode} (block={loop.Width} bytes, confidence={loop.Confidence}; "
                    + "a loop steps the block routine call)", "crypto");
            else
                add(Va(f.Start), "crypto: mode not determined (no loop calls the block routine"
                    + (facts.Extent.Partial ? $"; {facts.Extent.Note}" : "") + ")", "crypto");
        }

        if (algorithmNames.Contains("AES"))
        {
            // Only a compare against the constant counts; a move or subtract can be anything.
            var rounds = lines.Concat(reached.SelectMany(r => Lines(index, r.Callee)))
                .Select(x => Rounds().Match(x.Text)).Where(m => m.Success)
                .Select(m => m.Groups[1].Value.ToUpperInvariant()).Distinct().ToList();
            add(null, rounds.Count == 1
                ? $"crypto: AES key size {(rounds[0] switch { "0AH" => "128", "0CH" => "192", _ => "256" })} "
                  + $"bits (round count {rounds[0]} compared)"
                : "crypto: AES key size not determined (no single round count constant)", "crypto");
        }

        if (lines.Any(x => Mask15().IsMatch(x.Text)))
            add(null, "crypto: padding to 16-byte blocks (mask 0Fh seen); scheme not determined", "crypto");

        // Wrappers list their callers too; the count line shows what a section limit cut.
        var callers = index.Callers(f).Where(c => c.Caller != null).GroupBy(c => c.Caller!.Start)
            .Select(g => (Caller: g.First().Caller!, From: g.Min(c => c.From), Count: g.Count()))
            .OrderBy(c => c.From).ToList();
        add(null, $"crypto: {callers.Count} caller{(callers.Count == 1 ? "" : "s")}", "crypto");
        foreach (var (caller, from, n) in callers)
            add(Va(from), $"crypto caller: {Name(caller)}{(n > 1 ? $" ({n} sites)" : "")}", "crypto");

        var path = StorageStrings(index, f, ct);
        if (path.Count > 0)
            add(null, $"crypto: local record path ({string.Join(", ", path.Take(3))}); "
                      + "stored data, not network traffic", "crypto");
    }

    private static List<DisasmLine> Lines(NativeCodeIndex index, NativeFunction fn)
    {
        var all = new List<DisasmLine>();
        var disassembler = new NativeDisassembler(index.Image);
        foreach (var (s, e) in index.Ranges(fn))
            all.AddRange(disassembler.Disassemble(s, MaxLines, e));
        return all;
    }

    // Smallest shared loop in the function that contains a block routine call.
    private static CryptoConstantRules.BlockLoop? BlockLoop(
        NativeCodeIndex index, NativeFunction f, CryptoConstantRules.CryptoFacts facts, HashSet<uint> sites)
    {
        var ranges = index.Ranges(f).ToList();
        return facts.Loops
            .Where(l => ranges.Exists(r => l.Start >= r.Start && l.Start < r.End)
                        && sites.Any(s => s >= l.Start && s < l.Start + l.Length))
            .OrderBy(l => l.Length).FirstOrDefault();
    }

    // Strings that name a storage operation, from the function and two caller levels.
    private static List<string> StorageStrings(
        NativeCodeIndex index, NativeFunction f, CancellationToken ct)
    {
        var found = new List<string>();
        var seen = new HashSet<uint>();
        var level = new List<NativeFunction> { f };
        for (int depth = 0; depth < MaxDepth && level.Count > 0; depth++)
        {
            var next = new List<NativeFunction>();
            foreach (var fn in level)
            {
                if (!seen.Add(fn.Start)) continue;
                ct.ThrowIfCancellationRequested();
                foreach (var r in index.RefsFrom(fn))
                    if (index.StringAt(r.To) is { } s && index.ReadString(s, 200) is var text
                        && StoragePath().IsMatch(text) && !found.Contains(text))
                        found.Add(text);
                next.AddRange(index.Callers(fn).Select(c => c.Caller).OfType<NativeFunction>());
            }
            level = next;
        }
        return found;
    }
}
