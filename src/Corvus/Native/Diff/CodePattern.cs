using System.Text;
using Corvus.Native.Code;

namespace Corvus.Native.Diff;

/// <summary>A byte pattern with wildcards; <see cref="Mask"/>[i] false means any byte.</summary>
public sealed record BytePattern(byte[] Bytes, bool[] Mask)
{
    public int Length => Bytes.Length;
    public int FixedBytes => Mask.Count(m => m);

    /// <summary>IDA style: "48 8B 05 ?? ?? ?? ??".</summary>
    public override string ToString()
    {
        var sb = new StringBuilder(Bytes.Length * 3);
        for (int i = 0; i < Bytes.Length; i++)
        {
            if (i > 0) sb.Append(' ');
            sb.Append(Mask[i] ? Bytes[i].ToString("X2") : "??");
        }
        return sb.ToString();
    }

    public bool MatchesAt(ReadOnlySpan<byte> data, int at)
    {
        if (at < 0 || at + Bytes.Length > data.Length) return false;
        for (int j = 0; j < Bytes.Length; j++)
            if (Mask[j] && data[at + j] != Bytes[j]) return false;
        return true;
    }
}

/// <summary>A pattern made by <see cref="CodePatterns.Make"/>.</summary>
public sealed record MadePattern(
    BytePattern Pattern,
    uint Start,
    bool Unique,
    int Hits,
    string Anchor,
    uint Target,
    int? ReferenceOffset,
    int? OperandOffset,
    int? OperandSize,
    string? OperandKind,
    int? InstructionEnd,
    string Note);

/// <summary>Code patterns with addresses as wildcards, grown until unique in the executable sections, so they survive rebuilds.</summary>
public static class CodePatterns
{
    public const int MaxPatternBytes = 512;
    private const int MaxCandidates = 2_000_000;
    /// <summary>A unique pattern still grows to this many fixed bytes, so it stays unique in other builds (opcodes alone rarely do).</summary>
    public const int MinFixedBytes = 6;

    /// <summary>The executable sections of an image as (rva, bytes).</summary>
    public static List<(uint Rva, byte[] Bytes, string Name)> CodeSections(INativeImage image, bool allSections = false)
    {
        var result = new List<(uint, byte[], string)>();
        foreach (var s in image.Sections)
        {
            if (!allSections && !s.IsExecutable) continue;
            result.Add((s.Rva, image.ReadFileBytes(s, 512L << 20), s.Name));
        }
        return result;
    }

    /// <summary>Every offset (as an RVA) where <paramref name="pattern"/> occurs, up to <paramref name="max"/>; total counts all.</summary>
    public static List<uint> Find(List<(uint Rva, byte[] Bytes, string Name)> sections, BytePattern pattern, int max, out int total, CancellationToken ct)
    {
        var hits = new List<uint>();
        total = 0;
        if (pattern.Length == 0) return hits;
        // Anchor the scan on the first fixed byte.
        int first = Array.IndexOf(pattern.Mask, true);
        if (first < 0) return hits;
        byte lead = pattern.Bytes[first];
        foreach (var (rva, bytes, _) in sections)
        {
            var span = bytes.AsSpan();
            int at = first;
            int scanned = 0;
            while (at < span.Length)
            {
                int k = span[at..].IndexOf(lead);
                if (k < 0) break;
                at += k;
                int start = at - first;
                if (pattern.MatchesAt(span, start))
                {
                    total++;
                    if (hits.Count < max) hits.Add(rva + (uint)start);
                }
                at++;
                if ((++scanned & 0xFFFF) == 0) ct.ThrowIfCancellationRequested();
            }
        }
        return hits;
    }

    /// <summary>A unique pattern at <paramref name="rva"/> (anchor "address"), else near a referencing instruction (anchor "reference").</summary>
    public static MadePattern Make(NativeCodeIndex index, uint rva, int maxBytes, bool allowReference, bool referenceOnly, CancellationToken ct)
    {
        maxBytes = Math.Clamp(maxBytes, 8, MaxPatternBytes);
        var image = index.Image;
        var decoder = new MaskedDecoder(image, index);
        var sections = CodeSections(image);
        MadePattern? direct = null;
        if (!referenceOnly)
        {
            direct = Grow(decoder, sections, rva, maxBytes, ct);
            if (direct.Unique || !allowReference) return direct;
        }

        MadePattern? best = null;
        foreach (var from in ReferenceSites(index, rva, []).Take(16))
        {
            ct.ThrowIfCancellationRequested();
            if (AtReference(index, decoder, sections, rva, from, maxBytes, ct) is not { } made) continue;
            if (best == null || made.Pattern.Length < best.Pattern.Length) best = made;
            if (best.Pattern.Length <= 16) break;
        }
        if (best != null) return best;
        return direct ?? new MadePattern(new BytePattern([], []), rva, false, 0, "reference", rva, null, null, null, null, null,
            "no instruction that references the address yields a unique pattern");
    }

    /// <summary>Up to <paramref name="max"/> unique patterns at instructions referencing <paramref name="rva"/>, shortest first.</summary>
    public static List<MadePattern> MakeAtReferences(NativeCodeIndex index, uint rva, int maxBytes, int max, IEnumerable<uint> extraSites, CancellationToken ct)
    {
        maxBytes = Math.Clamp(maxBytes, 8, MaxPatternBytes);
        var decoder = new MaskedDecoder(index.Image, index);
        var sections = CodeSections(index.Image);
        var made = new List<MadePattern>();
        foreach (var from in ReferenceSites(index, rva, extraSites).Take(64))
        {
            ct.ThrowIfCancellationRequested();
            if (AtReference(index, decoder, sections, rva, from, maxBytes, ct) is { } p) made.Add(p);
        }
        return made.OrderBy(p => p.Pattern.Length).ThenByDescending(p => p.Pattern.FixedBytes).ThenBy(p => p.Start).Take(Math.Max(1, max)).ToList();
    }

    /// <summary>Instructions that reference <paramref name="rva"/> as code (not data pointers, jumps or switch cases), then the extra sites.</summary>
    private static IEnumerable<uint> ReferenceSites(NativeCodeIndex index, uint rva, IEnumerable<uint> extraSites) =>
        index.RefsTo(rva, 256).Where(x => x.Kind is not (XrefKind.Pointer or XrefKind.Jump or XrefKind.ConditionalJump or XrefKind.SwitchCase))
            .Select(x => x.From).Concat(extraSites).Distinct();

    /// <summary>The first unique pattern starting at or up to six instructions before <paramref name="from"/>, with how to recover the address.</summary>
    private static MadePattern? AtReference(NativeCodeIndex index, MaskedDecoder decoder, List<(uint Rva, byte[] Bytes, string Name)> sections, uint rva, uint from,
        int maxBytes, CancellationToken ct)
    {
        if (decoder.DecodeOne(from) is not { } refInsn) return null;
        foreach (var start in StartsBefore(index, decoder, from, 6))
        {
            var p = Grow(decoder, sections, start, maxBytes, ct);
            if (!p.Unique) continue;
            int refOffset = (int)(from - start);
            if (refOffset >= p.Pattern.Length) continue;
            return p with
            {
                Anchor = "reference",
                Target = rva,
                ReferenceOffset = refOffset,
                OperandOffset = refInsn.OperandKind != AddressOperand.None ? refOffset + refInsn.OperandOffset : null,
                OperandSize = refInsn.OperandKind != AddressOperand.None ? refInsn.OperandSize : null,
                OperandKind = refInsn.OperandKind switch
                {
                    AddressOperand.Relative => "relative",
                    AddressOperand.RipRelative => "rip_relative",
                    AddressOperand.Absolute => "absolute",
                    _ => null,
                },
                InstructionEnd = refOffset + refInsn.Length,
                Note = refInsn.OperandKind switch
                {
                    AddressOperand.Relative or AddressOperand.RipRelative =>
                        $"address = hit + {refOffset + refInsn.Length} + signed {refInsn.OperandSize * 8}-bit value at hit + {refOffset + refInsn.OperandOffset}",
                    AddressOperand.Absolute => $"address = the {refInsn.OperandSize * 8}-bit value at hit + {refOffset + refInsn.OperandOffset} (a VA; subtract the image base)",
                    _ => $"the referencing instruction is at hit + {refOffset}",
                },
            };
        }
        return null;
    }

    /// <summary>Instruction starts at <paramref name="at"/> and up to <paramref name="back"/> instructions before it in its block.</summary>
    private static IEnumerable<uint> StartsBefore(NativeCodeIndex index, MaskedDecoder decoder, uint at, int back)
    {
        yield return at;
        if (index.FunctionAt(at) is not { } fn) yield break;
        FunctionGraph graph;
        try { graph = index.GetGraph(fn); }
        catch (NotSupportedException) { yield break; }
        if (graph.BlockAt(at) is not { } block) yield break;
        var list = new List<MaskedInsn>();
        decoder.Decode(block.Start, at, list);
        for (int k = list.Count - 1, n = 0; k >= 0 && n < back; k--, n++)
            if (list[k].End <= at) yield return list[k].Rva;
    }

    private static MadePattern Grow(MaskedDecoder decoder, List<(uint Rva, byte[] Bytes, string Name)> sections, uint start, int maxBytes, CancellationToken ct)
    {
        var bytes = new List<byte>();
        var mask = new List<bool>();
        List<(int Section, int Offset)>? candidates = null;
        int section = sections.FindIndex(s => start >= s.Rva && start - s.Rva < s.Bytes.Length);
        uint at = start;
        string note = "";
        while (bytes.Count < maxBytes)
        {
            ct.ThrowIfCancellationRequested();
            if (decoder.DecodeOne(at) is not { } insn) { note = "stopped at bytes that do not decode"; break; }
            for (int i = 0; i < insn.Length && bytes.Count < maxBytes; i++) { bytes.Add(insn.Bytes[i]); mask.Add(!insn.IsWild(i)); }
            at = insn.End;
            var pattern = new BytePattern(bytes.ToArray(), mask.ToArray());
            if (candidates == null)
            {
                if (pattern.FixedBytes < 2 && bytes.Count < maxBytes) continue;
                var found = Find(sections, pattern, MaxCandidates, out int total, ct);
                candidates = found.Select(r => Locate(sections, r)).Where(c => c.Section >= 0).ToList();
                if (total > found.Count) { candidates = null; continue; }
            }
            else
                candidates = candidates.Where(c => pattern.MatchesAt(sections[c.Section].Bytes, c.Offset)).ToList();
            if (candidates.Count <= 1 && pattern.FixedBytes >= MinFixedBytes) break;
            if (insn.Flow is FlowKind.Return && bytes.Count >= 32) { note = "the code ends with a return before the pattern became unique"; }
        }
        var result = Trim(new BytePattern(bytes.ToArray(), mask.ToArray()));
        int hits = candidates?.Count(c => result.MatchesAt(sections[c.Section].Bytes, c.Offset)) ?? CountAll(sections, result, ct);
        bool unique = hits == 1 && section >= 0;
        if (!unique && note.Length == 0) note = $"not unique within {maxBytes} bytes ({hits} hits)";
        return new MadePattern(result, start, unique, hits, "address", start, null, null, null, null, null, note);
    }

    private static (int Section, int Offset) Locate(List<(uint Rva, byte[] Bytes, string Name)> sections, uint rva)
    {
        int i = sections.FindIndex(s => rva >= s.Rva && rva - s.Rva < s.Bytes.Length);
        return (i, i < 0 ? 0 : (int)(rva - sections[i].Rva));
    }

    private static int CountAll(List<(uint Rva, byte[] Bytes, string Name)> sections, BytePattern p, CancellationToken ct)
    {
        Find(sections, p, 0, out int total, ct);
        return total;
    }

    private static BytePattern Trim(BytePattern p)
    {
        int n = p.Length;
        while (n > 0 && !p.Mask[n - 1]) n--;
        return n == p.Length ? p : new BytePattern(p.Bytes[..n], p.Mask[..n]);
    }
}
