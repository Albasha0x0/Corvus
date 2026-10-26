using System.Buffers.Binary;

namespace Corvus.Native;

/// <summary>One signature's hits in a region, and how many chance alone would give.</summary>
public sealed record SignatureCount(string Name, int Hits, double Expected);

/// <summary>
/// An instruction set a headerless region reads as. <see cref="Score"/> is the signature hits above twice chance per
/// 64 KiB, each signature capped at <see cref="RawCandidates.SignatureCap"/>; a signature another instruction set shares
/// counts only once one of this set's own clears chance. <see cref="Evidence"/> lists each signature.
/// </summary>
public sealed record IsaCandidate(string Arch, double Score, IReadOnlyList<SignatureCount> Evidence);

/// <summary>
/// A load base for a region: <see cref="Votes"/> distinct pointer values that land on a string start when the region is
/// mapped at <see cref="Base"/>, less those that land inside a string; <see cref="Strings"/> of the region's strings
/// referenced from a start; <see cref="Source"/> is
/// "pointers" or "vector table" (a Cortex-M reset handler and its neighbours, votes 0).
/// </summary>
public sealed record BaseCandidate(ulong Base, int Votes, int Strings, string Source);

/// <summary>The load bases a region's pointers imply for one instruction set, best first, with what bounded the count.</summary>
public sealed record BaseReport(IReadOnlyList<BaseCandidate> Bases, int Pointers, int Targets, bool Clear, IReadOnlyList<string> Notes);

/// <summary>
/// Reads headerless code (firmware, a memory region) for the instruction sets it can be and the load bases its absolute
/// pointers imply. Pure and bounded: nothing is decoded or run; every limit reached is named in the notes.
/// </summary>
public static class RawCandidates
{
    /// <summary>Lowest score a candidate is reported with; data and text stay under 2.</summary>
    public const double MinScore = 20;
    /// <summary>Most any one signature adds to a score.</summary>
    public const double SignatureCap = 200;
    /// <summary>Bytes scored whole; a larger region is sampled in <see cref="SampleWindows"/> windows of 1 MiB.</summary>
    public const int ScoreWhole = 16 << 20;
    private const int SampleWindows = 16;
    /// <summary>Most distinct pointer values, string starts and votes a base search keeps.</summary>
    public const int MaxPointers = 1 << 20, MaxTargets = 1 << 16, MaxVotes = 4 << 20;
    /// <summary>Bases are multiples of this, as load_assembly format=raw takes them.</summary>
    public const ulong BaseAlignment = 0x1000;
    private const int MinString = 6, MaxBases = 5, MinVotes = 16, MaxRanked = 16;

    /// <summary>Instruction sets without a signature here; named, not scored.</summary>
    public static readonly IReadOnlyList<string> NotChecked = ["6502", "x86-16", "dos-mz"];

    private enum Unit { Bytes, BytesNotAfterRex, Le32, Be32, Le16, Thumb32, Le32At2, Be16 }

    private sealed record Signature(string Name, Unit Unit, uint Value, uint Mask, byte[]? Bytes = null)
    {
        public static Signature Seq(string name, params byte[] bytes) => new(name, Unit.Bytes, 0, 0, bytes);
    }

    // Returns, prologues and epilogues each compiler emits for the instruction set, one table for every scorer.
    private static readonly (string Arch, Signature[] Signatures)[] Table =
    [
        ("x86", [Signature.Seq("push ebp; mov ebp, esp", 0x55, 0x89, 0xE5), Signature.Seq("push ebp; mov ebp, esp (8B EC)", 0x55, 0x8B, 0xEC),
            Signature.Seq("mov ebx, [esp]; ret", 0x8B, 0x1C, 0x24, 0xC3), Signature.Seq("add esp, 0x10; pop ebx", 0x83, 0xC4, 0x10, 0x5B),
            new("sub esp, imm8 (no REX)", Unit.BytesNotAfterRex, 0, 0, [0x83, 0xEC])]),
        ("x64", [Signature.Seq("sub rsp, imm8", 0x48, 0x83, 0xEC), Signature.Seq("mov [rsp+N], rbx", 0x48, 0x89, 0x5C, 0x24),
            Signature.Seq("mov rax, [rip+N]", 0x48, 0x8B, 0x05), Signature.Seq("lea rax, [rip+N]", 0x48, 0x8D, 0x05), Signature.Seq("mov rbp, rsp", 0x48, 0x89, 0xE5)]),
        ("arm", [new("bx lr", Unit.Le32, 0xE12FFF1E, 0xFFFFFFFF), new("push {..., lr}", Unit.Le32, 0xE92D4000, 0xFFFF4000),
            new("pop {..., pc}", Unit.Le32, 0xE8BD8000, 0xFFFF8000)]),
        ("thumb", [new("bx lr", Unit.Le16, 0x4770, 0xFFFF), new("push.w {..., lr}", Unit.Thumb32, 0xE92D4000, 0xFFFF4000),
            new("pop.w {..., pc}", Unit.Thumb32, 0xE8BD8000, 0xFFFF8000)]),
        ("arm64", [new("ret", Unit.Le32, 0xD65F03C0, 0xFFFFFFFF), new("stp x29, x30, [sp, #-N]!", Unit.Le32, 0xA9807BFD, 0xFFC07FFF),
            new("mov x29, sp", Unit.Le32, 0x910003FD, 0xFFFFFFFF)]),
        ("mips", [new("jr ra", Unit.Be32, 0x03E00008, 0xFFFFFFFF), new("addiu sp, sp, N", Unit.Be32, 0x27BD0000, 0xFFFF0000),
            new("sw ra, N(sp)", Unit.Be32, 0xAFBF0000, 0xFFFF0000)]),
        ("mipsel", [new("jr ra", Unit.Le32, 0x03E00008, 0xFFFFFFFF), new("addiu sp, sp, N", Unit.Le32, 0x27BD0000, 0xFFFF0000),
            new("sw ra, N(sp)", Unit.Le32, 0xAFBF0000, 0xFFFF0000)]),
        ("mips64", [new("jr ra", Unit.Be32, 0x03E00008, 0xFFFFFFFF), new("daddiu sp, sp, N", Unit.Be32, 0x67BD0000, 0xFFFF0000),
            new("sd ra, N(sp)", Unit.Be32, 0xFFBF0000, 0xFFFF0000)]),
        ("mips64el", [new("jr ra", Unit.Le32, 0x03E00008, 0xFFFFFFFF), new("daddiu sp, sp, N", Unit.Le32, 0x67BD0000, 0xFFFF0000),
            new("sd ra, N(sp)", Unit.Le32, 0xFFBF0000, 0xFFFF0000)]),
        ("ppc", [new("blr", Unit.Be32, 0x4E800020, 0xFFFFFFFF), new("mflr r0", Unit.Be32, 0x7C0802A6, 0xFFFFFFFF),
            new("stwu r1, N(r1)", Unit.Be32, 0x94210000, 0xFFFF0000)]),
        ("ppc64", [new("blr", Unit.Be32, 0x4E800020, 0xFFFFFFFF), new("mflr r0", Unit.Be32, 0x7C0802A6, 0xFFFFFFFF),
            new("stdu r1, N(r1)", Unit.Be32, 0xF8210001, 0xFFFF0003)]),
        ("ppc64le", [new("blr", Unit.Le32, 0x4E800020, 0xFFFFFFFF), new("mflr r0", Unit.Le32, 0x7C0802A6, 0xFFFFFFFF),
            new("stdu r1, N(r1)", Unit.Le32, 0xF8210001, 0xFFFF0003)]),
        ("riscv32", [new("c.ret", Unit.Le16, 0x8082, 0xFFFF), new("ret", Unit.Le32At2, 0x00008067, 0xFFFFFFFF),
            new("c.swsp ra, N(sp)", Unit.Le16, 0xC006, 0xE07F)]),
        ("riscv64", [new("c.ret", Unit.Le16, 0x8082, 0xFFFF), new("ret", Unit.Le32At2, 0x00008067, 0xFFFFFFFF),
            new("c.sdsp ra, N(sp)", Unit.Le16, 0xE006, 0xE07F)]),
        ("m68k", [new("rts", Unit.Be16, 0x4E75, 0xFFFF), new("link.w a6, #N", Unit.Be16, 0x4E56, 0xFFFF), new("unlk a6", Unit.Be16, 0x4E5E, 0xFFFF),
            new("movem.l <regs>, -(sp)", Unit.Be16, 0x48E7, 0xFFFF)]),
    ];

    // A signature with the same encoding in another instruction set (c.ret in riscv32 and riscv64) tells them apart only
    // through the signatures each has alone.
    private static readonly bool[][] Shared = [.. Table.Select(t => t.Signatures.Select(s =>
        Table.Count(o => o.Signatures.Any(x => x.Unit == s.Unit && x.Value == s.Value && x.Mask == s.Mask &&
                                               (x.Bytes ?? []).AsSpan().SequenceEqual(s.Bytes ?? []))) > 1).ToArray())];

    /// <summary>The instruction sets <paramref name="data"/> reads as at or above <see cref="MinScore"/>, best first; empty when none does.</summary>
    public static IReadOnlyList<IsaCandidate> Isas(ReadOnlySpan<byte> data, CancellationToken ct = default) =>
        [.. Score(data, ct).Where(c => c.Score >= MinScore)];

    /// <summary>Every scored instruction set, best first, including those under <see cref="MinScore"/>.</summary>
    public static IReadOnlyList<IsaCandidate> Score(ReadOnlySpan<byte> data, CancellationToken ct = default)
    {
        var counts = Table.Select(t => new int[t.Signatures.Length]).ToArray();
        long scanned = 0;
        if (data.Length <= ScoreWhole) { Count(data, counts, ct); scanned = data.Length; }
        else
        {
            const int window = 1 << 20;
            long step = (data.Length - window) / (SampleWindows - 1);
            for (int w = 0; w < SampleWindows; w++)
            {
                Count(data.Slice((int)(w * step & ~3L), window), counts, ct);
                scanned += window;
            }
        }
        if (scanned == 0) return [];
        double per64k = scanned / 65536.0;
        var result = new List<IsaCandidate>();
        for (int a = 0; a < Table.Length; a++)
        {
            var evidence = new List<SignatureCount>();
            double own = 0, shared = 0;
            for (int s = 0; s < Table[a].Signatures.Length; s++)
            {
                var sig = Table[a].Signatures[s];
                double expected = Expected(sig, scanned);
                evidence.Add(new SignatureCount(sig.Name, counts[a][s], Math.Round(expected, 1)));
                double part = Math.Min(SignatureCap, Math.Max(0, counts[a][s] - 2 * expected) / per64k);
                if (Shared[a][s]) shared += part;
                else own += part;
            }
            result.Add(new IsaCandidate(Table[a].Arch, Math.Round(own > 0 ? own + shared : 0, 1), evidence));
        }
        return [.. result.OrderByDescending(c => c.Score).ThenBy(c => c.Arch, StringComparer.Ordinal)];
    }

    private static double Expected(Signature sig, long n) => sig.Unit switch
    {
        Unit.Bytes or Unit.BytesNotAfterRex => n / Math.Pow(256, sig.Bytes!.Length),
        Unit.Le32 or Unit.Be32 => n / 4 / Math.Pow(2, System.Numerics.BitOperations.PopCount(sig.Mask)),
        _ => n / 2 / Math.Pow(2, System.Numerics.BitOperations.PopCount(sig.Mask)),
    };

    // One pass per unit over the bytes, testing every signature of that unit.
    private static void Count(ReadOnlySpan<byte> data, int[][] counts, CancellationToken ct)
    {
        var byUnit = new List<(int A, int S, uint Value, uint Mask)>[8];
        for (int u = 0; u < byUnit.Length; u++) byUnit[u] = [];
        for (int a = 0; a < Table.Length; a++)
            for (int s = 0; s < Table[a].Signatures.Length; s++)
            {
                var sig = Table[a].Signatures[s];
                if (sig.Unit is Unit.Bytes or Unit.BytesNotAfterRex) counts[a][s] += Occurrences(data, sig.Bytes!, sig.Unit == Unit.BytesNotAfterRex);
                else byUnit[(int)sig.Unit].Add((a, s, sig.Value, sig.Mask));
            }
        ct.ThrowIfCancellationRequested();
        var halves = System.Runtime.InteropServices.MemoryMarshal.Cast<byte, ushort>(data);
        bool little = BitConverter.IsLittleEndian;
        Words(halves, 2, 2, byUnit[(int)Unit.Le32], counts, little ? Order.Low : Order.LowSwapped, ct);
        Words(halves, 2, 2, byUnit[(int)Unit.Be32], counts, little ? Order.LowSwapped : Order.Low, ct);
        Words(halves, 1, 1, byUnit[(int)Unit.Le16], counts, little ? Order.Low : Order.LowSwapped, ct);
        Words(halves, 1, 1, byUnit[(int)Unit.Be16], counts, little ? Order.LowSwapped : Order.Low, ct);
        Words(halves, 1, 2, byUnit[(int)Unit.Thumb32], counts, little ? Order.High : Order.HighSwapped, ct);
        Words(halves, 1, 2, byUnit[(int)Unit.Le32At2], counts, little ? Order.Low : Order.LowSwapped, ct);
    }

    // How a unit's value is built from halfwords read in host order: Low puts the first halfword in the low half, High
    // in the high half (a Thumb-2 instruction); Swapped reverses the bytes of the value read.
    private enum Order { Low, LowSwapped, High, HighSwapped }

    // Signatures are indexed by the bits every mask of the unit tests, so most words cost one table read.
    private static void Words(ReadOnlySpan<ushort> halves, int step, int width, List<(int A, int S, uint Value, uint Mask)> sigs,
        int[][] counts, Order order, CancellationToken ct)
    {
        if (sigs.Count == 0) return;
        const int bits = 12;
        uint common = sigs.Aggregate(uint.MaxValue, (m, t) => m & t.Mask);
        var masks = sigs.Select(t => t.Mask).ToArray();
        var values = sigs.Select(t => t.Value).ToArray();
        var first = new int[1 << bits];
        var next = new int[sigs.Count];
        Array.Fill(first, -1);
        for (int t = sigs.Count - 1; t >= 0; t--)
        {
            uint key = (values[t] & common) * 0x9E3779B1u >> (32 - bits);
            next[t] = first[key];
            first[key] = t;
        }
        var hits = new int[sigs.Count];
        bool swap = order is Order.LowSwapped or Order.HighSwapped, high = order is Order.High or Order.HighSwapped;
        for (int i = 0; i + width <= halves.Length; i += step)
        {
            if ((i & 0x7FFFF) == 0) ct.ThrowIfCancellationRequested();
            uint v;
            if (width == 1) v = swap ? (uint)(ushort)(halves[i] << 8 | halves[i] >> 8) : halves[i];
            else
            {
                uint lo = halves[i], hi = halves[i + 1];
                if (swap)
                {
                    lo = (lo >> 8 | lo << 8) & 0xFFFF;
                    hi = (hi >> 8 | hi << 8) & 0xFFFF;
                    v = lo << 16 | hi;
                }
                else v = high ? lo << 16 | hi : hi << 16 | lo;
            }
            for (int t = first[(v & common) * 0x9E3779B1u >> (32 - bits)]; t >= 0; t = next[t])
                if ((v & masks[t]) == values[t]) hits[t]++;
        }
        for (int t = 0; t < sigs.Count; t++) counts[sigs[t].A][sigs[t].S] += hits[t];
    }

    private static int Occurrences(ReadOnlySpan<byte> data, byte[] pattern, bool notAfterRex)
    {
        int n = 0;
        for (int at = 0; ;)
        {
            int i = data[at..].IndexOf(pattern);
            if (i < 0) return n;
            at += i;
            // REX.W before the opcode makes it the 64-bit form.
            if (!notAfterRex || at == 0 || data[at - 1] != 0x48) n++;
            at++;
        }
    }

    /// <summary>
    /// The load bases <paramref name="data"/>'s aligned pointers imply when read as <paramref name="isa"/>, best first:
    /// each distinct pointer value votes for every <see cref="BaseAlignment"/>-aligned base that puts it on a string start,
    /// and the best bases lose a vote for each pointer value they put inside a string.
    /// A Thumb image starting with a Cortex-M vector table adds the base its handlers imply. 16-bit code is not searched.
    /// </summary>
    public static BaseReport Bases(ReadOnlySpan<byte> data, RawArch isa, CancellationToken ct = default)
    {
        var notes = new List<string>();
        var bases = new List<BaseCandidate>();
        if (VectorTableBase(data, isa) is { } vector) bases.Add(new BaseCandidate(vector, 0, 0, "vector table"));
        if (isa.Bits == 16)
        {
            notes.Add($"{isa.Name}: 16-bit code loads at a paragraph; bases are not searched");
            return new BaseReport(bases, 0, 0, false, notes);
        }
        var inside = new System.Collections.BitArray(data.Length);
        var targets = Strings(data, inside, notes, ct);
        var pointers = Pointers(data, isa, notes, ct);
        if (targets.Length == 0 || pointers.Count == 0)
        {
            notes.Add($"no base found: {pointers.Count:N0} pointer values, {targets.Length:N0} strings");
            return new BaseReport(bases, pointers.Count, targets.Length, false, notes);
        }

        // Targets by their offset within a page: a page-aligned base keeps that offset, so a pointer meets only its own bucket.
        const int pageMask = (int)BaseAlignment - 1;
        Array.Sort(targets, (x, y) => (x & pageMask).CompareTo(y & pageMask));
        var first = new int[BaseAlignment + 1];
        foreach (var t in targets) first[(t & pageMask) + 1]++;
        for (int i = 1; i < first.Length; i++) first[i] += first[i - 1];
        ulong top = isa.Bits == 64 ? ulong.MaxValue : (1UL << isa.Bits) - 1;
        var votes = new List<ulong>(Math.Min(MaxVotes, pointers.Count * 4));
        foreach (var p in pointers)
        {
            int lo = (int)(p & (ulong)pageMask);
            for (int i = first[lo]; i < first[lo + 1]; i++)
            {
                ulong t = (ulong)targets[i];
                if (p < t || p - t > top - (ulong)data.Length) continue;
                if (votes.Count == MaxVotes) break;
                votes.Add(p - t);
            }
            if (votes.Count == MaxVotes)
            {
                notes.Add($"stopped at {MaxVotes:N0} votes; later pointer values did not vote");
                break;
            }
        }
        ct.ThrowIfCancellationRequested();
        // A chance value lands inside a string as often as its length allows; a pointer lands on the start.
        ulong size = (ulong)data.Length;
        var ranked = Top(votes).Select(r => (r.Base, Votes: r.Votes - pointers.Count(p => p - r.Base < size && inside[(int)(p - r.Base)])))
            .OrderByDescending(r => r.Votes).ThenBy(r => r.Base).Where(r => r.Votes > 0).Take(MaxBases).ToList();
        foreach (var (b, n) in ranked)
        {
            int referenced = targets.Count(t => pointers.Contains(b + (ulong)t));
            if (bases.FirstOrDefault(x => x.Base == b) is { } v) bases[bases.IndexOf(v)] = new BaseCandidate(b, n, referenced, "vector table, pointers");
            else bases.Add(new BaseCandidate(b, n, referenced, "pointers"));
        }
        var byPointers = bases.Where(b => b.Votes > 0).ToList();
        bool clear = byPointers.Count > 0 && byPointers[0].Votes >= MinVotes && (byPointers.Count == 1 || byPointers[0].Votes >= 2 * byPointers[1].Votes);
        if (!clear) notes.Add($"no clear base: {pointers.Count:N0} pointer values, {targets.Length:N0} strings; the code may be position independent");
        return new BaseReport(bases, pointers.Count, targets.Length, clear, notes);
    }

    private static List<(ulong Base, int Votes)> Top(List<ulong> votes)
    {
        var all = votes.ToArray();
        Array.Sort(all);
        var runs = new List<(ulong, int)>();
        for (int i = 0; i < all.Length;)
        {
            int j = i;
            while (j < all.Length && all[j] == all[i]) j++;
            if ((all[i] & (BaseAlignment - 1)) == 0) runs.Add((all[i], j - i));
            i = j;
        }
        return [.. runs.OrderByDescending(r => r.Item2).ThenBy(r => r.Item1).Take(MaxRanked)];
    }

    // NUL-preceded printable runs of MinString or more bytes ending in NUL, the targets string pointers name; their
    // other bytes are set in inside.
    private static int[] Strings(ReadOnlySpan<byte> data, System.Collections.BitArray inside, List<string> notes, CancellationToken ct)
    {
        var found = new List<int>();
        for (int i = 0; i < data.Length;)
        {
            if ((i & 0xFFFFF) == 0) ct.ThrowIfCancellationRequested();
            if (i > 0 && data[i - 1] != 0 || !Printable(data[i])) { i++; continue; }
            int j = i;
            while (j < data.Length && Printable(data[j])) j++;
            if (j - i >= MinString && j < data.Length && data[j] == 0)
            {
                found.Add(i);
                for (int k = i + 1; k < j; k++) inside[k] = true;
            }
            i = j + 1;
        }
        if (found.Count <= MaxTargets) return [.. found];
        notes.Add($"{found.Count:N0} strings; every {(found.Count + MaxTargets - 1) / MaxTargets}th is a target");
        int stride = (found.Count + MaxTargets - 1) / MaxTargets;
        return [.. found.Where((_, k) => k % stride == 0)];
    }

    private static bool Printable(byte b) => b is >= 0x20 and < 0x7F or (byte)'\t' or (byte)'\n' or (byte)'\r';

    private static HashSet<ulong> Pointers(ReadOnlySpan<byte> data, RawArch isa, List<string> notes, CancellationToken ct)
    {
        int width = isa.Bits == 64 ? 8 : 4;
        var values = new HashSet<ulong>();
        for (int i = 0; i + width <= data.Length; i += width)
        {
            if ((i & 0xFFFFF) == 0) ct.ThrowIfCancellationRequested();
            var w = data.Slice(i, width);
            ulong v = width == 8
                ? isa.BigEndian ? BinaryPrimitives.ReadUInt64BigEndian(w) : BinaryPrimitives.ReadUInt64LittleEndian(w)
                : isa.BigEndian ? BinaryPrimitives.ReadUInt32BigEndian(w) : BinaryPrimitives.ReadUInt32LittleEndian(w);
            if (v < BaseAlignment) continue;
            if (values.Count == MaxPointers)
            {
                notes.Add($"stopped at {MaxPointers:N0} distinct pointer values, at offset 0x{i:X}");
                break;
            }
            values.Add(v);
        }
        return values;
    }

    /// <summary>
    /// The base a Cortex-M vector table at the start of a Thumb image implies: an aligned initial stack pointer, an odd
    /// reset handler, and vectors 2 to 15 each zero or odd. The base is the handlers' lowest address rounded down to
    /// the image size's power of two, so every handler lands inside; null without such a table.
    /// </summary>
    public static ulong? VectorTableBase(ReadOnlySpan<byte> data, RawArch isa)
    {
        if (!isa.Thumb || isa.BigEndian || data.Length < 64) return null;
        uint sp = BinaryPrimitives.ReadUInt32LittleEndian(data);
        if (sp == 0 || (sp & 3) != 0) return null;
        var handlers = new List<uint>();
        for (int i = 1; i < 16; i++)
        {
            uint v = BinaryPrimitives.ReadUInt32LittleEndian(data[(i * 4)..]);
            if (v == 0) continue;
            if ((v & 1) == 0) return null;
            handlers.Add(v & ~1u);
        }
        if ((BinaryPrimitives.ReadUInt32LittleEndian(data[4..]) & 1) == 0) return null;
        ulong span = System.Numerics.BitOperations.RoundUpToPowerOf2((ulong)data.Length);
        ulong low = handlers.Min(), b = low & ~(span - 1), length = (ulong)data.Length;
        return handlers.All(h => h - b < length) && b % BaseAlignment == 0 ? b : null;
    }

    /// <summary>The load_assembly call for <paramref name="path"/> as <paramref name="arch"/> at <paramref name="base"/> (base omitted when null).</summary>
    public static string LoadCall(string path, string arch, ulong? @base) =>
        $"load_assembly path={path} format=raw arch={arch}" + (@base is { } b ? $" base=0x{b:X}" : "");
}
