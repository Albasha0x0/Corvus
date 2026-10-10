using System.Collections.Concurrent;
using System.Text;
using NetDecompilerMcp.Native.Code;

namespace NetDecompilerMcp.Native.ReadyToRun;

/// <summary>How a runtime function belongs to its method: the main body, an exception handler funclet, or split-off cold code.</summary>
public enum R2RRangeKind { Hot, Funclet, Cold }

public sealed record R2RRange(R2RRuntimeFunction Function, R2RRangeKind Kind);

/// <summary>A method entry point with the code ranges it owns; entries sharing one runtime function share its ranges.</summary>
public sealed record R2RBody(int Index, R2REntry Entry, IReadOnlyList<R2RRange> Ranges)
{
    public uint EntryRva => Ranges.Count > 0 ? Ranges[0].Function.Begin : 0;
    public int Size => Ranges.Sum(r => (int)(r.Function.End - r.Function.Begin));
}

/// <summary>
/// The method bodies of a ReadyToRun image: which runtime functions each entry point owns (its own, the funclets
/// that follow it up to the next entry point, and the cold parts the hot/cold map assigns to it), and the reverse
/// lookup from a code address to its body.
/// </summary>
public sealed class R2RCodeMap
{
    private readonly int[] _byBegin;     // runtime function indices sorted by begin address
    private readonly int[] _owner;       // runtime function index -> body index, -1 when no entry point owns it
    private readonly Dictionary<int, IReadOnlyList<R2RBody>> _sharing; // entry runtime function -> bodies starting there

    public R2RCodeMap(R2RImage image)
    {
        Image = image;
        var rfs = image.RuntimeFunctions;
        var first = new Dictionary<int, int>();
        for (int i = 0; i < image.Entries.Count; i++) first.TryAdd(image.Entries[i].RuntimeFunction, i);

        _owner = new int[rfs.Count];
        var kinds = new R2RRangeKind[rfs.Count];
        int current = -1;
        var kind = R2RRangeKind.Hot;
        for (int i = 0; i < rfs.Count; i++)
        {
            if (first.TryGetValue(i, out int entry)) { current = entry; kind = R2RRangeKind.Hot; }
            else if (image.ColdToHot.TryGetValue(i, out int hot)) { current = hot >= 0 && hot < i ? _owner[hot] : -1; kind = R2RRangeKind.Cold; }
            else if (kind == R2RRangeKind.Hot) kind = R2RRangeKind.Funclet;
            _owner[i] = current;
            kinds[i] = kind;
        }

        var ranges = new Dictionary<int, List<R2RRange>>();
        for (int i = 0; i < rfs.Count; i++)
            if (_owner[i] >= 0)
            {
                if (!ranges.TryGetValue(_owner[i], out var list)) ranges[_owner[i]] = list = [];
                list.Add(new R2RRange(rfs[i], kinds[i]));
            }
        var bodies = new R2RBody[image.Entries.Count];
        for (int i = 0; i < bodies.Length; i++)
        {
            int group = first[image.Entries[i].RuntimeFunction];
            bodies[i] = new R2RBody(i, image.Entries[i], ranges.TryGetValue(group, out var list) ? list : []);
        }
        Bodies = bodies;
        _sharing = bodies.GroupBy(b => b.Entry.RuntimeFunction).ToDictionary(g => g.Key, g => (IReadOnlyList<R2RBody>)g.ToList());
        _byBegin = Enumerable.Range(0, rfs.Count).OrderBy(i => rfs[i].Begin).ToArray();
    }

    public R2RImage Image { get; }
    /// <summary>One per entry point of <see cref="R2RImage.Entries"/>, same order.</summary>
    public IReadOnlyList<R2RBody> Bodies { get; }

    /// <summary>The runtime function containing <paramref name="rva"/>, or null.</summary>
    public R2RRuntimeFunction? FunctionAt(uint rva)
    {
        var rfs = Image.RuntimeFunctions;
        int lo = 0, hi = _byBegin.Length - 1, found = -1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >>> 1;
            if (rfs[_byBegin[mid]].Begin <= rva) { found = mid; lo = mid + 1; }
            else hi = mid - 1;
        }
        if (found < 0) return null;
        var rf = rfs[_byBegin[found]];
        return rva < rf.End ? rf : null;
    }

    /// <summary>The bodies whose code contains <paramref name="rva"/> (several when entry points share code), with the range.</summary>
    public (IReadOnlyList<R2RBody> Bodies, R2RRange? Range) BodiesAt(uint rva)
    {
        if (FunctionAt(rva) is not { } rf || _owner[rf.Index] < 0) return ([], null);
        var owner = Bodies[_owner[rf.Index]];
        var range = owner.Ranges.First(r => r.Function.Index == rf.Index);
        return (_sharing[owner.Entry.RuntimeFunction], range);
    }

    /// <summary>The body whose code starts at <paramref name="rva"/>, or null.</summary>
    public R2RBody? BodyStartingAt(uint rva) =>
        FunctionAt(rva) is { } rf && rf.Begin == rva && _owner[rf.Index] >= 0 && Bodies[_owner[rf.Index]].EntryRva == rva ? Bodies[_owner[rf.Index]] : null;
}

/// <summary>
/// Names for ReadyToRun disassembly: import cells by what their fixup resolves to (a called method, a type handle,
/// a helper, a string literal) and method entry points by their method. Thread-safe.
/// </summary>
public sealed class R2RSymbols(R2RCodeMap map, IR2RNames names, Func<R2RBody, string> label) : ICodeSymbols
{
    private readonly ConcurrentDictionary<uint, R2RFixup?> _cells = new();

    /// <summary>The fixup behind an import cell, or null when <paramref name="rva"/> is no cell or its signature is unreadable.</summary>
    public R2RFixup? CellAt(uint rva) => _cells.GetOrAdd(rva, at =>
    {
        if (map.Image.CellAt(at) is not { } found) return null;
        var (section, cell) = found;
        try
        {
            uint sig = map.Image.CellSignature(section, cell);
            return sig == 0 ? null : new R2RSignatures(map.Image.View, names).Fixup(sig);
        }
        catch (R2RFormatException) { return null; }
    });

    public string? NameAt(uint rva)
    {
        if (CellAt(rva) is { } fixup) return fixup.Describe();
        return map.BodyStartingAt(rva) is { } body ? label(body) : null;
    }

    public string? CommentFor(uint rva) => null;
}

/// <summary>Disassembly of a ReadyToRun method body (x86 / x64) with branch labels and named import cells.</summary>
public static class R2RDisassembly
{
    /// <summary>An image that reports <paramref name="arch"/> (ReadyToRun images for other OSes XOR the machine field).</summary>
    private sealed class ArchImage(INativeImage inner, NativeArch arch) : INativeImage
    {
        public string Path => inner.Path;
        public string Sha256 => inner.Sha256;
        public NativeArch Arch => arch;
        public bool Is64Bit => arch is NativeArch.X64 or NativeArch.Arm64;
        public bool IsDll => inner.IsDll;
        public ulong ImageBase => inner.ImageBase;
        public uint EntryPointRva => inner.EntryPointRva;
        public uint SizeOfImage => inner.SizeOfImage;
        public IReadOnlyList<NativeSection> Sections => inner.Sections;
        public IReadOnlyList<NativeImport> Imports => inner.Imports;
        public IReadOnlyList<NativeExport> Exports => inner.Exports;
        public IReadOnlyList<RuntimeFunction> RuntimeFunctions => inner.RuntimeFunctions;
        public IReadOnlyList<uint> RelocationRvas => inner.RelocationRvas;
        public IReadOnlyList<uint> TlsCallbackRvas => inner.TlsCallbackRvas;
        public IReadOnlyList<ParseIssue> Issues => inner.Issues;
        public ImageFormat Format => inner.Format;
        public int Read(uint rva, Span<byte> destination) => inner.Read(rva, destination);
        public bool TryRvaToFileOffset(uint rva, out long fileOffset) => inner.TryRvaToFileOffset(rva, out fileOffset);
        public bool TryFileOffsetToRva(long fileOffset, out uint rva) => inner.TryFileOffsetToRva(fileOffset, out rva);
        public NativeSection? SectionAt(uint rva) => inner.SectionAt(rva);
    }

    public static bool CanDecode(NativeArch arch) => arch is NativeArch.X86 or NativeArch.X64;

    public static NativeDisassembler Disassembler(R2RImage image, ICodeSymbols symbols) =>
        new(image.Image.Arch == image.Arch ? image.Image : new ArchImage(image.Image, image.Arch), symbols);

    /// <summary>
    /// The instructions of every range of <paramref name="body"/>, a label line before each branch target, at most
    /// <paramref name="maxInstructions"/> in all. <paramref name="truncated"/> tells whether the limit cut it short.
    /// </summary>
    public static List<(string? Label, R2RRange? Range, DisasmLine? Line)> Lines(NativeDisassembler disassembler, R2RBody body, int maxInstructions, out bool truncated)
    {
        var decoded = new List<(R2RRange Range, List<DisasmLine> Lines)>();
        int budget = maxInstructions;
        truncated = false;
        foreach (var range in body.Ranges)
        {
            var lines = disassembler.Disassemble(range.Function.Begin, budget, range.Function.End);
            budget -= lines.Count;
            decoded.Add((range, lines));
            if (budget <= 0) { truncated = true; break; }
        }
        var targets = new SortedSet<uint>();
        foreach (var (_, lines) in decoded)
            foreach (var l in lines)
                if (l.Facts.Flow is FlowKind.Jump or FlowKind.ConditionalJump && l.Facts.BranchTarget is uint t
                    && body.Ranges.Any(r => t >= r.Function.Begin && t < r.Function.End))
                    targets.Add(t);
        var labels = targets.ToDictionary(t => t, t => $"loc_{t:X}");
        var result = new List<(string?, R2RRange?, DisasmLine?)>();
        foreach (var (range, lines) in decoded)
        {
            result.Add((null, range, null));
            foreach (var l in lines)
            {
                if (labels.TryGetValue(l.Rva, out var label)) result.Add((label, null, null));
                // Re-decode so branch operands show the labels.
                result.Add((null, null, labels.Count > 0 && l.Facts.BranchTarget is uint bt && labels.ContainsKey(bt) ? disassembler.DecodeOne(l.Rva, labels) ?? l : l));
            }
        }
        return result;
    }

    public static string Line(DisasmLine l) => $"  {l.Address:X}  {l.Bytes,-24} {l.Text}{(l.Comment != null ? "  ; " + l.Comment : "")}";

    public static string RangeLine(INativeImage image, R2RRange r) =>
        $"; {r.Kind.ToString().ToLowerInvariant()} code {NativeAddress.Va(image, r.Function.Begin)}-{NativeAddress.Va(image, r.Function.End)} ({r.Function.End - r.Function.Begin} bytes)";

    /// <summary>Text of a body's disassembly, ranges as comment lines.</summary>
    public static string Text(NativeDisassembler disassembler, INativeImage image, R2RBody body, int maxInstructions)
    {
        var sb = new StringBuilder();
        var lines = Lines(disassembler, body, maxInstructions, out bool truncated);
        foreach (var (label, range, line) in lines)
        {
            if (range != null) sb.AppendLine(RangeLine(image, range));
            if (label != null) sb.AppendLine(label + ":");
            if (line != null) sb.AppendLine(Line(line));
        }
        if (truncated) sb.AppendLine($"; (stopped after {maxInstructions} instructions)");
        return sb.ToString();
    }
}
