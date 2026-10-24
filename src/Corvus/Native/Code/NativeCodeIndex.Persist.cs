using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Corvus.Native.Msvc;

namespace Corvus.Native.Code;

public sealed partial class NativeCodeIndex
{
    /// <summary>
    /// Version of the saved index (<see cref="CodeIndexCache"/>). Bump it whenever what the index holds changes shape
    /// (new fields, new cross-reference kinds such as virtual-call edges) or the analysis gives different results for the
    /// same bytes: saved indexes of another version are ignored and rebuilt.
    /// </summary>
    public const int PersistFormatVersion = 18;

    /// <summary>Read from the code index cache instead of built; <see cref="CacheLoadTime"/> says how long that took.</summary>
    public bool LoadedFromCache { get; private set; }

    public TimeSpan CacheLoadTime { get; private set; }

    /// <summary>
    /// Digest of every build input besides the image bytes: the limits and symbol starts of <paramref name="options"/>
    /// and whether the file name marks a kernel-mode image. Indexes are reused only for the same bytes and digest.
    /// </summary>
    public static string OptionsDigest(INativeImage image, CodeIndexOptions? options)
    {
        options ??= new CodeIndexOptions();
        using var h = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var b = new byte[8];
        void I64(long v) { BinaryPrimitives.WriteInt64LittleEndian(b, v); h.AppendData(b); }
        I64(PersistFormatVersion);
        I64(options.MaxFunctions);
        I64(options.MaxInstructionsPerFunction);
        I64(options.MaxXrefs);
        I64(options.MaxSwitchEntries);
        I64(options.MaxStringLength);
        I64(options.MaxNoReturnRounds);
        I64(options.ScanPrologues ? 1 : 0);
        I64(options.ResolveVirtualCalls ? 1 : 0);
        I64(options.MaxVirtualTargets);
        I64(CodeContext.KernelModeByName(image.Path) ? 1 : 0);
        var starts = (options.SymbolStarts ?? []).Distinct().ToArray();
        Array.Sort(starts);
        I64(starts.Length);
        h.AppendData(MemoryMarshal.AsBytes(starts.AsSpan()));
        return Convert.ToHexStringLower(h.GetHashAndReset());
    }

    /// <summary>Writes everything a loaded index needs (functions, ranges, cross-references, strings, exception metadata, analysis state).</summary>
    /// <param name="times">false writes zero elapsed times, so builds of the same bytes compare equal.</param>
    internal void WritePayload(PayloadWriter w, bool times = true)
    {
        if (_ctx == null || Support != CodeSupport.Full) throw new InvalidOperationException("Only a full code index is saved.");
        w.Strings(Truncations);
        w.Strings(Issues);
        var s = Stats;
        w.I32(s.Functions); w.I32(s.Thunks); w.I32(s.NoReturnFunctions); w.I64(s.Instructions); w.I64(s.Blocks); w.I64(s.Xrefs);
        w.I32(s.Strings); w.I32(s.ResolvedSwitches); w.I32(s.UnresolvedJumps); w.I32(s.FunctionsWithInvalidCode); w.I32(s.DiscoveryPasses);
        w.I32(s.NoReturnRounds); w.I64(times ? s.Elapsed.Ticks : 0);

        int n = _functions.Length;
        var u = new uint[n];
        var k = new int[n];
        void Column(Func<NativeFunction, uint> get) { for (int i = 0; i < n; i++) u[i] = get(_functions[i]); w.UInts(u); }
        void IntColumn(Func<NativeFunction, int> get) { for (int i = 0; i < n; i++) k[i] = get(_functions[i]); w.Ints(k); }
        w.I32(n);
        for (int i = 0; i < n; i++) u[i] = _functions[i].Start;
        w.DeltaUInts(u);
        Column(f => (uint)f.Sources);
        Column(f => (uint)f.Flags);
        Column(f => f.End);
        Column(f => f.Size);
        IntColumn(f => f.BlockCount);
        IntColumn(f => f.InstructionCount);
        IntColumn(f => f.FirstRange);
        IntColumn(f => f.RangeCount);
        IntColumn(f => f.Parent?.Index ?? -1);
        // names the analysis gave (exports, thunks), not names set later by users or symbol layers
        var names = new List<(int, string)>();
        lock (_builtinNames)
            foreach (var f in _functions)
                if ((_builtinNames.TryGetValue(f.Start, out var builtin) ? builtin : f.KnownName) is { } name) names.Add((f.Index, name));
        w.I32(names.Count);
        foreach (var (i, name) in names) { w.I32(i); w.String(name); }
        var withChunks = _functions.Where(f => f.Chunks.Count > 0).ToList();
        w.I32(withChunks.Count);
        foreach (var f in withChunks)
        {
            w.I32(f.Index);
            w.I32(f.Chunks.Count);
            foreach (var c in f.Chunks) { w.U32(c.Start); w.U8((byte)c.Kind); }
        }

        w.DeltaUInts(_rangeStarts);
        w.DeltaUInts(_rangeEnds);

        int x = _xrefs.Length;
        var from = new uint[x];
        var to = new uint[x];
        var kinds = new byte[x];
        for (int i = 0; i < x; i++) { from[i] = _xrefs[i].From; to[i] = _xrefs[i].To; kinds[i] = (byte)_xrefs[i].Kind; }
        w.DeltaUInts(from);
        w.UInts(to);
        w.Bytes(kinds);
        w.Ints(_byTo);

        int sn = _strings.Length;
        var rvas = new uint[sn];
        var lengths = new int[sn];
        var encodings = new byte[sn];
        for (int i = 0; i < sn; i++) { rvas[i] = _strings[i].Rva; lengths[i] = _strings[i].Length; encodings[i] = (byte)_strings[i].Encoding; }
        w.DeltaUInts(rvas);
        w.Ints(lengths);
        w.Bytes(encodings);
        w.Strings(_strings.Where(s => s.Encoding == StringEncoding.Inline).Select(s => InlineText[s.Rva]).ToList());

        // analysis state the walker consults when it decodes a function graph again
        w.DeltaUInts(Sorted(_ctx.FunctionStarts));
        w.DeltaUInts(Sorted(_ctx.NoReturn));
        w.DeltaUInts(Sorted(_ctx.LocalSubroutines));
        w.DeltaUInts(Sorted(_ctx.Funclets));
        var thunks = Sorted(_ctx.Thunks.Keys);
        w.DeltaUInts(thunks);
        w.UInts(thunks.Select(t => _ctx.Thunks[t]).ToArray());
        w.DeltaUInts(_ctx.ArmModes?.ArmStarts ?? []);

        WriteEh(w, ExceptionInfo, times);
        WriteVirtualCalls(w, times);
    }

    private static uint[] Sorted(IEnumerable<uint> values)
    {
        var a = values.ToArray();
        Array.Sort(a);
        return a;
    }

    private static void WriteEh(PayloadWriter w, MsvcEhResult eh, bool times)
    {
        w.I32(eh.Frames.Count);
        foreach (var f in eh.Frames)
        {
            w.U32(f.FunctionRva); w.U8((byte)f.Scheme); w.U32(f.HandlerRva); w.String(f.HandlerName); w.U32(f.DataRva);
            w.OptI32(f.GsCookieOffset); w.U8(f.IsCatchFunclet ? (byte)1 : (byte)0); w.I32(f.MaxState);
            w.I32(f.TryBlocks.Count);
            foreach (var t in f.TryBlocks)
            {
                w.I32(t.TryLow); w.I32(t.TryHigh); w.I32(t.CatchHigh);
                w.I32(t.Catches.Count);
                foreach (var c in t.Catches)
                {
                    w.U32(c.HandlerRva); w.U32(c.Adjectives); w.OptU32(c.TypeDescriptorRva); w.String(c.TypeName); w.String(c.DecoratedTypeName);
                    w.I32(c.CatchObjectOffset); w.UInts(c.Continuations.ToArray());
                }
            }
            w.I32(f.Unwind.Count);
            foreach (var x in f.Unwind) { w.I32(x.State); w.I32(x.ToState); w.U8((byte)x.Kind); w.OptU32(x.ActionRva); w.OptI32(x.ObjectOffset); }
            w.I32(f.IpToState.Count);
            foreach (var x in f.IpToState) { w.U32(x.Rva); w.I32(x.State); }
            w.I32(f.Scopes.Count);
            foreach (var x in f.Scopes)
            {
                w.I32(x.Index); w.OptU32(x.BeginRva); w.OptU32(x.EndRva); w.I32(x.EnclosingLevel); w.OptU32(x.FilterRva); w.OptI32(x.FilterConstant);
                w.U32(x.HandlerRva); w.U8(x.IsFinally ? (byte)1 : (byte)0);
            }
            w.I32(f.Children.Count);
            foreach (var x in f.Children) { w.U32(x.Rva); w.U8((byte)x.Kind); }
        }
        w.I32(eh.Parents.Count);
        foreach (var (child, owners) in eh.Parents)
        {
            w.U32(child);
            w.I32(owners.Count);
            foreach (var (p, kind) in owners) { w.U32(p); w.U8((byte)kind); }
        }
        w.I32(eh.Fragments.Count);
        foreach (var (begin, primary) in eh.Fragments) { w.U32(begin); w.U32(primary); }
        w.I32(eh.Rejects.Count);
        foreach (var r in eh.Rejects) { w.U32(r.Rva); w.String(r.Structure); w.String(r.Reason); }
        w.I32(eh.RejectCount);
        var s = eh.Stats;
        w.I32(s.Frames); w.I32(s.CSpecific); w.I32(s.Cxx3); w.I32(s.Cxx4); w.I32(s.GsOnly); w.I32(s.Seh3); w.I32(s.Seh4); w.I32(s.Unknown);
        w.I32(s.Children); w.I32(s.Fragments); w.I32(s.Rejected); w.I64(times ? s.Elapsed.Ticks : 0);
    }

    /// <summary>
    /// Rebuilds an index of <paramref name="image"/> from a payload <see cref="WritePayload"/> wrote for the same bytes and
    /// options. Throws <see cref="InvalidDataException"/> when the payload does not hold together.
    /// </summary>
    internal static NativeCodeIndex ReadPayload(ReadOnlySpan<byte> payload, INativeImage image, CodeIndexOptions? options, CancellationToken ct)
    {
        options ??= new CodeIndexOptions();
        var (support, _) = InstructionSets.For(image.Arch);
        if (support != CodeSupport.Full) throw new InvalidDataException("the image's instruction set has no saved index");
        var r = new PayloadReader(payload);
        var truncations = r.Strings();
        var issues = r.Strings();
        var stats = new CodeIndexStats(r.I32(), r.I32(), r.I32(), r.I64(), r.I64(), r.I64(), r.I32(), r.I32(), r.I32(), r.I32(), r.I32(), r.I32(),
            TimeSpan.FromTicks(r.Ticks()));

        int n = r.Count(1);
        var starts = r.DeltaUInts(n);
        var sources = r.UInts(n);
        var flags = r.UInts(n);
        var ends = r.UInts(n);
        var sizes = r.UInts(n);
        var blocks = r.Ints(n);
        var instructions = r.Ints(n);
        var firstRange = r.Ints(n);
        var rangeCount = r.Ints(n);
        var parents = r.Ints(n);
        ct.ThrowIfCancellationRequested();
        var functions = new NativeFunction[n];
        for (int i = 0; i < n; i++)
        {
            if (i > 0 && starts[i] <= starts[i - 1]) throw new InvalidDataException("function starts out of order");
            functions[i] = new NativeFunction
            {
                Start = starts[i], Index = i, Sources = (FunctionSource)sources[i], Flags = (FunctionFlags)flags[i], End = ends[i], Size = sizes[i],
                BlockCount = blocks[i], InstructionCount = instructions[i], FirstRange = firstRange[i], RangeCount = rangeCount[i],
            };
        }
        int named = r.Count(8);
        for (int i = 0; i < named; i++) functions[r.Index(n)].KnownName = r.String();
        var plan = new ChunkPlan();
        int withChunks = r.Count(8);
        for (int i = 0; i < withChunks; i++)
        {
            uint start = starts[r.Index(n)];
            int count = r.Count(5);
            var list = new List<FunctionChunk>(count);
            for (int c = 0; c < count; c++) list.Add(new FunctionChunk(r.U32(), r.Enum<MsvcEhChildKind>()));
            plan.ByParent[start] = list;
        }
        for (int i = 0; i < n; i++)
            if (parents[i] >= 0)
            {
                if (parents[i] >= n) throw new InvalidDataException("parent index out of range");
                plan.Funclets[starts[i]] = starts[parents[i]];
            }

        var rangeStarts = r.DeltaUInts();
        var rangeEnds = r.DeltaUInts(rangeStarts.Length);
        for (int i = 0; i < n; i++)
            if (firstRange[i] < 0 || rangeCount[i] < 0 || (long)firstRange[i] + rangeCount[i] > rangeStarts.Length)
                throw new InvalidDataException("function ranges out of bounds");

        var from = r.DeltaUInts();
        int x = from.Length;
        var to = r.UInts(x);
        var kinds = r.Bytes(x);
        var byTo = r.Ints(x);
        ct.ThrowIfCancellationRequested();
        var xrefs = new CodeXref[x];
        for (int i = 0; i < x; i++)
        {
            if (kinds[i] > (byte)XrefKind.Pointer) throw new InvalidDataException("unknown cross-reference kind");
            xrefs[i] = new CodeXref(from[i], to[i], (XrefKind)kinds[i]);
        }
        for (int i = 0; i < x; i++)
            if ((uint)byTo[i] >= (uint)x) throw new InvalidDataException("cross-reference order out of range");

        var rvas = r.DeltaUInts();
        int sn = rvas.Length;
        var lengths = r.Ints(sn);
        var encodings = r.Bytes(sn);
        var strings = new StringLiteral[sn];
        for (int i = 0; i < sn; i++)
        {
            if (encodings[i] > (byte)StringEncoding.Inline) throw new InvalidDataException("unknown string encoding");
            strings[i] = new StringLiteral(rvas[i], lengths[i], (StringEncoding)encodings[i]);
        }
        var texts = r.Strings();
        var inlineText = new Dictionary<uint, string>();
        foreach (var s in strings)
            if (s.Encoding == StringEncoding.Inline)
                inlineText[s.Rva] = inlineText.Count < texts.Count ? texts[inlineText.Count] : throw new InvalidDataException("inline string text missing");
        if (inlineText.Count != texts.Count) throw new InvalidDataException("inline string texts differ from their strings");

        var functionStarts = r.DeltaUInts();
        var noReturn = r.DeltaUInts();
        var localSubroutines = r.DeltaUInts();
        var funclets = r.DeltaUInts();
        var thunkStarts = r.DeltaUInts();
        int tn = thunkStarts.Length;
        var thunkSlots = r.UInts(tn);
        var armStarts = r.DeltaUInts();
        plan.Eh = ReadEh(ref r);
        var (virtualCalls, virtualEdges, metadataAdded) = ReadVirtualCalls(ref r);
        if (!r.AtEnd) throw new InvalidDataException("data after the end of the index");
        ct.ThrowIfCancellationRequested();

        var ctx = new CodeContext(image, new ImageCode(image), options)
        {
            FunctionStarts = [.. functionStarts],
            NoReturn = [.. noReturn],
        };
        ctx.ArmModes?.Load(functionStarts, armStarts);
        foreach (var s in localSubroutines) ctx.LocalSubroutines.Add(s);
        foreach (var s in funclets) ctx.Funclets.Add(s);
        for (int i = 0; i < tn; i++) ctx.Thunks[thunkStarts[i]] = thunkSlots[i];
        foreach (var f in functions)
            if ((f.Flags & FunctionFlags.Thunk) != 0 && ctx.Thunks.TryGetValue(f.Start, out var slot)) f.ThunkImport = ctx.ImportSlots.GetValueOrDefault(slot);

        var index = new NativeCodeIndex(image, CodeSupport.Full, null, ctx, functions, rangeStarts, rangeEnds, xrefs, strings, truncations, stats, byTo)
        {
            InlineText = inlineText,
        };
        index.Apply(plan);
        index.SetVirtualCalls(virtualCalls, virtualEdges);
        index.MetadataVirtualCallsAdded = metadataAdded;
        index.LoadedFromCache = true;
        index.Issues = issues;
        return index;
    }

    internal void MarkLoaded(TimeSpan elapsed) => CacheLoadTime = elapsed;

    private static MsvcEhResult ReadEh(ref PayloadReader r)
    {
        int fc = r.Count(16);
        var frames = new List<MsvcEhFrame>(fc);
        for (int i = 0; i < fc; i++)
        {
            uint function = r.U32();
            var scheme = r.Enum<MsvcEhScheme>();
            uint handler = r.U32();
            string? handlerName = r.String();
            uint data = r.U32();
            int? gs = r.OptI32();
            bool catchFunclet = r.U8() != 0;
            int maxState = r.I32();
            var tryBlocks = new MsvcEhTryBlock[r.Count(16)];
            for (int t = 0; t < tryBlocks.Length; t++)
            {
                int low = r.I32(), high = r.I32(), catchHigh = r.I32();
                var catches = new MsvcEhCatch[r.Count(16)];
                for (int c = 0; c < catches.Length; c++)
                    catches[c] = new MsvcEhCatch(r.U32(), r.U32(), r.OptU32(), r.String(), r.String(), r.I32(), r.UInts());
                tryBlocks[t] = new MsvcEhTryBlock(low, high, catchHigh, catches);
            }
            var unwind = new MsvcEhUnwind[r.Count(10)];
            for (int u = 0; u < unwind.Length; u++) unwind[u] = new MsvcEhUnwind(r.I32(), r.I32(), r.Enum<MsvcEhUnwindKind>(), r.OptU32(), r.OptI32());
            var ip = new MsvcEhIpState[r.Count(8)];
            for (int k = 0; k < ip.Length; k++) ip[k] = new MsvcEhIpState(r.U32(), r.I32());
            var scopes = new MsvcEhScope[r.Count(16)];
            for (int k = 0; k < scopes.Length; k++)
                scopes[k] = new MsvcEhScope(r.I32(), r.OptU32(), r.OptU32(), r.I32(), r.OptU32(), r.OptI32(), r.U32(), r.U8() != 0);
            var children = new MsvcEhChild[r.Count(5)];
            for (int k = 0; k < children.Length; k++) children[k] = new MsvcEhChild(r.U32(), r.Enum<MsvcEhChildKind>());
            frames.Add(new MsvcEhFrame(function, scheme, handler, handlerName, data, gs, catchFunclet, maxState, tryBlocks, unwind, ip, scopes, children));
        }
        int pc = r.Count(8);
        var parents = new Dictionary<uint, List<(uint Parent, MsvcEhChildKind Kind)>>(pc);
        for (int i = 0; i < pc; i++)
        {
            uint child = r.U32();
            int oc = r.Count(5);
            var owners = new List<(uint, MsvcEhChildKind)>(oc);
            for (int k = 0; k < oc; k++) owners.Add((r.U32(), r.Enum<MsvcEhChildKind>()));
            if (!parents.TryAdd(child, owners)) throw new InvalidDataException("duplicate exception child");
        }
        int gc = r.Count(8);
        var fragments = new Dictionary<uint, uint>(gc);
        for (int i = 0; i < gc; i++)
            if (!fragments.TryAdd(r.U32(), r.U32())) throw new InvalidDataException("duplicate exception fragment");
        int rc = r.Count(12);
        var rejects = new List<MsvcEhReject>(rc);
        for (int i = 0; i < rc; i++) rejects.Add(new MsvcEhReject(r.U32(), r.String() ?? "", r.String() ?? ""));
        int rejectCount = r.I32();
        var stats = new MsvcEhStats(r.I32(), r.I32(), r.I32(), r.I32(), r.I32(), r.I32(), r.I32(), r.I32(), r.I32(), r.I32(), r.I32(), TimeSpan.FromTicks(r.Ticks()));
        return new MsvcEhResult(frames, parents, fragments, rejects, rejectCount, stats, framesSorted: true);
    }
}

/// <summary>Little-endian payload writer: buffers, forwards full buffers to <paramref name="sink"/>.</summary>
internal sealed class PayloadWriter(Action<ReadOnlySpan<byte>> sink) : IDisposable
{
    public const int BufferSize = 1 << 20;

    private readonly byte[] _buffer = new byte[BufferSize];
    private int _used;

    public long Length { get; private set; }

    private Span<byte> Take(int size)
    {
        if (_used + size > _buffer.Length) Flush();
        var span = _buffer.AsSpan(_used, size);
        _used += size;
        Length += size;
        return span;
    }

    public void Flush()
    {
        if (_used == 0) return;
        sink(_buffer.AsSpan(0, _used));
        _used = 0;
    }

    public void U8(byte v) => Take(1)[0] = v;
    public void I32(int v) => BinaryPrimitives.WriteInt32LittleEndian(Take(4), v);
    public void U32(uint v) => BinaryPrimitives.WriteUInt32LittleEndian(Take(4), v);
    public void I64(long v) => BinaryPrimitives.WriteInt64LittleEndian(Take(8), v);
    public void OptI32(int? v) { U8(v.HasValue ? (byte)1 : (byte)0); if (v.HasValue) I32(v.Value); }
    public void OptU32(uint? v) { U8(v.HasValue ? (byte)1 : (byte)0); if (v.HasValue) U32(v.Value); }

    public void String(string? s)
    {
        if (s == null) { I32(-1); return; }
        int size = Encoding.UTF8.GetByteCount(s);
        I32(size);
        Raw(Encoding.UTF8.GetBytes(s));
    }

    public void Strings(IReadOnlyList<string> list)
    {
        I32(list.Count);
        foreach (var s in list) String(s);
    }

    public void UInts(uint[] a) { I32(a.Length); Raw(MemoryMarshal.AsBytes(a.AsSpan())); }
    public void Ints(int[] a) { I32(a.Length); Raw(MemoryMarshal.AsBytes(a.AsSpan())); }
    public void Bytes(byte[] a) { I32(a.Length); Raw(a); }

    /// <summary>Differences of consecutive values (wrapping): small for sorted columns, so the block compression shrinks them.</summary>
    public void DeltaUInts(uint[] a)
    {
        var d = new uint[a.Length];
        uint prev = 0;
        for (int i = 0; i < a.Length; i++) { d[i] = a[i] - prev; prev = a[i]; }
        UInts(d);
    }

    private void Raw(ReadOnlySpan<byte> bytes)
    {
        while (bytes.Length > 0)
        {
            if (_used == _buffer.Length) Flush();
            int n = Math.Min(bytes.Length, _buffer.Length - _used);
            bytes[..n].CopyTo(_buffer.AsSpan(_used));
            _used += n;
            Length += n;
            bytes = bytes[n..];
        }
    }

    public void Dispose() => Flush();
}

/// <summary>Bounds-checked little-endian payload reader; anything out of bounds is <see cref="InvalidDataException"/>.</summary>
internal ref struct PayloadReader(ReadOnlySpan<byte> data)
{
    private readonly ReadOnlySpan<byte> _data = data;
    private int _at;

    public readonly bool AtEnd => _at == _data.Length;

    private ReadOnlySpan<byte> Take(long size)
    {
        if (size < 0 || size > _data.Length - _at) throw new InvalidDataException("index data ends early");
        var span = _data.Slice(_at, (int)size);
        _at += (int)size;
        return span;
    }

    public byte U8() => Take(1)[0];
    public int I32() => BinaryPrimitives.ReadInt32LittleEndian(Take(4));
    public uint U32() => BinaryPrimitives.ReadUInt32LittleEndian(Take(4));
    public long I64() => BinaryPrimitives.ReadInt64LittleEndian(Take(8));
    public int? OptI32() => U8() != 0 ? I32() : null;
    public uint? OptU32() => U8() != 0 ? U32() : null;

    public long Ticks()
    {
        long t = I64();
        return t is >= 0 and <= TimeSpan.TicksPerDay * 365 ? t : throw new InvalidDataException("duration out of range");
    }

    /// <summary>A count whose elements take at least <paramref name="minSize"/> bytes each in what remains.</summary>
    public int Count(int minSize)
    {
        int n = I32();
        if (n < 0 || (long)n * minSize > _data.Length - _at) throw new InvalidDataException("count out of range");
        return n;
    }

    public int Index(int count)
    {
        int i = I32();
        return (uint)i < (uint)count ? i : throw new InvalidDataException("index out of range");
    }

    public T Enum<T>() where T : struct, System.Enum
    {
        byte v = U8();
        var e = (T)System.Enum.ToObject(typeof(T), v);
        return System.Enum.IsDefined(e) ? e : throw new InvalidDataException($"unknown {typeof(T).Name} {v}");
    }

    public string? String()
    {
        int size = I32();
        if (size == -1) return null;
        return Encoding.UTF8.GetString(Take(size));
    }

    public List<string> Strings()
    {
        int n = Count(4);
        var list = new List<string>(n);
        for (int i = 0; i < n; i++) list.Add(String() ?? throw new InvalidDataException("null string in a list"));
        return list;
    }

    public uint[] UInts() => MemoryMarshal.Cast<byte, uint>(Take((long)Count(4) * 4)).ToArray();

    public uint[] DeltaUInts() => PrefixSum(UInts());

    public uint[] DeltaUInts(int expected) => PrefixSum(UInts(expected));

    private static uint[] PrefixSum(uint[] a)
    {
        uint sum = 0;
        for (int i = 0; i < a.Length; i++) a[i] = sum += a[i];
        return a;
    }

    public uint[] UInts(int expected)
    {
        if (I32() != expected) throw new InvalidDataException("column length differs");
        return MemoryMarshal.Cast<byte, uint>(Take((long)expected * 4)).ToArray();
    }

    public int[] Ints(int expected)
    {
        if (I32() != expected) throw new InvalidDataException("column length differs");
        return MemoryMarshal.Cast<byte, int>(Take((long)expected * 4)).ToArray();
    }

    public byte[] Bytes(int expected)
    {
        if (I32() != expected) throw new InvalidDataException("column length differs");
        return Take(expected).ToArray();
    }
}
