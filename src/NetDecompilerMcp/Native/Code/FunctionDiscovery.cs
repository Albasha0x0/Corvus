namespace NetDecompilerMcp.Native.Code;

/// <summary>
/// Finds function starts: the roots the image declares (.pdata, exports, entry point, TLS callbacks), then everything
/// reachable from them by recursive descent (call targets, x64 jumps leaving a .pdata function), then weaker
/// candidates that must decode cleanly before they are accepted (relocated pointers in data, addresses taken by code,
/// x86 prologues in gaps between known code). Every byte is decoded at most once per offset (global bitmaps).
/// </summary>
internal sealed class FunctionDiscovery
{
    /// <summary>Instructions a weak candidate may decode during verification.</summary>
    private const int VerifyLimit = 20_000;

    private readonly CodeContext _ctx;
    private readonly X86Decoder _dec;
    private readonly X86Decoder _peek;
    private readonly CodeBitmap _starts;
    private readonly CodeBitmap _covered;
    private readonly Dictionary<uint, FunctionSource> _functions = [];
    private readonly Queue<uint> _roots = new();
    private readonly Stack<(uint Rva, IndexBound Bound)> _work = new();
    private readonly HashSet<uint> _addressCandidates = [];
    /// <summary>Addresses in executable sections that code reads or writes as memory: data, never a function.</summary>
    private readonly HashSet<uint> _dataInCode = [];
    private readonly byte[] _stringBuffer = new byte[160];
    /// <summary>Starts of tables in code read as [index*4 + table]: their entries are case labels, not functions.</summary>
    private readonly HashSet<uint> _codeTables = [];
    private readonly SortedSet<uint> _pendingSwitches = [];
    private readonly Dictionary<uint, uint?> _thunkCache = [];
    private readonly CancellationToken _ct;
    private readonly Action<long>? _progress;
    private long _decoded;

    public bool FunctionsTruncated { get; private set; }

    public FunctionDiscovery(CodeContext ctx, CancellationToken ct, Action<long>? progress)
    {
        _ctx = ctx;
        _ct = ct;
        _progress = progress;
        _dec = ctx.NewDecoder(computeAccess: false);
        _peek = ctx.NewDecoder(computeAccess: false);
        _starts = new CodeBitmap(ctx.Code.TotalBytes);
        _covered = new CodeBitmap(ctx.Code.TotalBytes);
    }

    /// <summary>Function starts and how each was found.</summary>
    public Dictionary<uint, FunctionSource> Run()
    {
        var image = _ctx.Image;
        foreach (var (primary, _) in _ctx.PdataRanges) Add(primary, FunctionSource.Pdata, strong: true);
        foreach (var e in image.Exports)
            if (e.ForwardedTo == null && _ctx.Code.IsCode(e.Rva)) Add(e.Rva, FunctionSource.Export, strong: true);
        if (image.EntryPointRva != 0 && _ctx.Code.IsCode(image.EntryPointRva)) Add(image.EntryPointRva, FunctionSource.EntryPoint, strong: true);
        foreach (var t in image.TlsCallbackRvas)
            if (_ctx.Code.IsCode(t)) Add(t, FunctionSource.TlsCallback, strong: true);
        Drain();

        for (int round = 0; round < 8; round++)
        {
            int before = _functions.Count;
            foreach (var t in DataPointerTargets(inCode: false)) TryCandidate(t, FunctionSource.DataPointer);
            Drain();
            foreach (var t in _addressCandidates.ToList()) TryCandidate(t, FunctionSource.CodeAddress);
            Drain();
            if (image.Arch == NativeArch.X86 && _ctx.Options.ScanPrologues) ScanGaps();
            if (_functions.Count != before) continue;
            // pointers stored inside code sections last: by now the functions owning switch tables there are
            // decoded, so case labels are covered
            foreach (var t in DataPointerTargets(inCode: true)) TryCandidate(t, FunctionSource.DataPointer);
            Drain();
            if (_functions.Count == before) break;
        }
        return _functions;
    }

    private void Add(uint rva, FunctionSource source, bool strong)
    {
        if (_functions.TryGetValue(rva, out var existing)) { _functions[rva] = existing | source; return; }
        if (_functions.Count >= _ctx.Options.MaxFunctions) { FunctionsTruncated = true; return; }
        _functions[rva] = source;
        _ctx.FunctionStarts.Add(rva);
        if (ThunkSlot(rva) is { } slot)
        {
            _ctx.Thunks[rva] = slot;
            if (_ctx.NoReturn.Contains(slot)) _ctx.NoReturn.Add(rva);
        }
        _roots.Enqueue(rva);
    }

    /// <summary>The import slot when the code at <paramref name="rva"/> is "jmp [slot]".</summary>
    private uint? ThunkSlot(uint rva)
    {
        if (_thunkCache.TryGetValue(rva, out var cached)) return cached;
        uint? slot = null;
        if (_peek.Decode(rva, out var insn) && insn.Flow == FlowKind.IndirectJump && insn.HasMem && _ctx.ImportSlots.ContainsKey(insn.MemTarget))
            slot = insn.MemTarget;
        _thunkCache[rva] = slot;
        return slot;
    }

    private bool IsNoReturnTarget(uint target) =>
        _ctx.NoReturn.Contains(target) || (ThunkSlot(target) is { } slot && _ctx.NoReturn.Contains(slot));

    private void Drain()
    {
        while (_roots.Count > 0)
        {
            _ct.ThrowIfCancellationRequested();
            Explore(_roots.Dequeue());
        }
    }

    private void Explore(uint root)
    {
        List<(uint Begin, uint End)>? own = _ctx.PdataRanges.TryGetValue(root, out var r) ? r : null;
        _work.Clear();
        _work.Push((root, IndexBound.None));
        while (_work.Count > 0)
        {
            var (a, bound) = _work.Pop();
            var region = _ctx.Code.RegionAt(a);
            if (region == null) continue;
            if (_starts[region.BitBase + (a - region.Rva)])
            {
                if (bound.IsKnown && _pendingSwitches.Count > 0) RetrySwitches(a, bound, own);
                continue;
            }
            _dec.BeginRun(bound);
            while (true)
            {
                if (a - region.Rva >= (uint)region.Bytes.Length)
                {
                    region = _ctx.Code.RegionAt(a);
                    if (region == null) break;
                }
                long bit = region.BitBase + (a - region.Rva);
                if (_starts[bit]) break;
                _dec.Decode(region, a, out var insn);
                if (insn.Flow == FlowKind.Invalid) break;
                _starts[bit] = true;
                int n = (int)Math.Min(insn.Length, region.End - a);
                _covered.SetRange(bit, n);
                if ((++_decoded & 0xFFFF) == 0)
                {
                    _ct.ThrowIfCancellationRequested();
                    _progress?.Invoke(_decoded);
                }
                if (insn.HasMem && _ctx.Code.IsCode(insn.MemTarget))
                {
                    if (insn.MemAccess == OperandAccess.Address) _addressCandidates.Add(insn.MemTarget);
                    else
                    {
                        _dataInCode.Add(insn.MemTarget);
                        // [index*4 + table] in code: an x86 switch table (or another pointer table), whatever the dispatch
                        if (_dec.Last.MemoryIndex != Iced.Intel.Register.None && _dec.Last.MemoryIndexScale == 4) _codeTables.Add(insn.MemTarget);
                    }
                }
                if (insn.HasImm && _ctx.Code.IsCode(insn.ImmTarget)) _addressCandidates.Add(insn.ImmTarget);
                if (!Follow(in insn, root, own)) break;
                a = insn.Next;
            }
        }
    }

    /// <summary>Queues the successors of one instruction; false when the linear run ends.</summary>
    private bool Follow(in Insn insn, uint root, List<(uint Begin, uint End)>? own)
    {
        switch (insn.Flow)
        {
            case FlowKind.Call:
                if (insn.HasTarget && insn.Target != insn.Next && _ctx.Code.IsCode(insn.Target))
                {
                    Add(insn.Target, FunctionSource.Call, strong: true);
                    if (IsNoReturnTarget(insn.Target)) return false;
                }
                return true;
            case FlowKind.IndirectCall:
                return !(insn.HasMem && _ctx.NoReturn.Contains(insn.MemTarget));
            case FlowKind.Jump:
                if (insn.HasTarget && _ctx.Code.IsCode(insn.Target)) Branch(insn.Target, root, own, IndexBound.None);
                return false;
            case FlowKind.ConditionalJump:
                if (insn.HasTarget && _ctx.Code.IsCode(insn.Target))
                {
                    _dec.ConditionalBounds(out var taken, out _);
                    Branch(insn.Target, root, own, taken);
                }
                return true;
            case FlowKind.IndirectJump:
                if (insn.HasMem && _ctx.ImportSlots.ContainsKey(insn.MemTarget)) return false;
                if (_dec.MatchSwitch(out _) is { } m && _ctx.ReadSwitch(insn.Rva, m, own, out _) is { } table)
                    foreach (var t in table.Targets) _work.Push((t, IndexBound.None));
                else _pendingSwitches.Add(insn.Rva);
                return false;
            case FlowKind.Next:
                return true;
            default:
                return false;
        }
    }

    /// <summary>A path with a known index bound reaches decoded code: retries the unresolved switches it leads to.</summary>
    private void RetrySwitches(uint a, IndexBound bound, List<(uint Begin, uint End)>? own)
    {
        foreach (uint jump in _pendingSwitches.GetViewBetween(a, a + 512).ToList())
        {
            if (SwitchDispatch.Redecode(_peek, _ctx, a, bound, jump, own) is not { } table) continue;
            _pendingSwitches.Remove(jump);
            foreach (var t in table.Targets) _work.Push((t, IndexBound.None));
        }
    }

    private void Branch(uint target, uint root, List<(uint Begin, uint End)>? own, IndexBound bound)
    {
        if (target != root && _functions.ContainsKey(target)) return;
        if (own != null && !InRanges(own, target) && _ctx.PdataOwner(target) == null)
        {
            // x64: a jump out of a .pdata function into code no .pdata entry covers is a tail call to a leaf function
            Add(target, FunctionSource.TailJump, strong: true);
            return;
        }
        _work.Push((target, bound));
    }

    private static bool InRanges(List<(uint Begin, uint End)> ranges, uint rva)
    {
        foreach (var (b, e) in ranges) if (rva >= b && rva < e) return true;
        return false;
    }

    /// <summary>
    /// Targets in code of relocated pointers stored in data: outside executable sections, or inside them but not
    /// part of a decoded instruction (data merged into the code section, x86 vtables and pointer tables).
    /// </summary>
    private List<uint> DataPointerTargets(bool inCode)
    {
        var result = new List<uint>();
        var tableEntries = inCode ? TableEntries() : null;
        int i = 0;
        foreach (var reloc in _ctx.Relocations)
        {
            if ((++i & 0xFFFF) == 0) _ct.ThrowIfCancellationRequested();
            long bit = _ctx.Code.BitIndex(reloc);
            if ((bit >= 0) != inCode) continue;
            if (bit >= 0 && (_covered[bit] || tableEntries!.Contains(reloc))) continue;
            if (_ctx.TryReadPointer(reloc, out uint target) && _ctx.Code.IsCode(target)) result.Add(target);
        }
        return result;
    }

    /// <summary>Locations of the relocated code pointers that make up the tables in <see cref="_codeTables"/>.</summary>
    private HashSet<uint> TableEntries()
    {
        var result = new HashSet<uint>();
        uint size = (uint)_ctx.PointerSize;
        foreach (var table in _codeTables)
            for (uint p = table, n = 0; n < _ctx.Options.MaxSwitchEntries; p += size, n++)
            {
                if (!_ctx.IsRelocated(p) || !_ctx.TryReadPointer(p, out uint t) || !_ctx.Code.IsCode(t)) break;
                result.Add(p);
            }
        return result;
    }

    /// <summary>
    /// Accepts a weak candidate when it is not inside known code, not data that code reads or a string, and decodes
    /// cleanly: no invalid or implausible instruction, no jump into the middle of known instructions, no branch out
    /// of executable code, every path ends.
    /// </summary>
    private bool TryCandidate(uint rva, FunctionSource source)
    {
        if (_functions.ContainsKey(rva)) { _functions[rva] |= source; return false; }
        long bit = _ctx.Code.BitIndex(rva);
        if (bit < 0 || _covered[bit]) return false;
        if (_dataInCode.Contains(rva)) return false;
        if (StringDetector.Detect(_ctx.Image, rva, 64, _stringBuffer) != null) return false;
        if (!Verify(rva)) return false;
        Add(rva, source, strong: false);
        return true;
    }

    private bool Verify(uint root)
    {
        var seen = new HashSet<uint>();
        var work = new Stack<uint>();
        work.Push(root);
        int count = 0;
        while (work.Count > 0)
        {
            uint a = work.Pop();
            _peek.BeginRun(IndexBound.None);
            while (true)
            {
                if (!seen.Add(a)) break;
                long bit = _ctx.Code.BitIndex(a);
                if (bit < 0) return false;
                // a function never flows into the middle of another one (case labels of an unresolved switch do)
                if (_starts[bit]) { if (!_functions.ContainsKey(a)) return false; break; }
                if (_covered[bit]) return false;
                if (++count > VerifyLimit) return false;
                if (!_peek.Decode(a, out var insn) || insn.Flow is FlowKind.Invalid || _peek.LastIsImplausible()) return false;
                if (insn.HasMem && _ctx.Code.IsCode(insn.MemTarget) && insn.MemAccess != OperandAccess.Address && _starts[_ctx.Code.BitIndex(insn.MemTarget)])
                    return false; // reads or writes known instructions as data
                for (int k = 1; k < insn.Length; k++)
                    if (_covered[_ctx.Code.BitIndex(a + (uint)k)]) return false;
                switch (insn.Flow)
                {
                    case FlowKind.Call:
                        if (!insn.HasTarget || !_ctx.Code.IsCode(insn.Target)) return false;
                        if (insn.Target != insn.Next && IsNoReturnTarget(insn.Target)) goto endRun;
                        break;
                    case FlowKind.Jump:
                        if (!insn.HasTarget || !_ctx.Code.IsCode(insn.Target)) return false;
                        if (!_functions.ContainsKey(insn.Target)) work.Push(insn.Target);
                        goto endRun;
                    case FlowKind.ConditionalJump:
                        if (!insn.HasTarget || !_ctx.Code.IsCode(insn.Target)) return false;
                        if (!_functions.ContainsKey(insn.Target)) work.Push(insn.Target);
                        break;
                    case FlowKind.IndirectCall:
                        if (insn.HasMem && _ctx.NoReturn.Contains(insn.MemTarget)) goto endRun;
                        break;
                    case FlowKind.IndirectJump:
                    case FlowKind.Return:
                    case FlowKind.Trap:
                        goto endRun;
                }
                a = insn.Next;
                if (_functions.ContainsKey(a)) break;
            }
            endRun:;
        }
        return true;
    }

    /// <summary>
    /// x86: in each gap between known code, skips alignment padding and accepts a function where a standard prologue
    /// starts and the code verifies.
    /// </summary>
    private void ScanGaps()
    {
        foreach (var region in _ctx.Code.Regions)
        {
            var bytes = region.Bytes;
            int p = 0;
            // candidates only right after known code or padding, or 16-byte aligned
            bool boundary = true;
            while (p < bytes.Length)
            {
                if ((p & 0xFFFF) == 0) _ct.ThrowIfCancellationRequested();
                if (_covered[region.BitBase + p]) { p++; boundary = true; continue; }
                int pad = PaddingLength(bytes, p, bytes.Length);
                if (pad > 0) { p += pad; boundary = true; continue; }
                if ((boundary || (p & 15) == 0) && IsPrologue(bytes, p, bytes.Length) && TryCandidate(region.Rva + (uint)p, FunctionSource.Prologue))
                {
                    Drain();
                    continue;
                }
                boundary = false;
                p++;
            }
        }
    }

    /// <summary>Length of alignment padding at <paramref name="p"/>: int3 / nop runs, zero bytes, MSVC multi-byte nops.</summary>
    private static int PaddingLength(byte[] b, int p, int end)
    {
        byte x = b[p];
        if (x is 0xCC or 0x90 or 0x00) return 1;
        ReadOnlySpan<byte> s = b.AsSpan(p, end - p);
        if (s.StartsWith((ReadOnlySpan<byte>)[0x8D, 0xA4, 0x24, 0x00, 0x00, 0x00, 0x00])) return 7; // lea esp, [esp+0]
        if (s.StartsWith((ReadOnlySpan<byte>)[0x8D, 0x9B, 0x00, 0x00, 0x00, 0x00])) return 6;       // lea ebx, [ebx+0]
        if (s.StartsWith((ReadOnlySpan<byte>)[0x8D, 0x64, 0x24, 0x00])) return 4;                   // lea esp, [esp+0]
        if (s.StartsWith((ReadOnlySpan<byte>)[0x8D, 0x49, 0x00])) return 3;                         // lea ecx, [ecx+0]
        if (s.StartsWith((ReadOnlySpan<byte>)[0x8D, 0x40, 0x00])) return 3;                         // lea eax, [eax+0]
        if (s.StartsWith((ReadOnlySpan<byte>)[0x0F, 0x1F])) return s.Length >= 3 ? NopLength(s) : 0; // nop r/m
        return 0;
    }

    private static int NopLength(ReadOnlySpan<byte> s)
    {
        // 0F 1F /0 with modrm: 00 -> 3, 40 xx -> 4, 44 xx xx -> 5, 80 xx xx xx xx -> 7, 84 xx xx xx xx xx -> 8
        return s[2] switch
        {
            0x00 => 3,
            0x40 => 4,
            0x44 => 5,
            0x80 => 7,
            0x84 => 8,
            _ => 0,
        };
    }

    /// <summary>push ebp; mov ebp, esp (either encoding), optionally after the hot-patch mov edi, edi.</summary>
    private static bool IsPrologue(byte[] b, int p, int end)
    {
        ReadOnlySpan<byte> s = b.AsSpan(p, end - p);
        if (s.StartsWith((ReadOnlySpan<byte>)[0x8B, 0xFF])) s = s[2..];
        return s.StartsWith((ReadOnlySpan<byte>)[0x55, 0x8B, 0xEC]) || s.StartsWith((ReadOnlySpan<byte>)[0x55, 0x89, 0xE5]);
    }
}
