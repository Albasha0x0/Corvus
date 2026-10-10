using System.Buffers.Binary;

namespace NetDecompilerMcp.Native.Msvc;

public static partial class MsvcEh
{
    /// <summary>Decoded handler data of one x64 frame, before it becomes a <see cref="MsvcEhFrame"/>.</summary>
    private sealed class Decoded
    {
        public MsvcEhScheme Scheme;
        public uint DataRva;
        public int MaxState;
        public bool IsCatch;
        public List<MsvcEhTryBlock> TryBlocks = [];
        public List<MsvcEhUnwind> Unwind = [];
        public List<MsvcEhIpState> IpToState = [];
        public List<MsvcEhScope> Scopes = [];
        public List<MsvcEhChild> Children = [];
        /// <summary>Bytes of handler data before the GS data of the __GSHandlerCheck variants.</summary>
        public uint GsDataOffset;
    }

    private sealed partial class Run
    {
        private const uint UnwFlagEHandler = 1, UnwFlagUHandler = 2, UnwFlagChainInfo = 4;

        /// <summary>A .pdata function with a language-specific handler.</summary>
        private readonly record struct HandlerUse(RuntimeFunction Function, uint Handler, uint Data);

        private readonly Dictionary<uint, List<(uint Begin, uint End)>> _ranges = [];
        private readonly Dictionary<uint, Decoded?> _fh3 = [];

        public void X64()
        {
            var functions = image.RuntimeFunctions;
            var byBegin = new Dictionary<uint, RuntimeFunction>();
            foreach (var rf in functions) byBegin.TryAdd(rf.BeginRva, rf);
            var uses = new List<HandlerUse>();
            Span<byte> header = stackalloc byte[4];
            int i = 0;
            foreach (var rf in functions)
            {
                if ((++i & 0xFFF) == 0) ct.ThrowIfCancellationRequested();
                uint primary = PrimaryOf(rf, byBegin, out bool chained);
                if (!_ranges.TryGetValue(primary, out var list)) _ranges[primary] = list = [];
                list.Add((rf.BeginRva, rf.EndRva));
                if (chained)
                {
                    if (primary != rf.BeginRva) _fragments.TryAdd(rf.BeginRva, primary);
                    continue;
                }
                if ((rf.UnwindInfoRva & 1) != 0 || !_r.Bytes(rf.UnwindInfoRva, header)) continue;
                uint flags = (uint)header[0] >> 3;
                if ((flags & (UnwFlagEHandler | UnwFlagUHandler)) == 0) continue;
                uint at = rf.UnwindInfoRva + 4 + (uint)(((header[2] + 1) & ~1) * 2);
                if (!_r.U32(at, out uint handler)) { Reject(rf.BeginRva, "unwind info", "handler field outside the image"); continue; }
                if (!_r.IsCode(handler)) { Reject(rf.BeginRva, "unwind info", $"language-specific handler {handler:X} is not in executable code"); continue; }
                uses.Add(new HandlerUse(rf, handler, at + 4));
            }

            foreach (var group in uses.GroupBy(u => u.Handler))
            {
                ct.ThrowIfCancellationRequested();
                var name = HandlerName(group.Key);
                var (scheme, gs) = name != null ? SchemeOf(name) : (null, false);
                scheme ??= Classify(group.ToList());
                foreach (var use in group)
                {
                    var d = Decode(use, scheme.Value, out string? reason);
                    if (d == null)
                    {
                        Reject(use.Function.BeginRva, $"{scheme} handler data at {use.Data:X}", reason ?? "does not decode");
                        continue;
                    }
                    int? cookie = null;
                    if (gs || d.Scheme == MsvcEhScheme.GsOnly) cookie = GsCookie(use.Data + d.GsDataOffset);
                    AddFrame(new MsvcEhFrame(use.Function.BeginRva, d.Scheme, use.Handler, name, d.DataRva, cookie, d.IsCatch, d.MaxState,
                        d.TryBlocks, d.Unwind, d.IpToState, d.Scopes, d.Children));
                }
            }
            MarkCatchFunclets();
        }

        /// <summary>FH3 frames that share their FuncInfo with the function they are a catch funclet of.</summary>
        private void MarkCatchFunclets()
        {
            var catches = new HashSet<uint>();
            foreach (var f in _frames)
                foreach (var c in f.Children)
                    if (c.Kind == MsvcEhChildKind.Catch && c.Rva != f.FunctionRva) catches.Add(c.Rva);
            for (int k = 0; k < _frames.Count; k++)
                if (!_frames[k].IsCatchFunclet && catches.Contains(_frames[k].FunctionRva)) _frames[k] = _frames[k] with { IsCatchFunclet = true };
        }

        /// <summary>Follows UNW_FLAG_CHAININFO links to the function an entry is a fragment of (at most 32 links).</summary>
        private uint PrimaryOf(RuntimeFunction rf, Dictionary<uint, RuntimeFunction> byBegin, out bool chained)
        {
            chained = false;
            Span<byte> header = stackalloc byte[4];
            Span<byte> link = stackalloc byte[12];
            var current = rf;
            for (int depth = 0; depth < 32; depth++)
            {
                uint unwind = current.UnwindInfoRva;
                uint parent;
                if ((unwind & 1) != 0)
                {
                    // the unwind data field points at the RUNTIME_FUNCTION of the parent
                    if (!_r.Bytes(unwind & ~1u, link)) return current.BeginRva;
                    parent = BinaryPrimitives.ReadUInt32LittleEndian(link);
                }
                else
                {
                    if (!_r.Bytes(unwind, header) || ((header[0] >> 3) & UnwFlagChainInfo) == 0) return current.BeginRva;
                    uint at = unwind + 4 + (uint)(((header[2] + 1) & ~1) * 2);
                    if (!_r.Bytes(at, link)) return current.BeginRva;
                    parent = BinaryPrimitives.ReadUInt32LittleEndian(link);
                }
                if (parent == current.BeginRva) return current.BeginRva;
                chained = true;
                current = byBegin.TryGetValue(parent, out var p) ? p
                    : new RuntimeFunction(parent, BinaryPrimitives.ReadUInt32LittleEndian(link[4..]), BinaryPrimitives.ReadUInt32LittleEndian(link[8..]));
            }
            return current.BeginRva;
        }

        /// <summary>Import or export name of a handler: a jmp [import slot] thunk, or an exported function.</summary>
        private string? HandlerName(uint handler)
        {
            Span<byte> b = stackalloc byte[7];
            if (_r.Bytes(handler, b))
            {
                int at = b[0] == 0x48 ? 1 : 0;
                if (b[at] == 0xFF && b[at + 1] == 0x25)
                {
                    uint slot = (uint)(handler + at + 6 + BinaryPrimitives.ReadInt32LittleEndian(b[(at + 2)..]));
                    foreach (var imp in image.Imports)
                        if (imp.SlotRva == slot) return imp.Name;
                }
            }
            foreach (var e in image.Exports)
                if (e.Rva == handler && e.ForwardedTo == null && e.Name != null) return e.Name;
            return null;
        }

        /// <summary>The data format a named handler reads, and whether GS data follows it.</summary>
        private static (MsvcEhScheme?, bool Gs) SchemeOf(string name) => name switch
        {
            "__C_specific_handler" or "_C_specific_handler" or "__C_specific_handler_noexcept" or "_C_specific_handler_noexcept" => (MsvcEhScheme.CSpecific, false),
            "__GSHandlerCheck_SEH" or "__GSHandlerCheck_SEH_noexcept" => (MsvcEhScheme.CSpecific, true),
            "__CxxFrameHandler3" or "__CxxFrameHandler2" or "__CxxFrameHandler" => (MsvcEhScheme.Cxx3, false),
            "__GSHandlerCheck_EH" => (MsvcEhScheme.Cxx3, true),
            "__CxxFrameHandler4" => (MsvcEhScheme.Cxx4, false),
            "__GSHandlerCheck_EH4" => (MsvcEhScheme.Cxx4, true),
            "__GSHandlerCheck" => (MsvcEhScheme.GsOnly, true),
            _ => (MsvcEhScheme.Unknown, false),
        };

        /// <summary>
        /// A handler with no name (linked statically): the format that decodes for most of the functions that use it
        /// (at most 64 tried), GS data alone when none does but the data looks like a cookie offset.
        /// </summary>
        private MsvcEhScheme Classify(List<HandlerUse> uses)
        {
            var sample = uses.Count <= 64 ? uses : uses.Where((_, k) => k % (uses.Count / 64 + 1) == 0).Take(64).ToList();
            MsvcEhScheme best = MsvcEhScheme.Unknown;
            int bestCount = 0;
            foreach (var scheme in (ReadOnlySpan<MsvcEhScheme>)[MsvcEhScheme.CSpecific, MsvcEhScheme.Cxx3, MsvcEhScheme.Cxx4])
            {
                int ok = sample.Count(u => Decode(u, scheme, out _, probe: true) != null);
                if (ok > bestCount) { best = scheme; bestCount = ok; }
            }
            if (bestCount * 2 >= sample.Count && bestCount > 0) return best;
            int gs = sample.Count(u => GsCookie(u.Data) is not null);
            return gs * 2 >= sample.Count && gs > 0 ? MsvcEhScheme.GsOnly : MsvcEhScheme.Unknown;
        }

        /// <summary>GS_HANDLER_DATA: the cookie offset (low 3 bits are flags); null when implausible.</summary>
        private int? GsCookie(uint at)
        {
            if (!_r.I32(at, out int raw)) return null;
            int offset = raw & ~7;
            if (offset == 0 || offset < -0x1000000 || offset > 0x1000000) return null;
            if ((raw & 4) != 0 && !(_r.I32(at + 8, out int alignment) && alignment > 0 && alignment <= 0x10000 && (alignment & (alignment - 1)) == 0)) return null;
            return offset;
        }

        private Decoded? Decode(HandlerUse use, MsvcEhScheme scheme, out string? reason, bool probe = false)
        {
            reason = null;
            uint begin = use.Function.BeginRva;
            var ranges = _ranges.GetValueOrDefault(begin) ?? [(begin, use.Function.EndRva)];
            switch (scheme)
            {
                case MsvcEhScheme.CSpecific:
                    return ScopeTable(use.Data, ranges, out reason);
                case MsvcEhScheme.Cxx3:
                    if (!_r.U32(use.Data, out uint info)) { reason = "FuncInfo RVA outside the image"; return null; }
                    return FuncInfo3(info, out reason);
                case MsvcEhScheme.Cxx4:
                    if (!_r.U32(use.Data, out uint info4)) { reason = "FuncInfo4 RVA outside the image"; return null; }
                    var d4 = FuncInfo4(info4, begin, ranges, probe, out reason);
                    if (d4 != null) d4.GsDataOffset = 4;
                    return d4;
                case MsvcEhScheme.GsOnly:
                    if (GsCookie(use.Data) == null) { reason = "GS data has an implausible cookie offset"; return null; }
                    return new Decoded { Scheme = MsvcEhScheme.GsOnly, DataRva = use.Data };
                default:
                    return new Decoded { Scheme = MsvcEhScheme.Unknown, DataRva = use.Data };
            }
        }

        private static bool InRanges(List<(uint Begin, uint End)> ranges, uint rva)
        {
            foreach (var (b, e) in ranges) if (rva >= b && rva < e) return true;
            return false;
        }

        private static bool RangeInside(List<(uint Begin, uint End)> ranges, uint begin, uint end)
        {
            foreach (var (b, e) in ranges) if (begin >= b && end <= e) return true;
            return false;
        }

        /// <summary>
        /// SCOPE_TABLE: count, then (begin, end, handler, jump target) records. A record with a jump target is an
        /// __except (handler = filter funclet or constant); without, a __finally (handler = termination funclet).
        /// </summary>
        private Decoded? ScopeTable(uint at, List<(uint Begin, uint End)> ranges, out string? reason)
        {
            reason = null;
            if (!_r.U32(at, out uint count)) { reason = "scope count outside the image"; return null; }
            if (count > options.MaxScopes) { reason = $"{count} scopes (limit {options.MaxScopes})"; return null; }
            var raw = new byte[count * 16];
            if (!_r.Bytes(at + 4, raw)) { reason = "scope records run out of the image"; return null; }
            var d = new Decoded { Scheme = MsvcEhScheme.CSpecific, DataRva = at, GsDataOffset = 4 + count * 16 };
            for (int i = 0; i < count; i++)
            {
                var e = raw.AsSpan(i * 16);
                uint begin = BinaryPrimitives.ReadUInt32LittleEndian(e), end = BinaryPrimitives.ReadUInt32LittleEndian(e[4..]);
                uint handler = BinaryPrimitives.ReadUInt32LittleEndian(e[8..]), jump = BinaryPrimitives.ReadUInt32LittleEndian(e[12..]);
                if (end <= begin || !RangeInside(ranges, begin, end)) { reason = $"scope {i} range {begin:X}-{end:X} is not inside the function"; return null; }
                if (jump != 0)
                {
                    if (!InRanges(ranges, jump)) { reason = $"scope {i} __except block {jump:X} is not inside the function"; return null; }
                    bool constant = handler <= 0xFF || handler == 0xFFFFFFFF;
                    if (!constant && !_r.IsCode(handler)) { reason = $"scope {i} filter {handler:X} is not in executable code"; return null; }
                    d.Scopes.Add(new MsvcEhScope(i, begin, end, -1, constant ? null : handler, constant ? (int)handler : null, jump, false));
                    if (!constant) d.Children.Add(new MsvcEhChild(handler, MsvcEhChildKind.Filter));
                    d.Children.Add(new MsvcEhChild(jump, MsvcEhChildKind.ExceptBlock));
                }
                else
                {
                    if (!_r.IsCode(handler)) { reason = $"scope {i} __finally handler {handler:X} is not in executable code"; return null; }
                    d.Scopes.Add(new MsvcEhScope(i, begin, end, -1, null, null, handler, true));
                    d.Children.Add(new MsvcEhChild(handler, MsvcEhChildKind.Finally));
                }
            }
            return d;
        }

        /// <summary>x64 FuncInfo (magic 0x19930520-22), all pointers image-relative; cached per FuncInfo.</summary>
        private Decoded? FuncInfo3(uint info, out string? reason)
        {
            reason = null;
            if (_fh3.TryGetValue(info, out var cached))
            {
                if (cached == null) reason = "FuncInfo failed its checks (see the first function that uses it)";
                return cached;
            }
            var d = FuncInfo3Uncached(info, is64: true, out reason);
            _fh3[info] = d;
            return d;
        }

        /// <summary>
        /// FuncInfo of __CxxFrameHandler3: magic, max state, unwind map, try blocks with their handler arrays, and
        /// (x64) the IP-to-state map. x86 holds virtual addresses (relocated), x64 image-relative offsets.
        /// </summary>
        private Decoded? FuncInfo3Uncached(uint info, bool is64, out string? reason)
        {
            reason = null;
            var h = new byte[40];
            if (!_r.Bytes(info, h.AsSpan(0, 28))) { reason = "FuncInfo outside the image"; return null; }
            uint magic = BinaryPrimitives.ReadUInt32LittleEndian(h);
            if ((magic & ~0xFu) != 0x19930520 || (magic & 0xF) > 2) { reason = $"magic {magic:X8} is not a FuncInfo"; return null; }
            int maxState = BinaryPrimitives.ReadInt32LittleEndian(h.AsSpan(4));
            uint nTry = BinaryPrimitives.ReadUInt32LittleEndian(h.AsSpan(12));
            uint nIp = BinaryPrimitives.ReadUInt32LittleEndian(h.AsSpan(20));
            if (maxState < 0 || maxState > options.MaxStates) { reason = $"max state {maxState}"; return null; }
            if (nTry > options.MaxTryBlocks) { reason = $"{nTry} try blocks (limit {options.MaxTryBlocks})"; return null; }
            if (nIp > options.MaxIpStates) { reason = $"{nIp} IP-to-state entries (limit {options.MaxIpStates})"; return null; }
            bool Ptr(int field, out uint rva)
            {
                uint at = info + (uint)field;
                if (is64) { rva = BinaryPrimitives.ReadUInt32LittleEndian(h.AsSpan(field)); return true; }
                return _r.Pointer32(at, out rva);
            }
            if (!Ptr(8, out uint unwindMap) || !Ptr(16, out uint tryMap) || !Ptr(24, out uint ipMap)) { reason = "FuncInfo pointer outside the image or not relocated"; return null; }
            var d = new Decoded { Scheme = MsvcEhScheme.Cxx3, DataRva = info, MaxState = maxState, GsDataOffset = 4 };

            // unwind map: (to state, action)
            if (maxState > 0)
            {
                if (!_r.IsMapped(unwindMap)) { reason = $"unwind map {unwindMap:X} is not mapped"; return null; }
                var raw = new byte[maxState * 8];
                if (!_r.Bytes(unwindMap, raw)) { reason = "unwind map runs out of the image"; return null; }
                for (int s = 0; s < maxState; s++)
                {
                    int to = BinaryPrimitives.ReadInt32LittleEndian(raw.AsSpan(s * 8));
                    uint action;
                    if (is64) action = BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(s * 8 + 4));
                    else if (!_r.Pointer32(unwindMap + (uint)s * 8 + 4, out action)) { reason = $"unwind action of state {s} is outside the image or not relocated"; return null; }
                    if (to < -1 || to >= maxState) { reason = $"state {s} unwinds to state {to}"; return null; }
                    if (action != 0 && !_r.IsCode(action)) { reason = $"unwind action of state {s} ({action:X}) is not in executable code"; return null; }
                    d.Unwind.Add(new MsvcEhUnwind(s, to, action != 0 ? MsvcEhUnwindKind.Funclet : MsvcEhUnwindKind.None, action != 0 ? action : null, null));
                    if (action != 0) d.Children.Add(new MsvcEhChild(action, MsvcEhChildKind.Unwind));
                }
            }

            // try blocks: (try low, try high, catch high, catch count, handler array)
            if (nTry > 0)
            {
                var raw = new byte[nTry * 20];
                if (!_r.IsMapped(tryMap) || !_r.Bytes(tryMap, raw)) { reason = $"try block map {tryMap:X} is not mapped"; return null; }
                int handlerSize = is64 ? 20 : 16;
                for (int t = 0; t < nTry; t++)
                {
                    var e = raw.AsSpan(t * 20);
                    int low = BinaryPrimitives.ReadInt32LittleEndian(e), high = BinaryPrimitives.ReadInt32LittleEndian(e[4..]);
                    int catchHigh = BinaryPrimitives.ReadInt32LittleEndian(e[8..]);
                    uint nCatch = BinaryPrimitives.ReadUInt32LittleEndian(e[12..]);
                    uint array;
                    if (is64) array = BinaryPrimitives.ReadUInt32LittleEndian(e[16..]);
                    else if (!_r.Pointer32(tryMap + (uint)t * 20 + 16, out array)) { reason = $"handler array of try block {t} is outside the image or not relocated"; return null; }
                    if (low < 0 || high < low || catchHigh < high || catchHigh > maxState) { reason = $"try block {t} states {low}..{high}, catch high {catchHigh} (max {maxState})"; return null; }
                    if (nCatch == 0 || nCatch > options.MaxCatches) { reason = $"try block {t} has {nCatch} catch clauses"; return null; }
                    var handlers = new byte[nCatch * handlerSize];
                    if (!_r.IsMapped(array) || !_r.Bytes(array, handlers)) { reason = $"handler array of try block {t} is not mapped"; return null; }
                    var catches = new List<MsvcEhCatch>((int)nCatch);
                    for (int c = 0; c < nCatch; c++)
                    {
                        var x = handlers.AsSpan(c * handlerSize);
                        uint adjectives = BinaryPrimitives.ReadUInt32LittleEndian(x);
                        int catchObject = BinaryPrimitives.ReadInt32LittleEndian(x[8..]);
                        uint type, handler;
                        if (is64)
                        {
                            type = BinaryPrimitives.ReadUInt32LittleEndian(x[4..]);
                            handler = BinaryPrimitives.ReadUInt32LittleEndian(x[12..]);
                        }
                        else if (!_r.Pointer32(array + (uint)(c * handlerSize) + 4, out type) || !_r.Pointer32(array + (uint)(c * handlerSize) + 12, out handler))
                        {
                            reason = $"catch {c} of try block {t} points outside the image or is not relocated";
                            return null;
                        }
                        if (!_r.IsCode(handler)) { reason = $"catch {c} of try block {t}: handler {handler:X} is not in executable code"; return null; }
                        if (type != 0 && !_r.IsData(type)) { reason = $"catch {c} of try block {t}: type descriptor {type:X} is not in data"; return null; }
                        catches.Add(Catch(info, handler, adjectives, type, catchObject, []));
                        d.Children.Add(new MsvcEhChild(handler, MsvcEhChildKind.Catch));
                    }
                    d.TryBlocks.Add(new MsvcEhTryBlock(low, high, catchHigh, catches));
                }
            }

            // IP-to-state map (x64; x86 keeps the state in the frame)
            if (is64 && nIp > 0)
            {
                var raw = new byte[nIp * 8];
                if (!_r.IsMapped(ipMap) || !_r.Bytes(ipMap, raw)) { reason = $"IP-to-state map {ipMap:X} is not mapped"; return null; }
                for (int k = 0; k < nIp; k++)
                {
                    uint ip = BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(k * 8));
                    int state = BinaryPrimitives.ReadInt32LittleEndian(raw.AsSpan(k * 8 + 4));
                    if (!_r.IsCode(ip)) { reason = $"IP-to-state entry {k} ({ip:X}) is not in executable code"; return null; }
                    if (state < -1 || state >= Math.Max(maxState, 1)) { reason = $"IP-to-state entry {k} has state {state}"; return null; }
                    d.IpToState.Add(new MsvcEhIpState(ip, state));
                }
            }
            return d;
        }

        /// <summary>
        /// FH4 FuncInfo4: a header byte, then (by its flags) the BBT flags, unwind map, try block map, the
        /// IP-to-state map (directly or through the segment table of separated code) and, for catch funclets, the
        /// frame offset. Offsets are image-relative; IPs are relative to <paramref name="function"/>.
        /// </summary>
        private Decoded? FuncInfo4(uint info, uint function, List<(uint Begin, uint End)> ranges, bool probe, out string? reason)
        {
            reason = null;
            if (!_r.IsData(info)) { reason = $"FuncInfo4 {info:X} is not in data"; return null; }
            var c = new Fh4Cursor(_r.Window(info, 64));
            byte header = c.ReadByte();
            if ((header & 0x80) != 0) { reason = $"FuncInfo4 header {header:X2} has the reserved bit set"; return null; }
            bool isCatch = (header & 1) != 0, separated = (header & 2) != 0, bbt = (header & 4) != 0, hasUnwind = (header & 8) != 0, hasTry = (header & 16) != 0;
            if (bbt) c.ReadUnsigned();
            uint unwindMap = hasUnwind ? (uint)c.ReadInt() : 0;
            uint tryMap = hasTry ? (uint)c.ReadInt() : 0;
            uint ipMap = 0;
            uint segments = 0;
            if (separated) segments = (uint)c.ReadInt();
            else ipMap = (uint)c.ReadInt();
            if (isCatch) c.ReadUnsigned();
            if (c.Failed) { reason = "FuncInfo4 runs out of the image"; return null; }
            var d = new Decoded { Scheme = MsvcEhScheme.Cxx4, DataRva = info, IsCatch = isCatch };

            if (separated)
            {
                // segment table: count, then (segment begin, IP-to-state map of that segment)
                if (!_r.IsData(segments)) { reason = $"segment table {segments:X} is not in data"; return null; }
                var s = new Fh4Cursor(_r.Window(segments, 4096));
                uint n = s.ReadUnsigned();
                if (s.Failed || n == 0 || n > 4096) { reason = $"segment table has {n} entries"; return null; }
                for (int k = 0; k < n && !s.Failed; k++)
                {
                    uint segment = (uint)s.ReadInt();
                    uint map = (uint)s.ReadInt();
                    if (s.Failed) break;
                    if (!_r.IsCode(segment)) { reason = $"separated segment {segment:X} is not in executable code"; return null; }
                    if (segment == function) ipMap = map;
                    else d.Children.Add(new MsvcEhChild(segment, MsvcEhChildKind.Fragment));
                }
                if (s.Failed) { reason = "segment table runs out of the image"; return null; }
            }

            if (hasUnwind && !Fh4UnwindMap(unwindMap, d, out reason)) return null;
            if (hasTry && !Fh4TryMap(tryMap, function, d, out reason)) return null;
            if (ipMap != 0 && !Fh4IpMap(ipMap, function, ranges, d, probe, out reason)) return null;
            if (!hasUnwind && !hasTry && ipMap == 0 && !isCatch) { reason = "FuncInfo4 describes nothing"; return null; }
            return d;
        }

        /// <summary>A window over compressed data large enough for its entries (grown up to 1 MB).</summary>
        private bool Fh4Read(uint rva, Func<Fh4Cursor, (bool Done, string? Reason)> decode, out string? reason)
        {
            reason = null;
            for (int size = 1024; ; size *= 8)
            {
                var window = _r.Window(rva, size);
                var (done, why) = decode(new Fh4Cursor(window));
                if (done) { reason = why; return why == null; }
                if (window.Length < size || size >= 1 << 20) { reason = "runs out of the image"; return false; }
            }
        }

        /// <summary>
        /// FH4 unwind map: count, then entries of (next offset &lt;&lt; 2 | type) and, by type, the action and object offset.
        /// The next offset counts bytes back from the entry to the entry of the state it unwinds to; back to the
        /// map's start (or 0) is no state.
        /// </summary>
        private bool Fh4UnwindMap(uint map, Decoded d, out string? reason)
        {
            if (!_r.IsData(map)) { reason = $"unwind map {map:X} is not in data"; return false; }
            var entries = new List<MsvcEhUnwind>();
            var children = new List<MsvcEhChild>();
            int count = 0;
            bool ok = Fh4Read(map, c =>
            {
                entries.Clear();
                children.Clear();
                uint n = c.ReadUnsigned();
                if (c.Failed) return (false, null);
                if (n > options.MaxStates) return (true, $"{n} unwind states (limit {options.MaxStates})");
                var offsets = new Dictionary<int, int>();
                var positions = new List<int>();
                var nexts = new List<uint>();
                for (int s = 0; s < n; s++)
                {
                    int at = c.Position;
                    positions.Add(at);
                    uint word = c.ReadUnsigned();
                    uint type = word & 3;
                    uint action = 0;
                    int? obj = null;
                    if (type is 1 or 2)
                    {
                        action = (uint)c.ReadInt();
                        obj = (int)c.ReadUnsigned();
                    }
                    else if (type == 3) action = (uint)c.ReadInt();
                    if (c.Failed) return (false, null);
                    if (type != 0 && !_r.IsCode(action)) return (true, $"unwind action of state {s} ({action:X}) is not in executable code");
                    offsets[at] = s;
                    nexts.Add(word >> 2);
                    var kind = type switch { 1 => MsvcEhUnwindKind.DestructorWithObject, 2 => MsvcEhUnwindKind.DestructorWithPointer, 3 => MsvcEhUnwindKind.Funclet, _ => MsvcEhUnwindKind.None };
                    entries.Add(new MsvcEhUnwind(s, -1, kind, type != 0 ? action : null, obj));
                    if (type == 3) children.Add(new MsvcEhChild(action, MsvcEhChildKind.Unwind));
                }
                // resolve next offsets to states
                for (int s = 0; s < entries.Count; s++)
                {
                    int position = positions[s];
                    uint back = nexts[s];
                    // back to the start of the map (its count): no state
                    if (back == 0 || back == position) continue;
                    if (back > position || !offsets.TryGetValue(position - (int)back, out int to) || to >= s)
                        return (true, $"unwind state {s} links {back} bytes back to no earlier entry");
                    entries[s] = entries[s] with { ToState = to };
                }
                count = (int)n;
                return (true, null);
            }, out reason);
            if (!ok) { reason = "unwind map: " + reason; return false; }
            d.Unwind = entries;
            d.MaxState = count;
            d.Children.AddRange(children);
            return true;
        }

        /// <summary>
        /// FH4 try block map: count, then (try low, try high, catch high, handler array offset); each handler array:
        /// count, then a header byte and by its flags the adjectives, type descriptor, catch object offset, the handler,
        /// and zero to two continuation addresses (function-relative unless flagged as image-relative).
        /// </summary>
        private bool Fh4TryMap(uint map, uint function, Decoded d, out string? reason)
        {
            if (!_r.IsData(map)) { reason = $"try block map {map:X} is not in data"; return false; }
            var blocks = new List<(int Low, int High, int CatchHigh, uint Array)>();
            bool ok = Fh4Read(map, c =>
            {
                blocks.Clear();
                uint n = c.ReadUnsigned();
                if (c.Failed) return (false, null);
                if (n > options.MaxTryBlocks) return (true, $"{n} try blocks (limit {options.MaxTryBlocks})");
                for (int t = 0; t < n; t++)
                {
                    uint low = c.ReadUnsigned(), high = c.ReadUnsigned(), catchHigh = c.ReadUnsigned();
                    uint array = (uint)c.ReadInt();
                    if (c.Failed) return (false, null);
                    blocks.Add(((int)low, (int)high, (int)catchHigh, array));
                }
                return (true, null);
            }, out reason);
            if (!ok) { reason = "try block map: " + reason; return false; }
            for (int t = 0; t < blocks.Count; t++)
            {
                var (low, high, catchHigh, array) = blocks[t];
                if (low < 0 || high < low || catchHigh < high || (d.MaxState > 0 && catchHigh > d.MaxState))
                {
                    reason = $"try block {t} states {low}..{high}, catch high {catchHigh} (max {d.MaxState})";
                    return false;
                }
                if (!_r.IsData(array)) { reason = $"handler array of try block {t} ({array:X}) is not in data"; return false; }
                var catches = new List<MsvcEhCatch>();
                var children = new List<MsvcEhChild>();
                string? why = null;
                ok = Fh4Read(array, c =>
                {
                    catches.Clear();
                    children.Clear();
                    uint n = c.ReadUnsigned();
                    if (c.Failed) return (false, null);
                    if (n == 0 || n > options.MaxCatches) return (true, $"{n} catch clauses");
                    for (int k = 0; k < n; k++)
                    {
                        byte h = c.ReadByte();
                        if ((h & 0xC0) != 0 || ((h >> 4) & 3) == 3) return (true, $"catch {k} header {h:X2} uses reserved bits");
                        uint adjectives = (h & 1) != 0 ? c.ReadUnsigned() : 0;
                        uint type = (h & 2) != 0 ? (uint)c.ReadInt() : 0;
                        int catchObject = (h & 4) != 0 ? (int)c.ReadUnsigned() : 0;
                        uint handler = (uint)c.ReadInt();
                        var continuations = new List<uint>();
                        int contCount = (h >> 4) & 3;
                        for (int j = 0; j < contCount; j++)
                            continuations.Add((h & 8) != 0 ? (uint)c.ReadInt() : function + c.ReadUnsigned());
                        if (c.Failed) return (false, null);
                        if (!_r.IsCode(handler)) return (true, $"catch {k}: handler {handler:X} is not in executable code");
                        if (type != 0 && !_r.IsData(type)) return (true, $"catch {k}: type descriptor {type:X} is not in data");
                        foreach (var cont in continuations)
                            if (!_r.IsCode(cont)) return (true, $"catch {k}: continuation {cont:X} is not in executable code");
                        catches.Add(new MsvcEhCatch(handler, adjectives, type, null, null, catchObject, continuations));
                        children.Add(new MsvcEhChild(handler, MsvcEhChildKind.Catch));
                        // function-relative continuations of a catch funclet's own FuncInfo4 are relative to the parent
                        if (!d.IsCatch || (h & 8) != 0)
                            foreach (var cont in continuations) children.Add(new MsvcEhChild(cont, MsvcEhChildKind.Continuation));
                    }
                    return (true, null);
                }, out why);
                if (!ok) { reason = $"handler array of try block {t}: {why}"; return false; }
                var resolved = catches.Select(x => Catch(d.DataRva, x.HandlerRva, x.Adjectives, x.TypeDescriptorRva ?? 0, x.CatchObjectOffset, x.Continuations)).ToList();
                d.TryBlocks.Add(new MsvcEhTryBlock(low, high, catchHigh, resolved));
                d.Children.AddRange(children);
            }
            reason = null;
            return true;
        }

        /// <summary>FH4 IP-to-state map: count, then (IP delta from the previous entry, state + 1).</summary>
        private bool Fh4IpMap(uint map, uint function, List<(uint Begin, uint End)> ranges, Decoded d, bool probe, out string? reason)
        {
            if (!_r.IsData(map)) { reason = $"IP-to-state map {map:X} is not in data"; return false; }
            var entries = new List<MsvcEhIpState>();
            int maxState = d.MaxState;
            bool ok = Fh4Read(map, c =>
            {
                entries.Clear();
                uint n = c.ReadUnsigned();
                if (c.Failed) return (false, null);
                if (n > options.MaxIpStates) return (true, $"{n} entries (limit {options.MaxIpStates})");
                uint ip = function;
                for (int k = 0; k < n; k++)
                {
                    uint delta = c.ReadUnsigned();
                    int state = (int)c.ReadUnsigned() - 1;
                    if (c.Failed) return (false, null);
                    ip += delta;
                    if (k > 0 && delta == 0) return (true, $"entry {k} does not advance");
                    if (!InRanges(ranges, ip)) return (true, $"entry {k} ({ip:X}) is not inside the function");
                    if (state < -1 || (maxState > 0 && state >= maxState) || (maxState == 0 && state > 0)) return (true, $"entry {k} has state {state} (max {maxState})");
                    entries.Add(new MsvcEhIpState(ip, state));
                    if (probe && k >= 64) break;
                }
                return (true, null);
            }, out reason);
            if (!ok) { reason = "IP-to-state map: " + reason; return false; }
            d.IpToState = entries;
            return true;
        }
    }
}
