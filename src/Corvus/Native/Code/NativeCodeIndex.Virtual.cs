using Corvus.Native.Msvc;

namespace Corvus.Native.Code;

public sealed partial class NativeCodeIndex
{
    // virtual call edges (VirtualExact / VirtualPossible), sorted by (From, To), and an index sorted by (To, From); apart from
    // the other cross-references so their consumers (diffs, patterns, strings) see only what the instructions encode
    private CodeXref[] _virtualEdges = [];
    private int[] _virtualByTo = [];

    /// <summary>Virtual call sites resolved through MSVC RTTI (x86 / x64; empty when the image has no RTTI or the build skipped it).</summary>
    public VirtualCallSet VirtualCalls { get; private set; } = VirtualCallSet.Empty;

    /// <summary>The virtual call edges, sorted by source then target.</summary>
    public IReadOnlyList<CodeXref> VirtualEdges => _virtualEdges;

    /// <summary>Virtual call edges whose call instruction is in [<paramref name="start"/>, <paramref name="end"/>).</summary>
    public List<CodeXref> VirtualEdgesFrom(uint start, uint end)
    {
        var result = new List<CodeXref>();
        int lo = 0, hi = _virtualEdges.Length;
        while (lo < hi) { int mid = (lo + hi) >>> 1; if (_virtualEdges[mid].From < start) lo = mid + 1; else hi = mid; }
        for (int i = lo; i < _virtualEdges.Length && _virtualEdges[i].From < end; i++) result.Add(_virtualEdges[i]);
        return result;
    }

    /// <summary>Virtual call edges to <paramref name="rva"/>, sorted by source.</summary>
    public List<CodeXref> VirtualEdgesTo(uint rva)
    {
        var result = new List<CodeXref>();
        int lo = 0, hi = _virtualByTo.Length;
        while (lo < hi) { int mid = (lo + hi) >>> 1; if (_virtualEdges[_virtualByTo[mid]].To < rva) lo = mid + 1; else hi = mid; }
        for (int i = lo; i < _virtualByTo.Length; i++)
        {
            var x = _virtualEdges[_virtualByTo[i]];
            if (x.To != rva) break;
            result.Add(x);
        }
        return result;
    }

    /// <summary>Targets of the virtual call at <paramref name="site"/> (empty when it has no edges).</summary>
    public List<uint> VirtualTargets(uint site) => VirtualEdgesFrom(site, site + 1).Select(x => x.To).ToList();

    private void SetVirtualCalls(VirtualCallSet set, CodeXref[] edges)
    {
        var byTo = new int[edges.Length];
        var keys = new ulong[edges.Length];
        for (int i = 0; i < edges.Length; i++)
        {
            byTo[i] = i;
            keys[i] = (ulong)edges[i].To << 32 | edges[i].From;
        }
        Array.Sort(keys, byTo);
        _virtualEdges = edges;
        _virtualByTo = byTo;
        VirtualCalls = set;
    }

    /// <summary>x86 / x64 through the data flow, ARM64 and ARM32 through their call shapes.</summary>
    internal static bool ResolvesVirtualCalls(INativeImage image) => image.Arch is NativeArch.X86 or NativeArch.X64 or NativeArch.Arm64 or NativeArch.Arm;

    /// <summary>Runs RTTI analysis and the virtual call resolution over a built index; failures become a note, not an exception.</summary>
    private void ResolveVirtualCalls(CodeIndexOptions options, CancellationToken ct)
    {
        if (_ctx == null || !options.ResolveVirtualCalls || !ResolvesVirtualCalls(Image)) return;
        try
        {
            var rtti = Itanium.CppRtti.Analyze(Image, ct);
            var (set, edges) = Image.Arch is NativeArch.X86 or NativeArch.X64
                ? VirtualCallResolver.Resolve(this, _ctx, options, rtti, ct)
                : VirtualCallResolver.ResolveShapes(this, _ctx, options, rtti, () => Calls.ArmVirtualCalls.Find(this, ct), ct);
            SetVirtualCalls(set, edges);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            SetVirtualCalls(new VirtualCallSet([], VirtualCallStats.None, [$"virtual call resolution failed: {ex.GetType().Name}: {ex.Message}"]), []);
        }
    }

    private void WriteVirtualCalls(PayloadWriter w)
    {
        var sites = VirtualCalls.Sites;
        int n = sites.Count;
        var rva = new uint[n];
        var function = new uint[n];
        var slot = new int[n];
        var vfptr = new int[n];
        var td = new uint[n];
        var vftable = new uint[n];
        var count = new int[n];
        var flags = new byte[n];
        for (int i = 0; i < n; i++)
        {
            var s = sites[i];
            rva[i] = s.Rva; function[i] = s.Function; slot[i] = s.Slot; vfptr[i] = s.VfptrOffset; td[i] = s.ClassTypeDescriptor;
            vftable[i] = s.VftableRva; count[i] = s.TargetCount;
            flags[i] = (byte)((byte)s.Status | (byte)s.Reason << 2 | (byte)s.Receiver << 5 | (s.TailCall ? 0x80 : 0));
        }
        w.DeltaUInts(rva);
        w.UInts(function);
        w.Ints(slot);
        w.Ints(vfptr);
        w.UInts(td);
        w.UInts(vftable);
        w.Ints(count);
        w.Bytes(flags);
        w.Bytes(sites.Select(s => s.Incomplete ? (byte)1 : (byte)0).ToArray());
        var st = VirtualCalls.Stats;
        w.I32(st.Sites); w.I32(st.Exact); w.I32(st.Possible); w.I32(st.Unresolved); w.I32(st.Edges); w.I32(st.RttiClasses); w.I32(st.FunctionsAnalyzed);
        w.I32(st.FunctionsNotConverged); w.I32(st.PureTargetsExcluded); w.I32(st.IncompleteSites); w.I64(st.Elapsed.Ticks);
        w.Strings(VirtualCalls.Notes);

        int e = _virtualEdges.Length;
        var from = new uint[e];
        var to = new uint[e];
        var kinds = new byte[e];
        for (int i = 0; i < e; i++) { from[i] = _virtualEdges[i].From; to[i] = _virtualEdges[i].To; kinds[i] = (byte)_virtualEdges[i].Kind; }
        w.DeltaUInts(from);
        w.UInts(to);
        w.Bytes(kinds);
    }

    private static (VirtualCallSet Set, CodeXref[] Edges) ReadVirtualCalls(ref PayloadReader r)
    {
        var rva = r.DeltaUInts();
        int n = rva.Length;
        var function = r.UInts(n);
        var slot = r.Ints(n);
        var vfptr = r.Ints(n);
        var td = r.UInts(n);
        var vftable = r.UInts(n);
        var count = r.Ints(n);
        var flags = r.Bytes(n);
        var incomplete = r.Bytes(n);
        var sites = new VirtualCallSite[n];
        for (int i = 0; i < n; i++)
        {
            if (i > 0 && rva[i] <= rva[i - 1]) throw new InvalidDataException("virtual call sites out of order");
            int status = flags[i] & 3, reason = (flags[i] >> 2) & 7, receiver = (flags[i] >> 5) & 3;
            if (status > (int)VirtualCallStatus.Unresolved || reason > (int)VirtualCallReason.TooManyTargets || receiver > (int)VirtualReceiver.Name)
                throw new InvalidDataException("unknown virtual call site state");
            sites[i] = new VirtualCallSite(rva[i], function[i], slot[i], vfptr[i], (VirtualCallStatus)status, (VirtualCallReason)reason, (VirtualReceiver)receiver,
                td[i], vftable[i], count[i], (flags[i] & 0x80) != 0, incomplete[i] != 0);
        }
        var stats = new VirtualCallStats(r.I32(), r.I32(), r.I32(), r.I32(), r.I32(), r.I32(), r.I32(), r.I32(), r.I32(), r.I32(), TimeSpan.FromTicks(r.Ticks()));
        var notes = r.Strings();
        var from = r.DeltaUInts();
        int e = from.Length;
        var to = r.UInts(e);
        var kinds = r.Bytes(e);
        var edges = new CodeXref[e];
        for (int i = 0; i < e; i++)
        {
            if (kinds[i] is not ((byte)XrefKind.VirtualExact or (byte)XrefKind.VirtualPossible)) throw new InvalidDataException("unknown virtual call edge kind");
            edges[i] = new CodeXref(from[i], to[i], (XrefKind)kinds[i]);
            if (i > 0 && (edges[i].From < edges[i - 1].From || edges[i].From == edges[i - 1].From && edges[i].To <= edges[i - 1].To))
                throw new InvalidDataException("virtual call edges out of order");
        }
        return (new VirtualCallSet(sites, stats, notes), edges);
    }
}
