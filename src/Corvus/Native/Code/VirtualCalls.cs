namespace Corvus.Native.Code;

/// <summary>How far a virtual call site was resolved.</summary>
public enum VirtualCallStatus : byte
{
    /// <summary>One implementation can run: a virtual_exact edge.</summary>
    Exact,
    /// <summary>One of several implementations (or one, with derived classes RTTI does not place): virtual_possible edges.</summary>
    Possible,
    /// <summary>No target set; <see cref="VirtualCallSite.Reason"/> says why.</summary>
    Unresolved,
}

/// <summary>Why a virtual call site has no (exact) target set.</summary>
public enum VirtualCallReason : byte
{
    None,
    /// <summary>The receiver's class is not known: not this of a virtual method, no vftable stored into it in the function.</summary>
    ReceiverUnknown,
    /// <summary>The receiver's class has no vftable at the subobject offset the call reads it from.</summary>
    NoVftableAtOffset,
    /// <summary>The slot is past the end of the receiver class's vftable.</summary>
    SlotOutOfRange,
    /// <summary>Every implementation in the slot is a pure virtual stub (_purecall, a function that does not return).</summary>
    OnlyPureTargets,
    /// <summary>More implementations than <see cref="CodeIndexOptions.MaxVirtualTargets"/>.</summary>
    TooManyTargets,
}

/// <summary>How the receiver's class was found.</summary>
public enum VirtualReceiver : byte
{
    Unknown,
    /// <summary>this of a virtual method: the classes whose vftables hold the method, and their derived classes.</summary>
    This,
    /// <summary>The object's vftable itself is known: stored in the function, or by a constructor called on the object.</summary>
    Vftable,
    /// <summary>this of a non-virtual member function whose decorated (export) name gives its class.</summary>
    Name,
}

/// <summary>
/// An indirect call (or tail jump) through a pointer loaded from an object's vftable: [vfptr + <see cref="Slot"/> * pointer size],
/// the vfptr loaded from [object + <see cref="VfptrOffset"/>].
/// </summary>
/// <param name="Function">Start of the calling function.</param>
/// <param name="ClassTypeDescriptor">RTTI type descriptor of the receiver's class (static type), 0 when unknown.</param>
/// <param name="VftableRva">The receiver class's vftable the slot is read from, 0 when unknown.</param>
/// <param name="TargetCount">Distinct implementations found (pure virtual stubs excluded), also when there are too many for edges.</param>
/// <param name="Incomplete">A derived class reaches the receiver's class through a virtual base: its overrides are not placed.</param>
public readonly record struct VirtualCallSite(uint Rva, uint Function, int Slot, int VfptrOffset, VirtualCallStatus Status, VirtualCallReason Reason,
    VirtualReceiver Receiver, uint ClassTypeDescriptor, uint VftableRva, int TargetCount, bool TailCall, bool Incomplete);

/// <param name="Sites">Virtual call sites found: calls through a pointer loaded from a vftable (or a table loaded from an object).</param>
/// <param name="Edges">virtual_exact plus virtual_possible edges.</param>
/// <param name="RttiClasses">Classes with vftables the resolution used.</param>
/// <param name="FunctionsNotConverged">Functions whose data flow did not settle within the visit budget: their sites are not reported.</param>
/// <param name="PureTargetsExcluded">Slot entries left out as pure virtual stubs.</param>
public sealed record VirtualCallStats(int Sites, int Exact, int Possible, int Unresolved, int Edges, int RttiClasses, int FunctionsAnalyzed,
    int FunctionsNotConverged, int PureTargetsExcluded, int IncompleteSites, TimeSpan Elapsed)
{
    public static readonly VirtualCallStats None = new(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, TimeSpan.Zero);
}

/// <summary>The virtual call sites of an image, sorted by address, with totals and coverage notes.</summary>
public sealed class VirtualCallSet
{
    public static readonly VirtualCallSet Empty = new([], VirtualCallStats.None, []);

    private readonly VirtualCallSite[] _sites;

    public VirtualCallSet(VirtualCallSite[] sites, VirtualCallStats stats, IReadOnlyList<string> notes)
    {
        _sites = sites;
        Stats = stats;
        Notes = notes;
    }

    public IReadOnlyList<VirtualCallSite> Sites => _sites;
    public VirtualCallStats Stats { get; }
    /// <summary>Why nothing or not everything was resolved (no RTTI, analysis failure).</summary>
    public IReadOnlyList<string> Notes { get; }

    /// <summary>The site whose call instruction is at <paramref name="rva"/>, or null.</summary>
    public VirtualCallSite? SiteAt(uint rva)
    {
        int lo = 0, hi = _sites.Length - 1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >>> 1;
            if (_sites[mid].Rva == rva) return _sites[mid];
            if (_sites[mid].Rva < rva) lo = mid + 1; else hi = mid - 1;
        }
        return null;
    }

    /// <summary>Sites whose call instruction is in [<paramref name="start"/>, <paramref name="end"/>).</summary>
    public IEnumerable<VirtualCallSite> SitesIn(uint start, uint end)
    {
        int lo = 0, hi = _sites.Length;
        while (lo < hi) { int mid = (lo + hi) >>> 1; if (_sites[mid].Rva < start) lo = mid + 1; else hi = mid; }
        for (int i = lo; i < _sites.Length && _sites[i].Rva < end; i++) yield return _sites[i];
    }

    /// <summary>Snake-case reason code ("receiver_unknown"), null for <see cref="VirtualCallReason.None"/>.</summary>
    public static string? ReasonCode(VirtualCallReason r) => r switch
    {
        VirtualCallReason.ReceiverUnknown => "receiver_unknown",
        VirtualCallReason.NoVftableAtOffset => "no_vftable_at_offset",
        VirtualCallReason.SlotOutOfRange => "slot_out_of_range",
        VirtualCallReason.OnlyPureTargets => "only_pure_targets",
        VirtualCallReason.TooManyTargets => "too_many_targets",
        _ => null,
    };

    /// <summary>"exact", "possible" or "unresolved".</summary>
    public static string StatusCode(VirtualCallStatus s) => s switch
    {
        VirtualCallStatus.Exact => "exact",
        VirtualCallStatus.Possible => "possible",
        _ => "unresolved",
    };

    /// <summary>"this", "vftable", "name" or "unknown".</summary>
    public static string ReceiverCode(VirtualReceiver r) => r switch
    {
        VirtualReceiver.This => "this",
        VirtualReceiver.Vftable => "vftable",
        VirtualReceiver.Name => "name",
        _ => "unknown",
    };
}

/// <summary>
/// A virtual call an instruction-set-specific scan found: through [[object + <see cref="VfptrOffset"/>] + <see cref="Slot"/> *
/// pointer size], the object this of <see cref="Function"/> when <see cref="ThisReceiver"/>.
/// </summary>
public readonly record struct VirtualShape(uint Rva, uint Function, int VfptrOffset, int Slot, bool ThisReceiver, bool Tail);

/// <summary>Which call edges a call graph query follows.</summary>
public enum CallEdgeFilter
{
    All,
    /// <summary>Direct calls, tail calls, import calls: no virtual edges.</summary>
    Direct,
    /// <summary>Only virtual_exact and virtual_possible edges.</summary>
    Virtual,
}
