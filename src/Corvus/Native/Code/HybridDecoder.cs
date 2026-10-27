namespace Corvus.Native.Code;

/// <summary>Decodes a hybrid PE (ARM64X, ARM64EC) with the decoder of each address's code map range.</summary>
internal sealed class HybridDecoder(ICodeDecoder primary, ICodeDecoder other, (uint Start, uint End)[] otherRanges) : ICodeDecoder
{
    private ICodeDecoder? _current;
    private ICodeDecoder Current { get => _current ?? primary; set => _current = value; }

    public bool Is64 => true;

    /// <summary>The decoder of the header machine's instruction set.</summary>
    public ICodeDecoder Primary => primary;

    /// <summary>The decoder of <paramref name="decoder"/>'s image's own instruction set (itself unless hybrid).</summary>
    public static ICodeDecoder? PrimaryOf(ICodeDecoder? decoder) => decoder is HybridDecoder h ? h.Primary : decoder;

    private ICodeDecoder For(uint rva) => ImageCode.InRanges(otherRanges, rva) ? other : primary;

    public void BeginFunction() { primary.BeginFunction(); other.BeginFunction(); }

    public void BeginFunction(uint start)
    {
        Current = For(start);
        Current.BeginFunction(start);
    }

    public void BeginRun(IndexBound incoming) { primary.BeginRun(incoming); other.BeginRun(incoming); }

    public bool Decode(uint rva, out Insn insn) => (Current = For(rva)).Decode(rva, out insn);

    public void Decode(ImageCode.Region region, uint rva, out Insn insn) => (Current = For(rva)).Decode(region, rva, out insn);

    public bool DecodeMapped(uint rva, out Insn insn) => (Current = For(rva)).DecodeMapped(rva, out insn);

    public void ConditionalBounds(out IndexBound taken, out IndexBound fallThrough) => Current.ConditionalBounds(out taken, out fallThrough);

    public SwitchMatch? MatchSwitch(out string reason) => Current.MatchSwitch(out reason);

    public bool LastIsImplausible(bool strict = true) => Current.LastIsImplausible(strict);

    public bool LastHasImplausibleDisplacement(uint rva) => Current.LastHasImplausibleDisplacement(rva);

    public bool IsPadding(ImageCode.Region region, uint rva) => For(rva).IsPadding(region, rva);

    public uint? ThunkSlot(uint rva, Func<uint, bool> isImportSlot) => For(rva).ThunkSlot(rva, isImportSlot);
}
