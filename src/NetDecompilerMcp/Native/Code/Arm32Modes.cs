using System.Buffers.Binary;
using System.Collections.Concurrent;

namespace NetDecompilerMcp.Native.Code;

/// <summary>
/// The instruction state (ARM or Thumb) of code in a 32-bit ARM image. Facts come from the image (bit 0 of ELF function
/// symbols, $a / $t mapping symbols; Windows images are Thumb only) and from analysis (BL keeps the state, BLX switches
/// it, bit 0 of code pointers in data). A function start without a fact is sniffed: words decoding as A32 with
/// the always condition (three of four, or every word up to an early return) read as ARM, anything else as Thumb. Also the
/// per-image relocation facts the decoder needs (MOVW / MOVT relocations, GOT slots of exported functions). Thread-safe.
/// </summary>
internal sealed class Arm32Modes
{
    private readonly INativeImage _image;
    private readonly bool _allThumb;
    private readonly ConcurrentDictionary<uint, bool> _facts = new();
    private readonly (uint Rva, char Kind)[] _mapping;
    private (uint[] Starts, bool[] Thumb) _functions = ([], []);

    public Arm32Modes(INativeImage image)
    {
        _image = image;
        _allThumb = image.Format == ImageFormat.Pe;
        var mapping = new List<(uint, char)>();
        if (image is Elf.ElfFile elf)
        {
            foreach (var s in elf.DynamicSymbols.Concat(elf.StaticSymbols))
                if (s.IsDefined && s.IsFunction && s.Value != 0 && elf.TryVaToRva(s.Value & ~1UL, out uint rva))
                    _facts.TryAdd(rva, (s.Value & 1) != 0);
            if (elf.Entry != 0 && elf.TryVaToRva(elf.Entry & ~1UL, out uint entry)) _facts.TryAdd(entry, (elf.Entry & 1) != 0);
            foreach (var (rva, kind) in elf.MappingSymbols)
                if (kind is 'a' or 't' or 'd') mapping.Add((rva, kind));
        }
        _mapping = [.. mapping];
    }

    private HashSet<uint>? _mov32;

    /// <summary>Windows: MOVW / MOVT pairs a base relocation (THUMB_MOV32, ARM_MOV32) patches, by the MOVW's address.</summary>
    public bool IsRelocatedMov32(uint rva) => (_mov32 ??= _image is Pe.PeFile pe
        ? pe.BaseRelocations.Where(r => r.Type is Pe.PeRelocationType.ThumbMov32 or Pe.PeRelocationType.ArmMov32).Select(r => r.Rva).ToHashSet()
        : []).Contains(rva);

    private Dictionary<uint, uint>? _localSlots;

    /// <summary>
    /// ELF JUMP_SLOT / GLOB_DAT slots whose symbol this image defines (exported, so bound through the GOT): slot -> the
    /// function's address with its Thumb bit. A PLT stub or GOT load through such a slot reaches that function.
    /// </summary>
    public IReadOnlyDictionary<uint, uint> LocalSlots => _localSlots ??= ReadLocalSlots();

    private Dictionary<uint, uint> ReadLocalSlots()
    {
        var result = new Dictionary<uint, uint>();
        if (_image is not Elf.ElfFile elf) return result;
        var defined = new Dictionary<string, ulong>(StringComparer.Ordinal);
        foreach (var s in elf.DynamicSymbols)
            if (s.IsDefined && s.IsFunction && s.Value != 0) defined.TryAdd(s.Name, s.Value);
        foreach (var r in elf.Relocations)
            if (r.Kind is Elf.ElfRelocationKind.JumpSlot or Elf.ElfRelocationKind.GlobalData && r.Symbol != null && defined.TryGetValue(r.Symbol, out ulong va)
                && elf.TryVaToRva(r.Offset, out uint slot) && elf.TryVaToRva(va & ~1UL, out uint rva))
                result.TryAdd(slot, rva | (uint)(va & 1));
        return result;
    }

    /// <summary>Records what analysis learned about the code at <paramref name="rva"/> unless something is known already.</summary>
    public void Hint(uint rva, bool thumb)
    {
        if (!_allThumb) _facts.TryAdd(rva, thumb);
    }

    /// <summary>The state of a function starting at <paramref name="rva"/>.</summary>
    public bool StartMode(uint rva)
    {
        if (_allThumb) return true;
        if (_facts.TryGetValue(rva, out bool t)) return t;
        return MappingAt(rva) ?? Sniff(rva);
    }

    /// <summary>The state at any code address: its function's when the functions are known.</summary>
    public bool At(uint rva)
    {
        if (_allThumb) return true;
        if (_facts.TryGetValue(rva, out bool t)) return t;
        if (MappingAt(rva) is { } m) return m;
        var (starts, thumb) = _functions;
        int i = Array.BinarySearch(starts, rva);
        if (i < 0) i = ~i - 1;
        return i >= 0 ? thumb[i] : Sniff(rva);
    }

    /// <summary>Fixes the state of every function start for <see cref="At"/>.</summary>
    public void Seal(IEnumerable<uint> functionStarts)
    {
        var starts = functionStarts.ToArray();
        Array.Sort(starts);
        _functions = (starts, starts.Select(StartMode).ToArray());
    }

    /// <summary>Function starts in ARM state (the saved index keeps them; the rest are Thumb).</summary>
    public uint[] ArmStarts => _functions.Starts.Where((s, k) => !_functions.Thumb[k]).ToArray();

    /// <summary>Restores the states saved with an index.</summary>
    public void Load(IEnumerable<uint> functionStarts, IEnumerable<uint> armStarts)
    {
        var arm = armStarts.ToHashSet();
        var starts = functionStarts.ToArray();
        Array.Sort(starts);
        foreach (var s in starts) _facts[s] = !arm.Contains(s);
        _functions = (starts, starts.Select(s => !arm.Contains(s)).ToArray());
    }

    private bool? MappingAt(uint rva)
    {
        int lo = 0, hi = _mapping.Length - 1, best = -1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >>> 1;
            if (_mapping[mid].Rva <= rva) { best = mid; lo = mid + 1; } else hi = mid - 1;
        }
        for (; best >= 0; best--)
            if (_mapping[best].Kind != 'd') return _mapping[best].Kind == 't';
        return null;
    }

    private bool Sniff(uint rva)
    {
        if ((rva & 3) != 0) return true;
        Span<byte> b = stackalloc byte[32];
        int words = _image.Read(rva, b) / 4;
        int always = 0;
        for (int k = 0; k < words; k++)
        {
            uint w = BinaryPrimitives.ReadUInt32LittleEndian(b[(k * 4)..]);
            Arm32Decode.Arm(w, (uint)(_image.ImageBase + rva) + (uint)k * 4, out var x);
            if (!x.IsValid || w == 0) return true;
            if (w >> 28 is 0xE or 0xF) always++;
            // a short function: every word up to its end reads as ARM
            if (x.Flow is ArmFlow.Return or ArmFlow.Jump or ArmFlow.IndirectJump && !x.IsConditional) return always <= k;
            if (k == 3) return always < 3;
        }
        return true;
    }
}
