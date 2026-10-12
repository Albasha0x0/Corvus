using System.Buffers.Binary;
using System.Collections.Concurrent;

namespace Corvus.Native.Code;

/// <summary>
/// The instruction state (ARM or Thumb) of code in a 32-bit ARM image. Facts come from the image (bit 0 of ELF function
/// symbols, $a / $t mapping symbols; Windows images are Thumb only, Go functions ARM) and from analysis (BL keeps the state, BLX switches
/// it, bit 0 of code pointers in data). A function start without a fact is guessed (<see cref="Guess"/>); a guess between
/// two plausible states with no prologue to tell them apart takes the image's prevailing state and is unsure
/// (<see cref="IsUnsure"/>). Also the
/// per-image relocation facts the decoder needs (MOVW / MOVT relocations, GOT slots of exported functions). Thread-safe.
/// </summary>
internal sealed class Arm32Modes
{
    private readonly INativeImage _image;
    private readonly bool _allThumb;
    private readonly ConcurrentDictionary<uint, bool> _facts = new();
    private readonly ConcurrentDictionary<uint, byte> _unsure = new();
    private readonly (uint Rva, char Kind)[] _mapping;
    private (uint[] Starts, bool[] Thumb) _functions = ([], []);

    public Arm32Modes(INativeImage image)
    {
        _image = image;
        // the Go compiler emits A32 only, Windows on ARM included
        var go = Go.GoFunctionTable.Of(image);
        _allThumb = image.Format == ImageFormat.Pe && go == null;
        if (go != null)
            foreach (var f in go.Functions) _facts.TryAdd(f.Rva, false);
        var mapping = new List<(uint, char)>();
        if (image is Elf.ElfFile elf)
        {
            foreach (var s in elf.DynamicSymbols.Concat(elf.StaticSymbols))
                if (s.IsDefined && s.IsFunction && s.Value != 0 && elf.TryVaToRva(s.Value & ~1UL, out uint rva))
                    _facts.TryAdd(rva, (s.Value & 1) != 0);
            // linkers do not always set bit 0 of a Thumb entry point: only an odd one is a fact
            if ((elf.Entry & 1) != 0 && elf.TryVaToRva(elf.Entry & ~1UL, out uint entry)) _facts.TryAdd(entry, true);
            foreach (var (rva, kind) in elf.MappingSymbols)
                if (kind is 'a' or 't' or 'd') mapping.Add((rva, kind));
            CodePointers(elf);
        }
        _mapping = [.. mapping];
        int thumbFacts = _facts.Values.Count(t => t), armFacts = _facts.Count - thumbFacts;
        if (thumbFacts >= 16 && thumbFacts >= 9 * armFacts) _prior = true;
        else if (armFacts >= 16 && armFacts >= 9 * thumbFacts) _prior = false;
    }

    /// <summary>The state nine in ten of the image's own facts name (symbols, code pointers); null when mixed or few.</summary>
    private readonly bool? _prior;

    /// <summary>
    /// Relocated pointers in data name the state of the code they point to: an odd one Thumb, an even one to a declared
    /// function start (unwind tables carry no state bit) ARM.
    /// </summary>
    private void CodePointers(Elf.ElfFile elf)
    {
        var declared = elf.DeclaredFunctions.Select(d => d.Rva).ToHashSet();
        var even = new List<uint>();
        Span<byte> b = stackalloc byte[4];
        foreach (uint slot in elf.RelocationRvas)
        {
            if (elf.SectionAt(slot) is not { IsExecutable: false } || elf.Read(slot, b) != 4) continue;
            uint value = BinaryPrimitives.ReadUInt32LittleEndian(b);
            if (!elf.TryVaToRva(value & ~1u, out uint rva) || elf.SectionAt(rva) is not { IsExecutable: true }) continue;
            if ((value & 1) != 0) _facts.TryAdd(rva, true);
            else if (declared.Contains(rva)) even.Add(rva);
        }
        foreach (uint rva in even) _facts.TryAdd(rva, false);
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

    /// <summary>Records what analysis learned about the code at <paramref name="rva"/> unless something is known already (or the states are sealed).</summary>
    public void Hint(uint rva, bool thumb)
    {
        if (_allThumb || _sealed) return;
        if (!_facts.TryAdd(rva, thumb) && _facts.TryGetValue(rva, out bool known) && known == thumb) _unsure.TryRemove(rva, out _);
    }

    /// <summary>
    /// A hint from a value that may not be a code pointer (an unrelocated literal whose bit 0 happens to be set): taken
    /// unless the bytes read surely in the other state.
    /// </summary>
    public void HintUnconfirmed(uint rva, bool thumb)
    {
        if (_allThumb || _sealed || _facts.ContainsKey(rva)) return;
        var (guess, sure) = Guess(_image, rva);
        if (!sure || guess == thumb) Hint(rva, thumb);
    }

    private volatile bool _sealed;

    /// <summary>Discovery starts: hints are taken again.</summary>
    public void Open() => _sealed = false;

    /// <summary>Keeps the state a function is explored in, so later hints cannot change it.</summary>
    public void Fix(uint start)
    {
        if (_allThumb || _facts.ContainsKey(start)) return;
        var (thumb, sure) = MappingAt(start) is { } m ? (m, true) : GuessStart(start);
        if (_facts.TryAdd(start, thumb) && !sure) _unsure.TryAdd(start, 0);
    }

    /// <summary>The state of the function at <paramref name="start"/> was guessed between two plausible readings.</summary>
    public bool IsUnsure(uint start) => _unsure.ContainsKey(start);

    /// <summary>The state of a function starting at <paramref name="rva"/>.</summary>
    public bool StartMode(uint rva)
    {
        if (_allThumb) return true;
        if (_facts.TryGetValue(rva, out bool t)) return t;
        return MappingAt(rva) ?? GuessStart(rva).Thumb;
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
        return i >= 0 ? thumb[i] : GuessStart(rva).Thumb;
    }

    /// <summary>Fixes the state of every function start for <see cref="At"/>; hints are ignored until <see cref="Open"/>.</summary>
    public void Seal(IEnumerable<uint> functionStarts)
    {
        var starts = functionStarts.ToArray();
        Array.Sort(starts);
        _functions = (starts, starts.Select(StartMode).ToArray());
        _sealed = true;
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
        _sealed = true;
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

    private (bool Thumb, bool Sure) GuessStart(uint rva)
    {
        var g = Guess(_image, rva);
        return g.Sure || _prior is not { } p ? g : (p, false);
    }

    /// <summary>
    /// The state of code at <paramref name="rva"/> with no fact about it: a halfword-aligned start is Thumb; else the bytes
    /// are decoded in both states, and a state they do not decode in is ruled out. Both plausible: an ARM or Thumb prologue
    /// decides; with neither, words with the always condition (three of four, or all up to an early return) read as ARM,
    /// and the guess is unsure.
    /// </summary>
    internal static (bool Thumb, bool Sure) Guess(INativeImage image, uint rva)
    {
        if ((rva & 3) != 0) return (true, true);
        Span<byte> b = stackalloc byte[48];
        b = b[..image.Read(rva, b)];
        if (b.Length < 4) return (true, false);
        uint va = (uint)(image.ImageBase + rva);
        bool arm = ArmPlausible(b, va), thumb = ThumbPlausible(b, va);
        if (arm != thumb) return (thumb, true);
        if (!arm) return (true, false);
        uint w = BinaryPrimitives.ReadUInt32LittleEndian(b);
        // a stack probe (mov ip, #n) may come first
        bool armPrologue = ArmPrologue(w) || (w & 0xFFFFF000) == 0xE3A0C000 && b.Length >= 8 && ArmPrologue(BinaryPrimitives.ReadUInt32LittleEndian(b[4..]));
        bool thumbPrologue = ThumbPrologue(b);
        if (armPrologue != thumbPrologue) return (thumbPrologue, true);
        return (!ArmRun(b, va), false);
    }

    /// <summary>push {..} / str lr, [sp, #-4]! / mov ip, sp / sub sp, sp, #n.</summary>
    private static bool ArmPrologue(uint w) =>
        (w & 0xFFFF0000) == 0xE92D0000 || w == 0xE52DE004 || w == 0xE1A0C00D || (w & 0xFFFFF000) == 0xE24DD000;

    /// <summary>push {..} / push.w {.., lr} / sub sp, #n as the first or second instruction.</summary>
    private static bool ThumbPrologue(ReadOnlySpan<byte> b)
    {
        for (int k = 0, n = 0; n < 2 && k + 4 <= b.Length; n++)
        {
            ushort h1 = BinaryPrimitives.ReadUInt16LittleEndian(b[k..]), h2 = BinaryPrimitives.ReadUInt16LittleEndian(b[(k + 2)..]);
            if ((h1 & 0xFE00) == 0xB400 || h1 == 0xE92D && (h2 & 0xE000) == 0x4000 || (h1 & 0xFF80) == 0xB080) return true;
            k += Arm32Decode.ThumbLength(h1);
        }
        return false;
    }

    /// <summary>The first four words decode as A32, or every word up to an unconditional exit does.</summary>
    private static bool ArmPlausible(ReadOnlySpan<byte> b, uint va)
    {
        for (int k = 0; k < 16 && k + 4 <= b.Length; k += 4)
        {
            uint w = BinaryPrimitives.ReadUInt32LittleEndian(b[k..]);
            // zero padding after a few instructions ends the code (calls that do not return)
            if (w == 0) return k >= 8;
            Arm32Decode.Arm(w, va + (uint)k, out var x);
            if (!x.IsValid) return false;
            if (x.Flow is ArmFlow.Return or ArmFlow.Jump or ArmFlow.IndirectJump && !x.IsConditional) return true;
        }
        return true;
    }

    /// <summary>The first six instructions decode as T32, or every one up to an unconditional exit does.</summary>
    private static bool ThumbPlausible(ReadOnlySpan<byte> b, uint va)
    {
        int k = 0;
        for (int n = 0; n < 6 && k + 2 <= b.Length; n++)
        {
            if (b[k] == 0 && b[k + 1] == 0 && k + 4 <= b.Length && b[k + 2] == 0 && b[k + 3] == 0) return k >= 8;
            if (Arm32Decode.ThumbLength((ushort)(b[k] | b[k + 1] << 8)) == 4 && k + 4 > b.Length) return true;
            Arm32Decode.Thumb(b[k..], va + (uint)k, false, out var x);
            if (!x.IsValid) return false;
            if (x.Flow is ArmFlow.Return or ArmFlow.Jump or ArmFlow.IndirectJump && !x.IsConditional) return true;
            k += x.Length;
        }
        return true;
    }

    /// <summary>
    /// The first words read as ARM: three of four have the always condition (or two with the first), or every word up
    /// to an early exit does when the first has it.
    /// </summary>
    private static bool ArmRun(ReadOnlySpan<byte> b, uint va)
    {
        int always = 0;
        bool first = BinaryPrimitives.ReadUInt32LittleEndian(b) >> 28 == 0xE;
        for (int k = 0; k < 8 && k * 4 + 4 <= b.Length; k++)
        {
            uint w = BinaryPrimitives.ReadUInt32LittleEndian(b[(k * 4)..]);
            Arm32Decode.Arm(w, va + (uint)k * 4, out var x);
            if (!x.IsValid || w == 0) return false;
            if (w >> 28 == 0xE) always++;
            if (x.Flow is ArmFlow.Return or ArmFlow.Jump or ArmFlow.IndirectJump && !x.IsConditional) return first && always * 2 >= k + 1;
            if (k == 3) return always >= 3 || always >= 2 && first;
        }
        return false;
    }
}
