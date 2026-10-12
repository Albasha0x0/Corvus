using System.Runtime.CompilerServices;

namespace Corvus.Native.Code;

/// <summary>
/// ELF JUMP_SLOT / GLOB_DAT slots whose symbol the image itself defines (an exported function bound through the GOT, so
/// its PLT stub or GOT load reaches local code): slot RVA -> the function's RVA, bit 0 kept for ARM32 Thumb functions.
/// </summary>
internal static class ElfLocalSlots
{
    private static readonly ConditionalWeakTable<INativeImage, IReadOnlyDictionary<uint, uint>> Cache = new();

    public static IReadOnlyDictionary<uint, uint> Of(INativeImage image) => Cache.GetValue(image, Read);

    private static IReadOnlyDictionary<uint, uint> Read(INativeImage image)
    {
        var result = new Dictionary<uint, uint>();
        if (image is not Elf.ElfFile elf) return result;
        var defined = new Dictionary<string, ulong>(StringComparer.Ordinal);
        foreach (var s in elf.DynamicSymbols)
            if (s.IsDefined && s.IsFunction && s.Value != 0) defined.TryAdd(s.Name, s.Value);
        if (defined.Count == 0) return result;
        ulong thumbBit = image.Arch == NativeArch.Arm ? 1UL : 0;
        foreach (var r in elf.Relocations)
            if (r.Kind is Elf.ElfRelocationKind.JumpSlot or Elf.ElfRelocationKind.GlobalData && r.Symbol != null && defined.TryGetValue(r.Symbol, out ulong va)
                && elf.TryVaToRva(r.Offset, out uint slot) && elf.TryVaToRva(va & ~thumbBit, out uint rva))
                result.TryAdd(slot, rva | (uint)(va & thumbBit));
        return result;
    }
}
