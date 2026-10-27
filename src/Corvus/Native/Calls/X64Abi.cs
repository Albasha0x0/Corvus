using Iced.Intel;

namespace Corvus.Native.Calls;

/// <summary>The x64 calling convention of an image: Microsoft x64 on PE, System V on ELF and Mach-O.</summary>
internal sealed class X64Abi
{
    public static readonly X64Abi Microsoft = new(false, [Register.RCX, Register.RDX, Register.R8, Register.R9], 4, 0x20,
        [Register.RAX, Register.RCX, Register.RDX, Register.R8, Register.R9, Register.R10, Register.R11], 6);

    public static readonly X64Abi SystemV = new(true, [Register.RDI, Register.RSI, Register.RDX, Register.RCX, Register.R8, Register.R9], 8, 0,
        [Register.RAX, Register.RCX, Register.RDX, Register.RSI, Register.RDI, Register.R8, Register.R9, Register.R10, Register.R11], 32);

    private X64Abi(bool systemV, Register[] intArgs, int floatArgs, int homeArea, Register[] volatileInts, int volatileVectors)
    {
        IsSystemV = systemV;
        IntArgs = intArgs;
        FloatArgs = floatArgs;
        HomeArea = homeArea;
        VolatileInts = volatileInts;
        _volatileVectors = volatileVectors;
        foreach (var r in volatileInts) VolatileMask |= 1UL << FunctionCode.Bit(r);
    }

    /// <summary>System V on ELF and Mach-O, Microsoft on PE.</summary>
    public static X64Abi Of(INativeImage image) => image.Format == ImageFormat.Pe ? Microsoft : SystemV;

    public bool IsSystemV { get; }
    /// <summary>Integer argument registers in order (full registers).</summary>
    public Register[] IntArgs { get; }
    /// <summary>xmm argument registers.</summary>
    public int FloatArgs { get; }
    /// <summary>Bytes between the return address and the first stack argument (the Microsoft home area).</summary>
    public int HomeArea { get; }
    public Register[] VolatileInts { get; }
    /// <summary>Volatile general registers as <see cref="FunctionCode.Bit"/> bits.</summary>
    public ulong VolatileMask { get; }
    private readonly int _volatileVectors;

    public string Name => IsSystemV ? "System V" : "Microsoft x64";

    /// <summary>Clobbered by a call: the volatile general registers, xmm0-5 (Microsoft) or every vector register (System V).</summary>
    public bool IsVolatile(Register full) => VolatileInts.Contains(full) || full >= Register.ZMM0 && full < Register.ZMM0 + _volatileVectors;

    /// <summary>Where each parameter is passed at a call, before the return address is pushed; Microsoft passes variadic floats in integer registers.</summary>
    public List<(Loc Loc, string Label, Loc? Second)> Assign(IReadOnlyList<ApiParam> ps, int variadicFrom, bool tail, bool structReturn = false)
    {
        var result = new List<(Loc, string, Loc?)>(ps.Count);
        int hidden = structReturn ? 1 : 0, ints = hidden, floats = 0, stack = 0, shift = tail ? 8 : 0;
        for (int k = 0; k < ps.Count; k++)
        {
            var p = ps[k];
            int position = k + hidden;
            Register reg = Register.None, second = Register.None;
            if (!IsSystemV)
            {
                // Microsoft passes a 16-byte struct by reference, in the integer register of its position.
                if (position < 4) reg = p.IsFloat && position < variadicFrom ? Register.XMM0 + position : IntArgs[position];
            }
            else if (p.Type == ApiParamType.FloatPair) { if (floats + 2 <= FloatArgs) (reg, second) = (Register.XMM0 + floats, Register.XMM0 + floats + 1); floats += reg != Register.None ? 2 : 0; }
            else if (p.Type == ApiParamType.IntPair) { if (ints + 2 <= IntArgs.Length) (reg, second) = (IntArgs[ints], IntArgs[ints + 1]); ints += reg != Register.None ? 2 : 0; }
            else if (p.IsFloat) { if (floats < FloatArgs) reg = Register.XMM0 + floats++; }
            else if (ints < IntArgs.Length) reg = IntArgs[ints++];
            if (reg != Register.None)
            {
                string label = reg.ToString().ToLowerInvariant() + (second != Register.None ? ":" + second.ToString().ToLowerInvariant() : "");
                result.Add((Loc.Of(reg), label, second != Register.None ? Loc.Of(second) : null));
                continue;
            }
            int slot = (IsSystemV ? stack * 8 : HomeArea + 8 * (position - 4)) + shift;
            bool pairOnStack = IsSystemV && p.IsPair;
            stack += pairOnStack ? 2 : 1;
            result.Add((Loc.Stack(slot), pairOnStack ? $"[rsp+{slot:X}h]:[rsp+{slot + 8:X}h]" : $"[rsp+{slot:X}h]", pairOnStack ? Loc.Stack(slot + 8) : null));
        }
        return result;
    }

    /// <summary>The 0-based parameter position of an entry location; -1 for none.</summary>
    public int ParameterIndex(Loc entry)
    {
        if (entry.Kind == LocKind.Stack)
        {
            int first = 8 + HomeArea;
            if (entry.Slot < first || (entry.Slot - first) % 8 != 0) return -1;
            return (entry.Slot - first) / 8 + IntArgs.Length;
        }
        if (entry.Kind != LocKind.Register) return -1;
        int i = Array.IndexOf(IntArgs, entry.Reg);
        if (i >= 0) return i;
        return entry.Reg >= Register.ZMM0 && entry.Reg < Register.ZMM0 + FloatArgs ? entry.Reg - Register.ZMM0 : -1;
    }

    /// <summary>The entry location of parameter <paramref name="index"/> (an integer one unless <paramref name="isFloat"/>).</summary>
    public Loc ParameterEntry(int index, bool isFloat = false)
    {
        if (isFloat && index < FloatArgs) return Loc.Of(Register.ZMM0 + index);
        if (!isFloat && index < IntArgs.Length) return Loc.Of(IntArgs[index]);
        int regs = isFloat ? FloatArgs : IntArgs.Length;
        return Loc.Stack(8 + HomeArea + 8 * (index - regs));
    }
}
