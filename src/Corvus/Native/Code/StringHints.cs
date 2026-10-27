using System.Text;
using AsmArm64;
using Corvus.Native.Calls;
using Iced.Intel;

namespace Corvus.Native.Code;

/// <summary>Reads Rust &amp;str lengths and Swift small strings from one linear run; x86-64 and ARM64 only.</summary>
internal sealed class StringHints
{
    /// <summary>Instructions between the two halves of a pair at most.</summary>
    private const int Window = 6;

    /// <summary>Largest value taken as a string length.</summary>
    public const int MaxLength = 4096;

    // Integer argument registers in order: a pointer in one and its length in the next.
    private static readonly int[] SysV = [(int)Register.RDI, (int)Register.RSI, (int)Register.RDX, (int)Register.RCX, (int)Register.R8, (int)Register.R9];
    private static readonly int[] Win64 = [(int)Register.RCX, (int)Register.RDX, (int)Register.R8, (int)Register.R9];
    private static readonly int[] Aapcs64 = [Arm64Base, Arm64Base + 1, Arm64Base + 2, Arm64Base + 3, Arm64Base + 4, Arm64Base + 5, Arm64Base + 6, Arm64Base + 7];

    /// <summary>ARM64 X registers are numbered from here, apart from the x86 register numbers.</summary>
    private const int Arm64Base = 1000;

    private readonly bool _lengths, _inline;
    private readonly int[] _args;
    private readonly List<(int Reg, bool Address, ulong Value, int At)> _recent = [];
    private int _at;

    /// <summary>(data address, byte length) pairs seen in the walked code.</summary>
    public List<(uint Target, int Length)> Lengths { get; } = [];

    /// <summary>Swift small strings: the instruction that completes each one, and its text.</summary>
    public List<(uint Rva, string Text)> Inline { get; } = [];

    public StringHints(bool lengths, bool inline, NativeArch arch, ImageFormat format)
    {
        _lengths = lengths;
        _inline = inline;
        _args = arch == NativeArch.Arm64 ? Aapcs64 : format == ImageFormat.Pe ? Win64 : SysV;
    }

    public void Clear()
    {
        Lengths.Clear();
        Inline.Clear();
        BeginRun();
    }

    /// <summary>Forgets register values: a new run may be entered from anywhere.</summary>
    public void BeginRun() => _recent.Clear();

    /// <summary>Records what <paramref name="insn"/>, the last instruction <paramref name="decoder"/> decoded, writes.</summary>
    public void Observe(in Insn insn, ICodeDecoder decoder)
    {
        _at++;
        if (insn.Flow is FlowKind.Call or FlowKind.IndirectCall) { _recent.Clear(); return; }
        int reg;
        bool address = false;
        ulong value = 0;
        switch (HybridDecoder.PrimaryOf(decoder))
        {
            case X86Decoder x:
            {
                ref readonly var i = ref x.Last;
                if (i.Op0Kind != OpKind.Register) return;
                var full = i.Op0Register.GetFullRegister();
                reg = (int)full;
                if (i.Mnemonic == Mnemonic.Lea && insn.HasMem && insn.MemAccess == OperandAccess.Address && full.IsGPR64()) (address, value) = (true, insn.MemTarget);
                // A fixed-address executable moves addresses as immediates.
                else if (i.Mnemonic == Mnemonic.Mov && insn.HasImm && full.IsGPR64()) (address, value) = (true, insn.ImmTarget);
                else if (i.Mnemonic == Mnemonic.Mov && i.Op1Kind is OpKind.Immediate64 or OpKind.Immediate32to64) value = i.GetImmediate(1);
                // A 32-bit destination clears the upper half.
                else if (i.Mnemonic == Mnemonic.Mov && i.Op1Kind == OpKind.Immediate32 && i.Op0Register.IsGPR32()) value = (uint)i.GetImmediate(1);
                else { Forget(reg); return; }
                break;
            }
            case Arm64Decoder a:
            {
                var i = a.Last;
                if (A64Function.Dest(in i) is not { } dest || A64Function.Number(dest) is < 0 or >= A64Function.VBase) return;
                reg = Arm64Base + A64Function.Number(dest);
                bool w = A64Function.IsW(in i, 0);
                ulong mask = w ? 0xFFFF_FFFFUL : ulong.MaxValue;
                // adr, and add after adrp, take an address.
                if (insn.HasImm && !w) (address, value) = (true, insn.ImmTarget);
                else if (i.Mnemonic is Arm64Mnemonic.MOV or Arm64Mnemonic.MOVZ && A64Function.Imm(in i, 1) is { } imm) value = (ulong)imm & mask;
                else if (i.Mnemonic == Arm64Mnemonic.MOVN && A64Function.Imm(in i, 1) is { } inverted) value = ~(ulong)inverted & mask;
                else if (i.Mnemonic == Arm64Mnemonic.MOVK && A64Function.Imm(in i, 1) is { } part && Find(reg) is { Address: false } prior)
                {
                    int shift = i.OperandCount > 2 && i.GetOperand(2).Kind == Arm64OperandKind.Shift ? ((Arm64ShiftOperand)i.GetOperand(2)).Amount : 0;
                    ulong bits = 0xFFFFUL << shift;
                    value = ((prior.Value & ~bits) | ((ulong)part & bits)) & mask;
                }
                else { Forget(reg); return; }
                break;
            }
            default:
                return;
        }
        Forget(reg);
        _recent.RemoveAll(r => _at - r.At > Window);
        _recent.Add((reg, address, value, _at));
        if (_lengths) PairLength(reg, address, value);
        if (_inline && !address) PairInline(insn.Rva, reg, value);
    }

    private (int Reg, bool Address, ulong Value, int At)? Find(int reg)
    {
        foreach (var r in _recent) if (r.Reg == reg && _at - r.At <= Window) return r;
        return null;
    }

    private void Forget(int reg) => _recent.RemoveAll(r => r.Reg == reg);

    /// <summary>An address in one argument register and a small constant in the next make a length.</summary>
    private void PairLength(int reg, bool address, ulong value)
    {
        int k = Array.IndexOf(_args, reg);
        if (k < 0) return;
        if (address && k + 1 < _args.Length && Find(_args[k + 1]) is { Address: false, Value: >= 1 and <= MaxLength } length)
            Lengths.Add(((uint)value, (int)length.Value));
        else if (!address && value is >= 1 and <= MaxLength && k > 0 && Find(_args[k - 1]) is { Address: true } pointer)
            Lengths.Add(((uint)pointer.Value, (int)value));
    }

    /// <summary>A Swift small string: its count word (0xE0 | n ASCII, 0xA0 | n UTF-8 in the top byte) and the word with its first bytes.</summary>
    private void PairInline(uint rva, int reg, ulong value)
    {
        foreach (var other in _recent)
        {
            if (other.Reg == reg || other.Address) continue;
            if ((Small(other.Value, value) ?? Small(value, other.Value)) is { } text) { Inline.Add((rva, text)); return; }
        }
    }

    /// <summary>The text of a small string from its two words, or null when not one or shorter than <see cref="StringDetector.MinLength"/>.</summary>
    internal static string? Small(ulong first, ulong count)
    {
        byte top = (byte)(count >> 56);
        bool ascii = (top & 0xF0) == 0xE0;
        if (!ascii && (top & 0xF0) != 0xA0) return null;
        int n = top & 0x0F;
        if (n < StringDetector.MinLength) return null;
        Span<byte> bytes = stackalloc byte[15];
        for (int b = 0; b < 8; b++) bytes[b] = (byte)(first >> (8 * b));
        for (int b = 0; b < 7; b++) bytes[8 + b] = (byte)(count >> (8 * b));
        // Unused bytes are zero; used ones are text, never NUL.
        for (int b = 0; b < 15; b++)
            if ((b < n) == (bytes[b] == 0)) return null;
        var used = bytes[..n];
        if (ascii && used.ContainsAnyInRange((byte)0x80, (byte)0xFF) || !StringDetector.IsText(used)) return null;
        return Encoding.UTF8.GetString(used);
    }
}
