using Iced.Intel;

namespace Corvus.Native.Code;

/// <summary>Matches a slot-indexed vtable tail-call helper.</summary>
internal static class VirtualInvokerShape
{
    /// <summary>Name prefix of a matched helper; the suffix is its RVA in hex.</summary>
    internal const string NamePrefix = "VirtualSlotInvoker_";

    /// <summary>
    /// True for straight-line x86 / x64 code that loads the class, adds a
    /// scaled slot and jumps through the entry; false otherwise.
    /// </summary>
    internal static bool Matches(ReadOnlySpan<byte> code, bool is64, ulong address)
    {
        var bytes = code.ToArray();
        var decoder = Decoder.Create(is64 ? 64 : 32, new ByteArrayCodeReader(bytes), address, DecoderOptions.None);
        int scaleShift = is64 ? 3 : 2, scale = is64 ? 8 : 4;
        Register classReg = Register.None, slotReg = Register.None;
        bool combined = false;
        int count = 0;
        while (decoder.IP < address + (ulong)bytes.Length)
        {
            var i = decoder.Decode();
            if (i.IsInvalid || ++count > 16) return false;
            bool last = decoder.IP >= address + (ulong)bytes.Length;
            if (last)
            {
                if (!combined || i.Mnemonic != Mnemonic.Jmp || i.FlowControl != FlowControl.IndirectBranch) return false;
                if (i.Op0Kind != OpKind.Memory || i.MemoryIndex != Register.None || !IsGeneral(i.MemoryBase)) return false;
                long disp = is64 ? (long)i.MemoryDisplacement64 : (int)i.MemoryDisplacement32;
                return Full(i.MemoryBase) == classReg && disp >= 0x20;
            }
            if (i.FlowControl != FlowControl.Next) return false;
            if (i.Mnemonic == Mnemonic.Mov && i.Op0Kind == OpKind.Register && i.Op1Kind == OpKind.Memory
                && i.MemoryIndex == Register.None && IsGeneral(i.MemoryBase) && i.MemoryDisplacement64 == 0)
                classReg = Full(i.Op0Register);
            else if (i.Mnemonic == Mnemonic.Shl && i.Op0Kind == OpKind.Register && i.Op1Kind == OpKind.Immediate8
                && (i.Immediate8 == scaleShift || i.Immediate8 == scaleShift + 1))
                slotReg = Full(i.Op0Register);
            else if (i.Mnemonic == Mnemonic.Imul && i.OpCount == 3 && i.Op0Kind == OpKind.Register
                && i.Op2Kind == OpKind.Immediate8 && (i.Immediate8 == scale || i.Immediate8 == scale * 2))
                slotReg = Full(i.Op0Register);
            else if (i.Mnemonic == Mnemonic.Add && classReg != Register.None && slotReg != Register.None
                && i.Op0Kind == OpKind.Register && i.Op1Kind == OpKind.Register
                && Full(i.Op0Register) == classReg && Full(i.Op1Register) == slotReg)
                combined = true;
            else if (i.Mnemonic == Mnemonic.Lea && classReg != Register.None && i.Op0Kind == OpKind.Register
                && i.MemoryIndex != Register.None && i.MemoryIndexScale == scale && i.MemoryDisplacement64 == 0
                && Full(i.MemoryBase) == classReg && Full(i.Op0Register) == classReg)
                combined = true;
        }
        return false;
    }

    private static Register Full(Register r) => r.GetFullRegister();

    private static bool IsGeneral(Register r) => r != Register.None && r != Register.RIP && r != Register.EIP;
}
