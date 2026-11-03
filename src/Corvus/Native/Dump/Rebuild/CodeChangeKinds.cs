using Iced.Intel;

namespace Corvus.Native.Dump.Rebuild;

/// <summary>How a changed code range reads: a transfer to a target address, or plain bytes.</summary>
/// <param name="Kind"><c>jump</c>, <c>call</c> or <c>bytes</c>.</param>
/// <param name="Target">Branch target, or the address of the pointer an indirect jump reads; null for <c>bytes</c>.</param>
/// <param name="Indirect">True when <paramref name="Target"/> is the address of a pointer, not of code.</param>
public readonly record struct CodeChange(string Kind, ulong? Target, bool Indirect);

/// <summary>Describes a changed code range as a jump or call over the original code.</summary>
public static class CodeChangeKinds
{
    /// <summary>Kind of a range that is not a recognized transfer.</summary>
    public const string Bytes = "bytes";

    /// <summary>
    /// Reads the code in <paramref name="memory"/> as it stands at <paramref name="address"/>;
    /// returns <c>bytes</c> without a target when it equals <paramref name="file"/>, is empty,
    /// or does not begin with <c>E9</c>, <c>E8</c>, <c>EB</c>, <c>FF 25</c>, a 64-bit load of an
    /// immediate and <c>FF E0</c>, or <c>68</c> and <c>C3</c>.
    /// </summary>
    public static CodeChange Describe(ReadOnlySpan<byte> memory, ReadOnlySpan<byte> file, ulong address, bool is64)
    {
        var plain = new CodeChange(Bytes, null, false);
        if (memory.IsEmpty || memory.SequenceEqual(file)) return plain;

        var decoder = Decoder.Create(is64 ? 64 : 32, new ByteArrayCodeReader(memory.ToArray()), address);
        var first = decoder.Decode();
        if (first.IsInvalid) return plain;

        if (first.Mnemonic is Mnemonic.Jmp or Mnemonic.Call)
        {
            var kind = first.Mnemonic == Mnemonic.Jmp ? "jump" : "call";
            switch (first.Op0Kind)
            {
                case OpKind.NearBranch16:
                case OpKind.NearBranch32:
                case OpKind.NearBranch64:
                    return new CodeChange(kind, first.NearBranchTarget, false);
                case OpKind.Memory when first.IsIPRelativeMemoryOperand:
                    return new CodeChange(kind, first.IPRelativeMemoryAddress, true);
                case OpKind.Memory when first.MemoryBase == Register.None && first.MemoryIndex == Register.None:
                    return new CodeChange(kind, first.MemoryDisplacement64, true);
            }
            return plain;
        }

        if (first.Mnemonic == Mnemonic.Push && first.Op0Kind is OpKind.Immediate32 or OpKind.Immediate32to64)
        {
            var second = decoder.Decode();
            if (second.Mnemonic == Mnemonic.Ret && second.OpCount == 0)
                return new CodeChange("jump", first.GetImmediate(0), false);
            return plain;
        }

        if (is64 && first.Mnemonic == Mnemonic.Mov && first.Op0Kind == OpKind.Register
            && first.Op1Kind == OpKind.Immediate64)
        {
            var second = decoder.Decode();
            if (second.Mnemonic == Mnemonic.Jmp && second.Op0Kind == OpKind.Register
                && second.Op0Register == first.Op0Register)
                return new CodeChange("jump", first.Immediate64, false);
        }
        return plain;
    }
}
