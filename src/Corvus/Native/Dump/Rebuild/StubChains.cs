using System.Buffers.Binary;

namespace Corvus.Native.Dump.Rebuild;

/// <summary>One jump stub of a chain: where it sits, its form and where it jumps.</summary>
/// <param name="Address">Address of the stub.</param>
/// <param name="Form"><c>near</c>, <c>pointer</c>, <c>register</c> or <c>push-return</c>.</param>
/// <param name="Next">Address control moves to.</param>
public readonly record struct StubHop(ulong Address, string Form, ulong Next);

/// <summary>Where a chain of jump stubs ends.</summary>
/// <param name="Hops">Stubs followed, in order; empty when the start is not a stub.</param>
/// <param name="End"><c>final</c>, <c>unreadable</c>, <c>loop</c>, <c>limit</c> or <c>unknown</c>.</param>
/// <param name="Address">Final address, unreadable address or revisited address; null for <c>limit</c> and <c>unknown</c>.</param>
/// <param name="Detail">Reason for <c>unknown</c> and <c>limit</c>; null otherwise.</param>
public sealed record StubChain(IReadOnlyList<StubHop> Hops, string End, ulong? Address, string? Detail = null);

/// <summary>Follows x86, x64 and ARM64 jump stubs to the code control reaches.</summary>
public static class StubChains
{
    /// <summary>Most stubs followed from one start.</summary>
    public const int MaxHops = 8;

    private const int MaxInstruction = 16;

    /// <summary>
    /// Follows the stubs at <paramref name="start"/> in <paramref name="memory"/>; the chain ends at an
    /// export of <paramref name="exports"/> or at code that is not a stub. Other machines end as
    /// <c>unknown</c> naming the machine; a page the source does not hold ends as <c>unreadable</c>.
    /// </summary>
    public static StubChain Follow(IProcessMemory memory, ulong start, NativeArch machine, ExportMap exports)
    {
        List<StubHop> hops = [];
        if (machine is not (NativeArch.X86 or NativeArch.X64 or NativeArch.Arm64))
            return new StubChain(hops, "unknown", null, $"{machine} stubs are not followed");

        bool arm = machine == NativeArch.Arm64;
        bool is64 = machine != NativeArch.X86;
        HashSet<ulong> seen = [];
        var code = new byte[MaxInstruction];
        ulong at = start;
        while (true)
        {
            if (exports.NameAt(at) is not null) return new StubChain(hops, "final", at);
            if (!seen.Add(at)) return new StubChain(hops, "loop", at);

            int read = memory.ReadMemory(at, code);
            if (read == 0) return new StubChain(hops, "unreadable", at);

            ulong target;
            bool indirect;
            string form;
            if (arm)
            {
                if (!DecodeArm64(code.AsSpan(0, read), at, out form, out target, out indirect))
                    return new StubChain(hops, "final", at);
            }
            else
            {
                var change = CodeChangeKinds.Describe(code.AsSpan(0, read), [], at, is64);
                if (change.Kind != "jump" || change.Target is not ulong t)
                    return new StubChain(hops, "final", at);
                target = t;
                indirect = change.Indirect;
                form = indirect ? "pointer" : code[0] == 0x68 ? "push-return"
                    : code[0] is 0xE9 or 0xEB ? "near" : "register";
            }
            if (hops.Count >= MaxHops)
                return new StubChain(hops, "limit", null, $"more than {MaxHops} stubs");

            if (indirect)
            {
                ulong pointer = target;
                if (!memory.TryReadPointer(pointer, out target))
                    return new StubChain(hops, "unreadable", pointer);
            }
            hops.Add(new StubHop(at, form, target));
            at = target;
        }
    }

    // Matches b, ldr literal + br, adrp + ldr + br and adrp + add + br.
    // For an indirect form, target is the address of the pointer.
    private static bool DecodeArm64(ReadOnlySpan<byte> bytes, ulong pc, out string form, out ulong target, out bool indirect)
    {
        form = "";
        target = 0;
        indirect = false;
        if ((pc & 3) != 0 || bytes.Length < 4) return false;

        uint w = BinaryPrimitives.ReadUInt32LittleEndian(bytes);
        if ((w & 0xFC000000) == 0x14000000)
        {
            form = "near";
            target = pc + (ulong)(Signed(w & 0x3FFFFFF, 26) * 4);
            return true;
        }
        if ((w & 0xFF000000) == 0x58000000 && IsBr(bytes, 1, w & 31))
        {
            form = "pointer";
            indirect = true;
            target = pc + (ulong)(Signed(w >> 5 & 0x7FFFF, 19) * 4);
            return true;
        }
        if ((w & 0x9F000000) != 0x90000000 || bytes.Length < 8) return false;

        uint reg = w & 31;
        long pages = Signed((w >> 5 & 0x7FFFF) << 2 | w >> 29 & 3, 21);
        ulong page = (pc & ~0xFFFUL) + (ulong)(pages << 12);
        uint next = BinaryPrimitives.ReadUInt32LittleEndian(bytes[4..]);
        if ((next >> 5 & 31) != reg || (next & 31) != reg || !IsBr(bytes, 2, reg)) return false;

        if ((next & 0xFFC00000) == 0xF9400000)
        {
            form = "pointer";
            indirect = true;
            target = page + (next >> 10 & 0xFFF) * 8;
            return true;
        }
        if ((next & 0xFF800000) == 0x91000000)
        {
            form = "register";
            target = page + ((next >> 10 & 0xFFF) << ((next >> 22 & 1) != 0 ? 12 : 0));
            return true;
        }
        return false;
    }

    private static bool IsBr(ReadOnlySpan<byte> bytes, int index, uint reg)
    {
        if (bytes.Length < index * 4 + 4) return false;
        uint w = BinaryPrimitives.ReadUInt32LittleEndian(bytes[(index * 4)..]);
        return (w & 0xFFFFFC1F) == 0xD61F0000 && (w >> 5 & 31) == reg;
    }

    private static long Signed(uint value, int bits) => (long)((ulong)value << (64 - bits)) >> (64 - bits);
}
