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

/// <summary>Follows x86 and x64 jump stubs to the code control reaches.</summary>
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
        if (machine is not (NativeArch.X86 or NativeArch.X64))
            return new StubChain(hops, "unknown", null, $"{machine} stubs are not followed");

        bool is64 = machine == NativeArch.X64;
        HashSet<ulong> seen = [];
        var code = new byte[MaxInstruction];
        ulong at = start;
        while (true)
        {
            if (exports.NameAt(at) is not null) return new StubChain(hops, "final", at);
            if (!seen.Add(at)) return new StubChain(hops, "loop", at);

            int read = memory.ReadMemory(at, code);
            if (read == 0) return new StubChain(hops, "unreadable", at);

            var change = CodeChangeKinds.Describe(code.AsSpan(0, read), [], at, is64);
            if (change.Kind != "jump" || change.Target is not ulong target)
                return new StubChain(hops, "final", at);
            if (hops.Count >= MaxHops)
                return new StubChain(hops, "limit", null, $"more than {MaxHops} stubs");

            string form = change.Indirect ? "pointer" : code[0] == 0x68 ? "push-return"
                : code[0] is 0xE9 or 0xEB ? "near" : "register";
            if (change.Indirect)
            {
                ulong pointer = target;
                if (!memory.TryReadPointer(pointer, out target))
                    return new StubChain(hops, "unreadable", pointer);
            }
            hops.Add(new StubHop(at, form, target));
            at = target;
        }
    }
}
