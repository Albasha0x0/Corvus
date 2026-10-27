namespace Corvus.Native.Emulation;

/// <summary>One executed instruction: whether it called, from where, and where the call returns.</summary>
public readonly record struct EmulatorStep(bool IsCall, ulong Site, ulong FallThrough);

/// <summary>Where an argument of the calling convention goes: a register, or the stack at an offset from the stack pointer on entry.</summary>
public readonly record struct ArgumentSlot(string? Register, int StackOffset);

/// <summary>A processor the built-in emulator models: registers, single steps and the calling convention.</summary>
public interface IEmulatorCpu
{
    /// <summary>The instruction set, for the report ("x86-64", "x86", "AArch64").</summary>
    string Language { get; }

    int PointerSize { get; }

    ulong Pc { get; set; }

    ulong Sp { get; set; }

    /// <summary>Executes the instruction at <see cref="Pc"/>; throws <see cref="EmulatorFaultException"/> or <see cref="EmulatorUnsupportedException"/>.</summary>
    EmulatorStep Step(EmulatorMemory m);

    /// <summary>The last instruction decoded, as disassembly text.</summary>
    string LastText { get; }

    /// <summary>The general registers reported after a run.</summary>
    IReadOnlyList<string> MainRegisters { get; }

    string ReturnRegister { get; }

    /// <summary>Reads a register by name (case ignored); false for an unknown name.</summary>
    bool TryGet(string name, out ulong value);

    /// <summary>Writes a register by name (case ignored); false for an unknown name.</summary>
    bool TrySet(string name, ulong value);

    /// <summary>Makes a return from the code at <see cref="Pc"/> land on <paramref name="sentinel"/>.</summary>
    void SetReturnAddress(EmulatorMemory memory, ulong sentinel);

    /// <summary>Returns from an entered call without running it: <paramref name="value"/> in the return register, <paramref name="purge"/> argument bytes popped on x86.</summary>
    void ReturnFromCall(EmulatorMemory memory, ulong value, int purge);

    /// <summary>The places of the first <paramref name="count"/> integer arguments.</summary>
    IReadOnlyList<ArgumentSlot> Arguments(int count);
}
