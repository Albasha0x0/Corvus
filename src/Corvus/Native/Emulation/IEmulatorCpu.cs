namespace Corvus.Native.Emulation;

/// <summary>One executed instruction: whether it called, from where, and where the call returns.</summary>
public readonly record struct EmulatorStep(bool IsCall, ulong Site, ulong FallThrough);

/// <summary>Where an argument of the calling convention goes: a register, or the stack at an offset from the stack pointer on entry.</summary>
public readonly record struct ArgumentSlot(string? Register, int StackOffset);

/// <summary>The registers of an instruction's memory operand and the register each held at entry once register copies are followed; a null source means code changed the register.</summary>
public readonly record struct MemoryOperandOrigin(string? Base, string? BaseSource, string? Index, string? IndexSource);

/// <summary>A processor the built-in emulator models: registers, single steps and the calling convention.</summary>
public interface IEmulatorCpu
{
    /// <summary>The instruction set, for the report ("x86-64", "x86", "AArch64").</summary>
    string Language { get; }

    int PointerSize { get; }

    ulong Pc { get; set; }

    ulong Sp { get; set; }

    /// <summary>Executes the instruction at <see cref="Pc"/>; throws <see cref="EmulatorFaultException"/>, <see cref="EmulatorTrapException"/> (pc stays on the trap) or <see cref="EmulatorUnsupportedException"/>.</summary>
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

    /// <summary>Writes the registers, flags and program counter.</summary>
    void Save(BinaryWriter w);

    /// <summary>Restores what <see cref="Save"/> wrote.</summary>
    void Load(BinaryReader r);

    /// <summary>The memory operand of the last instruction with its registers traced to entry; null when the processor does not trace it or the history is too short.</summary>
    MemoryOperandOrigin? LastMemoryOperand => null;

    /// <summary>The places of the first <paramref name="count"/> integer arguments.</summary>
    IReadOnlyList<ArgumentSlot> Arguments(int count);
}
