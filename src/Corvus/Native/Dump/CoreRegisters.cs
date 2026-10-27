namespace Corvus.Native.Dump;

/// <summary>A core architecture's register file; slots are DWARF register numbers, <see cref="Pc"/> an extra slot except on x86 and x64.</summary>
public sealed class CoreArch
{
    private CoreArch(NativeArch arch, string name, bool is64, bool bigEndian, string[] names, int pc, int sp, int fp, int returnColumn, int? link, bool unwinds)
    {
        Arch = arch;
        Name = name;
        Is64 = is64;
        BigEndian = bigEndian;
        Names = names;
        Pc = pc;
        Sp = sp;
        Fp = fp;
        ReturnColumn = returnColumn;
        Link = link;
        Unwinds = unwinds;
    }

    public NativeArch Arch { get; }
    public string Name { get; }
    public bool Is64 { get; }
    public bool BigEndian { get; }
    /// <summary>Register names by slot.</summary>
    public string[] Names { get; }
    public int Count => Names.Length;
    public int Pc { get; }
    public int Sp { get; }
    public int Fp { get; }
    /// <summary>The CFI column of the return address.</summary>
    public int ReturnColumn { get; }
    /// <summary>The link register (ARM, AArch64), or null where calls push the return address.</summary>
    public int? Link { get; }
    /// <summary>Stacks are walked (CFI and frame pointer).</summary>
    public bool Unwinds { get; }
    /// <summary>Slots below this are DWARF registers; CFI rules for higher numbers (vector registers) are ignored.</summary>
    public int DwarfCount => Name switch { "x64" => 17, "x86" => 9, "ARM64" => 32, "ARM" => 16, "ppc64" or "ppc64le" => 32, "s390x" => 16, "riscv64" => 32, _ => 0 };

    /// <summary>The slot of DWARF register <paramref name="dwarf"/>, or -1 when it is not kept (vector and floating-point registers).</summary>
    public int Slot(int dwarf) => dwarf >= 0 && dwarf < DwarfCount ? dwarf
        : Arch == NativeArch.PowerPc ? dwarf switch { 65 => 33, 66 => 34, _ => -1 } : -1;
    public int PointerSize => Is64 ? 8 : 4;

    public static readonly CoreArch X64 = new(NativeArch.X64, "x64", true, false,
        ["rax", "rdx", "rcx", "rbx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip", "eflags", "fs_base", "gs_base"],
        16, 7, 6, 16, null, true);

    public static readonly CoreArch X86 = new(NativeArch.X86, "x86", false, false,
        ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "eip", "eflags"], 8, 4, 5, 8, null, true);

    public static readonly CoreArch Arm64 = new(NativeArch.Arm64, "ARM64", true, false,
        [.. Enumerable.Range(0, 29).Select(i => $"x{i}"), "fp", "lr", "sp", "pc", "pstate"], 32, 31, 29, 30, 30, true);

    public static readonly CoreArch Arm = new(NativeArch.Arm, "ARM", false, false,
        [.. Enumerable.Range(0, 11).Select(i => $"r{i}"), "fp", "ip", "sp", "lr", "pc", "cpsr"], 15, 13, 11, 14, 14, true);

    public static CoreArch Ppc64(bool bigEndian) => new(NativeArch.PowerPc, bigEndian ? "ppc64" : "ppc64le", true, bigEndian,
        [.. Enumerable.Range(0, 32).Select(i => $"r{i}"), "nip", "lr", "ctr", "msr"], 32, 1, 31, 33, 33, true);

    public static readonly CoreArch S390x = new(NativeArch.Other, "s390x", true, true,
        [.. Enumerable.Range(0, 16).Select(i => $"r{i}"), "psw_addr", "psw_mask"], 16, 15, 11, 14, 14, true);

    public static readonly CoreArch RiscV64 = new(NativeArch.RiscV, "riscv64", true, false,
        ["zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", .. Enumerable.Range(0, 8).Select(i => $"a{i}"), .. Enumerable.Range(2, 10).Select(i => $"s{i}"),
         "t3", "t4", "t5", "t6", "pc"], 32, 2, 8, 1, 1, true);

    /// <summary>The register file for e_machine, or null when the core's machine is not read.</summary>
    public static CoreArch? For(ushort machine, bool is64, bool bigEndian) => machine switch
    {
        62 when is64 => X64,
        3 when !is64 => X86,
        183 when is64 => Arm64,
        40 when !is64 => Arm,
        21 when is64 => Ppc64(bigEndian),
        22 when is64 => S390x,
        243 when is64 => RiscV64,
        _ => null,
    };

    /// <summary>Slot of each pr_reg word (elf_gregset_t order), -1 for words not kept.</summary>
    internal int[] GregMap => Name switch
    {
        // r15 r14 r13 r12 rbp rbx r11 r10 r9 r8 rax rcx rdx rsi rdi orig_rax rip cs eflags rsp ss fs_base gs_base
        "x64" => [15, 14, 13, 12, 6, 3, 11, 10, 9, 8, 0, 2, 1, 4, 5, -1, 16, -1, 17, 7, -1, 18, 19],
        // ebx ecx edx esi edi ebp eax ds es fs gs orig_eax eip cs eflags esp
        "x86" => [3, 1, 2, 6, 7, 5, 0, -1, -1, -1, -1, -1, 8, -1, 9, 4],
        "ARM64" => [.. Enumerable.Range(0, 34)],
        "ARM" => [.. Enumerable.Range(0, 17)],
        // gpr0-31 nip msr orig_gpr3 ctr link
        "ppc64" or "ppc64le" => [.. Enumerable.Range(0, 32), 32, 35, -1, 34, 33],
        // psw mask, psw addr, gpr0-15
        "s390x" => [17, 16, .. Enumerable.Range(0, 16)],
        // pc, x1-x31
        "riscv64" => [32, .. Enumerable.Range(1, 31)],
        _ => [],
    };
}

/// <summary>A thread's registers from NT_PRSTATUS, by <see cref="CoreArch"/> slot; slots the unwinder could not recover are unknown.</summary>
public sealed class CoreRegisters
{
    private readonly ulong[] values;
    private readonly bool[] known;

    public CoreRegisters(CoreArch arch)
    {
        Arch = arch;
        values = new ulong[arch.Count];
        known = new bool[arch.Count];
    }

    public CoreArch Arch { get; }
    public bool Complete { get; set; } = true;

    public ulong Pc { get => values[Arch.Pc]; set => Set(Arch.Pc, value); }
    public ulong Sp { get => values[Arch.Sp]; set => Set(Arch.Sp, value); }

    public bool IsKnown(int slot) => slot >= 0 && slot < values.Length && known[slot];

    public bool TryGet(int slot, out ulong value)
    {
        value = slot >= 0 && slot < values.Length ? values[slot] : 0;
        return IsKnown(slot);
    }

    public void Set(int slot, ulong value)
    {
        if (slot < 0 || slot >= values.Length) return;
        values[slot] = Arch.Is64 ? value : value & 0xFFFFFFFF;
        known[slot] = true;
    }

    public void Forget(int slot)
    {
        if (slot >= 0 && slot < values.Length) known[slot] = false;
    }

    public CoreRegisters Clone()
    {
        var c = new CoreRegisters(Arch) { Complete = Complete };
        values.CopyTo(c.values, 0);
        known.CopyTo(c.known, 0);
        return c;
    }

    /// <summary>pr_reg (elf_gregset_t) as the kernel writes it.</summary>
    internal static CoreRegisters Parse(CoreArch arch, ByteView greg)
    {
        var r = new CoreRegisters(arch);
        var map = arch.GregMap;
        int word = arch.PointerSize;
        r.Complete = greg.Length >= (long)map.Length * word;
        for (int i = 0; i < map.Length; i++)
            if (map[i] >= 0 && greg.Has((long)i * word, word)) r.Set(map[i], greg.Word((long)i * word, arch.Is64));
        if (arch == CoreArch.RiscV64) r.Set(0, 0);
        return r;
    }

    /// <summary>"name=value" for every known register, in slot order.</summary>
    public string Format()
    {
        string width = Arch.Is64 ? "x16" : "x8";
        return string.Join(" ", Enumerable.Range(0, values.Length).Where(i => known[i]).Select(i => $"{Arch.Names[i]}={values[i].ToString(width)}"));
    }
}
