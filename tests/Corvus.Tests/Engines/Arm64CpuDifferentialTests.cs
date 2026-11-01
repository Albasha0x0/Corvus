using System.Buffers.Binary;
using System.Runtime.InteropServices;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Emulation;
using Corvus.Native.Providers;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>A fact that runs only on a Windows ARM64 host.</summary>
public sealed class WindowsArm64FactAttribute : FactAttribute
{
    public WindowsArm64FactAttribute()
    {
        if (!OperatingSystem.IsWindows() || RuntimeInformation.ProcessArchitecture != Architecture.Arm64)
            Skip = "not a Windows ARM64 host";
    }
}


/// <summary>
/// Random A64 integer sequences leave the same registers, flags and memory in
/// <see cref="Arm64Cpu"/> and on a reference: an ARM64 host processor, or QEMU
/// user mode (CORVUS_QEMU_AARCH64, a Linux host or a wrapper script). QEMU is
/// an independent software model, not silicon.
/// </summary>
public sealed class Arm64CpuDifferentialTests(ITestOutputHelper output)
{
    private const ulong Base = 0x400000;
    private const int Registers = 8, Flags = 4, ScratchBytes = 64;
    // Registers, then N, Z, C, V as 0 or 1, then the scratch bytes.
    private const int ScratchAt = (Registers + Flags) * 8, StateBytes = ScratchAt + ScratchBytes;

    private delegate void Sequence(IntPtr state);

    private static class Kernel32
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAlloc(IntPtr address, nuint size, uint type, uint protect);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool VirtualFree(IntPtr address, nuint size, uint type);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool FlushInstructionCache(IntPtr process, IntPtr address, nuint size);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetCurrentProcess();
    }

    private static uint U(int v) => (uint)v;

    // Immediate of a logical instruction: an element of 2 to 64 bits holding
    // a rotated run of ones, repeated.
    private static (uint N, uint Immr, uint Imms) BitmaskImmediate(Random rng, bool sf)
    {
        int log = rng.Next(1, sf ? 7 : 6), size = 1 << log;
        int ones = rng.Next(1, size), rotation = rng.Next(size);
        uint imms = (uint)((-2 * size & 0x3F) | (ones - 1));
        return (size == 64 ? 1u : 0u, U(rotation), imms & 0x3F);
    }

    /// <summary>
    /// One random sequence: state pointer in x0, registers loaded from it,
    /// operations, then registers, flags and scratch stored back.
    /// </summary>
    private static (byte[] Code, List<uint> Words) Generate(Random rng, int count)
    {
        var w = new List<uint> { 0xAA0003E8 };
        // Load x0..x7 from the state through x8, then set the flags from the
        // inputs with subs xzr, x0, x1.
        for (int i = 0; i < Registers; i++) w.Add(0xF9400000 | U(i) << 10 | 8u << 5 | U(i));
        w.Add(0xEB01001F);
        int R() => rng.Next(Registers);
        for (int n = 0; n < count; n++)
        {
            bool sf = rng.Next(2) == 0;
            uint s = sf ? 0x80000000 : 0, d = U(R()), a = U(R()), b = U(R()), op = U(rng.Next(2)), flagged = U(rng.Next(2));
            int bits = sf ? 64 : 32;
            switch (rng.Next(16))
            {
                case 0:
                    w.Add(s | op << 30 | flagged << 29 | 0x11000000 | U(rng.Next(2)) << 22 | U(rng.Next(4096)) << 10 | a << 5 | d);
                    break;
                case 1:
                    w.Add(s | op << 30 | flagged << 29 | 0x0B000000 | U(rng.Next(3)) << 22 | b << 16 | U(rng.Next(bits)) << 10 | a << 5 | d);
                    break;
                case 2:
                    w.Add(s | op << 30 | flagged << 29 | 0x0B200000 | b << 16 | U(rng.Next(8)) << 13 | U(rng.Next(5)) << 10 | a << 5 | d);
                    break;
                case 3:
                {
                    var (nBit, immr, imms) = BitmaskImmediate(rng, sf);
                    w.Add(s | U(rng.Next(4)) << 29 | 0x12000000 | nBit << 22 | immr << 16 | imms << 10 | a << 5 | d);
                    break;
                }
                case 4:
                    w.Add(s | (uint)(new[] { 0, 2, 3 }[rng.Next(3)]) << 29 | 0x12800000 | U(rng.Next(sf ? 4 : 2)) << 21 | U(rng.Next(0x10000)) << 5 | d);
                    break;
                case 5:
                    w.Add(s | U(rng.Next(3)) << 29 | 0x13000000 | (sf ? 1u : 0u) << 22 | U(rng.Next(bits)) << 16 | U(rng.Next(bits)) << 10 | a << 5 | d);
                    break;
                case 6:
                    w.Add(s | 0x13800000 | (sf ? 1u : 0u) << 22 | b << 16 | U(rng.Next(bits)) << 10 | a << 5 | d);
                    break;
                case 7:
                    w.Add(s | U(rng.Next(4)) << 29 | 0x0A000000 | U(rng.Next(4)) << 22 | U(rng.Next(2)) << 21 | b << 16 | U(rng.Next(bits)) << 10 | a << 5 | d);
                    break;
                case 8:
                    w.Add(s | op << 30 | flagged << 29 | 0x1A000000 | b << 16 | a << 5 | d);
                    break;
                case 9:
                {
                    bool immediate = rng.Next(2) == 0;
                    w.Add(s | op << 30 | 1u << 29 | 0x1A400000 | (immediate ? U(rng.Next(32)) : b) << 16 | U(rng.Next(16)) << 12 | (immediate ? 1u : 0) << 11 | a << 5 | U(rng.Next(16)));
                    break;
                }
                case 10:
                    w.Add(s | op << 30 | 0x1A800000 | b << 16 | U(rng.Next(16)) << 12 | U(rng.Next(2)) << 10 | a << 5 | d);
                    break;
                case 11:
                    w.Add(s | 0x1AC00000 | b << 16 | (uint)(new[] { 2, 3, 8, 9, 10, 11 }[rng.Next(6)]) << 10 | a << 5 | d);
                    break;
                case 12:
                    // Reverse bits, reverse bytes (16, 32, 64) and count leading
                    // zero or sign bits.
                    w.Add(s | 0x5AC00000 | (sf ? new uint[] { 0, 1, 2, 3, 4, 5 } : new uint[] { 0, 1, 2, 4, 5 })[rng.Next(sf ? 6 : 5)] << 10 | a << 5 | d);
                    break;
                case 13:
                {
                    // MADD, MSUB, SMADDL, SMSUBL, UMADDL, UMSUBL, SMULH, UMULH.
                    // The high multiplies take Ra as the zero register.
                    int form = rng.Next(sf ? 4 : 1);
                    uint op31 = form switch { 0 => 0u, 1 => 1u, 2 => 5u, _ => rng.Next(2) == 0 ? 2u : 6u };
                    uint ra = form == 3 ? 31 : rng.Next(3) == 0 ? 31 : U(R());
                    w.Add(s | 0x1B000000 | op31 << 21 | b << 16 | (form == 3 ? 0 : op) << 15 | ra << 10 | a << 5 | d);
                    break;
                }
                case 14:
                {
                    // Scratch loads and stores through x8: STRB/STRH/STR,
                    // LDRB/LDRH/LDR and the sign-extending loads.
                    uint size = U(rng.Next(4)), kind = U(rng.Next(3));
                    uint opc = kind switch { 0 => 0u, 1 => 1u, _ => size == 3 ? 1u : size == 2 ? 2u : 2u + U(rng.Next(2)) };
                    int bytes = 1 << (int)size;
                    uint slot = U(ScratchAt / bytes + rng.Next(ScratchBytes / bytes));
                    w.Add(size << 30 | 0x39000000 | opc << 22 | slot << 10 | 8u << 5 | d);
                    break;
                }
                default:
                {
                    // LDP or STP, signed offset, within the scratch bytes.
                    int bytes = sf ? 8 : 4;
                    uint rt2 = U((int)(d + 1 + U(rng.Next(Registers - 1))) % Registers);
                    uint load = U(rng.Next(2)), slot = U((ScratchAt / bytes + rng.Next(ScratchBytes / bytes - 1)) & 0x7F);
                    w.Add((sf ? 0xA9000000 : 0x29000000) | load << 22 | slot << 15 | rt2 << 10 | 8u << 5 | d);
                    break;
                }
            }
        }
        for (int i = 0; i < Registers; i++) w.Add(0xF9000000 | U(i) << 10 | 8u << 5 | U(i));
        // CSET w9..w12 on mi, eq, hs, vs is CSINC on the inverse condition.
        uint[] inverse = [5, 1, 3, 7];
        for (int i = 0; i < Flags; i++) w.Add(0x1A9F07E0 | inverse[i] << 12 | U(9 + i));
        for (int i = 0; i < Flags; i++) w.Add(0xF9000000 | U(Registers + i) << 10 | 8u << 5 | U(9 + i));
        w.Add(0xD65F03C0);
        var code = new byte[w.Count * 4];
        for (int i = 0; i < w.Count; i++) BinaryPrimitives.WriteUInt32LittleEndian(code.AsSpan(i * 4), w[i]);
        return (code, w);
    }

    private static string Disassemble(IEnumerable<uint> words) =>
        string.Join("; ", words.Select(x => AsmArm64.Arm64Instruction.Decode(x).ToString() ?? $".word 0x{x:x8}"));

    private static byte[] RandomState(Random rng)
    {
        var state = new byte[StateBytes];
        for (int i = 0; i < Registers; i++)
            BinaryPrimitives.WriteUInt64LittleEndian(state.AsSpan(i * 8), rng.Next(5) switch
            {
                0 => 0UL,
                1 => ulong.MaxValue,
                2 => 0x8000000000000000UL >> rng.Next(64),
                _ => (ulong)rng.NextInt64() ^ ((ulong)rng.Next(2) << 63),
            });
        rng.NextBytes(state.AsSpan(ScratchAt));
        return state;
    }

    private static uint MovZ(int rd, uint imm16, int half = 0) => 0xD2800000 | U(half) << 21 | imm16 << 5 | U(rd);

    private static uint MovK(int rd, uint imm16, int half) => 0xF2800000 | U(half) << 21 | imm16 << 5 | U(rd);

    private const uint Svc = 0xD4000001;

    /// <summary>
    /// A static AArch64 Linux executable of one read-write-execute segment. A
    /// stub calls the sequence with the state pointer in x0, writes the state
    /// to standard output (write, 64) and exits (exit, 93). The sequence and
    /// the state follow the stub.
    /// </summary>
    private static byte[] DriverImage(byte[] code, byte[] state)
    {
        const int Header = 64 + 56, StubWords = 12;
        int sequenceAt = Header + StubWords * 4, stateAt = (sequenceAt + code.Length + 15) & ~15, length = stateAt + StateBytes;
        ulong statePointer = Base + (ulong)stateAt;
        int callAt = Header + 3 * 4;
        uint[] stub =
        [
            MovZ(19, (uint)(statePointer & 0xFFFF)), MovK(19, (uint)(statePointer >> 16 & 0xFFFF), 1),
            // The state pointer lives in x19, which the sequence leaves intact.
            0xAA1303E0,
            0x94000000 | (uint)((sequenceAt - callAt) / 4) & 0x3FFFFFF,
            MovZ(0, 1),
            0xAA1303E1,
            MovZ(2, StateBytes), MovZ(8, 64), Svc,
            MovZ(0, 0), MovZ(8, 93), Svc,
        ];
        var image = new byte[length];
        "\u007fELF"u8.CopyTo(image);
        image[4] = 2;
        image[5] = 1;
        image[6] = 1;
        BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(16), 2);
        BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(18), 183);
        BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(20), 1);
        BinaryPrimitives.WriteUInt64LittleEndian(image.AsSpan(24), Base + Header);
        BinaryPrimitives.WriteUInt64LittleEndian(image.AsSpan(32), 64);
        BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(52), 64);
        BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(54), 56);
        BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(56), 1);
        // PT_LOAD, flags read-write-execute, the whole file at Base.
        BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(64), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(68), 7);
        BinaryPrimitives.WriteUInt64LittleEndian(image.AsSpan(80), Base);
        BinaryPrimitives.WriteUInt64LittleEndian(image.AsSpan(88), Base);
        BinaryPrimitives.WriteUInt64LittleEndian(image.AsSpan(96), (ulong)length);
        BinaryPrimitives.WriteUInt64LittleEndian(image.AsSpan(104), (ulong)length);
        BinaryPrimitives.WriteUInt64LittleEndian(image.AsSpan(112), 0x1000);
        for (int i = 0; i < stub.Length; i++) BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(Header + i * 4), stub[i]);
        code.CopyTo(image, sequenceAt);
        state.CopyTo(image, stateAt);
        return image;
    }

    private static byte[] OnHost(byte[] code, byte[] input)
    {
        // Flags: MEM_COMMIT | MEM_RESERVE (0x3000), PAGE_EXECUTE_READWRITE (0x40).
        var page = Kernel32.VirtualAlloc(IntPtr.Zero, (nuint)code.Length, 0x3000, 0x40);
        Assert.NotEqual(IntPtr.Zero, page);
        var state = Marshal.AllocHGlobal(StateBytes);
        try
        {
            Marshal.Copy(code, 0, page, code.Length);
            Assert.True(Kernel32.FlushInstructionCache(Kernel32.GetCurrentProcess(), page, (nuint)code.Length));
            Marshal.Copy(input, 0, state, StateBytes);
            Marshal.GetDelegateForFunctionPointer<Sequence>(page)(state);
            var result = new byte[StateBytes];
            Marshal.Copy(state, result, 0, StateBytes);
            return result;
        }
        finally
        {
            Marshal.FreeHGlobal(state);
            Kernel32.VirtualFree(page, 0, 0x8000);
        }
    }

    private const ulong Region = 0x7ffe00000000, StateAddress = Region + 0x100000, Sentinel = Region + 0x1F0000;

    private static (EmulatorMemory Memory, Arm64Cpu Cpu) Prepare(byte[] code, byte[] input)
    {
        var image = new RawCodeImage(code, "sequence.bin", RawLayout.Parse("arm64", $"0x{Base:x}", null, code.Length));
        var memory = new EmulatorMemory(image, Base, Region, 0x200000);
        var cpu = new Arm64Cpu { Pc = Base, Sp = Region + 0xFF000 };
        memory.Write(StateAddress, input);
        cpu.TrySet("x0", StateAddress);
        cpu.SetReturnAddress(memory, Sentinel);
        return (memory, cpu);
    }

    private static byte[] InEmulator(byte[] code, byte[] input)
    {
        var (memory, cpu) = Prepare(code, input);
        for (int steps = 0; cpu.Pc != Sentinel; steps++)
        {
            Assert.True(steps < 10_000, "the sequence did not return");
            cpu.Step(memory);
        }
        var result = new byte[StateBytes];
        memory.Read(StateAddress, result);
        return result;
    }

    private static string Differences(byte[] reference, byte[] emulated)
    {
        var lines = new List<string>();
        for (int i = 0; i < Registers; i++)
            if (!reference.AsSpan(i * 8, 8).SequenceEqual(emulated.AsSpan(i * 8, 8)))
                lines.Add($"x{i}: reference 0x{BinaryPrimitives.ReadUInt64LittleEndian(reference.AsSpan(i * 8)):x}, emulator 0x{BinaryPrimitives.ReadUInt64LittleEndian(emulated.AsSpan(i * 8)):x}");
        string[] names = ["N", "Z", "C", "V"];
        for (int i = 0; i < Flags; i++)
            if (!reference.AsSpan((Registers + i) * 8, 8).SequenceEqual(emulated.AsSpan((Registers + i) * 8, 8)))
                lines.Add($"{names[i]}: reference {reference[(Registers + i) * 8]}, emulator {emulated[(Registers + i) * 8]}");
        if (!reference.AsSpan(ScratchAt).SequenceEqual(emulated.AsSpan(ScratchAt)))
            lines.Add($"scratch: reference {Convert.ToHexString(reference.AsSpan(ScratchAt))}, emulator {Convert.ToHexString(emulated.AsSpan(ScratchAt))}");
        return string.Join("; ", lines);
    }

    private void Compare(string reference, int rounds, Func<byte[], byte[], byte[]> run)
    {
        var rng = new Random(20261101);
        int operations = 0;
        for (int round = 0; round < rounds; round++)
        {
            var (code, words) = Generate(rng, rng.Next(1, 40));
            var input = RandomState(rng);
            var expected = run(code, input);
            var difference = Differences(expected, InEmulator(code, input));
            Assert.True(difference.Length == 0, $"round {round} against {reference}: {difference}; input {Convert.ToHexString(input)}; code {Disassemble(words)}");
            operations += words.Count;
        }
        output.WriteLine($"{rounds} sequences, {operations} instructions agree with {reference}");
    }

    [WindowsArm64Fact]
    public void Random_integer_sequences_match_the_host_processor()
    {
        // The sequences are called through the Windows ARM64 convention.
        Compare("the host processor", 400, OnHost);
    }

    // Needs a Linux host or a wrapper script that runs qemu-aarch64.
    [Trait("Speed", "Slow")]
    [RequiresRealDataFact("CORVUS_QEMU_AARCH64")]
    public void Random_integer_sequences_match_qemu_user_mode()
    {
        using var dir = new TempDir();
        var tool = ExternalTools.Locate(ExternalTools.QemuUser)!.Value.Path;
        int run = 0;
        Compare("QEMU user mode", 200, (code, input) =>
        {
            var path = dir.File($"driver-{run++}.elf");
            File.WriteAllBytes(path, DriverImage(code, input));
            var result = ExternalTools.Run(
                tool,
                ExternalTools.Arguments(ExternalTools.QemuUser, "run", ("file", path)),
                Timeout.InfiniteTimeSpan,
                1 << 16,
                default,
                watch: new ExternalTools.Watch(new StallRule(ServerOptions.StallWindow())));
            Assert.True(result.ExitCode == 0 && result.Output.Length == StateBytes && result.StalledAt is null && !result.Truncated,
                $"exit {result.ExitCode}, {result.Output.Length} bytes, stalled at {result.StalledAt}, truncated {result.Truncated}: {result.Stderr}{result.StartError}");
            return result.Output;
        });
    }

    [Fact]
    public void Every_generated_form_runs_in_the_built_in_emulator()
    {
        var rng = new Random(7);
        int instructions = 0;
        for (int round = 0; round < 300; round++)
        {
            var (code, words) = Generate(rng, 40);
            try
            {
                InEmulator(code, RandomState(rng));
            }
            catch (Exception ex) when (ex is EmulatorUnsupportedException or EmulatorFaultException)
            {
                Assert.Fail($"round {round}: {ex.Message}; code {Disassemble(words)}");
            }
            instructions += words.Count;
        }
        output.WriteLine($"{instructions} instructions run");
    }

    [Fact]
    public void The_driver_image_calls_the_sequence_with_the_state_and_writes_it()
    {
        var rng = new Random(11);
        var (code, _) = Generate(rng, 20);
        var input = RandomState(rng);
        var image = DriverImage(code, input);
        var elf = Corvus.Native.Elf.ElfFile.FromBytes(image, "driver.elf");
        Assert.Equal(Base + 120, elf.ImageBase + elf.EntryPointRva);
        // Run the stub in the emulator through its call and stop at the write
        // system call.
        var raw = new RawCodeImage(image, "driver.bin", RawLayout.Parse("arm64", $"0x{Base:x}", null, image.Length));
        var memory = new EmulatorMemory(raw, Base, Region, 0x200000);
        var cpu = new Arm64Cpu { Pc = Base + 120, Sp = Region + 0xFF000 };
        var unsupported = Assert.Throws<EmulatorUnsupportedException>(() => { for (int i = 0; i < 10_000; i++) cpu.Step(memory); });
        Assert.Contains("svc", unsupported.Message, StringComparison.OrdinalIgnoreCase);
        Assert.True(cpu.TryGet("x0", out var fd) && fd == 1);
        Assert.True(cpu.TryGet("x2", out var length) && length == StateBytes);
        Assert.True(cpu.TryGet("x8", out var call) && call == 64);
        Assert.True(cpu.TryGet("x1", out var state));
        var written = new byte[StateBytes];
        memory.Read(state, written);
        Assert.Equal(InEmulator(code, input), written);
    }
}
