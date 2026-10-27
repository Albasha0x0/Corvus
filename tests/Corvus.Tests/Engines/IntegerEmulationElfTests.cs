using System.Numerics;
using System.Text;
using Corvus.Core;
using Corvus.Native.Providers;
using Corvus.Services;
using Corvus.Tools;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>
/// The built-in emulator on clang -O2 output of IsaFixtures/emu.c for x86-64, x86 and AArch64 (build.ps1): every
/// function returns the value computed here.
/// </summary>
public sealed class IntegerEmulationElfTests(ITestOutputHelper output, IntegerEmulationElfTests.Rig rig) : IClassFixture<IntegerEmulationElfTests.Rig>
{
    /// <summary>The three fixtures in a workspace; with <c>engines</c>, the installed engines join it.</summary>
    public class Rig : IDisposable
    {
        private readonly TempDir _dir = new();
        public AssemblyWorkspace Workspace { get; }
        public NativeEngineService Engines { get; }
        public NativeEmulationTools Tools { get; }

        public Rig() : this(false) { }

        protected Rig(bool engines)
        {
            var options = new ServerOptions { TimeoutSeconds = 600, BackgroundIndexing = false };
            Workspace = new AssemblyWorkspace(options);
            Engines = engines
                ? new NativeEngineService(new Native.Providers.Ida.IdaProviderOptions { CacheRoot = _dir.File("cache") }, null, Workspace, options)
                : new NativeEngineService(Array.Empty<INativeDecompilerProvider>(), _dir.File("cache"));
            foreach (var arch in All) Workspace.LoadAny(Path.Combine(AppContext.BaseDirectory, "Engines", "IsaFixtures", $"emu-{arch}.elf"));
            Tools = new NativeEmulationTools(Workspace, Engines, new NativeCodeService(Workspace, options));
        }

        public void Dispose()
        {
            Engines.Dispose();
            Workspace.Dispose();
            _dir.Dispose();
            GC.SuppressFinalize(this);
        }
    }

    internal static readonly string[] All = ["x64", "x86", "arm64"];

    public static TheoryData<string> Arches => [.. All];

    // 64-bit division is a runtime helper call on x86, so emu.c leaves those functions out there.
    public static TheoryData<string> Arches64 => ["x64", "arm64"];

    private async Task<string> Run(string arch, string function, string? args = null, string? candidates = null, string engine = "ours")
    {
        var text = await rig.Tools.EmulateNative($"emu-{arch}.elf", function, args, candidates: candidates, engine: engine);
        output.WriteLine(text);
        return text;
    }

    private static string Returned(ulong value) => $" = 0x{value:x} ";

    [Theory]
    [MemberData(nameof(Arches))]
    public async Task A_string_hash_returns_its_value(string arch)
    {
        var text = await Run(arch, "fnv1a", "\"kernel32.dll\"");
        Assert.Contains("built-in emulation", text);
        Assert.Contains("Stopped: returned to the caller", text);
        Assert.Contains(Returned(NativeEmulationGhidraTests.Fnv1a("kernel32.dll")), text);
    }

    [Theory]
    [MemberData(nameof(Arches))]
    public async Task A_bitwise_crc_returns_the_check_value(string arch)
    {
        Assert.Contains(Returned(0xCBF43926), await Run(arch, "crc32", "\"123456789\", 9"));
    }

    [Theory]
    [MemberData(nameof(Arches))]
    public async Task A_decoder_writes_its_output_into_the_scratch_buffer(string arch)
    {
        const string plain = "Hello, emulator!";
        const byte key = 0x37;
        var encoded = Encoding.ASCII.GetBytes(plain).Select((b, i) => (byte)(b ^ (byte)(key + i))).ToArray();
        var text = await Run(arch, "xor_decode", $"buf:32, hex:{Convert.ToHexString(encoded)}, {plain.Length}, 0x{key:x}");
        Assert.Contains($"\"{plain}\"", text[text.IndexOf("Written memory", StringComparison.Ordinal)..]);
        var b64 = await Run(arch, "b64_decode", "buf:32, \"SGVsbG8sIHdvcmxkIQ==\"");
        Assert.Contains(Returned(13), b64);
        Assert.Contains("\"Hello, world!\"", b64);
    }

    [Theory]
    [MemberData(nameof(Arches))]
    public async Task An_insertion_sort_and_weighted_sum_match(string arch)
    {
        int[] values = [42, -7, 19, 0, 1000, -300, 5, 5, 77, -1];
        var bytes = values.SelectMany(BitConverter.GetBytes).ToArray();
        var sorted = values.Order().ToArray();
        long sum = sorted.Select((v, i) => (long)v * (i + 1)).Sum();
        var text = await Run(arch, "sum_sorted", $"hex:{Convert.ToHexString(bytes)}, {values.Length}");
        // An int result in a 32-bit register write is zero-extended on x86-64 and AArch64.
        Assert.Contains(Returned((uint)sum), text);
        Assert.Contains(string.Join(" ", BitConverter.GetBytes(sorted[0]).Select(b => b.ToString("X2"))), text[text.IndexOf("Written memory", StringComparison.Ordinal)..]);
    }

    [Theory]
    [MemberData(nameof(Arches))]
    public async Task A_jump_table_answers_every_case_and_the_default(string arch)
    {
        uint[] table = [0x1111, 0x2345, 0x3f00, 0x4, 0x55aa, 0x6060, 0x7007, 0x8888];
        var text = await Run(arch, "lookup", candidates: string.Join("; ", Enumerable.Range(-1, 10)));
        for (int k = -1; k <= 8; k++)
            Assert.Contains($"#{k + 2} ({k}): returned 0x{(k is >= 0 and < 8 ? table[k] : 0xdead):x},", text);
    }

    [Theory]
    [MemberData(nameof(Arches))]
    public async Task A_record_copy_through_vector_registers_keeps_every_field(string arch)
    {
        // Struct record { u64 id; u32 flags; u32 size; u64 a, b, c, d; } is 48 bytes; x86 aligns u64 to 4, the same layout.
        var record = new byte[48];
        BitConverter.GetBytes(0x1122334455667788UL).CopyTo(record, 0);
        BitConverter.GetBytes(0x10u).CopyTo(record, 8);
        BitConverter.GetBytes(0x300u).CopyTo(record, 12);
        BitConverter.GetBytes(0x1000UL).CopyTo(record, 16);
        BitConverter.GetBytes(0x2000UL).CopyTo(record, 24);
        BitConverter.GetBytes(0x3000UL).CopyTo(record, 32);
        BitConverter.GetBytes(0x40000000_00000004UL).CopyTo(record, 40);
        var text = await Run(arch, "copy_record", $"buf:48, hex:{Convert.ToHexString(record)}");
        ulong sum = 0x1000UL + 0x40000000_00000004UL + 0x300;
        Assert.Contains(Returned(arch == "x86" ? (uint)sum : sum), text);
        var written = text[text.IndexOf("Written memory", StringComparison.Ordinal)..];
        Assert.Contains("48 bytes", written);
        Assert.Contains("88 77 66 55 44 33 22 11 90 00 00 00 00 03 00 00", written);
    }

    [Theory]
    [MemberData(nameof(Arches64))]
    public async Task Multiply_divide_shift_and_bit_count_match_on_64_bit_values(string arch)
    {
        (ulong A, ulong B)[] pairs = [(0x123456789abcdef0, 0xfedcba9876543210), (1, 0), (ulong.MaxValue, 3), (0x8000000000000000, 0x7fffffffffffffff)];
        var text = await Run(arch, "mix64", candidates: string.Join("; ", pairs.Select(p => $"0x{p.A:x}, 0x{p.B:x}")));
        for (int i = 0; i < pairs.Length; i++) Assert.Contains($"#{i + 1} (0x{pairs[i].A:x}, 0x{pairs[i].B:x}): returned 0x{Mix(pairs[i].A, pairs[i].B):x},", text);
        (long A, long B)[] signed = [(-1234567, 89), (1234567, -89), (long.MaxValue, 7), (-5, 5)];
        var div = await Run(arch, "sdiv_mod", candidates: string.Join("; ", signed.Select(p => $"{p.A}, {p.B}")));
        for (int i = 0; i < signed.Length; i++) Assert.Contains($"returned 0x{(ulong)(signed[i].A / signed[i].B * 1000 + signed[i].A % signed[i].B):x},", div);
    }

    private static ulong Mix(ulong a, ulong b)
    {
        ulong r = a * b;
        r ^= a / (b | 1);
        r += a << 13 | a >> 51;
        r -= (ulong)((long)b >> 7);
        return r + (ulong)BitOperations.PopCount(a) + (ulong)BitOperations.LeadingZeroCount(b | 1) + (ulong)BitOperations.TrailingZeroCount(a | 0x8000000000000000);
    }
}

/// <summary>The built-in emulator against Ghidra's on the emu.c fixtures: the same return values.</summary>
[Trait("Speed", "Slow")]
public sealed class IntegerEmulationElfGhidraTests(ITestOutputHelper output, IntegerEmulationElfGhidraTests.EngineRig rig) : IClassFixture<IntegerEmulationElfGhidraTests.EngineRig>
{
    /// <summary>The fixtures with the installed engines.</summary>
    public sealed class EngineRig() : IntegerEmulationElfTests.Rig(true);

    [GhidraFact]
    public async Task Ghidra_returns_the_same_values()
    {
        foreach (var arch in IntegerEmulationElfTests.All)
            foreach (var (function, args) in new[] { ("fnv1a", "\"kernel32.dll\""), ("crc32", "\"123456789\", 9"), ("b64_decode", "buf:32, \"SGVsbG8sIHdvcmxkIQ==\""), ("lookup", "5") })
            {
                var ours = await rig.Tools.EmulateNative($"emu-{arch}.elf", function, args, engine: "ours");
                var ghidra = await rig.Tools.EmulateNative($"emu-{arch}.elf", function, args, engine: "ghidra");
                output.WriteLine($"{arch} {function}\n{ours}\n{ghidra}");
                Assert.Contains("Ghidra p-code emulation", ghidra);
                Assert.Equal(ReturnValue(ghidra), ReturnValue(ours));
            }
    }

    private static string ReturnValue(string text)
    {
        var line = text.Split('\n').Single(l => l.StartsWith("Return value:", StringComparison.Ordinal));
        return line[(line.IndexOf('=', StringComparison.Ordinal) + 1)..].Trim();
    }
}
