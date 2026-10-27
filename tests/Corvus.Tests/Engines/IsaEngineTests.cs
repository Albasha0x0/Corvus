using System.Text.Json;
using System.Text.RegularExpressions;
using ModelContextProtocol.Protocol;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>Every ISA-table architecture on a real engine gives the source's functions, a decompile and exactly its call edges; failures are reported together.</summary>
[Trait("Speed", "Slow")]
public sealed class IsaEngineTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    /// <summary>A fixture: file, arch and base, function addresses without symbols, call-target entry offset (PPC64 ELFv2), decompiler support and a non-image entry.</summary>
    public sealed record Fixture(string File, string? Arch = null, string? Base = null, IReadOnlyDictionary<string, ulong>? Addresses = null,
        uint LocalEntry = 0, bool IdaDecompiles = true, string? Entry = null);

    private static readonly IReadOnlyDictionary<string, string[]> Edges = new Dictionary<string, string[]>
    {
        ["_start"] = ["classify", "middle"], ["classify"] = ["leaf", "middle"], ["middle"] = ["leaf"],
    };

    private static readonly Fixture[] Fixtures =
    [
        new("mips32be.elf"), new("mips32le.elf"), new("ppc32.elf"), new("ppc64.elf", LocalEntry: 8), new("riscv32.elf"), new("riscv64.elf"), new("armbe.elf"),
        new("cortexm.bin", "thumb", "0x8000000",
            new Dictionary<string, ulong> { ["_start"] = 0x8000100, ["classify"] = 0x8000114, ["leaf"] = 0x8000150, ["middle"] = 0x800015C }),
        // IDA has no m68k decompiler.
        new("m68k.bin", "m68k", "0x0", new Dictionary<string, ulong> { ["_start"] = 0x400, ["classify"] = 0x42E, ["leaf"] = 0x4BC, ["middle"] = 0x4CE },
            IdaDecompiles: false),
    ];

    // nrom.s (build.ps1): reset → middle → leaf, PRG bank 0 at 0x8000 and its mirror at 0xC000.
    private static readonly Fixture Nrom = new("nrom.nes", "6502", "0x8000", new Dictionary<string, ulong> { ["_start"] = 0xC000, ["middle"] = 0xC00B, ["leaf"] = 0xC012 },
        IdaDecompiles: false, Entry: "0xC000");

    // 6502 (hand-assembled, see build.ps1): entry → middle → leaf, no switch; IDA has no 6502 decompiler
    private static readonly Fixture M6502 = new("m6502.bin", "6502", "0x8000", new Dictionary<string, ulong> { ["_start"] = 0x8000, ["middle"] = 0x8004, ["leaf"] = 0x800B },
        IdaDecompiles: false);

    [IdaFact]
    public Task Every_architecture_in_IDA() => Run("ida");

    [Trait("Tier", "Release")]
    [GhidraFact]
    public Task Every_architecture_in_Ghidra() => Run("ghidra");

    private async Task Run(string engine)
    {
        await using var server = await InProcessServer.StartAsync();
        var failures = new List<string>();
        foreach (var f in Fixtures.Append(M6502).Append(Nrom))
        {
            try
            {
                await Check(server, engine, f);
                output.WriteLine($"{f.File}: ok");
            }
            catch (Exception ex)
            {
                failures.Add($"{f.File}: {ex.Message}");
                output.WriteLine($"{f.File}: FAILED {ex.Message}");
            }
        }
        Assert.True(failures.Count == 0, string.Join("\n", failures));
    }

    private async Task Check(InProcessServer server, string engine, Fixture f)
    {
        var path = Path.Combine(AppContext.BaseDirectory, "Engines", "IsaFixtures", f.File);
        var bytes = File.ReadAllBytes(path);
        if (Corvus.Core.Firmware.InesRom.Looks(bytes))
        {
            path = _dir.File("prg-cpu.bin");
            File.WriteAllBytes(path, Corvus.Core.Firmware.InesRom.Read(bytes).CpuView(bytes));
        }
        var args = new Dictionary<string, object?> { ["path"] = path };
        if (f.Arch != null) { args["format"] = "raw"; args["arch"] = f.Arch; args["base"] = f.Base; }
        if (f.Entry != null) args["entry"] = f.Entry;
        var load = await Call(server, "load_assembly", args);
        var image = Regex.Match(load.Text, @"Loaded native image (\S+?):").Groups[1].Value;
        if (image.Length == 0) throw new Xunit.Sdk.XunitException("no image id: " + load.Text);

        var listed = await Call(server, "list_functions", new() { ["image"] = image, ["engine"] = engine });
        var functions = listed.Record.GetProperty("items").EnumerateArray()
            .ToDictionary(i => Convert.ToUInt64(i.GetProperty("address").GetString(), 16), i => i.GetProperty("name").GetString()!);
        var edges = f.Addresses == null ? Edges : Edges.Where(e => f.Addresses.ContainsKey(e.Key))
            .ToDictionary(e => e.Key, e => e.Value.Where(f.Addresses.ContainsKey).ToArray());
        // The source's functions, by name (symbols) or at their addresses.
        var names = f.Addresses ?? (await Symbols(server, image));
        foreach (var (name, address) in names)
            if (!functions.ContainsKey(address)) throw new Xunit.Sdk.XunitException($"{engine} has no function {name} at 0x{address:X}: {listed.Text}");

        if (engine != "ida" || f.IdaDecompiles)
        {
            var decompiled = names.ContainsKey("classify") ? "classify" : "middle";
            var code = await Call(server, "decompile_native", new() { ["image"] = image, ["address"] = $"0x{names[decompiled]:X}", ["engine"] = engine });
            if (!code.Text.Contains('{')) throw new Xunit.Sdk.XunitException($"decompile of {decompiled}: {code.Text}");
        }

        foreach (var (caller, want) in edges)
        {
            var tree = await Call(server, "native_call_tree", new() { ["image"] = image, ["function"] = $"0x{names[caller]:X}", ["engine"] = engine, ["depth"] = 1 });
            // The root's line, then its callees one level (two spaces) deeper.
            var rows = Regex.Matches(tree.Text, @"^( *)\S+\s+0x([0-9A-Fa-f]+)", RegexOptions.Multiline);
            var got = rows.Where(m => m.Groups[1].Length == rows[0].Groups[1].Length + 2)
                .Select(m => Convert.ToUInt64(m.Groups[2].Value, 16))
                .Select(a => names.FirstOrDefault(n => a == n.Value || a == n.Value + f.LocalEntry).Key ?? $"0x{a:X}").Order().ToArray();
            if (!got.SequenceEqual(want.Order())) throw new Xunit.Sdk.XunitException($"{caller} calls [{string.Join(", ", got)}], the source [{string.Join(", ", want.Order())}]: {tree.Text}");
        }
    }

    /// <summary>The ELF's symbols for the source's functions (code addresses; PPC64 ELFv1 descriptors resolved by our reader).</summary>
    private static async Task<IReadOnlyDictionary<string, ulong>> Symbols(InProcessServer server, string image)
    {
        var result = new Dictionary<string, ulong>();
        var ours = await Call(server, "list_functions", new() { ["image"] = image, ["engine"] = "ours" });
        foreach (var i in ours.Record.GetProperty("items").EnumerateArray())
            if (i.GetProperty("name").GetString() is "_start" or "classify" or "middle" or "leaf")
                result[i.GetProperty("name").GetString()!] = Convert.ToUInt64(i.GetProperty("address").GetString(), 16);
        if (result.Count != 4) throw new Xunit.Sdk.XunitException("our reader lacks the symbols: " + ours.Text);
        return result;
    }

    private static async Task<(string Text, JsonElement Record)> Call(InProcessServer server, string tool, Dictionary<string, object?> args)
    {
        var r = await server.Client.CallToolAsync(tool, args);
        var text = string.Concat(r.Content.OfType<TextContentBlock>().Select(b => b.Text));
        if (r.IsError == true) throw new Xunit.Sdk.XunitException($"{tool}: {text}");
        return (text, r.StructuredContent ?? default);
    }
}
