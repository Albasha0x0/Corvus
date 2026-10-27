using Corvus.Native.Providers.Ida;
using ModelContextProtocol.Protocol;

namespace Corvus.Tests;

/// <summary>load_assembly format=raw in IDA and Ghidra: the engine maps the bytes at the base with the given processor.</summary>
[Trait("Speed", "Slow")]
public sealed class RawImageEngineTests(Xunit.Abstractions.ITestOutputHelper output) : IDisposable
{
    // entry: push rbp; mov rbp, rsp; call f; pop rbp; ret
    // f (+0xB): mov eax, 42; ret
    private static readonly byte[] RawCode = [0x55, 0x48, 0x89, 0xE5, 0xE8, 0x02, 0x00, 0x00, 0x00, 0x5D, 0xC3, 0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3];

    private readonly TempDir _dir = new();
    public void Dispose() => _dir.Dispose();

    private async Task<(string Text, bool IsError)> Call(InProcessServer server, string tool, Dictionary<string, object?> args)
    {
        var r = await server.Client.CallToolAsync(tool, args);
        var text = string.Concat(r.Content.OfType<TextContentBlock>().Select(b => b.Text));
        output.WriteLine($"{tool}: {text}");
        return (text, r.IsError == true);
    }

    [IdaFact]
    public Task RawCode_in_IDA() => Engine("ida");

    [GhidraFact]
    public Task RawCode_in_Ghidra() => Engine("ghidra");

    /// <summary>get_engine_status lists Ghidra's analysis errors: code at the entry that does not decode is a Bad Instruction bookmark.</summary>
    [GhidraFact]
    public async Task Ghidra_analysis_errors_are_listed()
    {
        var path = _dir.File("bad.bin");
        File.WriteAllBytes(path, [0xFF, 0xFF, 0xFF, 0xFF, .. Guid.NewGuid().ToByteArray()]);
        await using var server = await InProcessServer.StartAsync();
        Assert.False((await Call(server, "load_assembly", new() { ["path"] = path, ["format"] = "raw", ["arch"] = "x64" })).IsError);
        await Call(server, "list_functions", new() { ["image"] = "bad.bin[x64@0x0]", ["engine"] = "ghidra" });
        var status = await Call(server, "get_engine_status", new() { ["image"] = "bad.bin[x64@0x0]", ["engine"] = "ghidra", ["bookmarks"] = true });
        Assert.Matches(@"analysis problems \(bookmarks\): [1-9]\d* error", status.Text);
        Assert.Contains("error 0x0 Bad Instruction", status.Text);
    }

    [IdaFact]
    public Task Memory_search_in_IDA() => MemorySearch("ida");

    [GhidraFact]
    public Task Memory_search_in_Ghidra() => MemorySearch("ghidra");

    /// <summary>search_bytes memory=ida|ghidra reads the engine's loaded bytes and finds what the file mapping holds.</summary>
    private async Task MemorySearch(string engine)
    {
        var path = _dir.File($"mem-{engine}.bin");
        File.WriteAllBytes(path, [.. RawCode, .. Guid.NewGuid().ToByteArray()]);
        await using var server = await InProcessServer.StartAsync();
        Assert.False((await Call(server, "load_assembly", new() { ["path"] = path, ["format"] = "raw", ["arch"] = "x64", ["base"] = "0x10000" })).IsError);
        var image = $"mem-{engine}.bin[x64@0x10000]";
        var file = await Call(server, "search_bytes", new() { ["image"] = image, ["pattern"] = "E8 ?? ?? ?? ?? 5? C3" });
        var memory = await Call(server, "search_bytes", new() { ["image"] = image, ["pattern"] = "E8 ?? ?? ?? ?? 5? C3", ["memory"] = engine });
        Assert.False(memory.IsError, memory.Text);
        Assert.StartsWith("1 hit (showing 1-1)", file.Text);
        Assert.StartsWith($"1 hit (showing 1-1) in {(engine == "ida" ? "IDA" : "Ghidra")}'s memory", memory.Text);
        Assert.Contains("0x10004", memory.Text);
        Assert.DoesNotContain("fixed up", memory.Text);
    }

    /// <summary>A __noreturn prototype stops the caller's flow at the call: the code after it leaves the caller.</summary>
    [GhidraFact]
    public Task No_return_stops_the_callers_flow_in_Ghidra() => NoReturn("ghidra");

    [IdaFact]
    public Task No_return_stops_the_callers_flow_in_IDA() => NoReturn("ida");

    private async Task NoReturn(string engine)
    {
        var path = _dir.File($"noret-{engine}.bin");
        // 0x00 call 0x10; 0x05 mov eax, 1; 0x0A ret; pad; 0x10 xor eax, eax; ret
        File.WriteAllBytes(path, [0xE8, 0x0B, 0x00, 0x00, 0x00, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x31, 0xC0, 0xC3,
            .. Guid.NewGuid().ToByteArray()]);
        await using var server = await InProcessServer.StartAsync();
        var image = $"noret-{engine}.bin[x64@0x0]";
        Assert.False((await Call(server, "load_assembly", new() { ["path"] = path, ["format"] = "raw", ["arch"] = "x64" })).IsError);
        var before = await Call(server, "get_cfg", new() { ["image"] = image, ["address"] = "0x0", ["engine"] = engine });
        output.WriteLine(before.Text);
        var set = await Call(server, "set_native_type", new() { ["image"] = image, ["address"] = "0x10", ["type"] = "void __noreturn stop(void)", ["engine"] = engine });
        Assert.False(set.IsError, set.Text);
        var after = await Call(server, "get_cfg", new() { ["image"] = image, ["address"] = "0x0", ["engine"] = engine });
        output.WriteLine(after.Text);
        Assert.Matches(@"0x0-0xB\s+3 insn", before.Text);
        // The call ends the caller's first block, with no edge on to the code after it.
        Assert.Matches(@"0x0-0x5\s+1 insn", after.Text);
    }

    /// <summary>An instruction set our index does not decode: Ghidra reads it with the language from the arch table.</summary>
    [GhidraFact]
    public async Task Mips_in_Ghidra()
    {
        var path = _dir.File("mips.bin");
        // Li v0, 42; jr ra; nop (little endian).
        File.WriteAllBytes(path, [0x2A, 0x00, 0x02, 0x24, 0x08, 0x00, 0xE0, 0x03, 0x00, 0x00, 0x00, 0x00, .. Guid.NewGuid().ToByteArray()]);
        await using var server = await InProcessServer.StartAsync();
        Assert.False((await Call(server, "load_assembly", new() { ["path"] = path, ["format"] = "raw", ["arch"] = "mipsel", ["base"] = "0x80000000" })).IsError);
        var code = await Call(server, "decompile_native", new() { ["image"] = "mips.bin[mipsel@0x80000000]", ["address"] = "0x80000000", ["engine"] = "ghidra" });
        Assert.False(code.IsError, code.Text);
        Assert.True(code.Text.Contains("0x2a", StringComparison.OrdinalIgnoreCase) || code.Text.Contains("42"), code.Text);
    }

    /// <summary>DOS table dispatch: our scan of the 16-bit dispatch table seeds Ghidra, which finds every handler (alone: none of 540).</summary>
    [GhidraFact]
    public async Task Dos_table_dispatched_handlers_in_Ghidra()
    {
        var (file, handlers) = RealModeDispatchTests.Mz();
        var exe = _dir.File("dispatch.exe");
        File.WriteAllBytes(exe, [.. file, .. Guid.NewGuid().ToByteArray()]);
        await using var server = await InProcessServer.StartAsync();
        Assert.False((await Call(server, "load_assembly", new() { ["path"] = exe, ["format"] = "raw", ["arch"] = "dos-mz" })).IsError);
        var starts = new HashSet<ulong>();
        for (int offset = 0; ; )
        {
            var r = await server.Client.CallToolAsync("list_functions", new Dictionary<string, object?> { ["image"] = "dispatch.exe[dos-mz@0x0]", ["engine"] = "ghidra", ["offset"] = offset, ["limit"] = 1000 });
            Assert.True(r.IsError != true);
            var items = r.StructuredContent!.Value.GetProperty("items").EnumerateArray().Select(i => Convert.ToUInt64(i.GetProperty("address").GetString(), 16)).ToList();
            if (items.Count == 0) break;
            starts.UnionWith(items);
            offset += items.Count;
        }
        // The entry is at module offset 0, the lowest function.
        ulong entry = starts.Min();
        var missing = handlers.Where(h => !starts.Contains(entry + h)).ToList();
        output.WriteLine($"{starts.Count} functions; {missing.Count} of {handlers.Length} handlers missing");
        Assert.Empty(missing);
    }

    /// <summary>DOS: a .COM file as 16-bit code at 0x100, and an MZ executable through Ghidra's MZ loader.</summary>
    [GhidraFact]
    public async Task Dos_in_Ghidra()
    {
        // mov ax, 42; ret
        byte[] code = [0xB8, 0x2A, 0x00, 0xC3];
        var com = _dir.File("prog.com");
        File.WriteAllBytes(com, [.. code, .. Guid.NewGuid().ToByteArray()]);
        // MZ header (2 paragraphs), CS:IP 0:0, then the code
        byte[] header = new byte[32];
        "MZ"u8.CopyTo(header);
        int size = 32 + code.Length + 16;
        BitConverter.GetBytes((ushort)(size % 512)).CopyTo(header, 2);
        BitConverter.GetBytes((ushort)((size + 511) / 512)).CopyTo(header, 4);
        BitConverter.GetBytes((ushort)2).CopyTo(header, 8);
        BitConverter.GetBytes((ushort)0xFFFF).CopyTo(header, 12);
        BitConverter.GetBytes((ushort)0x100).CopyTo(header, 16);
        BitConverter.GetBytes((ushort)0x1C).CopyTo(header, 24);
        var exe = _dir.File("prog.exe");
        File.WriteAllBytes(exe, [.. header, .. code, .. Guid.NewGuid().ToByteArray()]);

        await using var server = await InProcessServer.StartAsync();
        Assert.False((await Call(server, "load_assembly", new() { ["path"] = com, ["format"] = "raw", ["arch"] = "dos-com", ["base"] = "0x100" })).IsError);
        var c = await Call(server, "decompile_native", new() { ["image"] = "prog.com[x86-16@0x100]", ["address"] = "0x100", ["engine"] = "ghidra" });
        Assert.True(!c.IsError && (c.Text.Contains("0x2a", StringComparison.OrdinalIgnoreCase) || c.Text.Contains("42")), c.Text);

        Assert.False((await Call(server, "load_assembly", new() { ["path"] = exe, ["format"] = "raw", ["arch"] = "dos-mz" })).IsError);
        var functions = await Call(server, "list_functions", new() { ["image"] = "prog.exe[dos-mz@0x0]", ["engine"] = "ghidra" });
        Assert.False(functions.IsError, functions.Text);
        Assert.Contains("1 function", functions.Text);
        // IDA's refusal names Ghidra only where IDA is installed; elsewhere it says IDA is unavailable.
        if (IdaInstallation.Locate(null, out _, out _) != null)
            Assert.Contains("engine=ghidra", (await Call(server, "list_functions", new() { ["image"] = "prog.exe[dos-mz@0x0]", ["engine"] = "ida" })).Text);
    }

    private async Task Engine(string engine)
    {
        // Bytes of their own: the engines' databases are cached by content.
        var path = _dir.File("rawcode.bin");
        File.WriteAllBytes(path, [.. RawCode, .. Guid.NewGuid().ToByteArray()]);
        await using var server = await InProcessServer.StartAsync();
        var load = await Call(server, "load_assembly", new() { ["path"] = path, ["format"] = "raw", ["arch"] = "x64", ["base"] = "0x400000" });
        Assert.False(load.IsError, load.Text);
        const string id = "rawcode.bin[x64@0x400000]";

        var functions = await Call(server, "list_functions", new() { ["image"] = id, ["engine"] = engine });
        Assert.False(functions.IsError, functions.Text);
        Assert.True(functions.Text.Contains("0x400000") && functions.Text.Contains("0x40000B"), functions.Text);

        var code = await Call(server, "decompile_native", new() { ["image"] = id, ["address"] = "0x40000B", ["engine"] = engine });
        Assert.False(code.IsError, code.Text);
        Assert.True(code.Text.Contains("42") || code.Text.Contains("0x2a", StringComparison.OrdinalIgnoreCase), code.Text);
    }
}
