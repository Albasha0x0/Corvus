using ModelContextProtocol.Protocol;

namespace Corvus.Tests;

/// <summary>load_assembly format=raw in IDA and Ghidra: the engine maps the bytes at the base with the given processor.</summary>
[Trait("Speed", "Slow")]
public sealed class RawImageEngineTests(Xunit.Abstractions.ITestOutputHelper output) : IDisposable
{
    // entry: push rbp; mov rbp, rsp; call f; pop rbp; ret
    // f (+0xB): mov eax, 42; ret
    private static readonly byte[] Shellcode = [0x55, 0x48, 0x89, 0xE5, 0xE8, 0x02, 0x00, 0x00, 0x00, 0x5D, 0xC3, 0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3];

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
    public Task Shellcode_in_IDA() => Engine("ida");

    [GhidraFact]
    public Task Shellcode_in_Ghidra() => Engine("ghidra");

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

    /// <summary>An instruction set our index does not decode: Ghidra reads it with the language from the arch table.</summary>
    [GhidraFact]
    public async Task Mips_in_Ghidra()
    {
        var path = _dir.File("mips.bin");
        // li v0, 42; jr ra; nop (little endian)
        File.WriteAllBytes(path, [0x2A, 0x00, 0x02, 0x24, 0x08, 0x00, 0xE0, 0x03, 0x00, 0x00, 0x00, 0x00, .. Guid.NewGuid().ToByteArray()]);
        await using var server = await InProcessServer.StartAsync();
        Assert.False((await Call(server, "load_assembly", new() { ["path"] = path, ["format"] = "raw", ["arch"] = "mipsel", ["base"] = "0x80000000" })).IsError);
        var code = await Call(server, "decompile_native", new() { ["image"] = "mips.bin[mipsel@0x80000000]", ["address"] = "0x80000000", ["engine"] = "ghidra" });
        Assert.False(code.IsError, code.Text);
        Assert.True(code.Text.Contains("0x2a", StringComparison.OrdinalIgnoreCase) || code.Text.Contains("42"), code.Text);
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
        Assert.Contains("engine=ghidra", (await Call(server, "list_functions", new() { ["image"] = "prog.exe[dos-mz@0x0]", ["engine"] = "ida" })).Text);
    }

    private async Task Engine(string engine)
    {
        // bytes of their own: the engines' databases are cached by content
        var path = _dir.File("shellcode.bin");
        File.WriteAllBytes(path, [.. Shellcode, .. Guid.NewGuid().ToByteArray()]);
        await using var server = await InProcessServer.StartAsync();
        var load = await Call(server, "load_assembly", new() { ["path"] = path, ["format"] = "raw", ["arch"] = "x64", ["base"] = "0x400000" });
        Assert.False(load.IsError, load.Text);
        const string id = "shellcode.bin[x64@0x400000]";

        var functions = await Call(server, "list_functions", new() { ["image"] = id, ["engine"] = engine });
        Assert.False(functions.IsError, functions.Text);
        Assert.True(functions.Text.Contains("0x400000") && functions.Text.Contains("0x40000B"), functions.Text);

        var code = await Call(server, "decompile_native", new() { ["image"] = id, ["address"] = "0x40000B", ["engine"] = engine });
        Assert.False(code.IsError, code.Text);
        Assert.True(code.Text.Contains("42") || code.Text.Contains("0x2a", StringComparison.OrdinalIgnoreCase), code.Text);
    }
}
