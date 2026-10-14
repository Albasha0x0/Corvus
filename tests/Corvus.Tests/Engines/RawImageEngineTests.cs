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
