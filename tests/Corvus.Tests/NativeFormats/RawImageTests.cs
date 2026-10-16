using ModelContextProtocol.Protocol;

namespace Corvus.Tests;

/// <summary>load_assembly format=raw: headerless code mapped at a base, analyzed by the built-in index from its entry.</summary>
public sealed class RawImageTests : IDisposable
{
    // entry: push rbp; mov rbp, rsp; call f; pop rbp; ret
    // f (+0xB): mov eax, 42; ret
    private static readonly byte[] Shellcode = [0x55, 0x48, 0x89, 0xE5, 0xE8, 0x02, 0x00, 0x00, 0x00, 0x5D, 0xC3, 0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3];

    private readonly TempDir _dir = new();
    public void Dispose() => _dir.Dispose();

    private static async Task<(string Text, bool IsError)> Call(InProcessServer server, string tool, Dictionary<string, object?> args)
    {
        var r = await server.Client.CallToolAsync(tool, args);
        return (string.Concat(r.Content.OfType<TextContentBlock>().Select(b => b.Text)), r.IsError == true);
    }

    private string Blob()
    {
        var path = _dir.File("rawcode.bin");
        File.WriteAllBytes(path, Shellcode);
        return path;
    }

    [Fact]
    public async Task Shellcode_maps_at_its_base_and_its_calls_are_found()
    {
        var path = Blob();
        await using var server = await InProcessServer.StartAsync();
        var load = await Call(server, "load_assembly", new() { ["path"] = path, ["format"] = "raw", ["arch"] = "x64", ["base"] = "0x400000" });
        Assert.False(load.IsError, load.Text);
        Assert.Contains("rawcode.bin[x64@0x400000]", load.Text);
        const string id = "rawcode.bin[x64@0x400000]";

        var info = await Call(server, "get_pe_info", new() { ["image"] = id });
        Assert.False(info.IsError, info.Text);
        Assert.True(info.Text.Contains("raw"), info.Text);
        Assert.True(info.Text.Contains("0x400000"), info.Text);

        var functions = await Call(server, "list_functions", new() { ["image"] = id, ["engine"] = "ours" });
        Assert.False(functions.IsError, functions.Text);
        Assert.True(functions.Text.Contains("0x400000"), functions.Text);
        Assert.True(functions.Text.Contains("0x40000B"), functions.Text);

        var code = await Call(server, "disassemble", new() { ["image"] = id, ["address"] = "0x400000", ["engine"] = "ours" });
        Assert.False(code.IsError, code.Text);
        Assert.True(code.Text.Contains("call"), code.Text);
        Assert.True(code.Text.Contains("call   sub_B"), code.Text);

        var xrefs = await Call(server, "find_xrefs", new() { ["image"] = id, ["address"] = "0x40000B", ["engine"] = "ours" });
        Assert.False(xrefs.IsError, xrefs.Text);
        Assert.True(xrefs.Text.Contains("400004"), xrefs.Text);
    }

    [Fact]
    public async Task Another_base_is_another_entry_and_bad_layouts_are_refused()
    {
        var path = Blob();
        await using var server = await InProcessServer.StartAsync();
        Assert.False((await Call(server, "load_assembly", new() { ["path"] = path, ["format"] = "raw", ["arch"] = "x64", ["base"] = "0x400000" })).IsError);
        var again = await Call(server, "load_assembly", new() { ["path"] = path, ["format"] = "raw", ["arch"] = "x64", ["base"] = "0x400000" });
        Assert.Contains("rawcode.bin[x64@0x400000]", again.Text);
        var other = await Call(server, "load_assembly", new() { ["path"] = path, ["format"] = "raw", ["arch"] = "thumb", ["base"] = "0x8000000", ["entry"] = "0x8000004" });
        Assert.False(other.IsError, other.Text);
        Assert.Contains("rawcode.bin[thumb@0x8000000]", other.Text);
        Assert.Contains("entry 0x8000004", other.Text);

        var list = await Call(server, "list_assemblies", new());
        Assert.Contains("rawcode.bin[x64@0x400000]", list.Text);
        Assert.Contains("rawcode.bin[thumb@0x8000000]", list.Text);

        var mips = await Call(server, "load_assembly", new() { ["path"] = path, ["format"] = "raw", ["arch"] = "mipsel", ["base"] = "0x80000000" });
        Assert.False(mips.IsError, mips.Text);
        Assert.Contains("unsupported", (await Call(server, "disassemble", new() { ["image"] = "rawcode.bin[mipsel@0x80000000]", ["address"] = "0x80000000", ["engine"] = "ours" })).Text);

        Assert.Contains("needs arch",(await Call(server, "load_assembly", new() { ["path"] = path, ["format"] = "raw" })).Text);
        Assert.Contains("not 4 KiB aligned", (await Call(server, "load_assembly", new() { ["path"] = path, ["format"] = "raw", ["arch"] = "x64", ["base"] = "0x401" })).Text);
        Assert.Contains("outside", (await Call(server, "load_assembly", new() { ["path"] = path, ["format"] = "raw", ["arch"] = "x64", ["entry"] = "0x100" })).Text);
        Assert.Contains("apply to format=raw", (await Call(server, "load_assembly", new() { ["path"] = path, ["arch"] = "x64" })).Text);
    }

    /// <summary>A Thumb image that starts with a Cortex-M vector table enters at its reset handler, not at the table.</summary>
    [Fact]
    public async Task Cortex_m_image_enters_at_its_reset_vector()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "Engines", "IsaFixtures", "cortexm.bin");
        await using var server = await InProcessServer.StartAsync();
        var load = await Call(server, "load_assembly", new() { ["path"] = path, ["format"] = "raw", ["arch"] = "thumb", ["base"] = "0x8000000" });
        Assert.Contains("entry 0x8000100", load.Text);
        // the same bytes as ARM state are not a vector table
        Assert.Equal(0u, Corvus.Native.RawLayout.Parse("arm", "0x8000000", null, 0x200, File.ReadAllBytes(path).AsSpan(0, 8)).EntryOffset);
    }
}
