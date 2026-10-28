using ModelContextProtocol.Protocol;

namespace Corvus.Tests;

/// <summary>
/// Import overrides on a built PE and a raw image: a test folder and logged
/// tool calls.
/// </summary>
public abstract class ImportOverrideEngineTestBase(Xunit.Abstractions.ITestOutputHelper output) : IDisposable
{
    private protected readonly TempDir _dir = new();
    public void Dispose() => _dir.Dispose();

    private protected async Task<(string Text, bool IsError)> Call(InProcessServer server, string tool, Dictionary<string, object?> args)
    {
        var r = await server.Client.CallToolAsync(tool, args);
        var text = string.Concat(r.Content.OfType<TextContentBlock>().Select(b => b.Text));
        output.WriteLine($"{tool}: {text}");
        return (text, r.IsError == true);
    }

    /// <summary>
    /// A 32-bit PE at 0x400000: entry (0x401000) calls f (0x401010: mov eax, [0x402000]; ret); 0x401020 is code nothing reaches;
    /// .data at 0x402000. The bytes differ per call so each test gets its own cache entry.
    /// </summary>
    private protected string Pe(string name)
    {
        var code = new byte[0x40];
        Array.Fill(code, (byte)0xCC);
        byte[] entry = [0x55, 0x89, 0xE5, 0xE8, 0x08, 0x00, 0x00, 0x00, 0x5D, 0xC3];
        entry.CopyTo(code, 0);
        byte[] f = [0xA1, 0x00, 0x20, 0x40, 0x00, 0xC3];
        f.CopyTo(code, 0x10);
        byte[] loose = [0xB8, 0x07, 0x00, 0x00, 0x00, 0xC3];
        loose.CopyTo(code, 0x20);
        var b = new PeBuilder { Is64 = false, Machine = 0x14C, ImageBase = 0x400000, Characteristics = 0x0102 };
        var text = b.Add(".text", code, 0x60000020);
        b.EntryPoint = text.Rva;
        b.Add(".data", [.. Guid.NewGuid().ToByteArray(), .. new byte[16]], 0xC0000040);
        var path = _dir.File(name);
        File.WriteAllBytes(path, b.Build());
        return path;
    }

    /// <summary>compilerSpec=borlandcpp opens the PE as Borland; seeds carry their names; another override set is another database, reused when it returns.</summary>
    private protected async Task Seeded(string engine, string compiler)
    {
        var path = Pe($"borland-{engine}.exe");
        await using var server = await InProcessServer.StartAsync();
        var load = await Call(server, "load_assembly", new()
        {
            ["path"] = path, ["compilerSpec"] = "borlandcpp", ["seeds"] = new[] { "0x401020=seeded_func", "label:0x402000=seeded_table" },
            ["disableAnalyzers"] = new[] { engine == "ida" ? "AF_FLIRT" : "Stack" },
        });
        Assert.False(load.IsError, load.Text);
        Assert.Contains("engine import: compilerSpec=borlandcpp; seeds=", load.Text);
        var image = Path.GetFileName(path);
        var functions = await Call(server, "list_functions", new() { ["image"] = image, ["engine"] = engine });
        Assert.Contains("seeded_func", functions.Text);
        var status = await Call(server, "get_engine_status", new() { ["image"] = image, ["engine"] = engine });
        Assert.Contains($"compiler {compiler}", status.Text);
        Assert.Contains("import overrides: compilerSpec=borlandcpp", status.Text);
        var code = await Call(server, "decompile_native", new() { ["image"] = image, ["address"] = "0x401010", ["engine"] = engine });
        Assert.Contains("seeded_table", code.Text);
        var first = Database(status.Text);

        // Another override: the image reloads and the engine makes a database of its own.
        Assert.False((await Call(server, "load_assembly", new() { ["path"] = path, ["compilerSpec"] = "windows" })).IsError);
        await Call(server, "list_functions", new() { ["image"] = image, ["engine"] = engine });
        var other = await Call(server, "get_engine_status", new() { ["image"] = image, ["engine"] = engine });
        Assert.Contains("analyzed in this session", other.Text);
        Assert.NotEqual(first, Database(other.Text));
        Assert.DoesNotContain("borland", Database(other.Text), StringComparison.OrdinalIgnoreCase);

        // Back to the first set: its saved database is opened again.
        Assert.False((await Call(server, "load_assembly", new()
        {
            ["path"] = path, ["compilerSpec"] = "borlandcpp", ["seeds"] = new[] { "label:0x402000=seeded_table", "0x401020=seeded_func" },
            ["disableAnalyzers"] = new[] { engine == "ida" ? "AF_FLIRT" : "Stack" },
        })).IsError);
        await Call(server, "list_functions", new() { ["image"] = image, ["engine"] = engine });
        var again = await Call(server, "get_engine_status", new() { ["image"] = image, ["engine"] = engine });
        Assert.Contains("reused saved database", again.Text);
        Assert.Equal(first, Database(again.Text));
    }

    private protected static string Database(string status) =>
        System.Text.RegularExpressions.Regex.Match(status, @"database (.+?); worker pid").Groups[1].Value is { Length: > 0 } db ? db : throw new Xunit.Sdk.XunitException("no database line: " + status);

    /// <summary>A raw image takes the overrides too: the processor (IDA) or language (Ghidra) replaces the arch's, and the seed is a named function.</summary>
    private protected async Task SeededRaw(string engine)
    {
        var path = _dir.File($"raw-{engine}.bin");
        // entry: ret; 0x10: mov eax, 7; ret (nothing reaches it)
        File.WriteAllBytes(path, [0xC3, .. Enumerable.Repeat((byte)0xCC, 15), 0xB8, 0x07, 0x00, 0x00, 0x00, 0xC3, .. Guid.NewGuid().ToByteArray()]);
        await using var server = await InProcessServer.StartAsync();
        var load = await Call(server, "load_assembly", new()
        {
            ["path"] = path, ["format"] = "raw", ["arch"] = "x86", ["base"] = "0x10000", ["seeds"] = new[] { "0x10010=raw_seed" },
            [engine == "ida" ? "processor" : "language"] = engine == "ida" ? "80386p" : "x86:LE:32:default",
        });
        Assert.False(load.IsError, load.Text);
        var image = $"raw-{engine}.bin[x86@0x10000]";
        var functions = await Call(server, "list_functions", new() { ["image"] = image, ["engine"] = engine });
        Assert.Matches(@"0x10010\s+\d+\s+raw_seed", functions.Text);
        var status = await Call(server, "get_engine_status", new() { ["image"] = image, ["engine"] = engine });
        Assert.Contains(engine == "ida" ? "80386p" : "x86:LE:32:default", status.Text);
    }
}

/// <summary>
/// load_assembly import overrides through a real IDA: applied before the first
/// analysis, a database per set.
/// </summary>
[Trait("Speed", "Slow")]
public sealed class ImportOverrideEngineTests(Xunit.Abstractions.ITestOutputHelper output) : ImportOverrideEngineTestBase(output)
{
    [IdaFact]
    public Task Compiler_seeds_and_analyzers_before_analysis_in_IDA() => Seeded("ida", "Borland C++");

    [IdaFact]
    public Task Seeded_raw_image_in_IDA() => SeededRaw("ida");

    /// <summary>Names neither engine has are refused at load, with the nearest names the installed engine knows.</summary>
    [IdaFact]
    public async Task Unknown_processor_is_refused_with_IDAs_names()
    {
        var path = Pe("proc.exe");
        await using var server = await InProcessServer.StartAsync();
        var bad = await Call(server, "load_assembly", new() { ["path"] = path, ["processor"] = "metapcc" });
        Assert.True(bad.IsError);
        Assert.Contains("metapc", bad.Text);
        var good = await Call(server, "load_assembly", new() { ["path"] = path, ["processor"] = "metapc" });
        Assert.False(good.IsError, good.Text);
    }
}

/// <summary>
/// load_assembly import overrides through a real Ghidra: applied before the
/// first analysis, a database per set.
/// </summary>
[Trait("Speed", "Slow")]
public sealed class ImportOverrideEngineGhidraTests(Xunit.Abstractions.ITestOutputHelper output) : ImportOverrideEngineTestBase(output)
{
    [GhidraFact]
    public Task Compiler_seeds_and_analyzers_before_analysis_in_Ghidra() => Seeded("ghidra", "borlandcpp");

    [GhidraFact]
    public Task Seeded_raw_image_in_Ghidra() => SeededRaw("ghidra");

    [GhidraFact]
    public async Task Unknown_language_is_refused_with_Ghidras_names()
    {
        var path = Pe("lang.exe");
        await using var server = await InProcessServer.StartAsync();
        var bad = await Call(server, "load_assembly", new() { ["path"] = path, ["language"] = "x86:LE:32:defualt" });
        Assert.True(bad.IsError);
        Assert.Contains("x86:LE:32:default", bad.Text);
        var spec = await Call(server, "load_assembly", new() { ["path"] = path, ["language"] = "x86:LE:64:default", ["compilerSpec"] = "borlandcpp" });
        Assert.True(spec.IsError);
        Assert.Contains("windows", spec.Text);
    }
}
