using System.Text;
using Corvus.Core;
using Corvus.Core.WebAssembly;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>WebAssembly module structure: imports, exports, memories, producers; malformed input never throws.</summary>
public sealed class WasmTests
{
    private static byte[] Str(string s) => [(byte)s.Length, .. Encoding.UTF8.GetBytes(s)];
    private static byte[] Section(byte id, byte[] body) => [id, (byte)body.Length, .. body];

    /// <summary>One imported function env.log, a defined function exported as run, a memory of 1..2 pages, producers rustc.</summary>
    internal static byte[] Sample() =>
    [
        0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00,
        .. Section(1, [0x01, 0x60, 0x00, 0x00]),                                 // type: () -> ()
        .. Section(2, [0x01, .. Str("env"), .. Str("log"), 0x00, 0x00]),         // import env.log: func type 0
        .. Section(3, [0x01, 0x00]),                                             // one function of type 0
        .. Section(5, [0x01, 0x01, 0x01, 0x02]),                                 // memory min 1 max 2
        .. Section(7, [0x01, .. Str("run"), 0x00, 0x01]),                        // export run = func 1
        .. Section(10, [0x01, 0x02, 0x00, 0x0B]),                                // code: empty body
        .. Section(0, [.. Str("producers"), 0x01, .. Str("processed-by"), 0x01, .. Str("rustc"), .. Str("1.80.0")]),
    ];

    [Fact]
    public void A_module_lists_its_imports_exports_memories_and_producers()
    {
        var m = WasmModule.Read(Sample());
        Assert.Empty(m.Issues);
        Assert.Equal(new WasmSymbol("env", "log", "func"), Assert.Single(m.Imports));
        Assert.Equal(new WasmSymbol(null, "run", "func"), Assert.Single(m.Exports));
        Assert.Equal(1, m.DefinedFunctions);
        Assert.Equal((1UL, (ulong?)2), Assert.Single(m.Memories));
        Assert.Equal(("processed-by", "rustc 1.80.0"), Assert.Single(m.Producers));
    }

    /// <summary>A module with code, a 17 MiB data segment, a passive one and a 2 MiB DWARF section.</summary>
    private static byte[] Bulky()
    {
        var b = new WasmModuleBuilder();
        uint t = b.Type([WasmType.I32], [WasmType.I32]);
        b.Memory(400);
        b.Func(t, new WasmAsm().Op(0x20, 0x00).Bytes);
        b.Export("id", WasmExternal.Func, 0);
        b.Data(16, new byte[17 << 20]);
        b.PassiveData([1, 2, 3]);
        b.Custom(".debug_info", new byte[2 << 20]);
        b.Custom("producers", [0x01, .. Str("processed-by"), 0x01, .. Str("clang"), .. Str("19")]);
        return b.Build();
    }

    [Fact]
    public void A_streamed_module_keeps_its_facts_without_its_bulk()
    {
        using var dir = new TempDir();
        var path = dir.File("bulky.wasm");
        File.WriteAllBytes(path, Bulky());
        var whole = (WasmFileView.Facts)new WasmFileView().Inspect(new FileInput(path, File.ReadAllBytes(path), "wasm"), default)!.Detail;
        var view = new WasmFileView().Inspect(FileInput.Open(path, streamAbove: 64), default)!;
        var streamed = (WasmFileView.Facts)view.Detail;
        Assert.Equal(whole.Sections, streamed.Sections);
        Assert.Equal((whole.DataSegments, whole.DefinedFunctions, whole.Validation, whole.Toolchain), (streamed.DataSegments, streamed.DefinedFunctions, streamed.Validation, streamed.Toolchain));
        Assert.Equal("valid", streamed.Validation);
        Assert.Contains(view.Highlights, h => h.StartsWith("Read as a stream: ", StringComparison.Ordinal));
        using var stream = File.OpenRead(path);
        Assert.True(WasmCompact.Read(stream, default).Bytes.Length < 64 << 10);
    }

    [Fact]
    [FuzzEntry(typeof(WasmModule), typeof(WasmCompact))]
    public void Fuzzed_modules_never_throw()
    {
        var failures = FormatFuzz.Run(Sample(), b => WasmModule.Read(b), 2000);
        var sections = new WasmModuleBuilder();
        sections.Memory(1);
        sections.Data(8, [1, 2, 3, 4]);
        sections.DataIn(0, 4, [5]);
        sections.PassiveData([6, 7]);
        sections.Custom("dwarf", [9, 9, 9]);
        failures.AddRange(FormatFuzz.Run(sections.Build(), m => WasmModule.Read(WasmCompact.Read(new MemoryStream(m), default, 0, 0).Bytes), 500));
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }
}
