using System.Text;
using Corvus.Core;

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
    public void Imports_exports_memories_and_producers()
    {
        var m = WasmModule.Read(Sample());
        Assert.Empty(m.Issues);
        Assert.Equal(new WasmSymbol("env", "log", "func"), Assert.Single(m.Imports));
        Assert.Equal(new WasmSymbol(null, "run", "func"), Assert.Single(m.Exports));
        Assert.Equal(1, m.DefinedFunctions);
        Assert.Equal((1UL, (ulong?)2), Assert.Single(m.Memories));
        Assert.Equal(("processed-by", "rustc 1.80.0"), Assert.Single(m.Producers));
    }

    [Fact]
    public void Fuzzed_modules_never_throw()
    {
        var failures = FormatFuzz.Run(Sample(), b => WasmModule.Read(b), 2000);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }
}
