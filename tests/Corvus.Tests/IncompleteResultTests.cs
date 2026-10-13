using System.Buffers.Binary;
using System.Text;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>Searches whose regex timed out on some inputs, and reads cut short, say so instead of looking complete.</summary>
public class IncompleteResultTests
{
    /// <summary>Exponential backtracking on <see cref="Slow"/>: times out; every short input fails fast.</summary>
    private const string Catastrophic = "^(a|aa)+$";

    private static readonly string Slow = new string('a', 60) + "Z";

    /// <summary>An x64 image whose entry point loads the address of <see cref="Slow"/> (in .rdata, the last section).</summary>
    private static byte[] NativeWithSlowString()
    {
        var b = new PeBuilder();
        var code = new byte[] { 0x48, 0x8D, 0x0D, 0, 0, 0, 0, 0xC3 }; // lea rcx, [rip+rel32]; ret
        var text = b.Add(".text", code, 0x60000020);
        b.EntryPoint = text.Rva;
        var rdata = b.Add(".rdata", Encoding.ASCII.GetBytes(Slow + "\0"));
        BinaryPrimitives.WriteInt32LittleEndian(code.AsSpan(3), (int)(rdata.Rva - (text.Rva + 7)));
        return b.Build();
    }

    [Fact]
    public void MatcherCountsTimeouts()
    {
        // Short inputs under the default limit: on a busy machine even they can take 50 ms.
        var quickTimeouts = new RegexTimeouts();
        var quick = SearchService.CreateMatcher(Catastrophic, regex: true, quickTimeouts);
        Assert.True(quick("aaaa"));
        Assert.False(quick("b"));
        Assert.Equal("", quickTimeouts.Note("string"));

        using var limit = RegexTimeouts.UseLimit(TimeSpan.FromMilliseconds(50));
        var timeouts = new RegexTimeouts();
        var match = SearchService.CreateMatcher(Catastrophic, regex: true, timeouts);
        Assert.False(match(Slow));
        Assert.Equal(1, timeouts.Count);
        Assert.StartsWith("Incomplete: the regex timed out on 1 string (50 ms limit each)", timeouts.Note("string"));
    }

    [Fact]
    public async Task SearchNativeStringsReportsStringsTheRegexTimedOutOn()
    {
        using var limit = RegexTimeouts.UseLimit(TimeSpan.FromMilliseconds(50));
        using var dir = new TempDir();
        var path = dir.File("slow.dll");
        File.WriteAllBytes(path, NativeWithSlowString());
        using var h = new NativeToolHarness();

        Assert.Contains(Slow, await h.CodeTools.SearchNativeStrings(path, "aaaZ"));
        var collector = ToolOutput.Collect();
        var text = await h.CodeTools.SearchNativeStrings(path, Catastrophic, regex: true);
        Assert.StartsWith("Incomplete: the regex timed out on 1 string", text);
        var list = Assert.IsType<NativeStringList>(collector.Value);
        Assert.Equal(1, list.NotEvaluated);
        Assert.Empty(list.Items);

        // Image strings are fitted to 80% of the budget: packed tables of rare names are estimated low (G1 budget).
        var call = OutputCall.Begin(new OutputCall("search_native_strings", 6_000, null));
        await h.CodeTools.SearchNativeStrings(path, "aaaZ");
        Assert.Equal(4_800, call.Tokens);
        OutputCall.Begin(null!);
    }

    [Fact]
    public async Task ReadBytesReportsAReadCutShort()
    {
        using var dir = new TempDir();
        var path = dir.File("slow.dll");
        File.WriteAllBytes(path, NativeWithSlowString());
        using var h = new NativeToolHarness();

        Assert.Contains(", 16 bytes\n", await h.Native.ReadBytes(path, "rva:0x2000", 16));
        // .rdata is the last section: its 4 KB page ends at 0x3000.
        var text = await h.Native.ReadBytes(path, "rva:0x2FF0", 256);
        Assert.Contains("16 of 256 bytes requested: incomplete, nothing is mapped at 0x140003000", text);
        Assert.Contains("(length 100,000 capped at 65,536)", await h.Native.ReadBytes(path, "rva:0x2000", 100_000));
    }

    /// <summary>A class of its own so its timeouts run beside the native ones.</summary>
    public sealed class Managed
    {
        [Fact]
        public async Task SearchStringsAndSymbolsReportTimeouts()
        {
            using var limit = RegexTimeouts.UseLimit(TimeSpan.FromMilliseconds(50));
            using var dir = new TempDir();
            var path = dir.File("Slow.dll");
            File.WriteAllBytes(path, InspectionTests.Compile("Slow", $$"""
                public class {{Slow}} { public static string Get() => "{{Slow}}"; }
                """));
            using var env = new Env(path);
            var search = new SearchTools(env.Workspace, env.Search, env.Il2Cpp, env.Il2CppStrings);

            var collector = ToolOutput.Collect();
            var strings = await search.SearchStrings(Catastrophic, regex: true);
            Assert.StartsWith("Incomplete: the regex timed out on 1 string", strings);
            Assert.Equal(1, Assert.IsType<StringList>(collector.Value).NotEvaluated);

            collector = ToolOutput.Collect();
            var symbols = await search.SearchSymbols(Catastrophic, kind: "type", regex: true);
            Assert.StartsWith("Incomplete: the regex timed out on ", symbols);
            Assert.True(Assert.IsType<SymbolList>(collector.Value).NotEvaluated > 0);
        }
    }
}
