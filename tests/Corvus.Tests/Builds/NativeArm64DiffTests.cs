using System.Text;
using Corvus.Native;
using Corvus.Native.Code;
using Corvus.Native.Diff;

namespace Corvus.Tests;

/// <summary>Build matching and code patterns on two ARM64 builds whose code and data moved: branch, ADRP and low-12 fields are masked.</summary>
public class NativeArm64DiffTests
{
    private const uint Code = CodeTestImage.SyntheticCodeRva;
    private const uint Data = CodeTestImage.SyntheticDataRva;
    private const ulong Base = 0x10000000UL;

    private sealed record Build(NativeCodeIndex Index, Dictionary<string, uint> At);

    /// <summary>main calls A and B; A loads a global through ADRP + LDR; B passes a string (ADRP + ADD) to A. The new build inserts X first and moves the data.</summary>
    private static Build Make(bool newer)
    {
        uint shift = newer ? 0x1040u : 0;
        uint global = Data + 0x10 + shift, text = Data + 0x100 + shift;
        var a = new A64(Code);
        var at = new Dictionary<string, uint>();
        at["main"] = a.Here;
        a.Word(A64.StpFpLrPre).Word(A64.MovFpSp);
        if (newer) a.Later(x => A64.Bl(x, at["X"]));
        a.Later(x => A64.Bl(x, at["A"])).Later(x => A64.Bl(x, at["B"]));
        a.Word(A64.LdpFpLrPost).Word(A64.Ret);
        if (newer)
        {
            at["X"] = a.Here;
            a.Word(A64.MovW(0, 0x777)).Word(A64.Ret);
        }
        at["A"] = a.Here;
        a.Word(A64.Adrp(a.Here, global, 8, Base)).Word(A64.LdrX(0, 8, global & 0xFFF)).Word(0x91048C00 /* add x0, x0, #0x123 */).Word(A64.Ret);
        at["B"] = a.Here;
        a.Word(A64.StpFpLrPre).Word(A64.MovFpSp);
        a.Word(A64.Adrp(a.Here, text, 0, Base)).Word(A64.AddImm(0, 0, text & 0xFFF));
        a.Later(x => A64.Bl(x, at["A"]));
        a.Word(A64.MovW(1, 0x4242)).Word(A64.LdpFpLrPost).Word(A64.Ret);
        var data = new byte[0x2000];
        Encoding.ASCII.GetBytes("hello arm build\0").CopyTo(data, (int)(text - Data));
        var image = CodeTestImage.Synthetic(NativeArch.Arm64, a.Bytes(), data, entry: Code);
        return new Build(NativeCodeIndex.Build(image), at);
    }

    [Fact]
    public void Moved_functions_match_on_masked_bytes()
    {
        var (o, n) = (Make(false), Make(true));
        var m = BuildMatcher.Match(ImagePrints.Build(o.Index, default), ImagePrints.Build(n.Index, default), new MatchOptions { UseNames = false }, default);
        foreach (var name in new[] { "main", "A", "B" })
        {
            var pair = m.ForOldStart(o.At[name]);
            Assert.True(pair != null, $"{name} unmatched");
            Assert.Equal(n.At[name], m.New.Functions[pair!.New].Start);
        }
        // A and B only moved: identical once branch, page and low-12 fields are masked
        Assert.Equal(m.Old.Functions[m.ForOldStart(o.At["A"])!.Old].BytesHash, m.New.Functions[m.ForOldStart(o.At["A"])!.New].BytesHash);
        Assert.Equal(m.Old.Functions[m.ForOldStart(o.At["B"])!.Old].BytesHash, m.New.Functions[m.ForOldStart(o.At["B"])!.New].BytesHash);
        Assert.Null(m.ByNew[m.New.ByStart[n.At["X"]]]);
    }

    /// <summary>The glibc and musl builds of one library: most functions match, exports by name and many by masked bytes.</summary>
    [Trait("Speed", "Slow")]
    [Fact]
    public void Glibc_and_musl_builds_of_one_library_match()
    {
        var o = NativeCodeIndex.Build(NativeImageLoader.Open(NativeFormats.NativeFixtures.LinuxArm64DbgShim));
        var n = NativeCodeIndex.Build(NativeImageLoader.Open(NativeFormats.NativeFixtures.LinuxMuslArm64DbgShim));
        var m = BuildMatcher.Match(ImagePrints.Build(o, default), ImagePrints.Build(n, default), new MatchOptions(), default);
        int matched = m.Pairs.Count, identical = m.Pairs.Count(p => m.Old.Functions[p.Old].BytesHash == m.New.Functions[p.New].BytesHash);
        Assert.True(matched * 10 > o.Functions.Count * 6, $"{matched} of {o.Functions.Count} functions matched");
        Assert.True(identical * 10 > matched * 3, $"{identical} of {matched} pairs identical once masked");
        var export = o.Image.Exports.First(e => e.Name == "RegisterForRuntimeStartup");
        Assert.Equal(n.Image.Exports.First(e => e.Name == "RegisterForRuntimeStartup").Rva, m.New.Functions[m.ForOldStart(export.Rva)!.New].Start);
    }

    [Fact]
    public void Patterns_wildcard_address_fields_and_find_the_function_in_the_new_build()
    {
        var (o, n) = (Make(false), Make(true));
        var made = CodePatterns.Make(o.Index, o.At["B"], 64, allowReference: false, referenceOnly: false, default);
        Assert.True(made.Unique, made.Note);
        // stp / mov fixed, adrp fully wild, add with its low-12 bits wild
        Assert.StartsWith("FD 7B BF A9 FD 03 00 91 ?? ?? ?? ?? 00 ?? ?? 91", made.Pattern.ToString());
        var hits = CodePatterns.Find(CodePatterns.CodeSections(n.Index.Image), made.Pattern, 10, out int total, default);
        Assert.Equal(1, total);
        Assert.Equal(n.At["B"], hits[0]);
    }
}
