using System.Text;
using Corvus.Native;
using Corvus.Native.Code;
using Xunit.Abstractions;

namespace Corvus.Tests.NativeFormats;

/// <summary>The ARM64 code index on ELF and Mach-O images: roots from unwind tables and symbols, PLT and stub thunks, ADRP references.</summary>
public sealed class Arm64FormatCodeTests(ITestOutputHelper output)
{
    private NativeCodeIndex Index(string path)
    {
        var image = NativeImageLoader.Open(path);
        var index = NativeCodeIndex.Build(image);
        var s = index.Stats;
        output.WriteLine($"{Path.GetFileName(path)}: {s.Functions} functions ({image.DeclaredFunctions.Count} declared), {s.Thunks} thunks, {s.NoReturnFunctions} noreturn, " +
                         $"{s.Instructions} instructions, {s.Xrefs} xrefs, {s.Strings} strings, {s.FunctionsWithInvalidCode} with invalid code, {s.UnresolvedJumps} with unresolved jumps, {s.Elapsed.TotalMilliseconds:0} ms");
        return index;
    }

    [Theory]
    [InlineData("so")]
    [InlineData("dylib")]
    public void Unwind_and_symbol_starts_thunks_and_references(string kind)
    {
        var path = kind == "so" ? NativeFixtures.LinuxArm64DbgShim : NativeFixtures.OsxArm64DbgShim;
        var index = Index(path);
        var image = index.Image;
        Assert.Equal(CodeSupport.Full, index.Support);
        var starts = index.Functions.Select(f => f.Start).ToHashSet();
        Assert.All(image.DeclaredFunctions, d => Assert.Contains(d.Rva, starts));
        Assert.True(index.Stats.FunctionsWithInvalidCode * 50 < index.Functions.Count, $"{index.Stats.FunctionsWithInvalidCode} of {index.Functions.Count} run into invalid code");

        var thunks = index.Functions.Where(f => (f.Flags & FunctionFlags.Thunk) != 0).ToList();
        Assert.NotEmpty(thunks);
        Assert.All(thunks, t => Assert.StartsWith("j_", t.Name));
        // calls reach imports through the thunks
        var called = image.Imports.Where(i => index.Callers(i).Count > 0).ToList();
        Assert.True(called.Count * 2 > image.Imports.Count(i => i.Name != null && !i.Name.StartsWith("__", StringComparison.Ordinal)) / 2, $"{called.Count} of {image.Imports.Count} imports called");

        // ADRP + ADD references from code to strings
        var codeStrings = index.Strings.Count(s => index.RefsTo(s.Rva).Any(x => x.Kind == XrefKind.Address && index.FunctionAt(x.From) != null));
        Assert.True(codeStrings > 20, $"{codeStrings} strings referenced from code");
        var export = image.Exports.First(e => e.Name!.Contains("RegisterForRuntimeStartup", StringComparison.Ordinal));
        var fn = index.FunctionByStart(export.Rva)!;
        Assert.Equal(export.Name, fn.KnownName);
        Assert.NotEmpty(index.Callees(fn));
        Assert.Contains(index.Functions, f => (f.Sources & FunctionSource.Unwind) != 0 || (f.Sources & FunctionSource.FunctionStarts) != 0);
        Assert.Contains(index.Functions, f => (f.Flags & FunctionFlags.NoReturn) != 0);
    }

    /// <summary>Call arguments on a real library: imports called with signatures, string arguments recovered through ADRP pairs.</summary>
    [Permit("reference-tool")]
    [Trait("Speed", "Slow")]
    [Fact]
    public void Call_arguments_on_a_real_library()
    {
        var index = Index(NativeFixtures.LinuxArm64DbgShim);
        var analysis = Native.Calls.Arm64CallSites.For(index);
        var sites = index.Functions.SelectMany(f => analysis.CallsIn(f)).ToList();
        int strings = sites.Count(s => s.Arguments.Any(a => a.Kind == Native.Calls.ArgKind.String));
        output.WriteLine($"{sites.Count} call sites, {sites.Count(s => !s.Guessed)} with a signature, {strings} with a string argument");
        Assert.True(sites.Count(s => s.Kind == Native.Calls.CalleeKind.Import && !s.Guessed) > 20);
        Assert.True(strings > 20, $"{strings} call sites with a string argument");
    }

    /// <summary>A dylib whose code takes the address of a CFString constant: the disassembly shows the string; data in code is not decoded.</summary>
    [Fact]
    public void CfString_references_and_data_in_code()
    {
        const uint Cf = MachOWriter.ConstOffset, Chars = MachOWriter.ConstOffset + 0x40;
        var a = new A64(MachOWriter.TextOffset);
        a.Word(A64.Adrp(a.Here, Cf, 0, 0)).Word(A64.AddImm(0, 0, Cf & 0xFFF)).Word(A64.Ret);
        uint data = a.Here;
        a.Word(0x14000001).Word(A64.Nop); // a word that decodes as a branch, marked data in code
        var konst = new byte[0x100];
        Encoding.ASCII.GetBytes("hello cf\0").CopyTo(konst, 0x40);
        BitConverter.GetBytes(8UL).CopyTo(konst, 24);
        var w = new MachOWriter
        {
            Text = a.Bytes(), Const = konst, ChainedFormat = 6, Fixups = [new(Cf + 16, Target: Chars)],
            FunctionStarts = [MachOWriter.TextOffset], DataInCode = [(data, 4, 1)],
        };
        var bytes = w.Build();
        // the writer names the section __const: make it __cfstring
        var from = Encoding.ASCII.GetBytes("__const\0\0\0\0\0\0\0\0\0__DATA_CONST");
        int at = bytes.AsSpan().IndexOf(from);
        Assert.True(at > 0);
        Encoding.ASCII.GetBytes("__cfstring").CopyTo(bytes, at);
        var image = Native.MachO.MachOFile.FromBytes(bytes, "cf.dylib");
        var index = NativeCodeIndex.Build(image);
        var lines = index.Disassemble(MachOWriter.TextOffset, 3);
        Assert.Equal("@\"hello cf\"", lines[1].Comment);
        Assert.Equal(FlowKind.Invalid, index.Decode(data)!.Flow);
        Assert.Contains(index.Strings, s => s.Rva == Chars);
    }

    /// <summary>Both slices of a large universal dylib (x86_64 through the x86 decoder, arm64): function starts are declared, code decodes cleanly.</summary>
    [Permit("reference-tool")]
    [Trait("Speed", "Slow")]
    [Theory]
    [InlineData("arm64")]
    [InlineData("x86_64")]
    public void Universal_slices_index_cleanly(string slice)
    {
        var image = NativeImageLoader.Open(NativeFixtures.OsxFatSkia, slice);
        var index = NativeCodeIndex.Build(image);
        var s = index.Stats;
        output.WriteLine($"{slice}: {s.Functions} functions ({image.DeclaredFunctions.Count} declared), {s.Thunks} thunks, {s.Instructions} instructions, " +
                         $"{s.Strings} strings, {s.FunctionsWithInvalidCode} with invalid code, {s.UnresolvedJumps} with unresolved jumps, {s.Elapsed.TotalSeconds:0.0} s");
        var starts = index.Functions.Select(f => f.Start).ToHashSet();
        Assert.All(image.DeclaredFunctions, d => Assert.Contains(d.Rva, starts));
        Assert.True(s.FunctionsWithInvalidCode * 50 < s.Functions, $"{s.FunctionsWithInvalidCode} of {s.Functions} run into invalid code");
        Assert.True(s.Thunks > 50);
    }

    /// <summary>Every instruction of every function we decode against llvm-objdump's mnemonic at the same address (aliases aside).</summary>
    [Permit("reference-tool")]
    [Trait("Speed", "Slow")]
    [Theory]
    [InlineData("so")]
    [InlineData("dylib")]
    [InlineData("dll")]
    public void Mnemonics_agree_with_llvm_objdump(string kind)
    {
        var path = kind switch { "so" => NativeFixtures.LinuxArm64DbgShim, "dylib" => NativeFixtures.OsxArm64DbgShim, _ => NativeFixtures.WinArm64DbgShim };
        if (LlvmOracle.Run("llvm-objdump", LlvmOracle.Options.Disassemble, path) is not { } listing) { output.WriteLine($"{LlvmOracle.Variable} is not set"); return; }
        var index = Index(path);
        ulong bias = index.Image.Format == ImageFormat.Pe ? 0 : index.Image.ImageBase;
        var theirs = new Dictionary<ulong, string>();
        foreach (var line in listing.Split('\n'))
            if (System.Text.RegularExpressions.Regex.Match(line, @"^\s*([0-9a-f]+):\s+([a-z][a-z0-9.]*)") is { Success: true } m)
                theirs[Convert.ToUInt64(m.Groups[1].Value, 16) - bias] = m.Groups[2].Value;
        var dis = index.CreateDisassembler();
        int compared = 0, agreed = 0;
        var differ = new Dictionary<string, int>();
        foreach (var f in index.Functions)
            foreach (var (s, e) in index.Ranges(f))
                foreach (var l in dis.Disassemble(s, (int)((e - s) / 4), e))
                {
                    if (!theirs.TryGetValue(l.Rva + (index.Image.Format == ImageFormat.Pe ? index.Image.ImageBase : 0), out var mnemonic)) continue;
                    compared++;
                    var ours = l.Text.Split(' ', 2)[0];
                    if (ours == mnemonic) agreed++;
                    else { var key = $"{ours} / {mnemonic}"; differ[key] = differ.GetValueOrDefault(key) + 1; }
                }
        output.WriteLine($"{agreed} of {compared} mnemonics agree ({100.0 * agreed / Math.Max(1, compared):0.00}%)");
        foreach (var (k, n) in differ.OrderByDescending(kv => kv.Value).Take(15)) output.WriteLine($"  ours / llvm: {k}  x{n}");
        Assert.True(compared > 20_000, $"{compared} instructions compared");
        Assert.True(agreed >= compared * 0.98, $"{agreed} of {compared} agree");
    }
}
