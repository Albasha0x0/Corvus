using System.Diagnostics;
using System.Text.RegularExpressions;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Pe;
using Corvus.Native.ReadyToRun;
using Corvus.Services;
using Corvus.Services.Analysis;
using Corvus.Tools;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>ReadyToRun assemblies of the running .NET shared framework (crossgen'd on every supported platform).</summary>
internal static class R2RFramework
{
    private static readonly Lazy<string?> LinqPath = new(() => Find("System.Linq.dll"));

    public static string Directory => Path.GetDirectoryName(typeof(object).Assembly.Location)!;

    /// <summary>
    /// The framework file when it exists and is ReadyToRun code get_r2r_code disassembles (x86 / x64; macOS and Linux
    /// on ARM64 ship ARM64 code), else null.
    /// </summary>
    public static string? Find(string file)
    {
        var path = Path.Combine(Directory, file);
        return File.Exists(path) && AssemblyTraits.IsReadyToRun(File.ReadAllBytes(path))
               && R2RImage.Open(PeFile.Open(path)) is { } image && R2RDisassembly.CanDecode(image.Arch) ? path : null;
    }

    public static string? Linq => LinqPath.Value;

    /// <summary>The VA of the first precompiled method's entry in the framework's System.Linq.dll, or null.</summary>
    public static string? LinqEntryVa()
    {
        if (Linq == null) return null;
        var pe = PeFile.Open(Linq);
        var image = R2RImage.Open(pe)!;
        return NativeAddress.Va(pe, image.RuntimeFunctions[image.Entries[0].RuntimeFunction].Begin);
    }
}

public sealed class R2RFrameworkFactAttribute : FactAttribute
{
    public R2RFrameworkFactAttribute()
    {
        if (R2RFramework.Linq == null) Skip = "The shared framework's System.Linq.dll is not x86 / x64 ReadyToRun code here.";
    }
}

public class ReadyToRunTests(ITestOutputHelper output)
{
    private static (Env Env, ReadyToRunTools Tools, ReadyToRunService Service) Setup()
    {
        var env = new Env();
        var service = new ReadyToRunService(env.Workspace);
        return (env, new ReadyToRunTools(env.Workspace, service, env.Pager), service);
    }

    [R2RFrameworkFact]
    public async Task FrameworkMethodCodeNamesCallsAndMapsBack()
    {
        var (env, tools, _) = Setup();
        using var _ = env;
        var text = await tools.GetR2RCode("System.Linq.Enumerable::Any", R2RFramework.Linq, maxBodies: 2);
        output.WriteLine(text);
        Assert.Contains("native code in System.Linq.dll (ReadyToRun", text);
        Assert.Matches(@"(?m)^; hot code 0x[0-9A-F]+-0x[0-9A-F]+", text);
        Assert.Matches(@"(?m)\s ret\s*$", text);
        // A call through an import cell shows the managed callee.
        Assert.Matches(@"call\s+qword ptr \[[\w.`/<>, ]+::\w+(<[^>]*>)?\(", text);

        // Reverse: an instruction inside the first body maps back to the same method.
        var lines = Regex.Matches(text, @"(?m)^  ([0-9A-F]{8,16})  [0-9A-F]+ +\S").Select(m => m.Groups[1].Value).ToList();
        var inside = "0x" + lines[Math.Min(3, lines.Count - 1)];
        var found = await tools.FindR2RMethod("System.Linq", inside);
        output.WriteLine(found);
        Assert.Contains("into the hot code", found);
        Assert.Contains("System.Linq.Enumerable::Any<", found);
        Assert.Contains("instruction:", found);

        // An import cell address is described by what it resolves to.
        var cell = Regex.Match(text, @"(?m)^    \[(0x[0-9A-F]+)\] (.+)$");
        if (cell.Success)
            Assert.Contains(cell.Groups[2].Value.Trim(), await tools.FindR2RMethod("System.Linq", cell.Groups[1].Value));

        var info = env.Workspace.Read(() => env.Report.Build(env.Workspace.Get("System.Linq")));
        Assert.Matches(@"ReadyToRun: version \d+\.\d+, AMD64|ReadyToRun: version \d+\.\d+, \w+", info);
        Assert.Contains("methods with native code", info);
        Assert.Contains("not composite", info);
    }

    [Fact]
    public async Task IlOnlyAssemblyIsUnsupported()
    {
        var (env, tools, _) = Setup();
        using var _ = env;
        var error = await Assert.ThrowsAsync<ToolError>(() => tools.GetR2RCode("Account::Score"));
        Assert.Equal(ErrorCode.Unsupported, error.Code);
        Assert.Contains("not a ReadyToRun image", error.Message);
        Assert.NotNull(error.Remediation);
        Assert.Equal(ErrorCode.Unsupported, (await Assert.ThrowsAsync<ToolError>(() => tools.FindR2RMethod("TestFixture", "0x1000"))).Code);
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => tools.GetR2RCode("Fixture.Model.Account"))).Code);
        Assert.DoesNotContain("ReadyToRun:", env.Workspace.Read(() => env.Report.Build(env.Fixture)));
    }

    [R2RFrameworkFact]
    public async Task MethodsWithoutCodeAndAddressesOutsideCodeAreTypedErrors()
    {
        var (env, tools, _) = Setup();
        using var _ = env;
        var none = await Assert.ThrowsAsync<ToolError>(() => tools.GetR2RCode("System.Linq.Enumerable::Any", R2RFramework.Linq, instantiation: "NoSuchTypeArgument"));
        Assert.Equal(ErrorCode.Unsupported, none.Code);
        Assert.Contains("no compiled body matches", none.Message);
        var outside = await Assert.ThrowsAsync<ToolError>(() => tools.FindR2RMethod("System.Linq", "rva:0x10"));
        Assert.Equal(ErrorCode.NotFound, outside.Code);
    }

    [Fact]
    public void NativeFormatIntegers()
    {
        // Unsigned 1-byte and 2-byte forms, signed -1, then nibble-encoded integers (low nibble first).
        byte[] data = [0x7E, 0x05, 0x40, 0xFE, 0x93, 0x03, 0x00];
        var view = new ImageView(new BytesImage(data));
        Assert.Equal(1u, NativeFormat.DecodeUnsigned(view, 0, out uint a));
        Assert.Equal(63u, a);
        Assert.Equal(3u, NativeFormat.DecodeUnsigned(view, 1, out uint b));
        Assert.Equal((0x05u >> 2) | (0x40u << 6), b);
        Assert.Equal(4u, NativeFormat.DecodeSigned(view, 3, out int c));
        Assert.Equal(-1, c);
        // 0x93: low nibble 3 (value 3, end), high nibble 9 (continue: 1), then low nibble 3 (end) -> (1 << 3) | 3.
        var nibbles = new NibbleReader(view, 4);
        Assert.Equal(3u, nibbles.ReadUInt());
        Assert.Equal(11u, nibbles.ReadUInt());
        Assert.Throws<R2RFormatException>(() => view.U32(5));
    }

    /// <summary>A flat byte array as an image (RVA = offset).</summary>
    private sealed class BytesImage(byte[] data) : INativeImage
    {
        public string Path => "";
        public string Sha256 => "";
        public NativeArch Arch => NativeArch.X64;
        public bool Is64Bit => true;
        public bool IsDll => true;
        public ulong ImageBase => 0;
        public uint EntryPointRva => 0;
        public uint SizeOfImage => (uint)data.Length;
        public IReadOnlyList<NativeSection> Sections => [];
        public IReadOnlyList<NativeImport> Imports => [];
        public IReadOnlyList<NativeExport> Exports => [];
        public IReadOnlyList<RuntimeFunction> RuntimeFunctions => [];
        public IReadOnlyList<uint> RelocationRvas => [];
        public IReadOnlyList<uint> TlsCallbackRvas => [];
        public IReadOnlyList<ParseIssue> Issues => [];
        public int Read(uint rva, Span<byte> destination)
        {
            if (rva >= data.Length) return 0;
            int n = Math.Min(destination.Length, data.Length - (int)rva);
            data.AsSpan((int)rva, n).CopyTo(destination);
            return n;
        }
        public bool TryRvaToFileOffset(uint rva, out long fileOffset) { fileOffset = rva; return rva < data.Length; }
        public bool TryFileOffsetToRva(long fileOffset, out uint rva) { rva = (uint)fileOffset; return fileOffset < data.Length; }
        public NativeSection? SectionAt(uint rva) => null;
    }
}

/// <summary>Every precompiled body of several framework assemblies: decodes, lies in code, names resolve, reverse lookups agree.</summary>
[Trait("Speed", "Slow")]
public class ReadyToRunSweepTests(ITestOutputHelper output)
{
    [Theory]
    [InlineData("System.Private.CoreLib.dll")]
    [InlineData("System.Linq.dll")]
    [InlineData("System.Collections.dll")]
    [InlineData("System.Text.Json.dll")]
    [InlineData("System.Net.Http.dll")]
    [InlineData("System.Text.RegularExpressions.dll")]
    public void FrameworkAssembly(string file)
    {
        var path = R2RFramework.Find(file);
        if (path == null) { output.WriteLine($"{file}: not ReadyToRun here, skipped"); return; }
        using var env = new Env();
        var asm = env.Workspace.Load(path);
        var sw = Stopwatch.StartNew();
        var code = new ReadyToRunService(env.Workspace).Require(asm);
        var map = code.Map!;
        var image = code.CodeImage!;
        output.WriteLine($"{file}: {map.Bodies.Count} bodies, {image.RuntimeFunctions.Count} runtime functions, parsed in {sw.ElapsedMilliseconds} ms");
        Assert.NotEmpty(map.Bodies);

        var disassembler = R2RDisassembly.CanDecode(image.Arch) ? R2RDisassembly.Disassembler(image, code.Symbols) : null;
        int unresolved = 0, invalid = 0, instructions = 0;
        foreach (var body in map.Bodies)
        {
            Assert.NotEmpty(body.Ranges);
            Assert.Equal(R2RRangeKind.Hot, body.Ranges[0].Kind);
            foreach (var r in body.Ranges)
            {
                var section = image.Image.SectionAt(r.Function.Begin);
                Assert.True(section is { IsExecutable: true } && section.Contains(r.Function.End - 1), $"{code.Label(body)}: range 0x{r.Function.Begin:X}-0x{r.Function.End:X} outside code");
                foreach (uint at in new[] { r.Function.Begin, r.Function.Begin + (r.Function.End - r.Function.Begin) / 2, r.Function.End - 1 })
                {
                    var (bodies, range) = map.BodiesAt(at);
                    Assert.Contains(body, bodies);
                    Assert.Equal(r.Function.Index, range!.Function.Index);
                }
            }
            if (code.Label(body).Contains("]0x")) unresolved++;
            foreach (var (section, cell) in image.Fixups(body.Entry.FixupsRva))
                Assert.NotNull(code.Symbols.CellAt(image.ImportSections[section].Rva + (uint)cell * image.ImportSections[section].EntrySize));
            if (disassembler == null) continue;
            foreach (var (_, _, line) in R2RDisassembly.Lines(disassembler, body, 100_000, out _))
                if (line != null)
                {
                    instructions++;
                    if (line.Facts.Flow == Native.Code.FlowKind.Invalid) invalid++;
                }
        }
        output.WriteLine($"{instructions} instructions, {invalid} undecodable, {unresolved} unresolved names, {sw.ElapsedMilliseconds} ms");
        Assert.Equal(0, unresolved);
        Assert.Equal(0, invalid);
    }

    /// <summary>
    /// Mutated ReadyToRun data (header, entry point tables, runtime functions, import sections, signatures): parsing, the
    /// code map, fixup lists, cell signatures and disassembly either succeed or throw <see cref="R2RFormatException"/>, in bounded time.
    /// </summary>
    [Fact]
    public void MutatedImagesFailCleanly()
    {
        var path = R2RFramework.Linq;
        if (path == null) { output.WriteLine("System.Linq.dll is not ReadyToRun here, skipped"); return; }
        var clean = File.ReadAllBytes(path);
        var pe = PeFile.FromBytes(clean, path);
        var image = R2RImage.Open(pe)!;
        var targets = new List<(long Offset, int Length)>();
        void Add(uint rva, uint size)
        {
            if (size > 0 && pe.TryRvaToFileOffset(rva, out long off)) targets.Add((off, (int)Math.Min(size, clean.Length - off)));
        }
        Add(image.HeaderRva, 12 + 12 * (uint)image.Sections.Count);
        foreach (var s in image.Sections.Where(s => s.Type is 101 or 102 or 103 or 109 or 112 or 120)) Add(s.Rva, s.Size);
        foreach (var s in image.ImportSections.Where(s => s.SignaturesRva != 0)) Add(s.SignaturesRva, (uint)s.Count * 4);
        Add(image.ImportSections.Where(s => s.SignaturesRva != 0).Select(s => image.CellSignature(s, 0)).Min(), 4096);

        var random = new Random(1234);
        int failures = 0, runs = 300;
        var sw = Stopwatch.StartNew();
        for (int run = 0; run < runs; run++)
        {
            var bytes = (byte[])clean.Clone();
            for (int k = random.Next(1, 8); k > 0; k--)
            {
                var (off, len) = targets[random.Next(targets.Count)];
                long at = off + random.Next(len);
                bytes[at] = random.Next(3) switch { 0 => (byte)random.Next(256), 1 => (byte)(bytes[at] ^ (1 << random.Next(8))), _ => 0xFF };
            }
            var cpu = ThreadCpuClock.Now();
            try
            {
                var mutated = R2RImage.Open(PeFile.FromBytes(bytes, path));
                if (mutated == null) continue;
                var map = new R2RCodeMap(mutated);
                var sigs = new R2RSignatures(mutated.View, null);
                var symbols = new R2RSymbols(map, new NullNames(), _ => "m");
                var disassembler = R2RDisassembly.Disassembler(mutated, symbols);
                foreach (var body in map.Bodies.Take(200))
                {
                    foreach (var (section, cell) in mutated.Fixups(body.Entry.FixupsRva).Take(50))
                        sigs.Fixup(mutated.CellSignature(mutated.ImportSections[section], cell));
                    R2RDisassembly.Lines(disassembler, body, 2000, out _);
                }
            }
            catch (R2RFormatException) { failures++; }
            Assert.True(ThreadCpuClock.Now() - cpu is var took && took < TimeSpan.FromSeconds(10), $"run {run} took {took} of CPU");
        }
        output.WriteLine($"{runs} mutations: {failures} rejected as malformed, {sw.ElapsedMilliseconds} ms");
    }

    private sealed class NullNames : IR2RNames
    {
        public string Type(int module, uint token) => "t";
        public string Method(int module, uint token, string? owner, IReadOnlyList<string>? methodArgs) => "m";
        public string Field(int module, uint token, string? owner) => "f";
        public string UserString(int module, uint offset) => "s";
    }

    /// <summary>
    /// A composite ReadyToRun app (CORVUS_R2R_COMPOSITE_DIR: the output of dotnet publish --self-contained -p:PublishReadyToRun=true
    /// -p:PublishReadyToRunComposite=true): every component's code is found in the composite image and named.
    /// </summary>
    [RequiresRealDataFact("CORVUS_R2R_COMPOSITE_DIR")]
    public void CompositeComponents()
    {
        var dir = RealData.Get("CORVUS_R2R_COMPOSITE_DIR")!;
        using var env = new Env();
        var service = new ReadyToRunService(env.Workspace);
        int components = 0;
        foreach (var file in new[] { "System.Linq.dll", "System.Private.CoreLib.dll", "System.Collections.dll" })
        {
            var path = Path.Combine(dir, file);
            if (!File.Exists(path)) continue;
            var code = service.Require(env.Workspace.Load(path));
            Assert.True(code.Header.IsComponent);
            Assert.True(code.Component >= 0);
            Assert.NotEmpty(code.ByMethodDef);
            foreach (var body in code.ByMethodDef.Values.SelectMany(l => l).Take(2000))
            {
                Assert.DoesNotContain("]0x", code.Label(body));
                Assert.NotNull(code.MethodOf(body));
            }
            output.WriteLine(ReadyToRunService.Summary(env.Workspace, code.Assembly));
            components++;
        }
        Assert.True(components > 0);
    }
}
