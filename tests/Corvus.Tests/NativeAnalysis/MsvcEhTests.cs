using System.Buffers.Binary;
using System.Diagnostics;
using System.Text.RegularExpressions;
using Corvus.Native;
using Corvus.Native.Code;
using Corvus.Native.Msvc;
using Corvus.Native.Pe;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>
/// MSVC exception handling metadata: the FH4 encoding, invariants on system DLLs, corrupted metadata, the attachment
/// of funclets and handlers to their functions, an exact check against a compiled sample (Slow, needs the Visual C++
/// build tools), and a sweep over System32 / SysWOW64 (Slow).
/// </summary>
public class MsvcEhTests(ITestOutputHelper output)
{
    private static string? SystemFile(string name, bool wow64 = false)
    {
        if (!OperatingSystem.IsWindows()) return null;
        var dir = wow64 ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64") : Environment.SystemDirectory;
        var path = Path.Combine(dir, name);
        return File.Exists(path) ? path : null;
    }

    [Fact]
    public void Fh4_compressed_unsigned_values_of_every_length()
    {
        // length in the low bits of the first byte: x0 = 1 byte, 01 = 2, 011 = 3, 0111 = 4, 1111 = 5 (value in the next 4 bytes)
        byte[] data = [
            0x7F << 1,
            (0x1234 << 2 | 1) & 0xFF, 0x1234 << 2 >> 8,
            (0x12345 << 3 | 3) & 0xFF, (0x12345 << 3) >> 8 & 0xFF, 0x12345 << 3 >> 16,
            0x0F, 0x78, 0x56, 0x34, 0x12,
            0x00,
        ];
        var c = new Fh4Cursor(data);
        Assert.Equal(0x7Fu, c.ReadUnsigned());
        Assert.Equal(0x1234u, c.ReadUnsigned());
        Assert.Equal(0x12345u, c.ReadUnsigned());
        Assert.Equal(0x12345678u, c.ReadUnsigned());
        Assert.Equal(0u, c.ReadUnsigned());
        Assert.False(c.Failed);
        c.ReadInt();
        Assert.True(c.Failed); // past the end: failed, never thrown

        var four = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(four, 0x0ABCDEF0u << 4 | 7);
        var d = new Fh4Cursor(four);
        Assert.Equal(0x0ABCDEF0u, d.ReadUnsigned());
    }

    /// <summary>Cross-checks every decoded frame: handlers in executable code, scopes inside the function, parents that have frames.</summary>
    internal static void CheckInvariants(INativeImage image, MsvcEhResult r)
    {
        bool Code(uint rva) => image.SectionAt(rva) is { IsExecutable: true };
        Assert.True(r.Frames.Zip(r.Frames.Skip(1)).All(p => p.First.FunctionRva <= p.Second.FunctionRva), "frames sorted");
        foreach (var f in r.Frames)
        {
            Assert.All(f.Children, c => Assert.True(Code(c.Rva), $"{f.FunctionRva:X}: child {c.Rva:X} not in code"));
            foreach (var s in f.Scopes)
            {
                Assert.True(Code(s.HandlerRva));
                if (s.BeginRva is { } b) Assert.True(b < s.EndRva);
                if (s.FilterRva is { } filter) Assert.True(Code(filter));
            }
            foreach (var t in f.TryBlocks)
            {
                Assert.True(t.TryLow <= t.TryHigh && t.TryHigh <= t.CatchHigh);
                Assert.All(t.Catches, c => Assert.True(Code(c.HandlerRva)));
            }
            Assert.All(f.Unwind, u => Assert.True(u.ToState < u.State, $"{f.FunctionRva:X}: state {u.State} unwinds to {u.ToState}"));
        }
        foreach (var (child, parents) in r.Parents)
            Assert.All(parents, p => Assert.True(p.Parent != child && r.FrameOf(p.Parent) != null, $"{child:X} -> {p.Parent:X}"));
    }

    [Fact]
    public void X64_system_dll_with_cxx_and_seh()
    {
        if (SystemFile("msvcp_win.dll") is not { } path) return;
        var pe = PeFile.Open(path);
        var r = MsvcEh.Analyze(pe);
        output.WriteLine(r.Stats.ToString());
        CheckInvariants(pe, r);
        Assert.Equal(0, r.RejectCount);
        Assert.True(r.Stats.Cxx3 + r.Stats.Cxx4 > 300, r.Stats.ToString());
        Assert.True(r.Stats.CSpecific > 0 && r.Stats.GsOnly > 0 && r.Stats.Fragments > 0, r.Stats.ToString());
        var catches = r.Frames.SelectMany(f => f.TryBlocks).SelectMany(t => t.Catches).ToList();
        Assert.NotEmpty(catches);
        // every catch with a type descriptor has a demangled name
        Assert.All(catches.Where(c => c.TypeDescriptorRva != null), c => Assert.NotNull(c.TypeName));
        Assert.Contains(catches, c => c.TypeDescriptorRva == null); // catch (...)
    }

    /// <summary>
    /// ARM64 .xdata with the X bit: f's __C_specific_handler scope table (E set, one code word), g's FuncInfo4 (extension
    /// word, one epilog scope) whose catch funclet has packed unwind data, and h with packed unwind data (no frame).
    /// Handlers are named through adrp / ldr / br import thunks.
    /// </summary>
    [Fact]
    public void Arm64_xdata_handlers_and_packed_entries()
    {
        const uint Code = CodeTestImage.SyntheticCodeRva, Data = CodeTestImage.SyntheticDataRva, ImageBase = 0x10000000;
        const uint F = Code, G = Code + 0x40, H = Code + 0x80, Funclet = Code + 0x100, CSpecific = Code + 0x180, Fh4 = Code + 0x190;
        const uint CSpecificSlot = Data + 0x200, Fh4Slot = Data + 0x208;
        var a = new A64(Code);
        a.Word(A64.StpFpLrPre).Word(A64.MovFpSp).Word(A64.Nop).Word(A64.Nop).Word(A64.Nop).Word(A64.Nop).Word(A64.LdpFpLrPost).Word(A64.Ret);
        a.Word(A64.MovW(0, 1)).Word(A64.LdpFpLrPost).Word(A64.Ret);                            // __except block at F + 0x20
        while (a.Here < G) a.Word(A64.Nop);
        a.Word(A64.StpFpLrPre).Word(A64.MovFpSp).Word(A64.Nop).Word(A64.Nop).Word(A64.Nop).Word(A64.LdpFpLrPost).Word(A64.Ret);
        while (a.Here < G + 0x30) a.Word(A64.Nop);
        a.Word(A64.MovW(0, 2)).Word(A64.LdpFpLrPost).Word(A64.Ret);                            // catch continuation at G + 0x30
        while (a.Here < H) a.Word(A64.Nop);
        a.Word(A64.MovW(0, 3)).Word(A64.Ret);
        while (a.Here < Funclet) a.Word(A64.Nop);
        a.Word(A64.StpFpLrPre).Later(at => A64.Adr(at, G + 0x30, 0)).Word(A64.LdpFpLrPost).Word(A64.Ret);
        while (a.Here < CSpecific) a.Word(A64.Nop);
        a.Later(at => A64.Adrp(at, CSpecificSlot, 16, ImageBase)).Word(A64.LdrX(16, 16, CSpecificSlot & 0xFFF)).Word(A64.Br(16)).Word(A64.Nop);
        a.Later(at => A64.Adrp(at, Fh4Slot, 16, ImageBase)).Word(A64.LdrX(16, 16, Fh4Slot & 0xFFF)).Word(A64.Br(16)).Word(A64.Nop);

        var d = new PeBlob(Data);
        uint xdataF = d.U32(0x10 | 1u << 20 | 1u << 21 | 1u << 27);                              // 16 words, X, E, one code word
        d.U32(0xE4E4E4E4);
        d.U32(CSpecific);
        d.U32(1);                                                                                // one scope: constant filter, __except block
        d.U32(F + 8); d.U32(F + 0x10); d.U32(1); d.U32(F + 0x20);
        uint xdataG = d.U32(0x10 | 1u << 20);                                                    // X; epilog count and code words in the extension
        d.U32(1 | 1u << 16);
        d.U32(0x00000005);
        d.U32(0xE4E4E4E4);
        d.U32(Fh4);
        uint infoAt = d.U32(0);
        uint type = d.U64(0); d.U64(0); d.Ascii(".H"); d.Align(4);                               // type descriptor of int
        uint info = d.Here;
        d.Bytes([0x18]);                                                                         // unwind map, try block map, IP-to-state map
        uint unwindAt = d.U32(0), tryAt = d.U32(0), ipAt = d.U32(0);
        uint unwind = d.Bytes([0x04, 0x00, 0x08]);                                               // states 0 and 1 (1 unwinds to 0)
        uint tryMap = d.Bytes([0x02, 0x00, 0x00, 0x02]);                                         // one try block: states 0-0, catch high 1
        uint arrayAt = d.U32(0);
        uint array = d.Bytes([0x02, 0x12]);                                                      // one catch: type, one function-relative continuation
        d.U32(type); d.U32(Funclet); d.Bytes([0x60]);
        uint ip = d.Bytes([0x04, 0x08, 0x02, 0x20, 0x00]);                                       // G + 4 = state 0, G + 0x14 = no state
        d.Patch32(infoAt, info); d.Patch32(unwindAt, unwind); d.Patch32(tryAt, tryMap); d.Patch32(ipAt, ip); d.Patch32(arrayAt, array);
        while (d.Here < Fh4Slot + 8) d.U32(0);

        var image = CodeTestImage.Synthetic(NativeArch.Arm64, a.Bytes(), d.ToArray(),
            imports: [new NativeImport("vcruntime140.dll", "__C_specific_handler", null, 0, CSpecificSlot, false), new NativeImport("vcruntime140.dll", "__CxxFrameHandler4", null, 0, Fh4Slot, false)],
            pdata: [new RuntimeFunction(F, F + 0x40, xdataF), new RuntimeFunction(G, G + 0x40, xdataG), new RuntimeFunction(H, H + 8, 0), new RuntimeFunction(Funclet, Funclet + 0x10, 0)]);
        var index = NativeCodeIndex.Build(image);
        var eh = index.ExceptionInfo;

        Assert.Equal(0, eh.RejectCount);
        Assert.Equal(2, eh.Stats.Frames);
        var scopes = eh.FrameOf(F)!;
        Assert.Equal((MsvcEhScheme.CSpecific, "__C_specific_handler"), (scopes.Scheme, scopes.HandlerName));
        var scope = Assert.Single(scopes.Scopes);
        Assert.Equal((F + 8, F + 0x10, 1, F + 0x20), (scope.BeginRva!.Value, scope.EndRva!.Value, scope.FilterConstant!.Value, scope.HandlerRva));
        Assert.Equal(F, index.FunctionAt(F + 0x20)!.Start);

        var cxx = eh.FrameOf(G)!;
        Assert.Equal((MsvcEhScheme.Cxx4, "__CxxFrameHandler4"), (cxx.Scheme, cxx.HandlerName));
        var clause = Assert.Single(Assert.Single(cxx.TryBlocks).Catches);
        Assert.Equal(("int", Funclet, G + 0x30), (clause.TypeName, clause.HandlerRva, Assert.Single(clause.Continuations)));
        Assert.Equal([(G + 4, 0), (G + 0x14, -1)], cxx.IpToState.Select(x => (x.Rva, x.State)));
        Assert.Equal(G, index.FunctionByStart(Funclet)!.Parent!.Start);
        Assert.Null(eh.FrameOf(H));
        Assert.Null(eh.FrameOf(Funclet));
    }

    /// <summary>Patches bytes over an image: corrupted metadata without writing files.</summary>
    private sealed class PatchedImage(INativeImage inner, Func<uint, byte, byte> patch) : INativeImage
    {
        public string Path => inner.Path;
        public string Sha256 => inner.Sha256;
        public NativeArch Arch => inner.Arch;
        public bool Is64Bit => inner.Is64Bit;
        public bool IsDll => inner.IsDll;
        public ulong ImageBase => inner.ImageBase;
        public uint EntryPointRva => inner.EntryPointRva;
        public uint SizeOfImage => inner.SizeOfImage;
        public IReadOnlyList<NativeSection> Sections => inner.Sections;
        public IReadOnlyList<NativeImport> Imports => inner.Imports;
        public IReadOnlyList<NativeExport> Exports => inner.Exports;
        public IReadOnlyList<RuntimeFunction> RuntimeFunctions => inner.RuntimeFunctions;
        public IReadOnlyList<uint> RelocationRvas => inner.RelocationRvas;
        public IReadOnlyList<uint> TlsCallbackRvas => inner.TlsCallbackRvas;
        public IReadOnlyList<ParseIssue> Issues => inner.Issues;
        public bool TryRvaToFileOffset(uint rva, out long fileOffset) => inner.TryRvaToFileOffset(rva, out fileOffset);
        public bool TryFileOffsetToRva(long fileOffset, out uint rva) => inner.TryFileOffsetToRva(fileOffset, out rva);
        public NativeSection? SectionAt(uint rva) => inner.SectionAt(rva);

        public int Read(uint rva, Span<byte> destination)
        {
            int n = inner.Read(rva, destination);
            for (int i = 0; i < n; i++) destination[i] = patch(rva + (uint)i, destination[i]);
            return n;
        }
    }

    /// <summary>Every address in a function that starts at the previous 64-byte boundary: drives the x86 decoder without code analysis.</summary>
    private sealed class AlignedView : IMsvcEhCodeView
    {
        public uint? FunctionContaining(uint rva) => rva & ~63u;
        public IReadOnlyList<(uint Start, uint End)> RangesOf(uint start) => [(start, start + 64)];
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Corrupted_metadata_never_throws(bool wow64)
    {
        if (SystemFile("version.dll", wow64) is not { } path) return;
        var pe = PeFile.Open(path);
        var data = pe.Sections.Where(s => !s.IsExecutable).ToList();
        var cpu = ThreadCpuClock.Now();
        for (int seed = 0; seed < 24; seed++)
        {
            // flip about one byte in 32 of the data sections (handler data, FuncInfo, scope tables, unwind info)
            int s = seed;
            var image = new PatchedImage(pe, (rva, b) =>
            {
                if (!data.Any(d => d.Contains(rva))) return b;
                uint h = (rva * 2654435761u) ^ (uint)(s * 40503);
                return (h & 31) == 0 ? (byte)(b ^ (h >> 8)) : b;
            });
            var r = MsvcEh.Analyze(image, new AlignedView());
            Assert.True(r.Frames.Count <= pe.RuntimeFunctions.Count + 100_000);
        }
        Assert.True(ThreadCpuClock.Now() - cpu is var took && took < TimeSpan.FromSeconds(10), $"took {took} of CPU");
    }

    [Fact]
    public void Implausible_counts_are_rejected_with_a_reason()
    {
        if (SystemFile("msvcp_win.dll") is not { } path) return;
        var pe = PeFile.Open(path);
        var clean = MsvcEh.Analyze(pe);
        var frame = clean.Frames.First(f => f.Scheme == MsvcEhScheme.Cxx3 && f.MaxState > 0);
        // max state (FuncInfo + 4) set to 0x7FFFFFFF
        uint at = frame.DataRva + 4;
        var image = new PatchedImage(pe, (rva, b) => rva >= at && rva < at + 4 ? (rva == at + 3 ? (byte)0x7F : (byte)0xFF) : b);
        var r = MsvcEh.Analyze(image);
        Assert.Null(r.FrameOf(frame.FunctionRva));
        Assert.Contains(r.Rejects, x => x.Rva == frame.FunctionRva && x.Reason.Contains("max state"));
    }

    /// <summary>Exception chunks are part of their function: its code, its graph, and not functions of their own.</summary>
    internal static void CheckChunks(NativeCodeIndex index, int maxGraphs = int.MaxValue)
    {
        int graphs = 0;
        foreach (var f in index.Functions)
        {
            foreach (var c in f.Chunks)
            {
                Assert.Null(index.FunctionByStart(c.Start));
                Assert.NotNull(index.ChunkOwner(c.Start));
                Assert.NotNull(index.FunctionAt(c.Start));
            }
            if (f.Parent != null) Assert.NotNull(index.ExceptionInfo.FrameOf(f.Parent.Start));
            if (f.Chunks.Count == 0 || graphs++ >= maxGraphs) continue;
            var graph = index.GetGraph(f);
            Assert.Equal(f.InstructionCount, graph.Blocks.Sum(b => b.InstructionCount));
            Assert.All(f.Chunks, c => Assert.NotNull(graph.BlockAt(c.Start)));
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Seh_handlers_join_their_function(bool wow64)
    {
        if (SystemFile("version.dll", wow64) is not { } path) return;
        var pe = PeFile.Open(path);
        var index = NativeCodeIndex.Build(pe);
        var eh = index.ExceptionInfo;
        output.WriteLine(eh.Stats.ToString());
        CheckInvariants(pe, eh);
        Assert.Equal(0, eh.RejectCount);
        Assert.True(wow64 ? eh.Stats.Seh4 > 0 : eh.Stats.CSpecific > 0, eh.Stats.ToString());
        CheckChunks(index);
        var withChunks = index.Functions.Where(f => f.Chunks.Count > 0).ToList();
        Assert.NotEmpty(withChunks);
        foreach (var f in withChunks)
            foreach (var c in f.Chunks)
                Assert.Contains(eh.Parents.GetValueOrDefault(c.Start) ?? [], p => p.Parent == f.Start);
    }

    // ---- compiled sample (Slow) ----

    private const string SampleSource = """
        #include <windows.h>
        #include <stdexcept>
        struct Guard { int* p; Guard(int* q) : p(q) { ++*p; } ~Guard() { --*p; } };
        struct MyError { int code; };
        extern "C" __declspec(dllexport) __declspec(noinline) int Thrower(int x) {
            if (x == 1) throw MyError{ 7 };
            if (x == 2) throw std::runtime_error("bad");
            if (x == 3) throw 42;
            return x;
        }
        extern "C" __declspec(dllexport) __declspec(noinline) int CatchTypes(int x) {
            int counter = 0;
            Guard g(&counter);
            try {
                Guard inner(&counter);
                return Thrower(x);
            } catch (const MyError& e) {
                return e.code;
            } catch (const std::exception&) {
                return -2;
            } catch (int v) {
                return v;
            } catch (...) {
                return -4;
            }
        }
        extern "C" __declspec(dllexport) __declspec(noinline) int SehExcept(int* p) {
            __try {
                return *p;
            } __except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
                return -1;
            }
        }
        extern "C" __declspec(dllexport) __declspec(noinline) int SehFinally(int* p) {
            int r = 0;
            __try {
                r = *p;
            } __finally {
                if (AbnormalTermination()) OutputDebugStringA("abnormal");
            }
            return r;
        }
        extern "C" __declspec(dllexport) __declspec(noinline) int SehNested(int* p) {
            __try {
                __try {
                    return *p;
                } __finally {
                    OutputDebugStringA("finally");
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                return -3;
            }
        }
        """;

    private static Dictionary<string, uint> ReadMap(string path, ulong imageBase)
    {
        var map = new Dictionary<string, uint>(StringComparer.Ordinal);
        var line = new Regex(@"^\s*[0-9a-fA-F]{4}:[0-9a-fA-F]{8}\s+(\S+)\s+([0-9a-fA-F]{8,16})\s");
        foreach (var l in File.ReadLines(path))
        {
            var m = line.Match(l);
            if (!m.Success) continue;
            ulong va = Convert.ToUInt64(m.Groups[2].Value, 16);
            if (va >= imageBase) map.TryAdd(m.Groups[1].Value, (uint)(va - imageBase));
        }
        return map;
    }

    [Theory]
    [Trait("Speed", "Slow")]
    [InlineData("x64")]
    [InlineData("x86")]
    public void Compiled_sample_matches_the_source(string arch)
    {
        var vcvars = VisualStudio.VcVarsAll();
        if (vcvars == null) return; // no Visual C++ build tools
        using var dir = new TempDir();
        File.WriteAllText(dir.File("sample.cpp"), SampleSource);
        var psi = new ProcessStartInfo("cmd.exe")
        {
            WorkingDirectory = dir.Path,
            Arguments = $"/s /c \"\"{vcvars}\" {arch} >nul && cl /nologo /c /O2 /GS /EHs sample.cpp && link /nologo /DLL sample.obj /MAP:sample.map /OUT:sample.dll\"",
        };
        var (code, log) = Tools.Run(psi, 300_000);
        Assert.True(code == 0 && File.Exists(dir.File("sample.dll")), log);
        var pe = PeFile.Open(dir.File("sample.dll"));
        var map = ReadMap(dir.File("sample.map"), pe.ImageBase);
        bool x64 = arch == "x64";
        string Sym(string name) => x64 ? name : "_" + name;
        uint catchTypes = map[Sym("CatchTypes")];

        var index = NativeCodeIndex.Build(pe);
        var eh = index.ExceptionInfo;
        output.WriteLine($"{arch}: {eh.Stats}");
        CheckInvariants(pe, eh);
        CheckChunks(index);
        Assert.Equal(0, eh.RejectCount);

        // C++: the try block's catch clauses, in source order, with their types
        var cxx = eh.FrameOf(catchTypes);
        Assert.NotNull(cxx);
        Assert.Equal(x64 ? MsvcEhScheme.Cxx4 : MsvcEhScheme.Cxx3, cxx.Scheme);
        var tryBlock = Assert.Single(cxx.TryBlocks);
        Assert.Equal(["const MyError &", "const std::exception &", "int", null], tryBlock.Catches.Select(c => c.TypeName));
        Assert.Contains(cxx.Unwind, u => u.ActionRva is { } a && (x64 ? a == map["??1Guard@@QEAA@XZ"] : map.Any(m => m.Key.StartsWith("__unwindfunclet$_CatchTypes$") && m.Value == a)));
        var fn = index.FunctionByStart(catchTypes)!;
        if (x64)
        {
            // FH4: catch funclets are functions with CatchTypes as parent; continuations resume inside CatchTypes
            Assert.Equal(map["CatchTypes$catch$2"], tryBlock.Catches[0].HandlerRva);
            Assert.All(tryBlock.Catches.Skip(1), c => Assert.Equal(map["CatchTypes$catch$3"], c.HandlerRva));
            Assert.Equal(catchTypes, index.FunctionByStart(map["CatchTypes$catch$2"])?.Parent?.Start);
            Assert.All(tryBlock.Catches, c => Assert.All(c.Continuations, k => Assert.Same(fn, index.FunctionAt(k))));
        }
        else
        {
            // FH3 through the __ehhandler$ stub: catch blocks, unwind funclets and the stub are chunks of CatchTypes
            Assert.Equal(map["__ehhandler$_CatchTypes"], cxx.HandlerRva);
            Assert.Equal(Enumerable.Range(0, 4).Select(i => map[$"__catch$_CatchTypes${i}"]), tryBlock.Catches.Select(c => c.HandlerRva));
            var chunks = fn.Chunks.ToDictionary(c => c.Start, c => c.Kind);
            Assert.Equal(MsvcEhChildKind.HandlerStub, chunks[map["__ehhandler$_CatchTypes"]]);
            foreach (var (name, rva) in map.Where(m => m.Key.StartsWith("__unwindfunclet$_CatchTypes$") || m.Key.StartsWith("__catch$_CatchTypes$")))
                Assert.Same(fn, index.FunctionAt(rva));
        }

        // SEH: __except with a filter, __finally, and both nested
        var except = eh.FrameOf(map[Sym("SehExcept")])!;
        var scope = Assert.Single(except.Scopes);
        Assert.False(scope.IsFinally);
        Assert.NotNull(scope.FilterRva);
        Assert.Same(index.FunctionByStart(map[Sym("SehExcept")]), index.FunctionAt(scope.FilterRva!.Value));
        Assert.Same(index.FunctionByStart(map[Sym("SehExcept")]), index.FunctionAt(scope.HandlerRva));
        var fin = Assert.Single(eh.FrameOf(map[Sym("SehFinally")])!.Scopes);
        Assert.True(fin.IsFinally);
        Assert.Same(index.FunctionByStart(map[Sym("SehFinally")]), index.FunctionAt(fin.HandlerRva));
        var nested = eh.FrameOf(map[Sym("SehNested")])!.Scopes;
        Assert.Equal(2, nested.Count);
        Assert.Single(nested, s => s.IsFinally);
        var outer = Assert.Single(nested, s => !s.IsFinally);
        if (x64)
        {
            Assert.Equal(map["SehExcept$filt$0"], scope.FilterRva);
            Assert.Equal(map["SehFinally$fin$0"], fin.HandlerRva);
            Assert.Equal(1, outer.FilterConstant); // __except (EXCEPTION_EXECUTE_HANDLER)
            Assert.Equal(MsvcEhChildKind.Filter, index.FunctionAt(scope.FilterRva!.Value)!.Chunks.Single(c => c.Start == scope.FilterRva).Kind);
        }
        else
        {
            Assert.Equal(MsvcEhScheme.Seh4, eh.FrameOf(map[Sym("SehExcept")])!.Scheme);
            // the __finally is inside the __except: level 1 encloses level 0
            Assert.Equal(-2, nested[0].EnclosingLevel);
            Assert.Equal(0, nested[1].EnclosingLevel);
            Assert.True(nested[1].IsFinally);
        }
    }

    // ---- sweep (Slow) ----

    [Fact]
    [Trait("Speed", "Slow")]
    [Trait(PerfBudget.Trait, PerfBudget.Timing)]
    public void System32_x64_metadata_sweep()
    {
        if (!OperatingSystem.IsWindows()) return;
        int files = 0, rejects = 0;
        var totals = new long[8];
        var failures = new List<string>();
        var slow = new List<string>();
        var slowest = ("", TimeSpan.Zero);
        var total = Stopwatch.StartNew();
        foreach (var path in NativeCodeSweepTests.Sample(Environment.SystemDirectory))
        {
            PeFile pe;
            try { pe = PeFile.Open(path); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or BadImageFormatException) { continue; }
            if (pe.Arch != NativeArch.X64) continue;
            files++;
            var sw = Stopwatch.StartNew();
            try
            {
                var r = MsvcEh.Analyze(pe);
                sw.Stop();
                if (sw.Elapsed > slowest.Item2) slowest = (Path.GetFileName(path), sw.Elapsed);
                CheckInvariants(pe, r);
                var s = r.Stats;
                long[] add = [s.Frames, s.CSpecific, s.Cxx3, s.Cxx4, s.GsOnly, s.Unknown, s.Children, s.Fragments];
                for (int i = 0; i < add.Length; i++) totals[i] += add[i];
                rejects += r.RejectCount;
                if (r.RejectCount > 0) output.WriteLine($"{Path.GetFileName(path)}: {r.RejectCount} rejects, e.g. {r.Rejects[0].Structure}: {r.Rejects[0].Reason}");
                if (sw.Elapsed > TimeSpan.FromSeconds(10)) slow.Add($"{Path.GetFileName(path)}: {sw.Elapsed}");
            }
            catch (Exception ex) { failures.Add($"{Path.GetFileName(path)}: {ex.GetType().Name}: {ex.Message}"); }
        }
        output.WriteLine($"{files} files, {total.Elapsed.TotalSeconds:F1} s, slowest {slowest.Item1} {slowest.Item2.TotalMilliseconds:F0} ms");
        output.WriteLine($"frames {totals[0]} (C_specific {totals[1]}, FH3 {totals[2]}, FH4 {totals[3]}, GS only {totals[4]}, unknown {totals[5]}), " +
                         $"children {totals[6]}, fragments {totals[7]}, rejects {rejects}");
        foreach (var f in failures.Take(40)) output.WriteLine("FAIL " + f);
        Assert.Empty(failures);
        PerfBudget.Check(slow.Count == 0, $"{slow.Count} files over 10 s: {string.Join(", ", slow.Take(10))}", output);
    }
}
