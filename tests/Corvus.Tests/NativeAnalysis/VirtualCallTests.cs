using System.Diagnostics;
using Iced.Intel;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Code;
using Corvus.Native.Msvc;
using Corvus.Native.Pe;
using Corvus.Native.Providers.Ida;
using Corvus.Services;
using Corvus.Tools;
using Xunit.Abstractions;
using static Iced.Intel.AssemblerRegisters;

namespace Corvus.Tests;

/// <summary>Virtual call resolution through MSVC RTTI: a synthetic x64 image with exact edges, MSVC-compiled samples, the IDA cross-check.</summary>
public class VirtualCallTests(ITestOutputHelper output)
{
    private const ulong Base = 0x140000000UL;
    private const uint Data = CodeTestImage.SyntheticDataRva;

    /// <summary>Function slots of the synthetic image (0x40 bytes each from 0x1000).</summary>
    private static readonly string[] Functions =
    [
        "Base_f", "Base_g", "Mid_f", "Leaf_g", "Other_f", "StoreThenCall", "Leaf_ctor", "ConstructThenCall", "UnknownReceiver", "purecall",
        "Shape_name", "Circle_area", "Multi_g", "Multi_h", "Second_h", CallBase, GetLeaf, "UseGetLeaf", "MakeCircle",
    ];

    /// <summary>int __cdecl CallBase(class Base *) and class Leaf * __cdecl GetLeaf(void): classes from decorated names.</summary>
    private const string CallBase = "?CallBase@@YAHPEAVBase@@@Z", GetLeaf = "?GetLeaf@@YAPEAVLeaf@@XZ";

    private static uint At(string name) => 0x1000u + 0x40u * (uint)Array.IndexOf(Functions, name);

    private static byte[] Assemble(uint rva, Action<Assembler> build)
    {
        var a = new Assembler(64);
        build(a);
        var stream = new MemoryStream();
        a.Assemble(new StreamCodeWriter(stream), Base + rva);
        return stream.ToArray();
    }

    private static Instruction Rip(Iced.Intel.Code code, Register reg, uint rva) => Instruction.Create(code, reg, new MemoryOperand(Register.RIP, (long)(Base + rva)));

    /// <summary>
    /// Classes (x64 RTTI, no relocations): Base [f, g]; Mid : Base [Mid::f, g]; Leaf : Mid [Mid::f, Leaf::g]; Other : Base [Other::f, g];
    /// Shape [purecall, name]; Circle : Shape [Circle::area, name]; Second [Second::h]; Multi : Base, Second (at +8) [f, Multi::g] [Multi::h].
    /// </summary>
    internal static (CodeTestImage Image, Dictionary<string, uint> Vftables) Synthetic()
    {
        var d = new PeBlob(Data);
        d.Zero(16);
        var vftables = new Dictionary<string, uint>();
        var tds = new Dictionary<string, uint>();
        uint TypeDescriptor(string name)
        {
            d.Align(8);
            uint at = d.U64(Base + Data);
            d.U64(0);
            d.Ascii($".?AV{name}@@");
            return tds[name] = at;
        }
        foreach (var n in new[] { "Base", "Mid", "Leaf", "Other", "Shape", "Circle", "Second", "Multi" }) TypeDescriptor(n);
        // Hierarchy: (class, [(base, mdisp, contained)]).
        uint Hierarchy(string name, (string Base, int Mdisp, int Contained)[] bases)
        {
            d.Align(8);
            var bcds = new List<uint>();
            foreach (var (b, mdisp, contained) in new[] { (name, 0, bases.Length) }.Concat(bases))
            {
                d.Align(4);
                bcds.Add(d.U32(tds[b]));
                d.U32((uint)contained); d.U32((uint)mdisp); d.U32(unchecked((uint)-1)); d.U32(0); d.U32(0);
            }
            d.Align(4);
            uint array = d.Here;
            foreach (var b in bcds) d.U32(b);
            uint chd = d.U32(0);
            d.U32(bases.Length > 1 && bases.All(b => b.Contained == 0) ? 1u : 0u);
            d.U32((uint)bcds.Count);
            d.U32(array);
            return chd;
        }
        void Class(string name, (string Base, int Mdisp, int Contained)[] bases, params (uint Offset, string[] Slots)[] tables)
        {
            uint chd = Hierarchy(name, bases);
            foreach (var (offset, slots) in tables)
            {
                d.Align(8);
                uint col = d.U32(1);
                d.U32(offset); d.U32(0); d.U32(tds[name]); d.U32(chd); d.U32(col);
                d.Align(8);
                d.U64(Base + col);
                uint vft = d.Here;
                foreach (var s in slots) d.U64(Base + At(s));
                vftables[offset == 0 ? name : $"{name}+{offset}"] = vft;
            }
        }
        Class("Base", [], (0, ["Base_f", "Base_g"]));
        Class("Mid", [("Base", 0, 0)], (0, ["Mid_f", "Base_g"]));
        Class("Leaf", [("Mid", 0, 1), ("Base", 0, 0)], (0, ["Mid_f", "Leaf_g"]));
        Class("Other", [("Base", 0, 0)], (0, ["Other_f", "Base_g"]));
        Class("Shape", [], (0, ["purecall", "Shape_name"]));
        Class("Circle", [("Shape", 0, 0)], (0, ["Circle_area", "Shape_name"]));
        Class("Second", [], (0, ["Second_h"]));
        Class("Multi", [("Base", 0, 0), ("Second", 8, 0)], (0, ["Base_f", "Multi_g"]), (8, ["Multi_h"]));
        d.Align(8);
        d.Zero(16);

        var code = new byte[0x40 * Functions.Length];
        Array.Fill(code, (byte)0xCC);
        void Put(string name, Action<Assembler> build)
        {
            var bytes = Assemble(At(name), build);
            Assert.True(bytes.Length <= 0x40, name);
            bytes.CopyTo(code, At(name) - 0x1000);
        }
        Put("Base_f", a => { a.xor(eax, eax); a.ret(); });
        // this->f(), a tail call: Base and every derived class
        Put("Base_g", a => { a.mov(rax, __qword_ptr[rcx]); a.jmp(__qword_ptr[rax]); });
        Put("Mid_f", a => { a.mov(eax, 1); a.ret(); });
        // This spilled to the home slot and reloaded: Leaf has no derived class, slot 0 is Mid::f.
        Put("Leaf_g", a =>
        {
            a.push(rbx); a.sub(rsp, 0x20);
            a.mov(__qword_ptr[rsp + 0x30], rcx);
            a.xor(ecx, ecx);
            a.mov(rcx, __qword_ptr[rsp + 0x30]);
            a.mov(rax, __qword_ptr[rcx]);
            a.call(__qword_ptr[rax]);
            a.add(rsp, 0x20); a.pop(rbx); a.ret();
        });
        Put("Other_f", a => { a.mov(eax, 2); a.ret(); });
        // The vftable stored, then a call through it: Mid's slot 1.
        Put("StoreThenCall", a =>
        {
            a.sub(rsp, 0x28);
            a.AddInstruction(Rip(Iced.Intel.Code.Lea_r64_m, Register.RAX, vftables["Mid"]));
            a.mov(__qword_ptr[rcx], rax);
            a.mov(rax, __qword_ptr[rcx]);
            a.call(__qword_ptr[rax + 8]);
            a.add(rsp, 0x28); a.ret();
        });
        Put("Leaf_ctor", a =>
        {
            a.AddInstruction(Rip(Iced.Intel.Code.Lea_r64_m, Register.RAX, vftables["Leaf"]));
            a.mov(__qword_ptr[rcx], rax);
            a.mov(rax, rcx);
            a.ret();
        });
        // A constructor called on the object, then a call through its vftable: Leaf's slot 1.
        Put("ConstructThenCall", a =>
        {
            a.push(rbx); a.sub(rsp, 0x20);
            a.mov(rbx, rcx);
            a.call(Base + At("Leaf_ctor"));
            a.mov(rax, __qword_ptr[rbx]);
            a.mov(rcx, rbx);
            a.call(__qword_ptr[rax + 8]);
            a.add(rsp, 0x20); a.pop(rbx); a.ret();
        });
        // An argument's vftable: no class known.
        Put("UnknownReceiver", a => { a.sub(rsp, 0x28); a.mov(rax, __qword_ptr[rdx]); a.mov(rcx, rdx); a.call(__qword_ptr[rax + 8]); a.add(rsp, 0x28); a.ret(); });
        Put("purecall", a => a.ud2());
        // this->area(): Shape's slot is pure, Circle's is the only implementation
        Put("Shape_name", a => { a.mov(rax, __qword_ptr[rcx]); a.jmp(__qword_ptr[rax]); });
        Put("Circle_area", a => { a.mov(eax, __dword_ptr[rcx + 8]); a.ret(); });
        // An inlined Circle constructor: the vftable at +0, then the field at +8.
        Put("MakeCircle", a =>
        {
            a.AddInstruction(Rip(Iced.Intel.Code.Lea_r64_m, Register.RAX, vftables["Circle"]));
            a.mov(__qword_ptr[rcx], rax);
            a.mov(__dword_ptr[rcx + 8], 0x31);
            a.ret();
        });
        // This adjusted to the Second subobject (+8): Multi's vftable there.
        Put("Multi_g", a => { a.lea(rcx, __[rcx + 8]); a.mov(rax, __qword_ptr[rcx]); a.jmp(__qword_ptr[rax]); });
        Put("Multi_h", a => { a.mov(eax, 4); a.ret(); });
        Put("Second_h", a => { a.mov(eax, 5); a.ret(); });
        // A Base* parameter: g in Base and every derived class.
        Put(CallBase, a => { a.mov(rax, __qword_ptr[rcx]); a.jmp(__qword_ptr[rax + 8]); });
        Put(GetLeaf, a => { a.xor(eax, eax); a.ret(); });
        // The Leaf* GetLeaf returns: f in Leaf (Mid's).
        Put("UseGetLeaf", a =>
        {
            a.sub(rsp, 0x28);
            a.call(Base + At(GetLeaf));
            a.mov(rcx, rax);
            a.mov(rax, __qword_ptr[rax]);
            a.call(__qword_ptr[rax]);
            a.add(rsp, 0x28); a.ret();
        });

        var exports = Functions.Select((n, i) => new NativeExport(n, (uint)i + 1, At(n), null));
        return (CodeTestImage.Synthetic(NativeArch.X64, code, d.ToArray(), exports: exports), vftables);
    }

    private static string Name(NativeCodeIndex index, uint rva) => index.NameAt(rva) ?? $"sub_{rva:X}";

    /// <summary>"function: status target|target" per site, in address order.</summary>
    private static List<string> Describe(NativeCodeIndex index) =>
        index.VirtualCalls.Sites.Select(s => $"{Name(index, s.Function)}: {VirtualCallSet.StatusCode(s.Status)}" +
            (s.Status == VirtualCallStatus.Unresolved ? $" {VirtualCallSet.ReasonCode(s.Reason)}" : " " + string.Join("|", index.VirtualTargets(s.Rva).Select(t => Name(index, t)).Order()))).ToList();

    [Fact]
    public void Synthetic_virtual_calls_resolve_to_exact_and_possible_edges()
    {
        var (image, _) = Synthetic();
        var index = NativeCodeIndex.Build(image);
        Assert.Equal(
        [
            "Base_g: possible Base_f|Mid_f|Other_f",
            "Leaf_g: exact Mid_f",
            "StoreThenCall: exact Base_g",
            "ConstructThenCall: exact Leaf_g",
            "UnknownReceiver: unresolved receiver_unknown",
            "Shape_name: exact Circle_area",
            "Multi_g: exact Multi_h",
            $"{CallBase}: possible Base_g|Leaf_g|Multi_g",
            "UseGetLeaf: exact Mid_f",
        ], Describe(index));
        var s = index.VirtualCalls.Stats;
        Assert.Equal((9, 6, 2, 1, 12, 8, 1), (s.Sites, s.Exact, s.Possible, s.Unresolved, s.Edges, s.RttiClasses, s.PureTargetsExcluded));

        // Receivers: this of a virtual method, a known vftable, or a class from a decorated name.
        var receivers = index.VirtualCalls.Sites.ToDictionary(x => Name(index, x.Function), x => VirtualCallSet.ReceiverCode(x.Receiver));
        Assert.Equal(("this", "vftable", "vftable", "this", "name", "name"),
            (receivers["Leaf_g"], receivers["StoreThenCall"], receivers["ConstructThenCall"], receivers["Multi_g"], receivers[CallBase], receivers["UseGetLeaf"]));
        Assert.True(index.VirtualCalls.Sites.Single(x => Name(index, x.Function) == "Base_g").TailCall);
        Assert.Equal(8, index.VirtualCalls.Sites.Single(x => Name(index, x.Function) == "Multi_g").VfptrOffset);

        // The call graph: callers of Mid::f include both virtual sites; direct-only and virtual-only filters.
        var midF = index.FunctionByStart(At("Mid_f"))!;
        Assert.Equal([("Base_g", XrefKind.VirtualPossible), ("Leaf_g", XrefKind.VirtualExact), ("UseGetLeaf", XrefKind.VirtualExact)],
            index.Callers(midF).Select(c => (Name(index, c.Caller!.Start), c.Kind)));
        Assert.Empty(index.Callers(midF, CallEdgeFilter.Direct));
        var construct = index.FunctionByStart(At("ConstructThenCall"))!;
        Assert.Equal(["Leaf_ctor"], index.Callees(construct, CallEdgeFilter.Direct).Select(c => c.Function!.Name));
        Assert.Equal(["Leaf_g"], index.Callees(construct, CallEdgeFilter.Virtual).Select(c => c.Function!.Name));
        Assert.Equal(["Leaf_ctor", "Leaf_g"], index.Callees(construct).Select(c => c.Function!.Name));
        // The instruction cross-references do not change.
        Assert.DoesNotContain(index.RefsTo(At("Mid_f")), x => x.IsVirtualCall);

        // Without the option: nothing.
        var plain = NativeCodeIndex.Build(image, new CodeIndexOptions { ResolveVirtualCalls = false });
        Assert.Empty(plain.VirtualCalls.Sites);
        Assert.Empty(plain.Callers(midF));
    }

    [Fact]
    public void Decorated_names_give_parameter_and_return_classes()
    {
        var x64 = new MsvcDemangleOptions();
        string Locations(string name, bool is64 = true) =>
            string.Join(", ", VirtualCallResolver.ParameterLocations(VirtualCallResolver.Signature(name, is64 ? x64 : new MsvcDemangleOptions { X86 = true })!, is64)
                .Select(l => $"{(l.Reg >= 0 ? $"r{l.Reg}" : $"[{l.Slot}]")}={VirtualCallResolver.PointerClass(l.Type) ?? l.Type ?? "this"}"));
        // A constructor: this in rcx, then rdx, r8.
        Assert.Equal("r2=QString, r8=QWidget", Locations("??0QCheckBox@@QEAA@AEBVQString@@PEAVQWidget@@@Z"));
        // A record returned by value: its hidden pointer comes after this.
        Assert.Equal("r8=QByteArray", Locations("?toHtml@QTextDocument@@QEBA?AVQString@@AEBVQByteArray@@@Z"));
        // x86 __thiscall: the parameters on the stack
        Assert.Equal("[4]=QString, [8]=QWidget", Locations("??0QCheckBox@@QAE@ABVQString@@PAVQWidget@@@Z", is64: false));
        // A static member returning a class pointer.
        var sig = VirtualCallResolver.Signature("?instance@QApp@@SAPEAV1@XZ", x64)!;
        Assert.Equal((false, "QApp"), (sig.Member, VirtualCallResolver.PointerClass(sig.Return)));
        Assert.Null(VirtualCallResolver.Signature("?staticMetaObject@QPlatformMenuItem@@2UQMetaObject@@B", x64));
    }

    [Fact]
    public void Virtual_calls_survive_save_and_load()
    {
        var (image, _) = Synthetic();
        var built = NativeCodeIndex.Build(image);
        var stream = new MemoryStream();
        using (var w = new PayloadWriter(b => stream.Write(b))) built.WritePayload(w);
        var loaded = NativeCodeIndex.ReadPayload(stream.ToArray(), image, null, default);
        CodeIndexCacheTests.AssertSameIndex(built, loaded, graphs: int.MaxValue);
        Assert.Equal(Describe(built), Describe(loaded));
        // A damaged edge kind is rejected.
        var bytes = stream.ToArray();
        int kindAt = bytes.Length - built.VirtualEdges.Count;
        Assert.Equal((byte)XrefKind.VirtualPossible, bytes[kindAt]);
        bytes[kindAt] = (byte)XrefKind.Call;
        Assert.Throws<InvalidDataException>(() => NativeCodeIndex.ReadPayload(bytes, image, null, default));
    }

    // ---- MSVC-compiled samples ----

    private const string SampleSource = """
        #include <stdio.h>
        struct Base { virtual int f(); virtual int g(); virtual ~Base() {} };
        struct Mid : Base { int f() override; };
        struct Leaf : Mid { int g() override; };
        struct Other : Base { int f() override; int g() override; };
        struct Shape { virtual int area() = 0; virtual int name(); };
        struct Circle : Shape { int area() override; };
        struct Second { virtual int h(); };
        struct Multi : Base, Second { int g() override; int h() override; int k; };
        __declspec(noinline) int Base::f() { return printf("Base::f\n"); }
        __declspec(noinline) int Base::g() { return f() + 1; }
        __declspec(noinline) int Mid::f() { return printf("Mid::f\n"); }
        __declspec(noinline) int Leaf::g() { return f() * 2; }
        __declspec(noinline) int Other::f() { return printf("Other::f\n"); }
        __declspec(noinline) int Other::g() { return printf("Other::g\n"); }
        __declspec(noinline) int Shape::name() { return area() + 7; }
        __declspec(noinline) int Circle::area() { return printf("Circle::area\n"); }
        __declspec(noinline) int Second::h() { return printf("Second::h\n"); }
        __declspec(noinline) int Multi::g() { return h() + k; }
        __declspec(noinline) int Multi::h() { return printf("Multi::h\n"); }
        extern "C" __declspec(dllexport) __declspec(noinline) int UseLeaf() { Base* p = new Leaf; int r = p->g(); delete p; return r; }
        extern "C" __declspec(dllexport) __declspec(noinline) int CallAny(Base* p) { return p->g(); }
        extern "C" __declspec(dllexport) Base* MakeOther() { return new Other; }
        extern "C" __declspec(dllexport) Base* MakeMulti() { return new Multi; }
        extern "C" __declspec(dllexport) __declspec(noinline) int UseCircle() { Circle c; Shape* s = &c; return s->name(); }
        """;

    /// <summary>Compiles the sample; null when the build tools are missing.</summary>
    private static (PeFile Image, Dictionary<uint, string> Names)? Compile(TempDir dir, string arch, string flags)
    {
        var vcvars = VisualStudio.VcVarsAll();
        if (vcvars == null) return null;
        File.WriteAllText(dir.File("vcall.cpp"), SampleSource);
        var psi = new ProcessStartInfo("cmd.exe")
        {
            WorkingDirectory = dir.Path,
            Arguments = $"/s /c \"\"{vcvars}\" {arch} >nul && cl /nologo /c /O2 /Ob1 /GR /EHsc {flags} vcall.cpp && link /nologo /DLL vcall.obj /OPT:NOICF {flags.Replace("/guard:cf", "/GUARD:CF")} /MAP:vcall.map /OUT:vcall.dll\"",
        };
        var (code, log) = Tools.Run(psi, 300_000);
        Assert.True(code == 0 && File.Exists(dir.File("vcall.dll")), log);
        var image = PeFile.Open(dir.File("vcall.dll"));
        var names = new Dictionary<uint, string>();
        var line = new System.Text.RegularExpressions.Regex(@"^\s*[0-9a-fA-F]{4}:[0-9a-fA-F]{8}\s+(\S+)\s+([0-9a-fA-F]{8,16})\s");
        foreach (var l in File.ReadLines(dir.File("vcall.map")))
            if (line.Match(l) is { Success: true } m && Convert.ToUInt64(m.Groups[2].Value, 16) is var va && va >= image.ImageBase)
            {
                var symbol = m.Groups[1].Value;
                // x86 C names carry a leading underscore
                if (arch == "x86" && symbol.StartsWith('_') && !symbol.StartsWith("__", StringComparison.Ordinal)) symbol = symbol[1..];
                names.TryAdd((uint)(va - image.ImageBase), MsvcDemangler.Undecorate(symbol, MsvcNameStyle.NameOnly) ?? symbol);
            }
        return (image, names);
    }

    [Theory]
    [Trait("Speed", "Slow")]
    [InlineData("x64", "/guard:cf")]
    [InlineData("x64", "")]
    [InlineData("x86", "")]
    public void Compiled_sample_resolves_the_expected_edges(string arch, string flags)
    {
        using var dir = new TempDir();
        if (Compile(dir, arch, flags) is not var (image, names)) return;
        var index = NativeCodeIndex.Build(image);
        string N(uint rva) => names.GetValueOrDefault(rva) ?? $"sub_{rva:X}";
        var sites = index.VirtualCalls.Sites.Select(s => $"{N(s.Function)}: {VirtualCallSet.StatusCode(s.Status)} " +
            (s.Status == VirtualCallStatus.Unresolved ? VirtualCallSet.ReasonCode(s.Reason) : string.Join("|", index.VirtualTargets(s.Rva).Select(N).Order()))).ToList();
        foreach (var s in sites) output.WriteLine(s);
        output.WriteLine(index.VirtualCalls.Stats.ToString());
        // this->f() in Base::g: every implementation; in Leaf::g: Mid's only
        Assert.Contains("Base::g: possible Base::f|Mid::f|Other::f", sites);
        Assert.Contains("Leaf::g: exact Mid::f", sites);
        // The pure slot is left out.
        Assert.Contains("Shape::name: exact Circle::area", sites);
        // Through the Second subobject of Multi.
        Assert.Contains("Multi::g: exact Multi::h", sites);
        // An argument of unknown class.
        Assert.Contains("CallAny: unresolved receiver_unknown", sites);
        // The object constructed in the function (constructor inlined or called): Leaf's g, then its deleting destructor.
        Assert.Contains("UseLeaf: exact Leaf::g", sites);
        Assert.Contains("UseLeaf: exact Leaf::`vector deleting destructor'", sites);
        // The CRT's own virtual calls (exception objects) have no known receiver.
        Assert.Equal(["Base::g"], sites.Where(s => s.Contains(": possible", StringComparison.Ordinal)).Select(s => s[..s.IndexOf(": ", StringComparison.Ordinal)]));
        Assert.All(sites.Where(s => s.Contains(": unresolved", StringComparison.Ordinal)), s => Assert.EndsWith("receiver_unknown", s));
    }

    // ---- cross-check against IDA ----

    private static (AssemblyWorkspace Workspace, NativeVirtualCallTools Tools, NativeEngineService Engines) Rig(TempDir dir, EngineMode engine = EngineMode.Auto)
    {
        var options = new ServerOptions { TimeoutSeconds = 600, BackgroundIndexing = false, Engine = engine };
        var workspace = new AssemblyWorkspace(options);
        var code = new NativeCodeService(workspace, options, null, new Native.Annotations.AnnotationStore(dir.File("annotations")));
        var engines = new NativeEngineService(new IdaProviderOptions { CacheRoot = dir.File("cache") }, code, workspace, options);
        return (workspace, new NativeVirtualCallTools(workspace, code, engines, new NativeTypePush(workspace)), engines);
    }

    [Trait("Speed", "Slow")]
    [IdaFact]
    public async Task Cross_check_with_IDA_agrees_on_the_compiled_sample()
    {
        using var dir = new TempDir();
        if (Compile(dir, "x64", "") is not var (image, _)) return;
        var (_, tools, engines) = Rig(dir);
        using var _e = engines;
        var report = await tools.Report(image.Path, crossCheck: true, sampleFunctions: 50, seconds: 300);
        var c = report.CrossCheck!;
        output.WriteLine(System.Text.Json.JsonSerializer.Serialize(c));
        Assert.True(c.FunctionsDecompiled > 0);
        Assert.True(c.Agree + c.Compatible > 0);
        Assert.Equal(0, c.Disagree);
    }

    [Trait("Speed", "Slow")]
    [GhidraFact]
    public async Task Cross_check_with_Ghidra_agrees_on_the_compiled_sample()
    {
        using var dir = new TempDir();
        if (Compile(dir, "x64", "") is not var (image, _)) return;
        var (_, tools, engines) = Rig(dir, EngineMode.Ghidra);
        using var _e = engines;
        var report = await tools.Report(image.Path, crossCheck: true, sampleFunctions: 50, seconds: 300);
        var c = report.CrossCheck!;
        output.WriteLine(System.Text.Json.JsonSerializer.Serialize(c));
        Assert.Equal("ghidra", c.Engine);
        Assert.True(c.FunctionsDecompiled > 0);
        Assert.True(c.Agree + c.Compatible > 0);
        Assert.Equal(0, c.Disagree);
    }

    /// <summary>Call graph edges and site counts on CORVUS_VCALL_IMAGE before and after, with IDA agreement on a sample.</summary>
    [Trait("Speed", "Slow")]
    [IdaFact(RealData.VirtualCallImage)]
    public async Task Real_image_virtual_edges_and_agreement_with_IDA()
    {
        var path = RealData.Path(RealData.VirtualCallImage);
        using var dir = new TempDir();
        EngineSeed.Copy(dir.File("cache"), path, "ida");
        var (_, tools, engines) = Rig(dir);
        using var _e = engines;
        var clock = Stopwatch.StartNew();
        int sample = int.TryParse(Environment.GetEnvironmentVariable("CORVUS_VCALL_SAMPLE"), out var n) ? n : 150;
        var report = await tools.Report(path, limit: 1, crossCheck: true, sampleFunctions: sample, seconds: 1800);
        output.WriteLine($"{Path.GetFileName(path)}: direct call edges {report.DirectEdges}, virtual edges added {report.Edges} " +
                         $"(sites {report.Sites}: exact {report.Exact}, possible {report.Possible}, unresolved {report.Unresolved}; {report.RttiClasses} RTTI classes)");
        output.WriteLine(System.Text.Json.JsonSerializer.Serialize(report.CrossCheck, new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
        output.WriteLine($"{clock.Elapsed.TotalSeconds:0} s");
        Assert.True(report.Edges > 0);
    }
}
