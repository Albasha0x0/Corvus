using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Msvc;
using NetDecompilerMcp.Native.Pe;
using Xunit.Abstractions;

namespace NetDecompilerMcp.Tests;

/// <summary>MSVC RTTI and vftable recovery: a system C++ runtime DLL, a compiled sample checked against its linker map, and a sweep.</summary>
public class MsvcRttiTests(ITestOutputHelper output)
{
    /// <summary>The C++ standard library DLL of the Visual C++ runtime, present on most Windows machines.</summary>
    private static string? SystemCppRuntime(Environment.SpecialFolder folder)
    {
        var dir = Environment.GetFolderPath(folder);
        var path = dir.Length == 0 ? null : Path.Combine(dir, "msvcp140.dll");
        return path != null && File.Exists(path) ? path : null;
    }

    /// <summary>The image through the real PE parser; null when the file is not a PE image or cannot be read.</summary>
    internal static PeFile? TryOpen(string path)
    {
        try { return PeFile.Open(path); }
        catch (NetDecompilerMcp.Core.ToolError) { return null; }
    }

    [Theory]
    [InlineData(Environment.SpecialFolder.System)]
    [InlineData(Environment.SpecialFolder.SystemX86)]
    public void StandardLibraryExceptionHierarchy(Environment.SpecialFolder folder)
    {
        var path = SystemCppRuntime(folder);
        if (path == null) return; // no Visual C++ runtime installed
        var image = PeFile.Open(path);
        var result = MsvcRtti.Analyze(image);
        Assert.True(result.Stats.UsedRelocations);
        Assert.True(result.Classes.Count > 20, $"{result.Classes.Count} classes");

        var failure = Assert.Single(result.Classes, c => c.Name == "std::ios_base::failure");
        Assert.Equal(".?AVfailure@ios_base@std@@", failure.DecoratedName);
        Assert.Equal("class", failure.Kind);
        Assert.Equal(["std::system_error", "std::_System_error", "std::runtime_error", "std::exception"], failure.Bases.Select(b => b.Name));
        Assert.Equal([1, 2, 3, 4], failure.Bases.Select(b => b.Depth));
        Assert.All(failure.Bases, b => Assert.Equal((0, -1, 0, false), (b.Mdisp, b.Pdisp, b.Vdisp, b.IsVirtual)));
        var vftable = Assert.Single(failure.Vtables);
        Assert.Equal(0u, vftable.Offset);
        Assert.Equal(2, vftable.SlotRvas.Count); // deleting destructor, what()

        var badAlloc = Assert.Single(result.Classes, c => c.Name == "std::bad_alloc");
        Assert.Equal("std::exception", Assert.Single(badAlloc.Bases).Name);
        Assert.Empty(Assert.Single(result.Classes, c => c.Name == "std::exception").Bases);
        CheckInvariants(image, result);

        // without relocations the same structures are found by the other checks alone
        var plain = MsvcRtti.Analyze(MsvcTestImage.TryLoad(path, withRelocations: false)!);
        Assert.False(plain.Stats.UsedRelocations);
        Assert.Equal(result.Classes.Select(c => (c.Name, c.Vtables.Count)), plain.Classes.Select(c => (c.Name, c.Vtables.Count)));
    }

    [Fact]
    public void ImageWithoutRttiYieldsNothing()
    {
        // a .NET assembly is a PE image without MSVC RTTI
        var image = PeFile.Open(typeof(MsvcRtti).Assembly.Location);
        var result = MsvcRtti.Analyze(image);
        Assert.Empty(result.Classes);
        Assert.Equal(0, result.Stats.Locators);
    }

    /// <summary>Structural invariants every result must satisfy.</summary>
    internal static void CheckInvariants(INativeImage image, MsvcRttiResult result)
    {
        foreach (var td in result.TypeDescriptors)
            Assert.NotNull(MsvcDemangler.DemangleTypeDescriptorName(td.Name));
        foreach (var c in result.Classes)
        {
            Assert.NotNull(MsvcDemangler.DemangleTypeDescriptorName(c.DecoratedName));
            for (int i = 0; i < c.Bases.Count; i++)
            {
                var b = c.Bases[i];
                Assert.True(b.Depth >= 1);
                if (b.Parent is int p)
                {
                    Assert.True(p < i);
                    Assert.Equal(c.Bases[p].Depth + 1, b.Depth);
                    Assert.True(i <= p + c.Bases[p].ContainedBases, $"{c.Name}: base {i} outside its parent's range");
                }
                else
                    Assert.Equal(1, b.Depth);
                Assert.True(i + b.ContainedBases < c.Bases.Count, $"{c.Name}: base {i} contains more bases than follow it");
                Assert.True(b.Pdisp >= -1);
            }
            foreach (var v in c.Vtables)
            {
                Assert.NotEmpty(v.SlotRvas);
                Assert.All(v.SlotRvas, s => Assert.True(image.SectionAt(s)?.IsExecutable, $"{c.Name}: slot 0x{s:X} not in an executable section"));
            }
        }
    }

    // ---- compiled sample ----

    private const string SampleSource = """
        struct A { virtual ~A() {} virtual int f() { return 1; } int a = 0; };
        struct B { virtual int g() { return 2; } int b = 0; };
        struct C : A, B { int f() override { return 3; } int g() override { return 4; } virtual int h() { return 5; } int c = 0; };
        struct V { virtual int v() { return 6; } int x = 0; };
        struct D : virtual V { int v() override { return 7; } int d = 0; };
        struct E : virtual V { virtual int k() { return 8; } int e = 0; };
        struct F : D, E { int v() override { return 9; } int k() override { return 10; } };
        class G : public A { public: int f() override { return 11; } };
        namespace ns { template <class T> struct T1 : A { int f() override { return (int)sizeof(T) + 12; } }; }
        struct H : B { H() {} ~H() {} int g() override { return 13; } };
        struct I : virtual H { I() {} ~I() {} int g() override { return 14; } };

        extern "C" __declspec(dllexport) void* make(int i)
        {
            switch (i)
            {
                case 0: return new C;
                case 1: return new D;
                case 2: return new E;
                case 3: return new F;
                case 4: return new G;
                case 5: return new ns::T1<int>;
                case 6: return new I;
                case 7: return new B;
                case 8: return new V;
                case 9: return new H;
                default: return new A;
            }
        }
        """;

    /// <summary>Classes compiled without RTTI (/GR-): their vftables have no locator and may follow RTTI vftables directly.</summary>
    private const string PlainSource = """
        struct P1 { virtual int p() { return 20; } virtual int q() { return 21; } };
        struct P2 : P1 { int p() override { return 22; } virtual int r() { return 23; } };
        struct P3 { virtual int s() { return 24; } };
        extern "C" __declspec(dllexport) void* make_plain(int i)
        {
            if (i == 0) return new P1;
            if (i == 1) return new P2;
            return new P3;
        }
        """;

    /// <summary>
    /// Expected vftables per class, as "offset: slot targets" with the targets named by the linker map (name-only form).
    /// Offsets differ between x86 and x64; slot names do not.
    /// </summary>
    private static readonly Dictionary<string, string[]> ExpectedSlots = new()
    {
        ["A"] = ["A::`scalar deleting destructor'", "A::f"],
        ["B"] = ["B::g"],
        ["C"] = ["C::`scalar deleting destructor'", "C::f", "C::h", "|", "C::g"],
        ["V"] = ["V::v"],
        ["D"] = ["D::v"],
        ["E"] = ["E::k", "|", "V::v"],
        // E, the base with a vfptr, is laid out first; V is the virtual base at the end
        ["F"] = ["F::k", "|", "F::v"],
        ["G"] = ["G::`scalar deleting destructor'", "G::f"],
        ["ns::T1<int>"] = ["ns::T1<int>::`scalar deleting destructor'", "ns::T1<int>::f"],
        ["H"] = ["H::g"],
        // user-defined constructor and an override of a virtual base's function: a vtordisp thunk
        ["I"] = ["I::g [thunk]"],
    };

    [Theory]
    [Trait("Speed", "Slow")]
    [InlineData("x64")]
    [InlineData("x86")]
    public void CompiledSampleMatchesTheLinkerMap(string arch)
    {
        var vcvars = VisualStudio.VcVarsAll();
        if (vcvars == null) return; // no Visual C++ build tools
        using var dir = new TempDir();
        File.WriteAllText(dir.File("sample.cpp"), SampleSource);
        File.WriteAllText(dir.File("plain.cpp"), PlainSource);
        var psi = new ProcessStartInfo("cmd.exe")
        {
            WorkingDirectory = dir.Path,
            Arguments = $"/s /c \"\"{vcvars}\" {arch} >nul && cl /nologo /c /O1 /GR /EHsc sample.cpp && cl /nologo /c /O1 /GR- plain.cpp"
                + " && link /nologo /DLL sample.obj plain.obj /OPT:NOICF /MAP:sample.map /OUT:sample.dll\"",
        };
        var (code, log) = Tools.Run(psi, 300_000);
        Assert.True(code == 0 && File.Exists(dir.File("sample.dll")), log);

        var image = PeFile.Open(dir.File("sample.dll"));
        Assert.Equal(arch == "x64" ? NativeArch.X64 : NativeArch.X86, image.Arch);
        var map = ReadMap(dir.File("sample.map"), image.ImageBase);
        var byRva = map.GroupBy(m => m.Value).ToDictionary(g => g.Key, g => g.Select(m => m.Key).ToList());
        var result = MsvcRtti.Analyze(image);
        output.WriteLine($"{arch}: {result.Stats}");
        CheckInvariants(image, result);

        var classes = result.Classes.Where(c => ExpectedSlots.ContainsKey(c.Name)).ToDictionary(c => c.Name);
        var slotErrors = new List<string>();
        Assert.Equal(ExpectedSlots.Keys.Order(), classes.Keys.Order());
        foreach (var (name, c) in classes)
        {
            string Name(uint rva) => byRva.TryGetValue(rva, out var names)
                ? string.Join("|", names.Select(n => (MsvcDemangler.Undecorate(n, MsvcNameStyle.NameOnly) ?? n)
                    + (MsvcDemangler.Demangle(n).Kind == MsvcSymbolKind.Thunk ? " [thunk]" : "")).Distinct())
                : $"0x{rva:X}";

            // descriptors are where the compiler's own symbols say
            Assert.Equal(map[$"??_R0{c.DecoratedName[1..]}@8"], c.TypeDescriptorRva);
            Assert.Equal(c.HierarchyRva, map[map.Keys.Single(k => k.StartsWith("??_R3", StringComparison.Ordinal) &&
                MsvcDemangler.Undecorate(k) == $"{name}::`RTTI Class Hierarchy Descriptor'")]);

            // every base class descriptor matches its symbol's encoded displacements and attributes
            foreach (var b in c.Bases)
            {
                var symbol = byRva[b.DescriptorRva].Single(n => n.StartsWith("??_R1", StringComparison.Ordinal));
                var text = MsvcDemangler.Undecorate(symbol)!;
                Assert.Equal($"{b.Name}::`RTTI Base Class Descriptor at ({b.Mdisp}, {b.Pdisp}, {b.Vdisp}, {(uint)b.Attributes})'", text);
            }

            // vftables: one per ??_7 symbol of the class, its locator at the ??_R4 symbol with the same suffix
            var vftableSymbols = map.Keys.Where(k => k.StartsWith("??_7", StringComparison.Ordinal) &&
                MsvcDemangler.Undecorate(k, MsvcNameStyle.NameOnly)!.StartsWith(name + "::`vftable'", StringComparison.Ordinal)).ToList();
            Assert.Equal(vftableSymbols.Select(s => map[s]).Order(), c.Vtables.Select(v => v.VftableRva).Order());
            foreach (var v in c.Vtables)
            {
                var vftable = vftableSymbols.Single(s => map[s] == v.VftableRva);
                Assert.Equal(map["??_R4" + vftable[4..]], v.LocatorRva);
            }

            // slot targets, primary vftable first, "|" between vftables
            var slots = new List<string>();
            foreach (var v in c.Vtables)
            {
                if (slots.Count > 0) slots.Add("|");
                slots.AddRange(v.SlotRvas.Select(Name));
            }
            var expected = ExpectedSlots[name];
            if (!(expected.Length == slots.Count && expected.Zip(slots).All(p => Matches(p.First, p.Second))))
                slotErrors.Add($"{arch} {name}: expected [{string.Join(", ", expected)}], got [{string.Join(", ", slots)}]");
        }
        Assert.True(slotErrors.Count == 0, string.Join("\n", slotErrors));

        // the hierarchies themselves
        Assert.Empty(classes["A"].Bases);
        Assert.Equal(MsvcHierarchyAttributes.MultipleInheritance, classes["C"].Attributes);
        Assert.Equal(["A", "B"], classes["C"].Bases.Select(b => b.Name));
        Assert.Equal(arch == "x64" ? 16 : 8, classes["C"].Bases[1].Mdisp);
        var dv = Assert.Single(classes["D"].Bases);
        Assert.Equal(("V", true, 0, 4), (dv.Name, dv.IsVirtual, dv.Pdisp, dv.Vdisp));
        Assert.Equal(["D", "V", "E", "V"], classes["F"].Bases.Select(b => b.Name));
        Assert.Equal([1, 2, 1, 2], classes["F"].Bases.Select(b => b.Depth));
        Assert.Equal([false, true, false, true], classes["F"].Bases.Select(b => b.IsVirtual));
        // MSVC sets the virtual-inheritance bit only where a virtual base is shared (the diamond)
        Assert.Equal(MsvcHierarchyAttributes.None, classes["D"].Attributes);
        Assert.Equal(MsvcHierarchyAttributes.MultipleInheritance | MsvcHierarchyAttributes.VirtualInheritance, classes["F"].Attributes);
        Assert.Equal(arch == "x64" ? 16u : 8u, classes["D"].Vtables.Single().Offset);
        // the vtordisp field sits 4 bytes before the virtual base subobject
        Assert.Equal(4u, classes["I"].Vtables.Single().ConstructorDisplacementOffset);

        // no vftable runs into another one, with or without RTTI (P1..P3 have none and are not reported)
        var vftableStarts = map.Where(m => m.Key.StartsWith("??_7", StringComparison.Ordinal)).Select(m => m.Value).ToHashSet();
        Assert.Contains(map["??_7P1@@6B@"], vftableStarts);
        Assert.DoesNotContain(result.Classes, c => c.Name.StartsWith('P'));
        int ptr = image.Is64Bit ? 8 : 4;
        int Overruns(MsvcRttiResult r) => r.Classes.SelectMany(c => c.Vtables)
            .Count(v => Enumerable.Range(1, v.SlotRvas.Count - 1).Any(k => vftableStarts.Contains(v.VftableRva + (uint)(k * ptr))));
        Assert.Equal(0, Overruns(result));
        // the layout does put an RTTI-less vftable right after an RTTI one: without code references it is overrun
        var blind = MsvcRtti.Analyze(image, new MsvcRttiOptions { CodeReferences = [] });
        output.WriteLine($"overruns without code references: {Overruns(blind)}");
        Assert.True(Overruns(blind) > 0);

        // without relocations: the same vftables; on x86 their ends are not checked against code (no relocated operands)
        var plain = MsvcRtti.Analyze(MsvcTestImage.TryLoad(dir.File("sample.dll"), withRelocations: false)!);
        Assert.Equal(
            result.Classes.SelectMany(c => c.Vtables.Select(v => (c.Name, v.VftableRva))),
            plain.Classes.SelectMany(c => c.Vtables.Select(v => (c.Name, v.VftableRva))));
        if (arch == "x64")
            Assert.Equal(0, Overruns(plain));
    }

    /// <summary>"*" in an expected name matches any number; a slot matches when any of its aliases ("a|b") does.</summary>
    private static bool Matches(string expected, string actual) =>
        expected == "|" ? actual == "|" : actual.Split('|').Any(a => MatchesOne(expected, a));

    private static bool MatchesOne(string expected, string actual) =>
        Regex.IsMatch(actual,"^" + Regex.Escape(expected).Replace("\\*", "-?[0-9, ]+") + "$");

    /// <summary>Public symbols of a link.exe map file: decorated name to RVA.</summary>
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
}

/// <summary>The System32 / SysWOW64 RTTI sweep: timed per file, so it runs alone after the parallel tests.</summary>
[Collection(SweepCollection.Name)]
public class MsvcRttiSweepTests(ITestOutputHelper output)
{
    /// <summary>
    /// Every DLL and EXE in System32 and SysWOW64: no exception, bounded time per file, structural invariants, and the
    /// same classes and vftable starts with and without the relocation cross-check.
    /// </summary>
    [Fact]
    [Trait("Speed", "Slow")]
    public void SweepSystemImages()
    {
        var files = MsvcCorpus.SystemDirectories().Distinct(StringComparer.OrdinalIgnoreCase)
            .SelectMany(d => MsvcCorpus.SafeFiles(d, "*.dll").Concat(MsvcCorpus.SafeFiles(d, "*.exe"))).ToList();
        var sw = Stopwatch.StartNew();
        int images = 0, withRtti = 0, classes = 0, vtables = 0, locators = 0, noVtable = 0, tdRejected = 0, colRejected = 0, issues = 0;
        int startsDiffer = 0, slotsLonger = 0, slotsShorter = 0;
        var endReasons = new Dictionary<string, int>();
        var slowest = (File: "", Time: TimeSpan.Zero);
        var failures = new List<string>();
        var gate = new object();
        Parallel.ForEach(files, new ParallelOptions { MaxDegreeOfParallelism = Math.Max(2, Environment.ProcessorCount / 2) }, file =>
        {
            var image = MsvcRttiTests.TryOpen(file);
            if (image == null || image.Arch == NativeArch.Unknown) return;
            var t = Stopwatch.StartNew();
            MsvcRttiResult result, plain;
            try
            {
                result = MsvcRtti.Analyze(image);
                plain = MsvcRtti.Analyze(MsvcTestImage.TryLoad(file, withRelocations: false)!);
                MsvcRttiTests.CheckInvariants(image, result);
            }
            catch (Exception ex)
            {
                lock (gate) failures.Add($"{file}: {ex.GetType().Name}: {ex.Message.Split('\n')[0]}");
                return;
            }
            t.Stop();
            var withRelocs = result.Classes.SelectMany(c => c.Vtables).ToDictionary(v => v.VftableRva, v => v.SlotRvas.Count);
            var without = plain.Classes.SelectMany(c => c.Vtables).ToDictionary(v => v.VftableRva, v => v.SlotRvas.Count);
            lock (gate)
            {
                images++;
                if (result.Classes.Count > 0) withRtti++;
                classes += result.Classes.Count;
                vtables += result.Stats.Vtables;
                locators += result.Stats.Locators;
                noVtable += result.Stats.LocatorsWithoutVtable;
                tdRejected += result.Stats.TypeDescriptorCandidatesRejected;
                colRejected += result.Stats.LocatorCandidatesRejected;
                issues += result.Classes.Sum(c => c.Issues.Count);
                if (!withRelocs.Keys.Order().SequenceEqual(without.Keys.Order())) startsDiffer++;
                foreach (var (rva, n) in withRelocs)
                    if (without.TryGetValue(rva, out var m))
                    {
                        if (m > n) slotsLonger++;
                        else if (m < n) slotsShorter++;
                    }
                foreach (var v in result.Classes.SelectMany(c => c.Vtables))
                    endReasons[v.EndReason] = endReasons.GetValueOrDefault(v.EndReason) + 1;
                if (t.Elapsed > slowest.Time) slowest = (file, t.Elapsed);
                if (t.Elapsed > TimeSpan.FromSeconds(20)) failures.Add($"{file}: {t.Elapsed.TotalSeconds:F1} s");
            }
        });
        output.WriteLine($"{images} images in {sw.Elapsed.TotalSeconds:F1} s; {withRtti} with RTTI: {classes} classes, {locators} locators, {vtables} vftables");
        output.WriteLine($"locators without vftable {noVtable}; rejected candidates: type descriptors {tdRejected}, locators {colRejected}; class issues {issues}");
        output.WriteLine($"without relocations: images with different vftable starts {startsDiffer}, vftables longer {slotsLonger}, shorter {slotsShorter}");
        output.WriteLine("vftable end: " + string.Join(", ", endReasons.OrderByDescending(e => e.Value).Select(e => $"{e.Key} {e.Value}")));
        output.WriteLine($"slowest: {slowest.File} {slowest.Time.TotalSeconds:F2} s");
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(50)));
        Assert.True(images > 100, $"only {images} images");
    }
}
