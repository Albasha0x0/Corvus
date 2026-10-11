using System.Text;
using Corvus.Native.Elf;
using Corvus.Native.Itanium;
using Corvus.Native.MachO;
using Xunit.Abstractions;

namespace Corvus.Tests.NativeFormats;

public sealed class ItaniumDemangleTests(ITestOutputHelper output)
{
    /// <summary>Expected text is llvm-cxxfilt 21's.</summary>
    [Theory]
    [InlineData("_ZNSt6vectorIS_IiSaIiEESaIS1_EE9push_backERKS1_", "std::vector<std::vector<int, std::allocator<int>>, std::allocator<std::vector<int, std::allocator<int>>>>::push_back(std::vector<int, std::allocator<int>> const&)")]
    [InlineData("_ZNSsC1Ev", "std::basic_string<char, std::char_traits<char>, std::allocator<char>>::basic_string()")]
    [InlineData("_ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE4findEPKcmm", "std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char>>::find(char const*, unsigned long, unsigned long) const")]
    [InlineData("_Z1fILi5ELj3ELb1ELc97EEvv", "void f<5, 3u, true, (char)97>()")]
    [InlineData("_ZZ4mainENKUlvE_clEv", "main::'lambda'()::operator()() const")]
    [InlineData("_ZZ4mainENKUlvE0_clEv", "main::'lambda0'()::operator()() const")]
    [InlineData("_ZZ4mainENKUliPKcE_clEiS1_", "main::'lambda'(int, char const*)::operator()(int, 'lambda'(int, char const*)) const")]
    [InlineData("_ZZ4mainENKUlT_E_clIiEEDaS_", "auto main::'lambda'(auto)::operator()<int>(auto) const")]
    [InlineData("_ZN1AUt_E", "A::'unnamed'")]
    [InlineData("_Z3foov.cold", "foo() (.cold)")]
    [InlineData("_ZN1A1fEv.constprop.0", "A::f() (.constprop.0)")]
    [InlineData("_ZTVN1A1BE", "vtable for A::B")]
    [InlineData("_ZThn8_N1A1fEv", "non-virtual thunk to A::f()")]
    [InlineData("_ZTv0_n24_N1A1fEv", "virtual thunk to A::f()")]
    [InlineData("_ZTch0_h4_N1A1fEv", "covariant return thunk to A::f()")]
    [InlineData("_ZTTN1AE", "VTT for A")]
    [InlineData("_ZTC1B0_1A", "construction vtable for A-in-B")]
    [InlineData("_ZGR1x_", "reference temporary for x")]
    [InlineData("_ZTW1x", "thread-local wrapper routine for x")]
    [InlineData("_ZGVZ1fvE1x", "guard variable for f()::x")]
    [InlineData("_ZTSi", "typeinfo name for int")]
    [InlineData("_ZTIN10__cxxabiv117__class_type_infoE", "typeinfo for __cxxabiv1::__class_type_info")]
    [InlineData("_Z1fIJicEEvDpT_", "void f<int, char>(int, char)")]
    [InlineData("_Z1fIJEEvv", "void f<>()")]
    [InlineData("_Z1fIJiEEvDpRT_", "void f<int>(int&)")]
    [InlineData("_ZN12_GLOBAL__N_13fooEv", "(anonymous namespace)::foo()")]
    [InlineData("___Z3foov_block_invoke", "invocation function for block in foo()")]
    [InlineData("_ZN1AcviEv", "A::operator int()")]
    [InlineData("_ZNK3FooIiEcvT_IdEEv", "Foo<int>::operator double<double>() const")]
    [InlineData("_ZN1AplERKS_", "A::operator+(A const&)")]
    [InlineData("_ZN1AnwEm", "A::operator new(unsigned long)")]
    [InlineData("_ZN1AdlEPv", "A::operator delete(void*)")]
    [InlineData("_ZN1AixEi", "A::operator[](int)")]
    [InlineData("_ZN1AclEv", "A::operator()()")]
    [InlineData("_ZN1AaSEOS_", "A::operator=(A&&)")]
    [InlineData("_Z1fDn", "f(std::nullptr_t)")]
    [InlineData("_Z1fILin5EEvv", "void f<-5>()")]
    [InlineData("_ZN3FooB5cxx11Ev", "Foo[abi:cxx11]()")]
    [InlineData("_Z1fIiEDTcl1gfp_EET_", "decltype(g(fp)) f<int>(int)")]
    [InlineData("_Z1fIiEDTplfp_Li1EET_", "decltype(fp + 1) f<int>(int)")]
    [InlineData("_ZNK1A1fEv", "A::f() const")]
    [InlineData("_ZNKR1A1fEv", "A::f() const &")]
    [InlineData("_Z1fPA10_i", "f(int (*) [10])")]
    [InlineData("_Z1fRA_i", "f(int (&) [])")]
    [InlineData("_Z1fA10_A20_c", "f(char [10][20])")]
    [InlineData("_Z1fPFivEPA3_A4_i", "f(int (*)(), int (*) [3][4])")]
    [InlineData("_Z1fM1AKFvvE", "f(void (A::*)() const)")]
    [InlineData("_Z1fPVKi", "f(int const volatile*)")]
    [InlineData("_Z1fRKPi", "f(int* const&)")]
    [InlineData("_ZN1AC2ERKS_", "A::A(A const&)")]
    [InlineData("_ZN1AD0Ev", "A::~A()")]
    [InlineData("_ZNSiD1Ev", "std::basic_istream<char, std::char_traits<char>>::~basic_istream()")]
    [InlineData("_Z1fIiEvT_S0_", "void f<int>(int, int)")]
    [InlineData("_Z1fIiEvPFT_vE", "void f<int>(int (*)())")]
    [InlineData("_Z1fILl5ELm5ELx5ELy5ELs5ELa5ELh5ELf3f800000EEvv", "void f<5l, 5ul, 5ll, 5ull, (short)5, (signed char)5, (unsigned char)5, 0x1.0000000000000p+0f>()")]
    [InlineData("_Z1fDv4_f", "f(float vector[4])")]
    [InlineData("_Z1fU8__vectori", "f(int __vector)")]
    [InlineData("_Z1fPU3AS1i", "f(int AS1*)")]
    [InlineData("_ZZN1A1fEvE1x_0", "A::f()::x")]
    [InlineData("_ZSt4cout", "std::cout")]
    [InlineData("_ZL3foov", "foo()")]
    [InlineData("_Z5helloPKwPKDsPKDiPKDu", "hello(wchar_t const*, char16_t const*, char32_t const*, char8_t const*)")]
    [InlineData("_ZN3FooC1IiEET_", "Foo::Foo<int>(int)")]
    [InlineData("_Z1fSi", "f(std::istream)")]
    public void MatchesLlvm(string mangled, string expected) => Assert.Equal(expected, ItaniumDemangler.Demangle(mangled));

    [Theory]
    [InlineData("")]
    [InlineData("main")]
    [InlineData("_Z")]
    [InlineData("_Z3fo")]
    [InlineData("_ZN1AE1")]
    [InlineData("_Z1fS_")]
    [InlineData("_Z1fT_")]
    public void NotMangled_IsNull(string name) => Assert.Null(ItaniumDemangler.Demangle(name));

    [Fact]
    public void MachOUnderscore_IsStrippedOnRequest()
    {
        Assert.Null(ItaniumDemangler.Demangle("__Z3foov"));
        Assert.Equal("foo()", ItaniumDemangler.Demangle("__Z3foov", stripUnderscore: true));
        Assert.Equal("invocation function for block in foo()", ItaniumDemangler.Demangle("____Z3foov_block_invoke", stripUnderscore: true));
    }

    /// <summary>Names from the .NET runtime's own binaries (MIT), demangled by llvm-cxxfilt 21 (tab-separated).</summary>
    [Fact]
    public void Corpus_MatchesLlvm()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "NativeFormats", "ItaniumCorpus.txt");
        var failures = new List<string>();
        int count = 0;
        foreach (var line in File.ReadLines(path))
        {
            var parts = line.Split('\t');
            if (parts.Length != 2) continue;
            count++;
            var got = ItaniumDemangler.Demangle(parts[0]);
            if (got != parts[1]) failures.Add($"{parts[0]}\n  expected {parts[1]}\n  got      {got}");
        }
        Assert.True(count > 500, $"only {count} corpus lines");
        Assert.True(failures.Count == 0, $"{failures.Count} of {count} differ:\n" + string.Join("\n", failures.Take(15)));
    }

    /// <summary>Corpus names with random edits, and deeply nested names: no exception, bounded time.</summary>
    [Fact]
    public void MutatedNames_NeverThrow()
    {
        var names = File.ReadLines(Path.Combine(AppContext.BaseDirectory, "NativeFormats", "ItaniumCorpus.txt")).Select(l => l.Split('	')[0]).ToList();
        var rng = new Random(20261013);
        const string alphabet = "_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        foreach (var name in names)
            for (int k = 0; k < 4; k++)
            {
                var chars = name.ToCharArray().ToList();
                for (int e = rng.Next(1, 4); e > 0 && chars.Count > 2; e--)
                {
                    int at = rng.Next(2, chars.Count);
                    switch (rng.Next(3))
                    {
                        case 0: chars[at] = alphabet[rng.Next(alphabet.Length)]; break;
                        case 1: chars.RemoveAt(at); break;
                        default: chars.Insert(at, alphabet[rng.Next(alphabet.Length)]); break;
                    }
                }
                _ = ItaniumDemangler.Demangle(new string([.. chars]));
            }
        Assert.Null(ItaniumDemangler.Demangle("_Z1f" + string.Concat(Enumerable.Repeat("PU1x", 20000)) + "i"));
        Assert.Null(ItaniumDemangler.Demangle("_Z1f" + string.Concat(Enumerable.Repeat("PFv", 20000)) + "i"));
        Assert.Null(ItaniumDemangler.Demangle("_Z1fI" + string.Concat(Enumerable.Repeat("I", 20000)) + "iE"));
    }

    /// <summary>Every C++ symbol of the linux-arm64 and osx-arm64 runtime packs and of SkiaSharp against llvm-cxxfilt (needs NDM_LLVM_BIN).</summary>
    [Fact]
    [Trait("Speed", "Slow")]
    public void RuntimePackSymbols_MatchLlvm()
    {
        if (LlvmOracle.Bin == null) { output.WriteLine($"{LlvmOracle.Variable} is not set"); return; }
        var names = RuntimePackNames().Distinct().Order(StringComparer.Ordinal).ToList();
        var expected = LlvmOracle.Demangle(names)!;
        int agree = 0, nulls = 0;
        var report = new StringBuilder();
        for (int i = 0; i < names.Count; i++)
        {
            var got = ItaniumDemangler.Demangle(names[i]);
            var llvm = expected[i] == names[i] ? null : expected[i]; // llvm-cxxfilt echoes what it cannot demangle
            if (got == llvm) agree++;
            else
            {
                if (got == null) nulls++;
                report.AppendLine(names[i]).AppendLine("  llvm " + llvm).AppendLine("  ours " + got);
            }
        }
        var reportPath = Path.Combine(Path.GetTempPath(), "ndm-itanium-demangle-report.txt");
        File.WriteAllText(reportPath, report.ToString());
        output.WriteLine($"{names.Count} names, {agree} agree, {nulls} not demangled; report {reportPath}");
        Assert.True(agree >= names.Count * 0.995, $"{names.Count - agree} of {names.Count} differ; see {reportPath}");
    }

    internal static IEnumerable<string> RuntimePackNames()
    {
        var osx = Path.GetDirectoryName(RealPackages.File("Microsoft.NETCore.App.Runtime.osx-arm64", "10.0.11", "runtimes/osx-arm64/native/libcoreclr.dylib"))!;
        foreach (var dylib in Directory.EnumerateFiles(osx, "*.dylib"))
            foreach (var s in MachOFile.Open(dylib).SymbolTable)
                if (s.Name.StartsWith("__Z", StringComparison.Ordinal)) yield return s.Name[1..];
        foreach (var slice in new[] { "x86_64", "arm64" })
            foreach (var s in MachOFile.Open(NativeFixtures.OsxFatSkia, slice).SymbolTable)
                if (s.Name.StartsWith("__Z", StringComparison.Ordinal)) yield return s.Name[1..];
        var skia = RealPackages.File("SkiaSharp.NativeAssets.Linux", "3.119.4", "runtimes/linux-arm/native/libSkiaSharp.so");
        foreach (var s in ElfFile.Open(skia).StaticSymbols)
            if (s.Name.StartsWith("_Z", StringComparison.Ordinal)) yield return s.Name;
        var linux = Path.GetDirectoryName(RealPackages.File("Microsoft.NETCore.App.Runtime.linux-arm64", "10.0.11", "runtimes/linux-arm64/native/libcoreclr.so"))!;
        foreach (var so in Directory.EnumerateFiles(linux, "*.so"))
        {
            var elf = ElfFile.Open(so);
            foreach (var s in elf.DynamicSymbols.Concat(elf.StaticSymbols))
                if (s.Name.StartsWith("_Z", StringComparison.Ordinal)) yield return s.Name;
        }
    }
}
