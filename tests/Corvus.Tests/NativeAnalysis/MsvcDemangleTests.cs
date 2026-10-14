using System.Diagnostics;
using Corvus.Native.Msvc;

namespace Corvus.Tests;

/// <summary>The managed MSVC undecorator on a curated table of names, garbage input, and the DbgHelp oracle for the same table.</summary>
public class MsvcDemangleTests
{
    /// <summary>Decorated name, full form, kind. Outputs are this undecorator's own formatting (LLVM-like spacing, no __ptr64).</summary>
    public static readonly TheoryData<string, string, MsvcSymbolKind> Names = new()
    {
        // calling conventions, globals
        { "?f@@YAXXZ", "void __cdecl f(void)", MsvcSymbolKind.Function },
        { "?f@@YGHH@Z", "int __stdcall f(int)", MsvcSymbolKind.Function },
        { "?f@@YIXHH@Z", "void __fastcall f(int, int)", MsvcSymbolKind.Function },
        { "?f@@YQXN@Z", "void __vectorcall f(double)", MsvcSymbolKind.Function },
        { "?f@@$$J0YAXXZ", "extern \"C\" void __cdecl f(void)", MsvcSymbolKind.Function },
        { "?f@@YAXX_E", "void __cdecl f(void) noexcept", MsvcSymbolKind.Function },
        // members: access, virtual, static, cv and ref qualifiers
        { "?f@A@@QAEXXZ", "public: void __thiscall A::f(void)", MsvcSymbolKind.Function },
        { "?f@A@@QEAAXXZ", "public: void __cdecl A::f(void)", MsvcSymbolKind.Function },
        { "?f@A@@QEBAHXZ", "public: int __cdecl A::f(void) const", MsvcSymbolKind.Function },
        { "?f@A@@UEAAXXZ", "public: virtual void __cdecl A::f(void)", MsvcSymbolKind.Function },
        { "?f@A@@SAHXZ", "public: static int __cdecl A::f(void)", MsvcSymbolKind.Function },
        { "?f@A@@AAEXXZ", "private: void __thiscall A::f(void)", MsvcSymbolKind.Function },
        { "?f@A@@IAEXXZ", "protected: void __thiscall A::f(void)", MsvcSymbolKind.Function },
        { "?f@A@@QEGAAXXZ", "public: void __cdecl A::f(void) &", MsvcSymbolKind.Function },
        { "?f@A@@QEHAAXXZ", "public: void __cdecl A::f(void) &&", MsvcSymbolKind.Function },
        // structors and operators
        { "??0A@@QAE@XZ", "public: __thiscall A::A(void)", MsvcSymbolKind.Function },
        { "??1A@@UAE@XZ", "public: virtual __thiscall A::~A(void)", MsvcSymbolKind.Function },
        { "??0?$A@H@@QAE@XZ", "public: __thiscall A<int>::A<int>(void)", MsvcSymbolKind.Function },
        { "??1?$A@H@@QAE@XZ", "public: __thiscall A<int>::~A<int>(void)", MsvcSymbolKind.Function },
        { "??$?0H@A@@QAE@H@Z", "public: __thiscall A::A<int>(int)", MsvcSymbolKind.Function },
        { "??_GA@@UAEPAXI@Z", "public: virtual void * __thiscall A::`scalar deleting destructor'(unsigned int)", MsvcSymbolKind.Function },
        { "??_EA@@UAEPAXI@Z", "public: virtual void * __thiscall A::`vector deleting destructor'(unsigned int)", MsvcSymbolKind.Function },
        { "??2@YAPAXI@Z", "void * __cdecl operator new(unsigned int)", MsvcSymbolKind.Function },
        { "??3@YAXPAX@Z", "void __cdecl operator delete(void *)", MsvcSymbolKind.Function },
        { "??_U@YAPAXI@Z", "void * __cdecl operator new[](unsigned int)", MsvcSymbolKind.Function },
        { "??_V@YAXPAX@Z", "void __cdecl operator delete[](void *)", MsvcSymbolKind.Function },
        { "??4A@@QAEAAV0@ABV0@@Z", "public: class A & __thiscall A::operator=(class A const &)", MsvcSymbolKind.Function },
        { "??BA@@QBEHXZ", "public: __thiscall A::operator int(void) const", MsvcSymbolKind.Function },
        { "??RA@@QAEXXZ", "public: void __thiscall A::operator()(void)", MsvcSymbolKind.Function },
        { "??CA@@QAEPAV0@XZ", "public: class A * __thiscall A::operator->(void)", MsvcSymbolKind.Function },
        { "??__K_km@@YANO@Z", "double __cdecl operator \"\" _km(long double)", MsvcSymbolKind.Function },
        { "??__M@YA_NHH@Z", "bool __cdecl operator<=>(int, int)", MsvcSymbolKind.Function },
        { "??$?6U?$char_traits@D@std@@@std@@YAAAV?$basic_ostream@DU?$char_traits@D@std@@@0@AAV10@PBD@Z",
            "class std::basic_ostream<char, struct std::char_traits<char>> & __cdecl std::operator<<<struct std::char_traits<char>>(class std::basic_ostream<char, struct std::char_traits<char>> &, char const *)", MsvcSymbolKind.Function },
        // templates: type, integral, negative, nested, packs, arrays, qualified, function types, symbols, member pointers
        { "??$f@H@@YAXH@Z", "void __cdecl f<int>(int)", MsvcSymbolKind.Function },
        { "??$f@$0A@@@YAXXZ", "void __cdecl f<0>(void)", MsvcSymbolKind.Function },
        { "??$f@$0?0@@YAXXZ", "void __cdecl f<-1>(void)", MsvcSymbolKind.Function },
        { "??$f@$0BAA@@@YAXXZ", "void __cdecl f<256>(void)", MsvcSymbolKind.Function },
        { "??$f@$M_K0A@@@YAXXZ", "void __cdecl f<0>(void)", MsvcSymbolKind.Function },
        { "?f@@YAXV?$A@V?$B@H@@@@@Z", "void __cdecl f(class A<class B<int>>)", MsvcSymbolKind.Function },
        { "?f@@YAXV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@Z",
            "void __cdecl f(class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char>>)", MsvcSymbolKind.Function },
        { "?f@@YAXV?$A@$$V@@@Z", "void __cdecl f(class A<>)", MsvcSymbolKind.Function },
        { "??$f@PAH@@YAXPAH@Z", "void __cdecl f<int *>(int *)", MsvcSymbolKind.Function },
        { "??$f@$$BY02H@@YAXXZ", "void __cdecl f<int[3]>(void)", MsvcSymbolKind.Function },
        { "??$f@$$CBH@@YAXXZ", "void __cdecl f<int const>(void)", MsvcSymbolKind.Function },
        { "??$f@$$A6AXH@Z@@YAXXZ", "void __cdecl f<void __cdecl(int)>(void)", MsvcSymbolKind.Function },
        { "??$f@$1?g@@YAXXZ@@YAXXZ", "void __cdecl f<&void __cdecl g(void)>(void)", MsvcSymbolKind.Function },
        { "??$f@$H?g@A@@QAEXXZA@@@YAXXZ", "void __cdecl f<{public: void __thiscall A::g(void), 0}>(void)", MsvcSymbolKind.Function },
        { "??$f@$F7A@@@YAXXZ", "void __cdecl f<{8, 0}>(void)", MsvcSymbolKind.Function },
        { "??$f@H@@YA?A_TH@Z", "decltype(auto) __cdecl f<int>(int)", MsvcSymbolKind.Function },
        { "?f@@YA?A_PXZ", "auto __cdecl f(void)", MsvcSymbolKind.Function },
        // types: pointers, references, qualifiers, function and member pointers, arrays, primitives
        { "?f@@YAXP6AHH@Z@Z", "void __cdecl f(int (__cdecl *)(int))", MsvcSymbolKind.Function },
        { "?f@@YAXP6AXXZ@Z", "void __cdecl f(void (__cdecl *)(void))", MsvcSymbolKind.Function },
        { "?f@@YAP6AHH@ZXZ", "int (__cdecl * __cdecl f(void))(int)", MsvcSymbolKind.Function },
        { "?f@@YAXP8A@@AEXXZ@Z", "void __cdecl f(void (__thiscall A::*)(void))", MsvcSymbolKind.Function },
        { "?f@@YAXP8A@@BEXXZ@Z", "void __cdecl f(void (__thiscall A::*)(void) const)", MsvcSymbolKind.Function },
        { "?f@@YAXP8A@@EAAXXZ@Z", "void __cdecl f(void (__cdecl A::*)(void))", MsvcSymbolKind.Function },
        { "?f@@YAXPQA@@H@Z", "void __cdecl f(int A::*)", MsvcSymbolKind.Function },
        { "?f@@YAXAAY02H@Z", "void __cdecl f(int (&)[3])", MsvcSymbolKind.Function },
        { "?f@@YAXPAY02H@Z", "void __cdecl f(int (*)[3])", MsvcSymbolKind.Function },
        { "?f@@YAX$$QAH@Z", "void __cdecl f(int &&)", MsvcSymbolKind.Function },
        { "?f@@YAX$$RAH@Z", "void __cdecl f(int && volatile)", MsvcSymbolKind.Function },
        { "?f@@YAXPIAH@Z", "void __cdecl f(int * __restrict)", MsvcSymbolKind.Function },
        { "?f@@YAXPFAH@Z", "void __cdecl f(int __unaligned *)", MsvcSymbolKind.Function },
        { "?f@@YAXPCH@Z", "void __cdecl f(int volatile *)", MsvcSymbolKind.Function },
        { "?f@@YAXPDH@Z", "void __cdecl f(int const volatile *)", MsvcSymbolKind.Function },
        { "?f@@YAXQAH@Z", "void __cdecl f(int * const)", MsvcSymbolKind.Function },
        { "?f@@YAXPAPAD@Z", "void __cdecl f(char **)", MsvcSymbolKind.Function },
        { "?f@@YAXPBQBD@Z", "void __cdecl f(char const * const *)", MsvcSymbolKind.Function },
        { "?f@@YAXPEAH@Z", "void __cdecl f(int *)", MsvcSymbolKind.Function },
        { "?f@@YAXHZZ", "void __cdecl f(int, ...)", MsvcSymbolKind.Function },
        { "?f@@YAXZZ", "void __cdecl f(...)", MsvcSymbolKind.Function },
        { "?f@@YAXW4E@@@Z", "void __cdecl f(enum E)", MsvcSymbolKind.Function },
        { "?f@@YAXTU@@@Z", "void __cdecl f(union U)", MsvcSymbolKind.Function },
        { "?f@@YAX$$T@Z", "void __cdecl f(std::nullptr_t)", MsvcSymbolKind.Function },
        { "?f@@YAX_N_W_J_K@Z", "void __cdecl f(bool, wchar_t, __int64, unsigned __int64)", MsvcSymbolKind.Function },
        { "?f@@YAX_S_U_Q@Z", "void __cdecl f(char16_t, char32_t, char8_t)", MsvcSymbolKind.Function },
        { "?f@@YA?AUS@@XZ", "struct S __cdecl f(void)", MsvcSymbolKind.Function },
        { "?f@@YA?BHXZ", "int const __cdecl f(void)", MsvcSymbolKind.Function },
        // back-references: parameters and names
        { "?f@@YAXPAUA@@0@Z", "void __cdecl f(struct A *, struct A *)", MsvcSymbolKind.Function },
        { "?f@A@B@@QAEXPAV12@@Z", "public: void __thiscall B::A::f(class B::A *)", MsvcSymbolKind.Function },
        // inside its own argument list a template's name back-reference is the bare name
        { "?f@@YAXV?$A@V0@@@@Z", "void __cdecl f(class A<class A>)", MsvcSymbolKind.Function },
        // scopes: anonymous namespace, function-local names, lambdas, extern "C" locals
        { "?f@?A0x12345678@@YAXXZ", "void __cdecl `anonymous namespace'::f(void)", MsvcSymbolKind.Function },
        { "??R<lambda_1>@?0??f@@YAXXZ@QBEXXZ", "public: void __thiscall `void __cdecl f(void)'::`1'::<lambda_1>::operator()(void) const", MsvcSymbolKind.Function },
        { "?x@?1??f@@YAXXZ@4HA", "int `void __cdecl f(void)'::`2'::x", MsvcSymbolKind.Variable },
        { "?$TSS0@?1??f@@YAXXZ@4HA", "int `void __cdecl f(void)'::`2'::$TSS0", MsvcSymbolKind.Variable },
        { "?f@@9", "f", MsvcSymbolKind.Function },
        { "?g@?1??f@@9@4HA", "int `f'::`2'::g", MsvcSymbolKind.Variable },
        // variables
        { "?x@@3HA", "int x", MsvcSymbolKind.Variable },
        { "?x@@3PAHA", "int *x", MsvcSymbolKind.Variable },
        { "?x@@3PEBDEB", "char const * const x", MsvcSymbolKind.Variable },
        { "?x@A@@2HA", "public: static int A::x", MsvcSymbolKind.Variable },
        { "?x@A@@0HB", "private: static int const A::x", MsvcSymbolKind.Variable },
        { "?x@@3PQA@@HQ1@", "int A::*x", MsvcSymbolKind.Variable },
        // tables, RTTI, guards, initializers
        { "??_7A@@6B@", "const A::`vftable'", MsvcSymbolKind.SpecialTable },
        { "??_7C@@6BA@@@", "const C::`vftable'{for `A'}", MsvcSymbolKind.SpecialTable },
        { "??_8C@@7BA@@@", "const C::`vbtable'{for `A'}", MsvcSymbolKind.SpecialTable },
        { "??_R0?AVA@@@8", "class A `RTTI Type Descriptor'", MsvcSymbolKind.RttiTypeDescriptor },
        { "??_R0?AUB@n@@@8", "struct n::B `RTTI Type Descriptor'", MsvcSymbolKind.RttiTypeDescriptor },
        { "??_R1A@?0A@EA@A@@8", "A::`RTTI Base Class Descriptor at (0, -1, 0, 64)'", MsvcSymbolKind.RttiBaseClassDescriptor },
        { "??_R2A@@8", "A::`RTTI Base Class Array'", MsvcSymbolKind.RttiBaseClassArray },
        { "??_R3A@@8", "A::`RTTI Class Hierarchy Descriptor'", MsvcSymbolKind.RttiClassHierarchyDescriptor },
        { "??_R4A@@6B@", "const A::`RTTI Complete Object Locator'", MsvcSymbolKind.SpecialTable },
        { "??_B?1??f@@YAXXZ@51", "`void __cdecl f(void)'::`2'::`local static guard'{2}'", MsvcSymbolKind.LocalStaticGuard },
        { "??__Ex@@YAXXZ", "void __cdecl `dynamic initializer for 'x''(void)", MsvcSymbolKind.Function },
        { "??__Fx@@YAXXZ", "void __cdecl `dynamic atexit destructor for 'x''(void)", MsvcSymbolKind.Function },
        // thunks
        { "?f@C@@W7EAAXXZ", "[thunk]: public: virtual void __cdecl C::f`adjustor{8}'(void)", MsvcSymbolKind.Thunk },
        { "?f@C@@$4PPPPPPPM@A@EAAXXZ", "[thunk]: public: virtual void __cdecl C::f`vtordisp{4294967292, 0}'(void)", MsvcSymbolKind.Thunk },
        { "?f@C@@$R4BA@7PPPPPPPM@A@AEXXZ", "[thunk]: public: virtual void __thiscall C::f`vtordispex{16, 8, 4294967292, 0}'(void)", MsvcSymbolKind.Thunk },
        { "??_9A@@$BA@AE", "[thunk]: __thiscall A::`vcall'{0, {flat}}", MsvcSymbolKind.Thunk },
        // string literals (decoded), MD5 names, C++/CX, imports
        { "??_C@_0M@ABCDEFGH@hello?5world?$AA@", "\"hello world\"", MsvcSymbolKind.StringLiteral },
        { "??_C@_1G@ABCDEFGH@?$AAh?$AAi?$AA?$AA@", "L\"hi\"", MsvcSymbolKind.StringLiteral },
        { "??_C@_0BL@ABCDEFGH@a?6b?$AN?7c?8d?$CCe?$AAf?$AA@", "\"a\\nb\\r\\tc'd\\\"e\\0f\\0\"...", MsvcSymbolKind.StringLiteral },
        { "??_C@_03ABCDEFGH@?$OE?$LF?$KJ?$AA@", "\"\\xE4\\xB5\\xA9\"", MsvcSymbolKind.StringLiteral },
        { "??_C@_05ABCDEFGH@h?$AAi?$AA?$AA?$AA@", "u\"hi\"", MsvcSymbolKind.StringLiteral },
        { "??@0123456789abcdef0123456789abcdef@", "??@0123456789abcdef0123456789abcdef@", MsvcSymbolKind.Md5Hash },
        { "?<Dispose>@?QIDisposable@Platform@@String@2@U$AAAXXZ", "public: virtual void __cdecl Platform::String::[Platform::IDisposable]::<Dispose>(void)", MsvcSymbolKind.Function },
        { "?f@@YAXP$AAVString@Platform@@@Z", "void __cdecl f(class Platform::String ^)", MsvcSymbolKind.Function },
        { "__imp_?f@@YAXXZ", "__declspec(dllimport) void __cdecl f(void)", MsvcSymbolKind.Function },
        // x86 C decorations
        { "_f@8", "__stdcall f", MsvcSymbolKind.CFunction },
        { "@f@8", "__fastcall f", MsvcSymbolKind.CFunction },
        { "f@@16", "__vectorcall f", MsvcSymbolKind.CFunction },
    };

    [Theory]
    [MemberData(nameof(Names))]
    public void Undecorates(string mangled, string expected, MsvcSymbolKind kind)
    {
        var r = MsvcDemangler.Demangle(mangled);
        Assert.True(r.Success, $"{mangled}: {r.Error}");
        Assert.Equal(expected, r.Text);
        Assert.Equal(kind, r.Kind);
    }

    /// <summary>The same table through DbgHelp (Windows): equal after whitespace normalization, with __ptr64 printed and literals as "`string'".</summary>
    [Fact]
    public void TableAgreesWithDbgHelp()
    {
        if (!DbgHelp.IsAvailable) return;
        var options = new MsvcDemangleOptions { Ptr64 = true, DecodeStringLiterals = false };
        // DbgHelp-specific forms: C decorations and __imp_ are not undecorated; vcall thunks get a malformed suffix.
        var skip = new[] { "_f@8", "@f@8", "f@@16", "__imp_?f@@YAXXZ", "??_9A@@$BA@AE" };
        var mismatches = new List<string>();
        foreach (var row in Names)
        {
            var mangled = (string)row[0];
            if (skip.Contains(mangled)) continue;
            var ours = MsvcDemangler.Demangle(mangled, options).Text!;
            var theirs = DbgHelp.Undecorate(mangled, DbgHelp.Complete);
            if (theirs == null || DbgHelp.Normalize(ours) != DbgHelp.Normalize(theirs))
                mismatches.Add($"{mangled}\n  ours:    {ours}\n  dbghelp: {theirs}");
        }
        Assert.True(mismatches.Count == 0, string.Join("\n", mismatches));
    }

    [Theory]
    [InlineData("??0?$A@H@@QAE@XZ", "A<int>::A<int>")]
    [InlineData("?f@A@@QEBAHXZ", "A::f")]
    [InlineData("??$f@$1?g@@YAXXZ@@YAXXZ", "f<&g>")]
    [InlineData("?f@@YAXV?$A@V?$B@H@@@@@Z", "f")]
    [InlineData("??_7?$A@W4E@@@@6B@", "A<enum E>::`vftable'")]
    [InlineData("??0?$A@VB@@@@QAE@XZ", "A<B>::A<B>")]
    [InlineData("?x@?1??f@A@@QAEXXZ@4HA", "`A::f'::`2'::x")]
    [InlineData("??_R0?AVA@@@8", "A `RTTI Type Descriptor'")]
    [InlineData("??_B?1??f@@YAXXZ@51", "`f'::`2'::`local static guard'")]
    public void NameOnly(string mangled, string expected) =>
        Assert.Equal(expected, MsvcDemangler.Undecorate(mangled, MsvcNameStyle.NameOnly));

    [Fact]
    public void Options()
    {
        Assert.Equal("public: int __cdecl A::f(char const * __ptr64) const __ptr64",
            MsvcDemangler.Demangle("?f@A@@QEBAHPEBD@Z", new MsvcDemangleOptions { Ptr64 = true }).Text);
        Assert.Equal("`string'", MsvcDemangler.Demangle("??_C@_0M@ABCDEFGH@hello?5world?$AA@", new MsvcDemangleOptions { DecodeStringLiterals = false }).Text);
        // a plain leading underscore is a decoration only for x86 names
        Assert.False(MsvcDemangler.Demangle("_f").Success);
        var cdecl = MsvcDemangler.Demangle("_f", new MsvcDemangleOptions { X86 = true });
        Assert.Equal(("__cdecl f", "__cdecl"), (cdecl.Text, cdecl.CallingConvention));
        var stdcall = MsvcDemangler.Demangle("_CreateFileW@28");
        Assert.Equal((MsvcSymbolKind.CFunction, "__stdcall", 28, "CreateFileW"),
            (stdcall.Kind, stdcall.CallingConvention, stdcall.ArgumentBytes, MsvcDemangler.Undecorate("_CreateFileW@28", MsvcNameStyle.NameOnly)));
        Assert.True(MsvcDemangler.Demangle("__imp__CreateFileW@28").IsImport);
    }

    [Theory]
    [InlineData(".?AVA@@", "class A", "A")]
    [InlineData(".?AUB@n@@", "struct n::B", "n::B")]
    [InlineData(".?AV?$C@H@x@@", "class x::C<int>", "x::C<int>")]
    [InlineData(".?AV<lambda_1>@?0??f@@YAXXZ@", "class `void __cdecl f(void)'::`1'::<lambda_1>", "`void __cdecl f(void)'::`1'::<lambda_1>")]
    [InlineData(".H", "int", "int")]
    public void TypeDescriptorNames(string name, string type, string bare)
    {
        var r = MsvcDemangler.DemangleTypeDescriptorName(name);
        Assert.NotNull(r);
        Assert.Equal((type, bare), r.Value);
    }

    [Theory]
    [InlineData("")]
    [InlineData("?")]
    [InlineData("??")]
    [InlineData("???")]
    [InlineData("?@")]
    [InlineData("?f@@YA")]
    [InlineData("?f@@YAX")]
    [InlineData("?f@@YAXH")]
    [InlineData("?f@@YAXXZjunk")]
    [InlineData("?f@@YAX9@Z")]
    [InlineData("??_C@_0")]
    [InlineData("??_C@_0M@ABCDEFGH@hello")]
    [InlineData("??_C@_0M@ABCDEFGH@?$ZZ@")]
    [InlineData("??_R0?AV")]
    [InlineData("??_7A@@6")]
    [InlineData("??$f@$0@@YAXXZ")]
    [InlineData("??$f@$0PPPPPPPPPPPPPPPPPPPP@@@YAXXZ")]
    [InlineData("?f@?1?@YAXXZ")]
    [InlineData("??@")]
    [InlineData("?f@@YAXYA@H@Z")]
    [InlineData(".?AV")]
    [InlineData("_")]
    [InlineData("@@8")]
    [InlineData("__imp_")]
    [InlineData("hello")]
    public void GarbageIsRejectedWithAReason(string name)
    {
        var r = MsvcDemangler.Demangle(name);
        Assert.False(r.Success);
        Assert.False(string.IsNullOrEmpty(r.Error));
        Assert.DoesNotContain("internal error", r.Error);
        Assert.Null(MsvcDemangler.DemangleTypeDescriptorName(name));
    }

    [Fact]
    public void DeepAndLongInputsAreBounded()
    {
        var cpu = ThreadCpuClock.Now();
        var deepPointers = "?x@@3" + string.Concat(Enumerable.Repeat("PA", 50_000)) + "HA";
        var deepTemplates = "?f@@YAXV" + string.Concat(Enumerable.Repeat("?$A@V", 5_000)) + "B@@Z";
        var deepScopes = "?x@" + string.Concat(Enumerable.Repeat("?1??f@", 3_000)) + "@YAXXZ@4HA";
        var tooLong = "?f@@YAX" + new string('H', MsvcDemangler.MaxInputLength) + "@Z";
        foreach (var name in new[] { deepPointers, deepTemplates, deepScopes, tooLong })
        {
            var r = MsvcDemangler.Demangle(name);
            Assert.False(r.Success);
            Assert.DoesNotContain("internal error", r.Error);
        }
        // exponential output through back-references stays capped
        var blowup = "?f@@YAX" + string.Concat(Enumerable.Range(0, 9).Select(i => i == 0 ? "PAH" : $"P6AX{i - 1}{i - 1}{i - 1}{i - 1}@Z")) + "@Z";
        var b = MsvcDemangler.Demangle(blowup);
        Assert.True(b.Success || b.Error!.Contains("longer than"), b.Error);
        // Catches exponential blow-ups, not speed.
        Assert.True(ThreadCpuClock.Now() - cpu is var took && took < TimeSpan.FromSeconds(20), $"{took} of CPU");
    }

    /// <summary>Deterministic mutations of the table: no exception escapes, no internal error, bounded time.</summary>
    [Fact]
    public void MutatedNamesNeverFailInternally()
    {
        var rng = new Random(1234);
        var seeds = Names.Select(r => (string)r[0]).ToList();
        const string alphabet = "?@$0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcxyz";
        var cpu = ThreadCpuClock.Now();
        for (int i = 0; i < 10_000; i++)
        {
            var chars = seeds[rng.Next(seeds.Count)].ToCharArray().ToList();
            int edits = rng.Next(1, 4);
            for (int e = 0; e < edits && chars.Count > 0; e++)
            {
                int at = rng.Next(chars.Count);
                switch (rng.Next(3))
                {
                    case 0: chars[at] = alphabet[rng.Next(alphabet.Length)]; break;
                    case 1: chars.RemoveAt(at); break;
                    default: chars.Insert(at, alphabet[rng.Next(alphabet.Length)]); break;
                }
            }
            var name = new string(chars.ToArray());
            var r = MsvcDemangler.Demangle(name);
            Assert.True(r.Error == null || !r.Error.StartsWith("internal error", StringComparison.Ordinal), $"{name}: {r.Error}");
            MsvcDemangler.Demangle(name, new MsvcDemangleOptions { Style = MsvcNameStyle.NameOnly, Ptr64 = true });
        }
        Assert.True(ThreadCpuClock.Now() - cpu is var took && took < TimeSpan.FromSeconds(30), $"{took} of CPU");
    }
}
