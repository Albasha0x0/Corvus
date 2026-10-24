using dnlib.DotNet;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Corvus.Core;
using Corvus.Services;

namespace Corvus.Tests;

/// <summary>
/// generate_cpp_binding for Il2Cpp builds: the il2cpp style on a module shaped like a dummy assembly, and the
/// projects that call the runtime's exports themselves choosing it.
/// </summary>
public sealed class CppBindingIl2CppTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private const string Source = """
        using System;
        namespace Il2CppDummyDll
        {
            public class AddressAttribute : Attribute { public string RVA; public string Offset; public string VA; }
            public class TokenAttribute : Attribute { public string Token; }
            public class FieldOffsetAttribute : Attribute { public string Offset; }
        }
        namespace App
        {
            using Il2CppDummyDll;
            public struct Vec { [FieldOffset(Offset = "0x0")] public float x; [FieldOffset(Offset = "0x4")] public float y; [FieldOffset(Offset = "0x8")] public float z; }
            public struct Pair<T> { public bool hasValue; public T value; }
            public class Player
            {
                public int health;
                public Pair<int> pending;
                public static Player Local;
                public static int Count;
                public float magnitude { get { return 0; } }
                [Address(RVA = "0x1000", Offset = "0x400", VA = "0x180001000")] [Token(Token = "0x06000101")]
                public static float Magnitude(Vec v) { return 0; }
                [Address(RVA = "0x1100", Offset = "0x500", VA = "0x180001100")] [Token(Token = "0x06000102")]
                public bool Damage(int amount, Player source) { return false; }
                [Address(RVA = "0x1200", Offset = "0x600", VA = "0x180001200")] [Token(Token = "0x06000103")]
                public void Move(Vec to) { }
                [Address(RVA = "0x1300", Offset = "0x700", VA = "0x180001300")] [Token(Token = "0x06000104")]
                public void Move(Pair<int> to) { }
            }
            public class Base<T> { public int count; public T first; }
            public class Box<T> : Base<T>
            {
                public T value;
                public bool flag;
                public T[] items;
                public Vec where;
                public Pair<T> pending;
                public static int Instances;
                public T Current { get { return value; } }
                [Address(RVA = "0x1400", Offset = "0x800", VA = "0x180001400")]
                public T Get(int index) { return value; }
                [Address(RVA = "0x1500", Offset = "0x900", VA = "0x180001500")]
                public void Set(T item, bool notify) { }
            }
        }
        """;

    private string Generate(string? projectDir = null, string? style = null, string type = "App.Player")
    {
        var path = _dir.File("App.dll");
        if (!File.Exists(path))
            File.WriteAllBytes(path, Roslyn.Compile("App", Source, new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary)));
        using var ws = new AssemblyWorkspace(new ServerOptions { BackgroundIndexing = false, WatchFiles = false });
        var asm = ws.Load(path);
        return ws.Read(() =>
        {
            var def = asm.Module.Find(type, false)!;
            var target = CppBindingGenerator.ChooseStyle(style, projectDir, null, null, default, il2cppAssembly: true);
            return new CppBindingGenerator().Generate(asm, def, null, false, target);
        });
    }

    [Fact]
    public void Il2CppStyleResolvesThroughTheRuntimeExports()
    {
        var code = Generate();
        Assert.StartsWith("// Style il2cpp: Il2Cpp dummy assembly ([Address] attributes); no projectDir.", code);
        Assert.Contains("get(class_from_name, \"il2cpp_class_from_name\");", code);
        Assert.Contains("klass = FindClass(api, \"App\", \"App\", \"Player\");", code);
        Assert.Contains("m_healthOff = FieldOffset(api, klass, \"health\");", code);
        Assert.Contains("void* PendingAddr(void* obj) const", code); // a generic value-type instance is embedded, not a pointer
        Assert.Contains("Il2CppObject* Local(const Il2CppApi& api) const { return ReadStatic<Il2CppObject*>(api, m_localField); }", code);
        Assert.Contains("bool SetCount(const Il2CppApi& api, int32_t value) const", code);
        // Overloads are matched by the [Token] attribute, not the dummy's own token.
        Assert.Contains("m_move = MethodByToken(api, klass, 0x06000103);", code);
        Assert.Contains("m_move2 = MethodByToken(api, klass, 0x06000104);", code);
        Assert.Contains("Damage(int amount, Player source)  [RVA 0x1100]", code);
        Assert.Contains("void* DamagePointer() const { return MethodPointer(m_damage); }", code);
        Assert.Contains("bool CallDamage(void* obj, int32_t amount, void* source) const { return reinterpret_cast<bool (*)(void*, int32_t, void*, const MethodInfo*)>(MethodPointer(m_damage))(obj, amount, source, m_damage); }", code);
        Assert.DoesNotContain("CallMove", code); // a struct parameter: no typed direct call
    }

    [Fact]
    public void GetterAndStaticMethodOfOneNameGetDistinctWrappers()
    {
        var code = Generate();
        Assert.Contains("float Magnitude(const Il2CppApi& api, void* obj) const", code);
        Assert.Contains("Il2CppObject* Magnitude2(const Il2CppApi& api, void* v, Il2CppObject** exception = nullptr) const", code);
    }

    /// <summary>The two shapes of native projects that call Il2Cpp's exports, and one on Mono.</summary>
    [Theory]
    [InlineData("typedef void Il2CppClass;\ntypedef Il2CppClass* (*il2cpp_class_from_name_t)(const void* image, const char* ns, const char* name);\n" +
                "namespace il2cpp { inline il2cpp_class_from_name_t class_from_name = nullptr; }\n", "il2cpp")]
    [InlineData("namespace il2cpp {\nstruct Il2CppClass;\nusing fn_class_from_name = Il2CppClass* (*)(const void* image, const char* ns, const char* name);\n" +
                "extern fn_class_from_name class_from_name;\n}\n", "il2cpp")]
    [InlineData("typedef void* (*mono_class_from_name_fn)(void*, const char*, const char*);\n", "mono")]
    public void ProjectsThatCallTheRuntimeChooseItsStyle(string header, string style)
    {
        var project = _dir.File($"project-{style}-{header.Length}");
        Directory.CreateDirectory(Path.Combine(project, "src"));
        File.WriteAllText(Path.Combine(project, "src", "runtime_api.h"), header);
        var target = CppBindingGenerator.ChooseStyle(null, project, null, null, default);
        Assert.Equal(style, target.Style);
        Assert.Contains("src/runtime_api.h", target.Reason);
    }

    [Fact]
    public void GenericDefinitionBindsAsATemplateResolvedOnAnInstantiation()
    {
        var code = Generate(type: "App.Box`1");
        Assert.Contains("template <class T>\nstruct Box_1Binding {", code.ReplaceLineEndings("\n"));
        Assert.Contains("static Il2CppClass* Definition(const Il2CppApi& api) { return FindClass(api, \"App\", \"App\", \"Box`1\"); }", code);
        Assert.Contains("bool Resolve(const Il2CppApi& api, Il2CppClass* instance) {", code);
        Assert.Contains("T Value(const void* obj) const { return Read<T>(obj, m_valueOff); }", code);
        Assert.Contains("T Current(const Il2CppApi& api, void* obj) const { return Result<T>(api, Invoke(api, m_getCurrent, obj, nullptr)); }", code);
        Assert.Contains("void* a[2] = { Arg(item), &notify };", code);
        Assert.Contains("T CallGet(void* obj, int32_t index) const { return reinterpret_cast<T (*)(void*, int32_t, const MethodInfo*)>(MethodPointer(m_get))(obj, index, m_get); }", code);
        // The layout: the generic base's fields first, each class level pointer-aligned; a value type over T is not laid out.
        var layout = code[code.IndexOf("struct Box_1Layout {", StringComparison.Ordinal)..];
        Assert.Contains("alignas(8) int32_t count;", layout);
        Assert.Contains("alignas(8) T value;", layout);
        Assert.Contains("alignas(4) nd_bytes where[12];", layout);
        Assert.Contains("// pending (Pair<T>) and the fields after it depend on a type argument inside a value type: not laid out.", code);
        // Closed types keep the plain struct and lookup by name.
        Assert.Contains("bool Resolve(const Il2CppApi& api) {", Generate());
    }

    private const string ClangPlusPlus = @"C:\Program Files\LLVM\bin\clang++.exe";

    /// <summary>The template compiles instantiated over a value type and a reference, in every style; the layout's offsets are Il2Cpp's.</summary>
    [Trait("Speed", "Slow")]
    [Fact]
    public void GenericBindingsCompileForValueAndReferenceArguments()
    {
        if (!File.Exists(ClangPlusPlus)) return;
        foreach (var (style, ns) in new[] { ("il2cpp", "il2cppbind"), ("mono", "monobind") })
        {
            File.WriteAllText(_dir.File($"Box_{style}.h"), Generate(style: style, type: "App.Box`1"));
            var checks = style == "il2cpp"
                ? "#include <cstddef>\n" +
                  "static_assert(offsetof(il2cppbind::Box_1Layout<int32_t>, first) == 0x14 && offsetof(il2cppbind::Box_1Layout<int32_t>, value) == 0x18, \"int\");\n" +
                  "static_assert(offsetof(il2cppbind::Box_1Layout<void*>, first) == 0x18 && offsetof(il2cppbind::Box_1Layout<void*>, value) == 0x20, \"ref\");\n" +
                  "static_assert(offsetof(il2cppbind::Box_1Layout<int32_t>, where) == 0x28, \"vec\");\n"
                : "";
            File.WriteAllText(_dir.File($"box_{style}.cpp"), $"#include \"Box_{style}.h\"\n{checks}template struct {ns}::Box_1Binding<int32_t>;\ntemplate struct {ns}::Box_1Binding<void*>;\nint main() {{ return 0; }}\n");
            var (code, text) = Tools.Run(ClangPlusPlus, $"-std=c++17 -fsyntax-only -Wall -Wextra -Werror -Wno-invalid-offsetof \"{_dir.File($"box_{style}.cpp")}\"");
            Assert.True(code == 0, $"{style}: {text}");
        }
    }

    /// <summary>The header compiles with -Wall -Werror, twice in one translation unit and next to a project's own Il2Cpp declarations.</summary>
    [Trait("Speed", "Slow")]
    [Fact]
    public void Il2CppBindingCompilesNextToTheProjectsDeclarations()
    {
        if (!File.Exists(ClangPlusPlus)) return;
        File.WriteAllText(_dir.File("Player.h"), Generate());
        File.WriteAllText(_dir.File("host.h"), "#pragma once\ntypedef void Il2CppClass;\ntypedef void Il2CppObject;\nstruct MethodInfo;\nnamespace il2cpp { inline void* (*class_from_name)(const void*, const char*, const char*) = nullptr; }\n");
        File.WriteAllText(_dir.File("all.cpp"), "#include \"host.h\"\n#include \"Player.h\"\n#include \"Player.h\"\nint main() { il2cppbind::PlayerBinding b; return b.Resolved() ? 1 : 0; }\n");
        var (code, text) = Tools.Run(ClangPlusPlus, $"-std=c++17 -fsyntax-only -Wall -Wextra -Werror \"{_dir.File("all.cpp")}\"");
        Assert.True(code == 0, text);
    }
}
