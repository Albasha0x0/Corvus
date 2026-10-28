using dnlib.DotNet;
using Corvus.Core;
using Corvus.Services;

namespace Corvus.Tests;

public class CppBindingTests : IDisposable
{
    private readonly Env _env = new();
    public void Dispose() => _env.Dispose();

    private string Generate(string type, string? only = null, bool inherited = false, string style = "mono") =>
        new CppBindingGenerator().Generate(_env.Fixture, _env.Def<TypeDef>(type, SymbolKind.Type), only?.Split(','), inherited, style);

    private const string ClangPlusPlus = @"C:\Program Files\LLVM\bin\clang++.exe";

    [Fact]
    public void The_Mono_embedding_API_style_generates_its_binding()
    {
        var code = Generate("Account");
        Assert.Contains("klass = FindClass(api, \"TestFixture\", \"Fixture.Model\", \"Account\");", code);
        Assert.Contains("m_balanceOff = FieldOffset(api, klass, \"_balance\");", code);
        Assert.Contains("m_accountCountStaticOff = FieldOffset(api, klass, \"AccountCount\");", code);
        Assert.Contains("m_static = StaticData(api, klass);", code);
        Assert.Contains("int32_t Balance(const void* obj) const { return Read<int32_t>(obj, m_balanceOff); }", code);
        Assert.Contains("bool SetBalance(void* obj, int32_t value) const { return Write<int32_t>(obj, m_balanceOff, value); }", code);
        Assert.Contains("api.class_get_method_from_name(klass, \"CheckPreview\", 0);", code);
        Assert.Contains("return CallValue<bool>(api, m_getIsActive, obj);", code);
        Assert.Contains("get(class_from_name, \"mono_class_from_name\");", code);
        Assert.Contains("namespace monobind {", code);
        Assert.DoesNotContain("HostApi", code);
        // Only standard headers.
        Assert.DoesNotContain("#include \"", code);
    }

    [Fact]
    public void Mono_overloads_by_token_nested_types_through_their_outer_class()
    {
        var shop = Generate("Shop", "Apply,_credit");
        var overloads = _env.Def<TypeDef>("Shop", SymbolKind.Type).Methods.Where(m => m.Name == "Apply").ToList();
        Assert.Equal(2, overloads.Count);
        foreach (var m in overloads)
            Assert.Contains($"MethodByToken(api, klass, 0x{m.MDToken.Raw:X8});", shop);
        Assert.Contains("regenerate this header when the assembly changes", shop);
        Assert.DoesNotContain("Buy", shop);

        var nested = Generate("Account+Inventory");
        Assert.Contains("klass = FindNested(api, FindClass(api, \"TestFixture\", \"Fixture.Model\", \"Account\"), \"Inventory\");", nested);

        Assert.Contains("MethodInHierarchy(api, klass, ", Generate("PremiumAccount", inherited: true));
        Assert.Contains("instance offsets include the object header", Generate("Vec2"));
    }

    [Fact]
    public void Unknown_members_and_styles_are_refused_by_name()
    {
        Assert.Contains("NoSuchMember", Assert.Throws<ToolError>(() => Generate("Shop", "NoSuchMember")).Message);
        // Generic definitions bind as templates.
        Assert.Contains("template <class T>", Generate("Container"));
        Assert.Contains("Unknown style 'custom'", Assert.Throws<ToolError>(() => Generate("Account", style: "custom")).Message);
    }

    /// <summary>Mono headers compile together in one translation unit.</summary>
    [Trait("Speed", "Slow")]
    [Fact]
    public void Mono_bindings_compile()
    {
        if (!File.Exists(ClangPlusPlus)) return;
        using var dir = new TempDir();
        var types = new[] { "Account", "Shop", "PremiumAccount", "Account+Inventory", "Vec2", "Entity", "Bank", "CountHolder" };
        var includes = new List<string>();
        foreach (var type in types)
        {
            var file = type.Replace('+', '_') + ".h";
            File.WriteAllText(dir.File(file), Generate(type, inherited: true));
            includes.Add($"#include \"{file}\"");
        }
        File.WriteAllText(dir.File("all.cpp"), string.Join("\n", includes) + """

            static void* Lookup(const char*) { return nullptr; }
            int main() {
                monobind::MonoApi api;
                bool loaded = api.Load(Lookup);
                monobind::AccountBinding account;
                monobind::InventoryBinding inventory;
                return loaded && account.Resolved() && inventory.Resolved() ? 0 : 1;
            }
            """);
        var (code, text) = Tools.Run(ClangPlusPlus, $"-std=c++17 -fsyntax-only -Wall -Wextra -Werror -I \"{dir.Path}\" \"{dir.File("all.cpp")}\"");
        Assert.True(code == 0, text);
    }

    [Fact]
    public void The_host_API_style_generates_its_binding()
    {
        var code = Generate("Account", style: "hostapi");
        Assert.Contains("klass = h->FindClass(\"TestFixture\", \"Fixture.Model\", \"Account\");", code);
        Assert.Contains("m_balanceOff = h->FieldOffset(klass, \"_balance\");", code);
        Assert.Contains("m_accountCountStaticOff = h->StaticFieldOffset(klass, \"AccountCount\");", code);
        Assert.Contains("m_static = h->GetStaticFieldData(klass);", code);
        Assert.Contains("int32_t Balance(const HostApi* h, const void* obj) const { return ReadField<int32_t>(h, obj, m_balanceOff); }", code);
        Assert.Contains("h->GetMethod(klass, \"CheckPreview\", 0);", code);
        Assert.Contains("return CallValue<bool>(h, m_getIsActive, obj);", code);
        // Without a project no includes or namespace are invented.
        Assert.DoesNotContain("#include", code);
        Assert.DoesNotContain("namespace", code);
        Assert.Contains("// Include the header that defines HostApi and the helpers this code calls", code);
    }

    [Fact]
    public void Host_API_overloads_use_exact_signatures_and_filters_work()
    {
        var code = Generate("Shop", "Apply,_credit", style: "hostapi");
        Assert.Contains("GetMethodExact(h, klass, \"Apply\", \"Int32\")", code);
        Assert.Contains("GetMethodExact(h, klass, \"Apply\", \"String\")", code);
        Assert.Contains("_credit", code);
        Assert.DoesNotContain("Buy", code);
        Assert.Contains("GetMethodInHierarchy", Generate("PremiumAccount", inherited: true, style: "hostapi"));
    }

    [Theory]
    [InlineData("mono")]
    [InlineData("hostapi")]
    public void Inherited_members_named_explicitly_are_bound_through_the_hierarchy(string style)
    {
        // Instance, Version and Touch are declared on Singleton<Bank>.
        var code = Generate("Bank", "Instance,Version,Touch,Credit", style: style);
        var (lookup, field) = style == "mono"
            ? ("MethodInHierarchy(api, klass, ", "FieldOffset(api, klass, \"Version\")")
            : ("GetMethodInHierarchy(h, klass, ", "h->FieldOffset(klass, \"Version\")");
        Assert.Contains(lookup + "\"get_Instance\", 0);", code);
        Assert.Contains(lookup + "\"Touch\", 0);  // declared on Fixture.Model.Singleton`1", code);
        Assert.Contains(field, code);
        // Static: no object.
        Assert.Contains(style == "mono" ? "MonoObject* Instance(const MonoApi& api) const" : "void* Instance(const HostApi* h) const", code);
        Assert.DoesNotContain("has no bindable", code);

        // The base's T is substituted: Holder<int>.Current is int.
        Assert.Contains(style == "mono" ? "int32_t Current(const MonoApi& api) const" : "int32_t Current(const HostApi* h) const", Generate("CountHolder", "Current", style: style));

        // Base-class static fields are not in the derived class's static data.
        var error = Assert.Throws<ToolError>(() => Generate("Bank", "_instance", style: style)).Message;
        Assert.Contains("Static base fields (_instance) live in the base class's static data", error);
        Assert.Contains("has no bindable member(s): Nope", Assert.Throws<ToolError>(() => Generate("Bank", "Nope", style: style)).Message);
    }

    [Fact]
    public void A_name_with_a_comment_end_and_a_line_break_stays_inside_one_comment()
    {
        const string name = "a*/b\nc\"d\\";
        Assert.Equal(@"a*\/b\nc""d\x5C", CText.Block(name));
        using var dir = new TempDir();
        var image = Roslyn.Compile("Odd", "public class Holder { public int Field; }",
            new Microsoft.CodeAnalysis.CSharp.CSharpCompilationOptions(Microsoft.CodeAnalysis.OutputKind.DynamicallyLinkedLibrary));
        using (var module = ModuleDefMD.Load(image))
        {
            module.Find("Holder", isReflectionName: false).Fields.Single().Name = name;
            module.Write(dir.File("Odd.dll"));
        }
        using var env = new Env(dir.File("Odd.dll"));
        var code = new CppBindingGenerator().Generate(env.Fixture, env.Def<TypeDef>("Holder", SymbolKind.Type), null, false, "mono");

        Assert.Contains("// int " + CText.Line(name), code);
        Assert.Contains("FieldOffset(api, klass, \"a*/b\\012c\\\"d\\\\\")", code);
        Assert.DoesNotContain(code.Split('\n'), l => l.StartsWith("c\"d", StringComparison.Ordinal));
        if (!File.Exists(ClangPlusPlus)) return;
        File.WriteAllText(dir.File("Holder.h"), code);
        File.WriteAllText(dir.File("all.cpp"), "#include \"Holder.h\"\nint main() { monobind::HolderBinding b; return b.Resolved() ? 0 : 1; }\n");
        var (exit, text) = Tools.Run(ClangPlusPlus, $"-std=c++17 -fsyntax-only -Wall -Wextra -Werror -I \"{dir.Path}\" \"{dir.File("all.cpp")}\"");
        Assert.True(exit == 0, text);
    }

    [Fact]
    public void Mono_header_names_every_runtime_file_name()
    {
        var code = Generate("Account");
        Assert.Contains("mono-2.0-bdwgc.dll / mono-2.0-sgen.dll / mono.dll", code);
        Assert.Contains("libmonosgen-2.0.so", code);
    }

    /// <summary>Detects a real host-table project and compiles the output against its headers.</summary>
    [Trait("Speed", "Slow")]
    [RequiresRealDataFact(RealData.HostApiProjectDir)]
    public void Host_API_bindings_compile_against_real_headers()
    {
        var project = RealData.Path(RealData.HostApiProjectDir);
        using var dir = new TempDir();
        foreach (var type in new[] { "Account", "Shop", "PremiumAccount", "Bank", "CountHolder", "Vec2" })
        {
            var header = dir.File(type + ".h");
            var target = CppBindingGenerator.ChooseStyle(null, project, header, null, default);
            Assert.Equal("hostapi", target.Style);
            var ns = target.Project!.Helpers.Values.Select(h => h.Namespace).FirstOrDefault(n => n != null);
            File.WriteAllText(header, new CppBindingGenerator().Generate(_env.Fixture, _env.Def<TypeDef>(type, SymbolKind.Type), null, true, target));
            if (!File.Exists(ClangPlusPlus)) continue;
            File.WriteAllText(dir.File(type + ".cpp"), $"#include \"{type}.h\"\nint main() {{ {(ns != null ? ns + "::" : "")}{type}Binding* b = nullptr; return b ? 0 : 1; }}\n");
            var (code, text) = Tools.Run(ClangPlusPlus, $"-std=c++20 -fsyntax-only \"{dir.File(type + ".cpp")}\"");
            Assert.True(code == 0, text);
        }
    }

    /// <summary>Real singletons with Instance on a generic base bind by name and compile against real host headers.</summary>
    [Trait("Speed", "Slow")]
    [RequiresRealDataFact(RealData.HostApiProjectDir, RealData.AssemblyDir)]
    public void Real_inherited_singletons_bind_and_compile()
    {
        using var app = new Env(Env.FixturePath);
        app.Workspace.LoadDirectory(RealData.Path(RealData.AssemblyDir), false);
        var singletons = app.Workspace.Read(() => app.Workspace.Assemblies.Where(RealData.IsAppAssembly)
            .SelectMany(a => a.Module.GetTypes().Select(t => (a, t)))
            .Where(x => !x.t.HasGenericParameters && !x.t.IsAbstract && x.t.BaseType is TypeSpec
                        && x.t.Properties.All(p => p.Name != "Instance")
                        && Try(() => x.t.BaseType.ResolveTypeDef())?.Properties.Any(p => p.Name == "Instance" && p.GetMethod is { IsStatic: true }) == true)
            .Take(5).ToList());
        Assert.NotEmpty(singletons);
        using var dir = new TempDir();
        var project = RealData.Path(RealData.HostApiProjectDir);
        foreach (var (asm, type) in singletons)
        {
            var name = Format.StripArity(type.Name);
            var header = dir.File(name + ".h");
            var target = CppBindingGenerator.ChooseStyle(null, project, header, null, default);
            var code = app.Workspace.Read(() => new CppBindingGenerator().Generate(asm, type, ["Instance"], false, target));
            Assert.Contains("GetMethodInHierarchy(h, klass, \"get_Instance\", 0);", code);
            File.WriteAllText(header, code);
            if (!File.Exists(ClangPlusPlus)) continue;
            var ns = target.Project!.Helpers.Values.Select(h => h.Namespace).FirstOrDefault(n => n != null);
            File.WriteAllText(dir.File(name + ".cpp"), $"#include \"{name}.h\"\nint main() {{ {(ns != null ? ns + "::" : "")}{name}Binding* b = nullptr; return b ? 0 : 1; }}\n");
            var (exit, text) = Tools.Run(ClangPlusPlus, $"-std=c++20 -fsyntax-only \"{dir.File(name + ".cpp")}\"");
            Assert.True(exit == 0, text + "\n" + code);
        }
    }

    private static T? Try<T>(Func<T> f) where T : class
    {
        try { return f(); }
        catch { return null; }
    }
}

/// <summary>generate_cpp_binding style choice: explicit style, then projectDir detection, then the server default, then mono.</summary>
public class CppBindingStyleTests : IDisposable
{
    private readonly Env _env = new();
    private readonly TempDir _dir = new();

    public void Dispose()
    {
        _env.Dispose();
        _dir.Dispose();
    }

    private const string ClangPlusPlus = @"C:\Program Files\LLVM\bin\clang++.exe";

    private string Write(string relative, string text)
    {
        var path = Path.Combine(_dir.Path, relative);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, text);
        return path;
    }

    private string Generate(string type, CppBindingGenerator.BindingTarget target, bool inherited = false) =>
        new CppBindingGenerator().Generate(_env.Fixture, _env.Def<TypeDef>(type, SymbolKind.Type), null, inherited, target);

    /// <summary>Host table "AppHost" in extern "C" with decoys to ignore, helpers in another folder, no GetMethodExact.</summary>
    private string HostTableProject()
    {
        Write("host/abi.h", """
            #pragma once
            #include <stdint.h>
            typedef void* KlassRef;
            typedef void* MethRef;
            /* typedef struct Decoy { KlassRef (*FindClass)(const char*, const char*, const char*); MethRef (*GetMethod)(KlassRef, const char*, int);
               int32_t (*FieldOffset)(KlassRef, const char*); int32_t (*StaticFieldOffset)(KlassRef, const char*);
               void* (*GetStaticFieldData)(KlassRef); void* (*Invoke)(MethRef, void*, void**, int); } Decoy; */
            struct Partial { KlassRef (*FindClass)(const char* a, const char* n, const char* c); };
            #ifdef __cplusplus
            extern "C" {
            #endif
            typedef struct AppHost {
                uint32_t version; // "struct NotThis { }" in a comment
                KlassRef (*FindClass)(const char* assembly, const char* ns, const char* name);
                MethRef  (*GetMethod)(KlassRef klass, const char* name, int argc);
                int32_t  (*FieldOffset)(KlassRef klass, const char* field);
                int32_t  (*StaticFieldOffset)(KlassRef klass, const char* field);
                void*    (*GetStaticFieldData)(KlassRef klass);
                void*    (*Invoke)(MethRef method, void* instance, void** args, int argc);
            } AppHost;
            #ifdef __cplusplus
            }
            #endif
            """);
        Write("lib/helpers.hpp", """
            #pragma once
            #include <cstring>
            #include "../host/abi.h"
            namespace tools { namespace mem {
            template <class T> inline T ReadField(const AppHost* h, const void* obj, int32_t offset, T def = T{}) {
                (void)h; if (!obj || offset < 0) return def; T v; std::memcpy(&v, static_cast<const char*>(obj) + offset, sizeof v); return v;
            }
            template <class T> inline bool WriteField(const AppHost* h, void* obj, int32_t offset, const T& value) {
                (void)h; if (!obj || offset < 0) return false; std::memcpy(static_cast<char*>(obj) + offset, &value, sizeof value); return true;
            }
            inline void* ReadPtr(const AppHost* h, const void* obj, int32_t offset) { return ReadField<void*>(h, obj, offset, nullptr); }
            template <class T> inline T CallValue(const AppHost* h, MethRef m, void* instance, T def = T{}) {
                void* boxed = h->Invoke(m, instance, nullptr, 0); return boxed ? ReadField<T>(h, boxed, 16, def) : def;
            }
            inline MethRef GetMethodInHierarchy(const AppHost* h, KlassRef klass, const char* name, int argc) { return h->GetMethod(klass, name, argc); }
            } }
            """);
        Write("src/main.cpp", "int main() { return 0; }\n");
        return _dir.Path;
    }

    [Trait("Speed", "Slow")]
    [Fact]
    public void Host_table_project_is_detected_with_includes_relative_to_the_header()
    {
        var project = HostTableProject();
        var target = CppBindingGenerator.ChooseStyle(null, project, "src/bindings/Account.h", null, default);
        Assert.Equal("hostapi", target.Style);
        Assert.Equal("AppHost", target.Project!.TableName);
        Assert.Equal(("KlassRef", "MethRef"), (target.Project.ClassHandle, target.Project.MethodHandle));
        Assert.DoesNotContain("GetMethodExact", target.Project.Helpers.Keys);

        var code = Generate("Account", target);
        var lines = code.Split('\n').Select(l => l.TrimEnd('\r')).ToList();
        Assert.StartsWith("// Style hostapi: projectDir has a host table: AppHost in host/abi.h (members FindClass, GetMethod, FieldOffset, StaticFieldOffset, GetStaticFieldData, Invoke).", lines[0]);
        Assert.Contains("#include \"../../host/abi.h\"", lines);
        Assert.Contains("#include \"../../lib/helpers.hpp\"", lines);
        Assert.Contains("namespace tools::mem {", lines);
        Assert.Contains("    KlassRef klass = nullptr;", lines);
        Assert.Contains("    bool Resolve(const AppHost* h) {", lines);
        Assert.Contains("int32_t Balance(const AppHost* h, const void* obj) const { return ReadField<int32_t>(h, obj, m_balanceOff); }", code);
        Assert.DoesNotContain("HostApi", code);
        Assert.DoesNotContain("plugin", code);

        // A binding that needs the missing helper reports it.
        var shop = Generate("Shop", CppBindingGenerator.ChooseStyle(null, project, "src/bindings/Shop.h", null, default));
        Assert.Contains("// NOTE: not found in", shop);
        Assert.Contains(": GetMethodExact. Define them (first parameter: const AppHost*)", shop);

        // Include paths are relative to the header's location.
        if (!File.Exists(ClangPlusPlus)) return;
        foreach (var type in new[] { "Account", "PremiumAccount" })
        {
            var header = Write($"src/bindings/{type}.h", Generate(type, CppBindingGenerator.ChooseStyle(null, project, $"src/bindings/{type}.h", null, default), inherited: true));
            // Account's getters, inherited.
            if (type == "PremiumAccount") Assert.Contains("GetMethodInHierarchy", File.ReadAllText(header));
            var cpp = Write($"src/bindings/{type}.cpp", $"#include \"{type}.h\"\nint main() {{ tools::mem::{type}Binding b; return b.Resolved() ? 0 : 1; }}\n");
            var (exit, output) = Tools.Run(ClangPlusPlus, $"-std=c++17 -fsyntax-only -Wall -Werror \"{cpp}\"");
            Assert.True(exit == 0, output);
        }
    }

    [Fact]
    public void Value_types_use_unboxed_offsets_and_size_when_the_table_has_them()
    {
        var project = HostTableProject();
        // Without the optional members: boxed offsets.
        var plain = Generate("Vec2", CppBindingGenerator.ChooseStyle(null, project, "src/bindings/Vec2.h", null, default));
        Assert.Contains("m_xOff = h->FieldOffset(klass, \"X\");", plain);
        Assert.Contains("instance offsets include the object header", plain);
        Assert.DoesNotContain("GetValueTypeSize", plain);

        // With EmbeddedStructOffset and GetValueTypeSize: unboxed offsets.
        var abi = Path.Combine(project, "host", "abi.h");
        File.WriteAllText(abi, File.ReadAllText(abi).Replace(
            "    void*    (*Invoke)(MethRef method, void* instance, void** args, int argc);",
            "    void*    (*Invoke)(MethRef method, void* instance, void** args, int argc);\n" +
            "    int32_t  (*EmbeddedStructOffset)(KlassRef klass, const char* field);\n" +
            "    int32_t  (*GetValueTypeSize)(KlassRef klass);"));
        var target = CppBindingGenerator.ChooseStyle(null, project, "src/bindings/Vec2.h", null, default);
        Assert.True(target.Project!.Has("EmbeddedStructOffset"));
        var code = Generate("Vec2", target);
        Assert.Contains("m_xOff = h->EmbeddedStructOffset(klass, \"X\");", code);
        Assert.Contains("m_size = h->GetValueTypeSize(klass);", code);
        Assert.Contains("int32_t Size() const { return m_size; }", code);
        Assert.Contains("instance offsets are into the unboxed data", code);
        Assert.Contains("m_balanceOff = h->FieldOffset(klass, \"_balance\");", Generate("Account", target));
        Assert.DoesNotContain("GetValueTypeSize", Generate("Account", target));

        if (!File.Exists(ClangPlusPlus)) return;
        var header = Write("src/bindings/Vec2.h", code);
        var cpp = Write("src/bindings/Vec2.cpp", "#include \"Vec2.h\"\nint main() { tools::mem::Vec2Binding b; return b.Resolved() && b.Size() == 8 ? 0 : 1; }\n");
        var (exit, output) = Tools.Run(ClangPlusPlus, $"-std=c++17 -fsyntax-only -Wall -Werror \"{cpp}\"");
        Assert.True(exit == 0, output + "\n" + File.ReadAllText(header));
    }

    [Fact]
    public void Plain_project_falls_back_to_Mono()
    {
        Write("include/util.h", "#pragma once\nstruct Partial { void* (*FindClass)(const char*, const char*, const char*); int (*FieldOffset)(void*, const char*); };\n");
        Write("src/app.cpp", "int main() { return 0; }\n");
        var target = CppBindingGenerator.ChooseStyle(null, _dir.Path, null, null, default);
        Assert.Equal("mono", target.Style);
        Assert.Null(target.Project);
        var first = Generate("Account", target).Split('\n')[0];
        Assert.StartsWith("// Style mono: self-contained default; no struct with FindClass, GetMethod, FieldOffset, StaticFieldOffset, GetStaticFieldData, Invoke in ", first);
        Assert.StartsWith("// Style mono: self-contained default; no projectDir.", Generate("Account", CppBindingGenerator.ChooseStyle(null, null, null, null, default)));
    }

    [Fact]
    public void Explicit_style_beats_detection_detection_beats_server_default()
    {
        var project = HostTableProject();
        var mono = CppBindingGenerator.ChooseStyle("mono", project, null, null, default);
        Assert.Equal("mono", mono.Style);
        Assert.StartsWith("// Style mono: style=mono requested.", Generate("Account", mono));

        var serverMono = new ServerOptions { BindingStyle = "mono" };
        Assert.Equal("hostapi", CppBindingGenerator.ChooseStyle(null, project, null, serverMono, default).Style);

        var serverHost = new ServerOptions { BindingStyle = "hostapi" };
        var fromServer = CppBindingGenerator.ChooseStyle(null, null, null, serverHost, default);
        Assert.Equal("hostapi", fromServer.Style);
        var code = Generate("Account", fromServer);
        Assert.StartsWith("// Style hostapi: server default --binding-style hostapi; no projectDir.", code);
        Assert.Contains("// Include the header that defines HostApi and the helpers this code calls (ReadField, WriteField, CallValue) before this one.", code);
        Assert.DoesNotContain("#include", code);

        // --binding-project stands in for projectDir.
        var serverProject = new ServerOptions { BindingProject = project };
        Assert.Contains("--binding-project has a host table: AppHost", CppBindingGenerator.ChooseStyle(null, null, null, serverProject, default).Reason);
        Assert.Contains("#include \"host/abi.h\"", Generate("Account", CppBindingGenerator.ChooseStyle("hostapi", project, null, null, default)));

        Assert.Contains("Unknown style 'plugin'", Assert.Throws<ToolError>(() => CppBindingGenerator.ChooseStyle("plugin", null, null, null, default)).Message);
        Assert.Contains("--binding-style must be mono, aot or hostapi", Assert.Throws<ArgumentException>(() => ServerOptions.Parse(["--binding-style", "x"])).Message);
        Assert.Equal(("hostapi", "D:/p"), (ServerOptions.Parse(["--binding-style", "HostApi", "--binding-project", "D:/p"]) is var o ? (o.BindingStyle, o.BindingProject) : default));
    }
}
