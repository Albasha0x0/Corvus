using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Corvus.Core;

namespace Corvus.Tests;

/// <summary>Defects found by running the server against real applications, each reduced to a fixture.</summary>
public sealed class RealScenarioRegressionTests
{
    /// <summary>Regression: a .NET 10 app using a .NET Standard library left Roslyn without a core library ("Predefined type 'System.Void' is not defined").</summary>
    private static string NetAppUsingNetStandardLibrary(TempDir dir)
    {
        var token = new PublicKeyToken("b03f5f7f11d50a3a");
        var runtime = new AssemblyRefUser("System.Runtime", new Version(10, 0, 0, 0), token);
        var module = new ModuleDefUser("NetApp.dll", Guid.NewGuid(), runtime)
        {
            Kind = ModuleKind.Dll,
            RuntimeVersion = dnlib.DotNet.MD.MDHeaderRuntimeVersion.MS_CLR_40,
        };
        var assembly = new AssemblyDefUser("NetApp", new Version(1, 0, 0, 0));
        assembly.Modules.Add(module);
        var t = module.CorLibTypes;
        var tfa = new TypeRefUser(module, "System.Runtime.Versioning", "TargetFrameworkAttribute", runtime);
        assembly.CustomAttributes.Add(new CustomAttribute(new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(t.Void, t.String), tfa),
            [new CAArgument(t.String, ".NETCoreApp,Version=v10.0")]));

        var newtonsoft = new AssemblyRefUser("Newtonsoft.Json", new Version(13, 0, 0, 0), new PublicKeyToken("30ad4fe6b2a6aeed"));
        var serialize = new MemberRefUser(module, "SerializeObject", MethodSig.CreateStatic(t.String, t.Object),
            new TypeRefUser(module, "Newtonsoft.Json", "JsonConvert", newtonsoft));
        var program = new TypeDefUser("NetApp", "Program", t.Object.TypeDefOrRef)
        {
            Attributes = TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed | TypeAttributes.BeforeFieldInit,
        };
        module.Types.Add(program);
        var run = new MethodDefUser("Run", MethodSig.CreateStatic(t.String, t.Object), MethodImplAttributes.IL | MethodImplAttributes.Managed,
            MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.HideBySig);
        run.ParamDefs.Add(new ParamDefUser("value", 1));
        program.Methods.Add(run);
        run.Body = new CilBody();
        foreach (var i in new[] { OpCodes.Ldarg_0.ToInstruction(), OpCodes.Call.ToInstruction(serialize), OpCodes.Ret.ToInstruction() })
            run.Body.Instructions.Add(i);

        var path = dir.File("NetApp.dll");
        module.Write(path);
        File.Copy(RealPackages.Lib("newtonsoft.json", "13.0.4", "netstandard2.0", "Newtonsoft.Json.dll"), dir.File("Newtonsoft.Json.dll"));
        return path;
    }

    /// <summary>Regression: a constructor call into an unresolved assembly matched every other ".ctor()" (dnlib's SigComparer ignores the declaring type).</summary>
    [Fact]
    public void References_to_a_constructor_ignore_same_signature_calls_into_unresolved_assemblies()
    {
        using var dir = new TempDir();
        var app = new IlLab("RefApp");
        var model = app.NewType("RefApp", "ViewModel", beforeFieldInit: true);
        var ctor = new MethodDefUser(".ctor", MethodSig.CreateInstance(app.T.Void), MethodImplAttributes.IL | MethodImplAttributes.Managed,
            MethodAttributes.Public | MethodAttributes.HideBySig | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName);
        model.Methods.Add(ctor);
        ctor.Body = new CilBody();
        ctor.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
        ctor.Body.Instructions.Add(OpCodes.Call.ToInstruction(new MemberRefUser(app.Module, ".ctor", MethodSig.CreateInstance(app.T.Void), app.T.Object.TypeDefOrRef)));
        ctor.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        app.Method("Create", model.ToTypeSig(), OpCodes.Newobj.ToInstruction(ctor), OpCodes.Ret.ToInstruction());
        File.WriteAllBytes(dir.File("RefApp.dll"), app.Write());

        var lib = new IlLab("RefLib");
        var missing = new AssemblyRefUser("Not.Shipped.Anywhere", new Version(4, 2, 1, 0));
        var container = new MemberRefUser(lib.Module, ".ctor", MethodSig.CreateInstance(lib.T.Void), new TypeRefUser(lib.Module, "System.ComponentModel", "Container", missing));
        lib.Method("Make", lib.T.Object, OpCodes.Newobj.ToInstruction(container), OpCodes.Ret.ToInstruction());
        File.WriteAllBytes(dir.File("RefLib.dll"), lib.Write());

        using var env = new Env(dir.File("RefApp.dll"));
        env.Workspace.Load(dir.File("RefLib.dll"));
        var found = env.Workspace.Read(() => env.References.FindReferences(env.One("RefApp.ViewModel::.ctor"), includeVirtualCalls: false, limit: 50, default));
        Assert.Equal(["Lab.P::Create()"], found.Items.Select(r => Format.MemberLabel(r.Where)));

        // Framework names are not stubbed: those references stay unresolved and compare by name.
        Assert.False(Corvus.Core.MetadataUtil.IsSameMethod(container, ctor));
        var sameType = new MemberRefUser(lib.Module, ".ctor", MethodSig.CreateInstance(lib.T.Void),
            new TypeRefUser(lib.Module, "RefApp", "ViewModel", new AssemblyRefUser("RefApp")));
        Assert.True(Corvus.Core.MetadataUtil.IsSameMethod(sameType, ctor));
    }

    /// <summary>Regression: metadata the decompiler's reader rejects failed every decompile; it now works on a normalized copy with the same tokens.</summary>
    [Fact]
    public void Post_processed_metadata_is_decompiled_from_a_normalized_copy()
    {
        using var dir = new TempDir();
        var lab = new IlLab("Guarded");
        lab.Method("Answer", lab.T.Int32, IlLab.Ldc(42), IlLab.Ret());
        var image = lab.Write();
        using (var pe = new System.Reflection.PortableExecutable.PEReader(new MemoryStream(image.ToArray())))
        {
            var md = System.Reflection.Metadata.PEReaderExtensions.GetMetadataReader(pe);
            int moduleRow = pe.PEHeaders.MetadataStartOffset + System.Reflection.Metadata.Ecma335.MetadataReaderExtensions.GetTableMetadataOffset(md, System.Reflection.Metadata.Ecma335.TableIndex.Module);
            // Module row: Generation (2 bytes), then Name: a string offset far past the #Strings heap.
            image[moduleRow + 2] = 0xFF;
            image[moduleRow + 3] = 0xFF;
        }
        File.WriteAllBytes(dir.File("Guarded.dll"), image);
        using var env = new Env(dir.File("Guarded.dll"));
        var text = env.Decompile("Lab.P::Answer");
        Assert.Contains("return 42;", text);
        Assert.Contains("normalized by dnlib", text);
        var il = env.Workspace.Read(() => env.Decompiler.Disassemble(env.Fixture, (IMemberDef)env.One("Lab.P::Answer").Member, default));
        Assert.Contains("ldc.i4", il);
    }

    /// <summary>Zero-width and bidi characters in names show as \uXXXX and resolve as shown.</summary>
    [Fact]
    public void Invisible_characters_in_names_are_shown_escaped_and_resolve_as_shown()
    {
        using var dir = new TempDir();
        var lab = new IlLab("Hidden");
        var name = "‮​Run⁪";
        lab.Method(name, lab.T.Int32, IlLab.Ldc(7), IlLab.Ret());
        File.WriteAllBytes(dir.File("Hidden.dll"), lab.Write());
        using var env = new Env(dir.File("Hidden.dll"));

        var shown = Format.EscapeInvisible($"Lab.P::{name}");
        Assert.Equal("Lab.P::\\u202e\\u200bRun\\u206a", shown);
        Assert.Equal(name, ((MethodDef)env.One(shown).Member).Name.String);
        Assert.Equal($"Lab.P::{name}", Format.UnescapeInvisible(shown));
        Assert.Equal("a\\u0041", Format.UnescapeInvisible("a\\u0041")); // visible characters stay escaped
    }

    /// <summary>Regression: a public member using an internal type failed every C# patch of its type (CS0050-CS0061).</summary>
    [Trait("Speed", "Slow")]
    [Fact]
    public void CSharp_patches_compile_when_the_decompiled_type_has_inconsistent_accessibility()
    {
        using var dir = new TempDir();
        var lab = new IlLab("Access");
        var hidden = lab.NewType("Lab", "Step", beforeFieldInit: true);
        hidden.Attributes = (hidden.Attributes & ~TypeAttributes.VisibilityMask) | TypeAttributes.NotPublic | TypeAttributes.Interface | TypeAttributes.Abstract;
        hidden.BaseType = null;
        var holder = lab.NewType("Lab", "Holder", abstractSealed: true);
        holder.Fields.Add(new FieldDefUser("Current", new FieldSig(hidden.ToTypeSig()), FieldAttributes.Public | FieldAttributes.Static));
        lab.Method("Count", lab.T.Int32, [], [IlLab.Ldc(1), IlLab.Ret()], owner: holder);
        File.WriteAllBytes(dir.File("Access.dll"), lab.Write());
        using var env = new Env(dir.File("Access.dll"));
        var result = env.Edit(() => env.Edits.PatchMethodCSharp(env.One("Lab.Holder::Count"), "return Current == null ? 2 : 3;", dryRun: false, default));
        Assert.DoesNotContain("failed", result);
    }

    /// <summary>Regression: types renamed at every build of a transformed app were not paired; strings, constants and bodies without numeric constants now match them.</summary>
    private static byte[] TransformedBuild(int seed, string classType, string constType, string enumType, string[] methodNames)
    {
        var random = new Random(seed);
        var lab = new IlLab("Obf");
        lab.Module.Mvid = new Guid(seed, 0, 0, [1, 2, 3, 4, 5, 6, 7, 8]); // each build its own
        var worker = lab.NewType("", classType);
        string[] texts = ["https://api.example.test/v2/upload", "Upload failed: {0}", "settings.json corrupt", "retry-after", "X-Session-Token"];
        for (int i = 0; i < texts.Length; i++)
        {
            // Filler: ldc.i4 <random>; stloc; ldloc; pop — then the real work.
            var local = new Local(lab.T.Int32);
            var m = lab.Method(methodNames[i], lab.T.String, [], [IlLab.Ldc(random.Next()), OpCodes.Stloc.ToInstruction(local), OpCodes.Ldloc.ToInstruction(local),
                IlLab.Op(OpCodes.Pop), OpCodes.Ldstr.ToInstruction(texts[i]), IlLab.Ret()], owner: worker);
            m.Body.Variables.Add(local);
        }
        var consts = lab.NewType("", constType, abstractSealed: true);
        foreach (var (name, value) in new[] { ("y", "815BAF99-0C5D-4FA8-8CCD-1129EE6D25B9"), ("d", "Example Corp PDF Previewer"), ("i", "PEOfficeAddIn.Connect") })
            consts.Fields.Add(new FieldDefUser(name, new FieldSig(lab.T.String), FieldAttributes.Public | FieldAttributes.Static | FieldAttributes.Literal | FieldAttributes.HasDefault)
            { Constant = new ConstantUser(value) });
        var e = new TypeDefUser("", enumType, lab.Module.CorLibTypes.GetTypeRef("System", "Enum")) { Attributes = TypeAttributes.Public | TypeAttributes.Sealed };
        e.Fields.Add(new FieldDefUser("value__", new FieldSig(lab.T.Int32), FieldAttributes.Public | FieldAttributes.SpecialName | FieldAttributes.RTSpecialName));
        int n = 0;
        foreach (var member in new[] { "Word", "Excel", "PowerPoint", "Outlook", "Visio" })
            e.Fields.Add(new FieldDefUser(member, new FieldSig(new ValueTypeSig(e)), FieldAttributes.Public | FieldAttributes.Static | FieldAttributes.Literal | FieldAttributes.HasDefault)
            { Constant = new ConstantUser(n++) });
        lab.Module.Types.Add(e);
        return lab.Write();
    }

    [Fact]
    public void Renamed_types_of_a_transformed_rebuild_are_matched_by_content()
    {
        using var dir = new TempDir();
        File.WriteAllBytes(dir.File("Old.dll"), TransformedBuild(1, "c7x", "cwb", "c7u", ["y", "d", "i", "n", "s"]));
        File.WriteAllBytes(dir.File("New.dll"), TransformedBuild(2, "ak7", "akl", "ak4", ["i", "y", "d", "s", "n"]));
        using var env = new Env(dir.File("Old.dll"));
        var newBuild = env.Workspace.Load(dir.File("New.dll"));
        var comparer = new Corvus.Services.AssemblyComparer(env.Workspace);
        var comparison = env.Workspace.Read(() => comparer.Compare(env.Fixture, newBuild, default));

        string Counterpart(string symbol) => env.Workspace.Read(() =>
            comparer.FindCounterpart(comparison, (IMemberDef)SymbolResolver.ResolveOne(env.Workspace, env.Fixture.Id, symbol).Member).Match is { } m ? Format.MemberLabel(m) : "none");
        Assert.Equal("ak7", Counterpart("c7x"));
        Assert.Equal("akl", Counterpart("cwb"));
        Assert.Equal("ak4", Counterpart("c7u"));
        // Same body (but for the filler constant), new name: old y() returned the upload URL, which new i() returns.
        Assert.Equal("ak7::i()", Counterpart("c7x::y"));
        Assert.Equal("ak7::y()", Counterpart("c7x::d"));
    }

    /// <summary>Regression: after a stub, the decompiled closure class name did not parse as C# and failed every later patch of the class.</summary>
    [Fact]
    public void CSharp_patches_work_next_to_an_orphaned_closure_class()
    {
        using var dir = new TempDir();
        var lab = new IlLab("Closures");
        var holder = lab.NewType("Lab", "Holder");
        lab.Method("Run", lab.T.Int32, [], [IlLab.Ldc(1), IlLab.Ret()], owner: holder);
        lab.StaticField(holder, "Count", lab.T.Int32, readOnly: false);
        var closure = new TypeDefUser("", "<>c__DisplayClass0_0", lab.T.Object.TypeDefOrRef)
        {
            Attributes = TypeAttributes.NestedPrivate | TypeAttributes.Sealed | TypeAttributes.BeforeFieldInit,
        };
        holder.NestedTypes.Add(closure);
        // Without [CompilerGenerated] the decompiler always shows the class.
        var captured = new FieldDefUser("p", new FieldSig(lab.T.Int32), FieldAttributes.Public);
        closure.Fields.Add(captured);
        var lambda = lab.Method("<Run>b__0", lab.T.Int32, [], [OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ldfld.ToInstruction(captured), IlLab.Ret()], owner: closure);
        lambda.Attributes = MethodAttributes.Assembly | MethodAttributes.HideBySig;
        lambda.MethodSig.HasThis = true;
        File.WriteAllBytes(dir.File("Closures.dll"), lab.Write());

        using var env = new Env(dir.File("Closures.dll"));
        var holderType = (TypeDef)env.One("Lab.Holder").Member;
        int SyntaxErrors(bool compilable) => Microsoft.CodeAnalysis.CSharp.CSharpSyntaxTree
            .ParseText(env.Workspace.Read(() => env.Decompiler.DecompileType(env.Fixture, holderType, default, compilable)))
            .GetDiagnostics().Count(d => d.Severity == Microsoft.CodeAnalysis.DiagnosticSeverity.Error);
        Assert.NotEqual(0, SyntaxErrors(compilable: false)); // what the user reads: the names as they are
        Assert.Equal(0, SyntaxErrors(compilable: true)); // what the patcher compiles
        var result = env.Edit(() => env.Edits.PatchMethodCSharp(env.One("Lab.Holder::Run"), "return Count + 2;", dryRun: false, default));
        Assert.StartsWith("patch C#", result);
        Assert.Contains("return Count + 2;", env.Decompile("Lab.Holder::Run"));
    }

    /// <summary>Regression: decompiled members overriding or using the target's internals failed to compile (CS0115, CS0507, CS0051-CS0053).</summary>
    [Fact]
    public void CSharp_patches_compile_when_the_type_overrides_internals_of_its_assembly()
    {
        using var env = new Env(RealPackages.Lib("newtonsoft.json", "13.0.4", "netstandard2.0", "Newtonsoft.Json.dll"));
        var result = env.Edit(() => env.Edits.PatchMethodCSharp(env.One("Newtonsoft.Json.Linq.JTokenWriter::WriteValue(char)"),
            "base.WriteValue(value);", dryRun: true, default));
        Assert.Contains("compiled OK", result, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Regression: the stand-in of a missing strong-named dependency did not bind to the target's reference (CS0012).</summary>
    [Fact]
    public void CSharp_patches_bind_to_the_stand_in_of_a_strong_named_dependency()
    {
        using var dir = new TempDir();
        var options = new Microsoft.CodeAnalysis.CSharp.CSharpCompilationOptions(Microsoft.CodeAnalysis.OutputKind.DynamicallyLinkedLibrary)
            .WithCryptoPublicKey([.. typeof(object).Assembly.GetName().GetPublicKey()!]).WithPublicSign(true);
        var lib = Roslyn.Compile("Lib", "namespace Lib { public class Node { public int Size; } }", options);
        File.WriteAllBytes(dir.File("App.dll"), ReferenceResolutionTests.Compile("App",
            "namespace App { public class Leaf : Lib.Node { } public class C { public int Run(Lib.Node n) { return n.Size; } } }", lib)); // Lib.dll is missing
        using var env = new Env(dir.File("App.dll"));
        var result = env.Edit(() => env.Edits.PatchMethodCSharp(env.One("App.C::Run"), "return new Leaf().Size + 1;", dryRun: true, default));
        Assert.Contains("compiled OK", result, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Regression: patches in the core library itself left Roslyn without a core library (CS0518).</summary>
    [Fact]
    public void CSharp_patches_compile_in_the_core_library()
    {
        using var dir = new TempDir();
        var core = Microsoft.CodeAnalysis.CSharp.CSharpCompilation.Create("MiniCore", [Microsoft.CodeAnalysis.CSharp.CSharpSyntaxTree.ParseText("""
            namespace System
            {
                public class Object { }
                public struct Void { }
                public struct Boolean { }
                public struct Byte { }
                public struct Char { }
                public struct Int32 { }
                public struct IntPtr { }
                public abstract class ValueType { }
                public abstract class Enum : ValueType { }
                public sealed class String { }
                public abstract class Array { }
                public class Attribute { }
                public class Exception { }
                public abstract class Delegate { }
                public abstract class MulticastDelegate : Delegate { }
                public struct Nullable<T> where T : struct { }
                public class Type { }
                public struct RuntimeTypeHandle { }
                public struct RuntimeFieldHandle { }
                public struct RuntimeMethodHandle { }
                public enum AttributeTargets { All = 32767 }
                public sealed class AttributeUsageAttribute : Attribute
                {
                    public AttributeUsageAttribute(AttributeTargets validOn) { }
                    public bool AllowMultiple { get; set; }
                    public bool Inherited { get; set; }
                }
                public static class Probe { public static bool IsEmpty(string s) { return s == null; } }
            }
            namespace System.Runtime.CompilerServices { public sealed class InternalsVisibleToAttribute : Attribute { public InternalsVisibleToAttribute(string assemblyName) { } } }
            """)], [], new Microsoft.CodeAnalysis.CSharp.CSharpCompilationOptions(Microsoft.CodeAnalysis.OutputKind.DynamicallyLinkedLibrary));
        using (var file = File.Create(dir.File("MiniCore.dll")))
            Assert.True(core.Emit(file).Success);
        using var env = new Env(dir.File("MiniCore.dll"));
        var result = env.Edit(() => env.Edits.PatchMethodCSharp(env.One("System.Probe::IsEmpty"), "return false;", dryRun: true, default));
        Assert.Contains("compiled OK", result, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Regression: System.Private.CoreLib and the System.Memory package both defined the span types (CS0433).</summary>
    [Trait("Speed", "Slow")]
    [Fact]
    public void CSharp_patches_of_a_NET_Standard_library_compile_against_one_copy_of_the_span_types()
    {
        using var env = new Env(RealPackages.Lib("system.text.json", "10.0.1", "netstandard2.0", "System.Text.Json.dll"));
        var result = env.Edit(() => env.Edits.PatchMethodCSharp(env.One("System.Text.Json.JsonDocument::Dispose"),
            "var span = MemoryExtensions.AsSpan(new byte[2]); span[0] = 1;", dryRun: true, default));
        Assert.Contains("compiled OK", result, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Regression: a reference to a core library of any version (65535.65535.65535.65535) failed every patch with CS1705.</summary>
    [Fact]
    public void CSharp_patches_compile_against_a_reference_naming_the_core_library_with_any_version()
    {
        using var dir = new TempDir();
        var lib = ReferenceResolutionTests.Compile("Lib", "namespace L { public class Marker { public int V() { return 1; } } }");
        using (var module = dnlib.DotNet.ModuleDefMD.Load(lib))
        {
            foreach (var r in module.GetAssemblyRefs()) r.Version = new Version(65535, 65535, 65535, 65535);
            module.Write(dir.File("Lib.dll"));
        }
        File.WriteAllBytes(dir.File("App.dll"), ReferenceResolutionTests.Compile("App", "namespace App { public class C { public int Run(L.Marker m) { return 0; } } }", lib));
        using var env = new Env(dir.File("App.dll"));
        var result = env.Edit(() => env.Edits.PatchMethodCSharp(env.One("App.C::Run"), "return m.V();", dryRun: true, default));
        Assert.Contains("compiled OK", result, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Regression: await in catch of a .NET Standard 2.0 library decompiled as catch (object).</summary>
    [Fact, Trait("Speed", "Slow")] // decompiles System.Text.Json: past the call deadline on small CI runners
    public void Await_in_catch_of_a_NET_Standard_library_decompiles_as_catch_exception()
    {
        using var env = new Env(RealPackages.Lib("system.text.json", "10.0.1", "netstandard2.0", "System.Text.Json.dll"));
        var code = env.Decompile("System.Text.Json.Serialization.Metadata.JsonTypeInfo`1::SerializeAsync(PipeWriter, T, int, CancellationToken, object)");
        Assert.Contains("await state.DisposePendingDisposablesOnExceptionAsync()", code);
        Assert.DoesNotContain("catch (object", code);
    }

    /// <summary>Regression: an internal global Exception type of a reference took every catch (Exception) (CS0155).</summary>
    [Fact]
    public void CSharp_patches_bind_usings_before_internal_global_types_of_references()
    {
        using var dir = new TempDir();
        var lib = ReferenceResolutionTests.Compile("Lib", "internal class Exception { } public class Marker { }");
        File.WriteAllBytes(dir.File("Lib.dll"), lib);
        File.WriteAllBytes(dir.File("App.dll"), ReferenceResolutionTests.Compile("App", """
            using System;
            namespace App { public class C { public Marker M; public int Run() { return M == null ? 1 : 0; } } }
            """, lib));
        using var env = new Env(dir.File("App.dll"));
        var result = env.Edit(() => env.Edits.PatchMethodCSharp(env.One("App.C::Run"), "try { return 2; } catch (Exception e) { return e.Message.Length; }", dryRun: true, default));
        Assert.Contains("compiled OK", result, StringComparison.OrdinalIgnoreCase);

        // add_types_csharp: the user's own file-level usings bind the same way
        const string added = """
            using System;
            namespace App.Extra { public class D { public int Run() { try { return 2; } catch (Exception e) { return e.Message.Length; } } } }
            """;
        Assert.Contains("compiled OK", env.Edit(() => env.Edits.AddTypesCSharp(env.Fixture, added, dryRun: true, default)), StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Regression: same-named internal types of the target and a reference failed patches with CS0433; the type the target references wins.</summary>
    [Trait("Speed", "Slow")]
    [Fact]
    public void CSharp_patches_bind_same_named_internal_types_to_the_assembly_the_target_uses()
    {
        using var dir = new TempDir();
        var lib = ReferenceResolutionTests.Compile("Lib", "namespace System { internal static class SR { public static string Name = \"lib\"; } } public class Marker { }");
        var other = ReferenceResolutionTests.Compile("Other", "namespace Util { internal class Helper { } public class Help { public static string Name = \"other\"; } }");
        var util = ReferenceResolutionTests.Compile("Util", "namespace Util { public class Helper { public static int Id = 1; } } public class UtilMarker { }");
        File.WriteAllBytes(dir.File("Lib.dll"), lib);
        File.WriteAllBytes(dir.File("Other.dll"), other);
        File.WriteAllBytes(dir.File("Util.dll"), util);
        File.WriteAllBytes(dir.File("App.dll"), ReferenceResolutionTests.Compile("App", """
            namespace System { internal static class SR { public static string Name = "app"; } }
            namespace App { public class C { public Marker M; public string Run() { return System.SR.Name + Util.Help.Name + Util.Helper.Id; } } }
            """, lib, other, util));
        using var env = new Env(dir.File("App.dll"));
        env.Edit(() => env.Edits.PatchMethodCSharp(env.One("App.C::Run"), "return System.SR.Name + Util.Helper.Id + \"!\";", dryRun: false, default));
        var fields = env.Def<MethodDef>("App.C::Run").Body.Instructions.Select(i => i.Operand).OfType<IField>().ToList();
        Assert.IsAssignableFrom<TypeDef>(fields.Single(f => f.Name == "Name").DeclaringType); // the target's own SR
        Assert.Equal("Util", ((AssemblyRef)((TypeRef)fields.Single(f => f.Name == "Id").DeclaringType).ResolutionScope).Name.String); // the Helper App uses
    }

    /// <summary>Regression: a library's own Func&lt;T, TResult&gt; was ambiguous with System.Func (CS0104); the target's type wins.</summary>
    [Trait("Speed", "Slow")]
    [Fact]
    public void CSharp_patches_prefer_the_targets_own_type_over_a_newer_framework_type_of_the_same_name()
    {
        using var env = new Env(RealPackages.Lib("Newtonsoft.Json", "13.0.1", "net20", "Newtonsoft.Json.dll"));
        Assert.Contains("compiled OK", env.Edit(() => env.Edits.PatchMethodCSharp(env.One("Newtonsoft.Json.Utilities.ThreadSafeStore`2::Get"),
            "return _creator(key);", dryRun: true, default)));
    }

    /// <summary>Regression: interfaces returning the target's own type failed every patch of the type (CS0738).</summary>
    [Trait("Speed", "Slow")]
    [Fact]
    public void CSharp_patches_compile_in_a_type_whose_interfaces_return_the_type()
    {
        using var env = new Env(RealPackages.Lib("System.Collections.Immutable", "1.3.1", "netstandard1.0", "System.Collections.Immutable.dll"));
        Assert.Contains("compiled OK", env.Edit(() => env.Edits.PatchMethodCSharp(env.One("System.Collections.Immutable.ImmutableList`1/Node::CopyTo(int, T[], int, int)"),
            "throw new System.InvalidOperationException();", dryRun: true, default)));
    }

    /// <summary>Regression: decimal overloads did not match because labels spell the type Decimal.</summary>
    [Trait("Speed", "Slow")]
    [Fact]
    public void CSharp_patches_find_decimal_overloads()
    {
        using var env = new Env(RealPackages.Lib("Newtonsoft.Json", "13.0.1", "netstandard2.0", "Newtonsoft.Json.dll"));
        Assert.Contains("compiled OK", env.Edit(() => env.Edits.PatchMethodCSharp(env.One("Newtonsoft.Json.JsonConvert::ToString(decimal)"), "return \"d\";", dryRun: true, default)));
    }

    /// <summary>Regression: an internal type of two references was ambiguous with the target's type of the same name in an enclosing namespace.</summary>
    [Trait("Speed", "Slow")]
    [Fact]
    public void CSharp_patches_bind_types_of_enclosing_namespaces_before_imported_ones()
    {
        using var dir = new TempDir();
        var lib = ReferenceResolutionTests.Compile("Lib", "namespace System { internal static class SR { public static string Name = \"lib\"; } } public class Marker { }");
        var other = ReferenceResolutionTests.Compile("Other", "namespace System { internal static class SR { public static string Name = \"other\"; } } public class OtherMarker { }");
        File.WriteAllBytes(dir.File("Lib.dll"), lib);
        File.WriteAllBytes(dir.File("Other.dll"), other);
        File.WriteAllBytes(dir.File("App.dll"), ReferenceResolutionTests.Compile("App", """
            namespace App { internal static class SR { public static string Name = "app"; } }
            namespace App.Sub { public class C { public Marker M; public OtherMarker O; public string Run() { return SR.Name; } } }
            """, lib, other));
        using var env = new Env(dir.File("App.dll"));
        foreach (var code in new[] { "return SR.Name + \"!\";", "string s = SR.Name; System.Func<string> f = () => s + SR.Name; return f();" })
        {
            env.Edit(() => env.Edits.PatchMethodCSharp(env.One("App.Sub.C::Run"), code, dryRun: false, default));
            var field = env.Def<MethodDef>("App.Sub.C::Run").Body.Instructions.Select(i => i.Operand).OfType<IField>().First(f => f.Name == "Name");
            Assert.Equal("App.SR", Assert.IsAssignableFrom<TypeDef>(field.DeclaringType).FullName);
        }
    }

    /// <summary>Regression: an attribute or public framework type the target defines again kept failing with CS0433.</summary>
    [Trait("Speed", "Slow")]
    [Fact]
    public void CSharp_patches_bind_attributes_and_redefined_framework_types_to_the_target()
    {
        using (var env = new Env(RealPackages.Lib("System.Collections.Immutable", "1.3.1", "netstandard1.0", "System.Collections.Immutable.dll")))
            Assert.Contains("compiled OK", env.Edit(() => env.Edits.PatchMethodCSharp(env.One("System.Collections.Immutable.ImmutableArray`1::IndexOf(T, int, int)"),
                "return -1;", dryRun: true, default)));
        using (var env = new Env(RealPackages.Lib("NUnit", "3.14.0", "net35", "nunit.framework.dll")))
            Assert.Contains("compiled OK", env.Edit(() => env.Edits.PatchMethodCSharp(env.One("NUnit.Framework.Constraints.Constraint::ToString()"),
                "return \"x\";", dryRun: true, default)));
    }

    /// <summary>Regression: decompiled types made public failed when an internal type exposed another internal type (CS0060, CS0053).</summary>
    [Trait("Speed", "Slow")]
    [Fact]
    public void CSharp_patches_compile_when_an_internal_type_uses_internal_types_of_its_assembly()
    {
        using var env = new Env(RealPackages.Lib("newtonsoft.json", "13.0.4", "netstandard2.0", "Newtonsoft.Json.dll"));
        const string member = "public static int Twice(int x) { return x * 2; }";
        Assert.Contains("compiled OK", env.Edit(() => env.Edits.AddMembersCSharp(env.One("Newtonsoft.Json.Linq.JsonPath.ScanFilter"), member, dryRun: true, default)));
        Assert.Contains("compiled OK", env.Edit(() => env.Edits.AddMembersCSharp(env.One("Newtonsoft.Json.Linq.JsonPath.JPath"), member, dryRun: true, default)));
    }

    /// <summary>Regression: member labels left out generic arity, so generic and non-generic overloads shared one label.</summary>
    [Fact]
    public void Generic_overloads_have_their_own_labels_in_diffs_and_replays()
    {
        using var dir = new TempDir();
        using var env = new Env(RealPackages.Lib("newtonsoft.json", "13.0.4", "netstandard2.0", "Newtonsoft.Json.dll"));
        const string plain = "Newtonsoft.Json.JsonConvert::DeserializeObject(string)", generic = "Newtonsoft.Json.JsonConvert::DeserializeObject<T>(string)";
        var plainSym = SymbolResolver.ResolveOne(env.Workspace, null, plain);
        var genericSym = SymbolResolver.ResolveOne(env.Workspace, null, generic);
        Assert.Equal((plain, generic), (plainSym.Label, genericSym.Label));
        Assert.Same(genericSym.Member, SymbolResolver.ResolveOne(env.Workspace, null, "Newtonsoft.Json.JsonConvert::DeserializeObject``1(string)").Member);

        env.Edit(() => env.Edits.StubMethod(plainSym, "null"));
        env.Edit(() => env.Edits.Rename(genericSym, "DeserializeAs"));
        var diff = env.Workspace.Read(() => env.History.Diff(env.Fixture, null, default));
        Assert.DoesNotContain("could not resolve", diff);
        Assert.Contains("current " + plain, diff);
        Assert.Contains("current Newtonsoft.Json.JsonConvert::DeserializeAs<T>(string)", diff);

        var script = dir.File("edits.json");
        env.Workspace.Read(() => env.History.Export(env.Fixture, script));
        using (var alone = new Env(RealPackages.Lib("newtonsoft.json", "13.0.1", "netstandard2.0", "Newtonsoft.Json.dll")))
        {
            var report = alone.Edit(() => alone.History.Apply(script, null, dryRun: false, stopOnError: true, default, Corvus.Services.EditHistoryService.TargetBuild.Other));
            Assert.Contains("2 applied, 0 failed", report);
            Assert.DoesNotContain("target renamed", report);
            Assert.Single(SymbolResolver.Resolve(alone.Workspace, null, "Newtonsoft.Json.JsonConvert::DeserializeAs<T>(string)"));
        }

        // A script from before arity labels: the bare label is resolved through the source build's recorded token.
        var legacy = dir.File("legacy.json");
        var json = System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllText(script))!.AsObject();
        foreach (var arg in json["edits"]!.AsArray().SelectMany(e => e!["args"]!.AsObject()).Where(a => a.Value?.ToString().Contains("<T>(") == true).ToList())
            arg.Value!.ReplaceWith(arg.Value.ToString().Replace("<T>(", "("));
        Assert.Contains("DeserializeObject(string)", json.ToJsonString());
        Assert.True(json.Remove("labels"));
        File.WriteAllText(legacy, json.ToJsonString());
        var other = env.Workspace.Load(RealPackages.Lib("newtonsoft.json", "13.0.1", "netstandard2.0", "Newtonsoft.Json.dll"));
        var replay = env.Edit(() => env.History.Apply(legacy, other.Id, dryRun: false, stopOnError: true, default, Corvus.Services.EditHistoryService.TargetBuild.Other));
        Assert.Contains("2 applied, 0 failed", replay);
        Assert.Single(SymbolResolver.Resolve(env.Workspace, other.Id, "Newtonsoft.Json.JsonConvert::DeserializeAs<T>(string)"));
    }

    /// <summary>Regression: a script from before arity labels failed as ambiguous; the recorded token picks the overload.</summary>
    [Fact]
    public void Legacy_edit_scripts_pick_between_overloads_of_one_label_by_the_recorded_token()
    {
        using var dir = new TempDir();
        static string Source(int version) => "namespace L { public static class C { public static object Read(string s) { return s; } " +
                                             "public static T Read<T>(string s) { return default(T); } public static int Version() { return " + version + "; } } }";
        File.WriteAllBytes(dir.File("Old.dll"), ReferenceResolutionTests.Compile("L", Source(1)));
        Directory.CreateDirectory(dir.File("new"));
        File.WriteAllBytes(dir.File("new/L.dll"), ReferenceResolutionTests.Compile("L", Source(2)));
        var script = dir.File("edits.json");
        using (var env = new Env(dir.File("Old.dll")))
        {
            env.Edit(() => env.Edits.StubMethod(env.One("L.C::Read(string)"), "null"));
            env.Edit(() => env.Edits.Rename(env.One("L.C::Read<T>(string)"), "ReadAs"));
            env.Workspace.Read(() => env.History.Export(env.Fixture, script));
        }
        var json = System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllText(script))!.AsObject();
        foreach (var arg in json["edits"]!.AsArray().SelectMany(e => e!["args"]!.AsObject()).Where(a => a.Value?.ToString().Contains("<T>(") == true).ToList())
            arg.Value!.ReplaceWith(arg.Value.ToString().Replace("<T>(", "("));
        Assert.True(json.Remove("labels"));
        File.WriteAllText(script, json.ToJsonString());

        using var other = new Env(dir.File("new/L.dll"));
        var replay = other.Edit(() => other.History.Apply(script, null, dryRun: false, stopOnError: true, default, Corvus.Services.EditHistoryService.TargetBuild.Other));
        Assert.Contains("2 applied, 0 failed", replay);
        Assert.Single(SymbolResolver.Resolve(other.Workspace, null, "L.C::ReadAs<T>(string)"));
        Assert.Contains("return null;", other.Decompile("L.C::Read(string)"));
    }

    /// <summary>Regression: on a build with other tokens a legacy label failed as ambiguous; the recorded signature picks the overload.</summary>
    [Fact]
    public void Legacy_edit_scripts_on_a_build_with_other_tokens_pick_overloads_by_the_recorded_signature()
    {
        using var dir = new TempDir();
        static string Source(string extra) => "namespace L { public static class C { " + extra + "public static object Read(string s) { return s; } " +
                                              "public static T Read<T>(string s) { return default(T); } } }";
        File.WriteAllBytes(dir.File("Old.dll"), ReferenceResolutionTests.Compile("L", Source("")));
        Directory.CreateDirectory(dir.File("new"));
        File.WriteAllBytes(dir.File("new/L.dll"), ReferenceResolutionTests.Compile("L", Source("public static int A() { return 1; } public static int B() { return 2; } ")));
        var script = dir.File("edits.json");
        using (var env = new Env(dir.File("Old.dll")))
        {
            env.Edit(() => env.Edits.StubMethod(env.One("L.C::Read<T>(string)"), "default"));
            env.Edit(() => env.Edits.StubMethod(env.One("L.C::Read(string)"), "null"));
            env.Workspace.Read(() => env.History.Export(env.Fixture, script));
        }
        var json = System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllText(script))!.AsObject();
        Assert.Contains("\"methodSignature\":\"0:System.Object(System.String)\"", json.ToJsonString());
        foreach (var arg in json["edits"]!.AsArray().SelectMany(e => e!["args"]!.AsObject()).Where(a => a.Value?.ToString().Contains("<T>(") == true).ToList())
            arg.Value!.ReplaceWith(arg.Value.ToString().Replace("<T>(", "("));
        Assert.True(json.Remove("labels"));
        File.WriteAllText(script, json.ToJsonString());

        using (var other = new Env(dir.File("new/L.dll")))
        {
            var replay = other.Edit(() => other.History.Apply(script, null, dryRun: false, stopOnError: true, default, Corvus.Services.EditHistoryService.TargetBuild.Other));
            Assert.Contains("2 applied, 0 failed", replay);
            Assert.Contains("return null;", other.Decompile("L.C::Read(string)"));
        }

        foreach (var args in json["edits"]!.AsArray().Select(e => e!["args"]!.AsObject()))
            args.Remove("methodSignature");
        File.WriteAllText(script, json.ToJsonString());
        using (var other = new Env(dir.File("new/L.dll")))
        {
            var replay = other.Edit(() => other.History.Apply(script, null, dryRun: true, stopOnError: false, default, Corvus.Services.EditHistoryService.TargetBuild.Other));
            Assert.Contains("0 would apply, 2 would fail", replay);
            Assert.Contains("predates generic arity in labels and recorded no signature", replay);
        }
    }

    /// <summary>Regression: apply_edits matched targets against the edited source build, so a replay onto a transformed rebuild failed.</summary>
    [Fact]
    public void Edits_replay_onto_a_transformed_rebuild_after_the_script_edited_its_source_build()
    {
        using var dir = new TempDir();
        File.WriteAllBytes(dir.File("Old.dll"), TransformedBuild(1, "c7x", "cwb", "c7u", ["y", "d", "i", "n", "s"]));
        File.WriteAllBytes(dir.File("New.dll"), TransformedBuild(2, "ak7", "akl", "ak4", ["i", "y", "d", "s", "n"]));
        using var env = new Env(dir.File("Old.dll"));
        var newBuild = env.Workspace.Load(dir.File("New.dll"));
        env.Edit(() => env.Edits.StubMethod(SymbolResolver.ResolveOne(env.Workspace, env.Fixture.Id, "c7x::y"), "\"stubbed\""));
        env.Edit(() => env.Edits.Rename(SymbolResolver.ResolveOne(env.Workspace, env.Fixture.Id, "c7x"), "Uploader"));
        var script = dir.File("edits.json");
        env.Workspace.Read(() => env.History.Export(env.Fixture, script));

        var result = env.Edit(() => env.History.Apply(script, newBuild.Id, dryRun: false, stopOnError: true, default, Corvus.Services.EditHistoryService.TargetBuild.Other));
        Assert.Contains("2 applied, 0 failed", result);
        Assert.Contains("ak7::i()", result); // y() is called i() in the new build
        Assert.Contains("\"stubbed\"", env.Workspace.Read(() => env.Decompiler.DecompileMembers(newBuild, [(IMemberDef)SymbolResolver.ResolveOne(env.Workspace, newBuild.Id, "Uploader::i").Member], default)));
    }

    /// <summary>Regression: saving an edited signed assembly dropped its signatures without a word.</summary>
    [Fact]
    public void Saving_an_edited_signed_assembly_says_what_happens_to_its_signatures()
    {
        var path = RealPackages.Lib("newtonsoft.json", "13.0.4", "netstandard2.0", "Newtonsoft.Json.dll");
        using var dir = new TempDir();
        using var env = new Env(path);
        env.Edit(() => env.Edits.StubMethod(env.One("Newtonsoft.Json.JsonConvert::ToString(bool)"), "\"x\""));
        var result = env.Workspace.Read(() => env.Edits.Save(env.Fixture, dir.File("Newtonsoft.Json.dll"), overwrite: false));
        Assert.Contains("strong-name signature no longer matches", result);
        using var pe = new System.Reflection.PortableExecutable.PEReader(File.OpenRead(path));
        Assert.Equal(pe.PEHeaders.PEHeader!.CertificateTableDirectory.Size > 0, result.Contains("Authenticode-signed"));

        using var clean = new Env(path);
        Assert.DoesNotContain("Signatures:", clean.Workspace.Read(() => clean.Edits.Save(clean.Fixture, dir.File("Unedited.dll"), overwrite: false)));
    }

    [Fact]
    public void Static_constructor_declaration_says_static_once()
    {
        var lab = new IlLab("Ctors");
        var cctor = lab.StaticConstructor(lab.Type, IlLab.Ret());
        Assert.Equal("private static P()", Format.Method(cctor));
        Assert.Equal("static P()", Format.Method(cctor, withModifiers: false));
    }

    [Trait("Speed", "Slow")]
    [Fact]
    public async Task Missing_required_argument_is_a_clear_tool_error()
    {
        await using var client = await McpProtocolTests.StartServerAsync("--load", Env.FixturePath);
        var result = await client.CallToolAsync("decompile_member", new Dictionary<string, object?>());
        // The first block is the readable error; the second repeats it as JSON.
        var text = result.Content.OfType<ModelContextProtocol.Protocol.TextContentBlock>().First().Text;
        Assert.True(result.IsError);
        Assert.StartsWith("Error (invalid_argument) in decompile_member: missing required parameter 'member'.\nNext: pass member: a string; `corvus describe decompile_member`", text);
        Assert.Equal("member", McpProtocolTests.ErrorJson(result).GetProperty("details").GetProperty("parameter").GetString());
    }

    [Fact]
    public void A_directory_passed_for_a_file_gets_an_explaining_error()
    {
        using var dir = new TempDir();
        using var env = new Env();
        var inspection = new Corvus.Services.Analysis.InspectionService(env.Workspace);
        var error = Assert.Throws<ToolError>(() => inspection.SurveyFeatures(null, dir.Path, null, default)).Message;
        Assert.Contains("is a directory", error);
        // summarize_file reads a folder as a source folder and still names the tool for its assemblies.
        Assert.Contains(inspection.Summarize(null, dir.Path, default).Highlights, h => h.Contains("list_assemblies with path", StringComparison.Ordinal));
    }

    [Trait("Speed", "Slow")]
    [Fact]
    public void CSharp_patches_compile_for_a_net_app_that_uses_a_NET_Standard_library()
    {
        using var dir = new TempDir();
        using var env = new Env(NetAppUsingNetStandardLibrary(dir));
        var added = env.Edit(() => env.Edits.AddTypesCSharp(env.Fixture,
            "namespace Probe { public static class Added { public static string Hello() => \"hi\"; } }", dryRun: true, default));
        Assert.Contains("compiled OK", added, StringComparison.OrdinalIgnoreCase);
        var patched = env.Edit(() => env.Edits.PatchMethodCSharp(env.One("NetApp.Program::Run"),
            "return Newtonsoft.Json.JsonConvert.SerializeObject(value) + \"!\";", dryRun: false, default));
        Assert.StartsWith("patch C#", patched);
        Assert.Contains("JsonConvert.SerializeObject(value) + \"!\"", env.Decompile("NetApp.Program::Run"));
        var members = env.Edit(() => env.Edits.AddMembersCSharp(env.One("NetApp.Program"), "public static int Twice(int x) { return x * 2; }", dryRun: false, default));
        Assert.DoesNotContain("failed", members);
    }
}
