using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Corvus.Core;

namespace Corvus.Tests;

/// <summary>Defects found by running the server against real applications, each reduced to a fixture.</summary>
public sealed class RealScenarioRegressionTests
{
    /// <summary>
    /// A .NET 10 application that uses a .NET Standard library (Newtonsoft.Json netstandard2.0), as most real apps do.
    /// netstandard resolves to the .NET Standard reference assembly, which defines System.Object itself next to the
    /// runtime's System.Private.CoreLib: Roslyn then had no core library ("Predefined type 'System.Void' is not defined").
    /// </summary>
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

    /// <summary>
    /// find_references: a call to a constructor in an assembly that is not loaded or resolvable (a framework assembly
    /// of a single-file app, say) matched every other ".ctor()": dnlib's SigComparer ignores the declaring type unless
    /// asked. Found in a WinForms + WebView2 app, where WebView2's "new Container()" was listed as creating a view model.
    /// </summary>
    [Fact]
    public void ReferencesToAConstructorIgnoreSameSignatureCallsIntoUnresolvedAssemblies()
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

        // The workspace stubs unknown assemblies, but not framework names (System.ComponentModel.TypeConverter in the
        // app above): those references stay unresolved and are compared by name. Outside a workspace nothing resolves.
        Assert.False(Corvus.Core.MetadataUtil.IsSameMethod(container, ctor));
        var sameType = new MemberRefUser(lib.Module, ".ctor", MethodSig.CreateInstance(lib.T.Void),
            new TypeRefUser(lib.Module, "RefApp", "ViewModel", new AssemblyRefUser("RefApp")));
        Assert.True(Corvus.Core.MetadataUtil.IsSameMethod(sameType, ctor));
    }

    /// <summary>
    /// An assembly processed by a toolchain (Babel / Goliath here) with metadata the decompiler's reader rejects: the module name's
    /// string offset past the heap, and a custom attribute whose constructor coded index is invalid. dnlib reads both
    /// leniently. Every decompile and get_il failed with an internal BadImageFormatException; the decompiler now works
    /// on a normalized copy with the same tokens, and says so.
    /// </summary>
    [Fact]
    public void PostProcessedMetadataIsDecompiledFromANormalizedCopy()
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

    /// <summary>
    /// Code transformers name members with zero-width and bidi characters (U+202E reverses the rest of the line). Tool output
    /// shows them as \uXXXX, the way the decompiler escapes identifiers, and the resolver accepts the name as shown.
    /// </summary>
    [Fact]
    public void InvisibleCharactersInNamesAreShownEscapedAndResolveAsShown()
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

    /// <summary>
    /// IL allows a public member to use an internal type; C# rejects the decompiled declaration with CS0050-CS0061, which
    /// failed every C# patch of such a type (found in Docker Desktop's installer).
    /// </summary>
    [Trait("Speed", "Slow")]
    [Fact]
    public void CSharpPatchesCompileWhenTheDecompiledTypeHasInconsistentAccessibility()
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

    /// <summary>
    /// Two builds of a transformed app (Dotfuscator in PDFelement's Office add-in): every type is renamed at each build,
    /// member names are handed out afresh, and control-flow transformation plants random integer constants in every body.
    /// compare_assemblies paired none of the renamed types, so find_counterpart and apply_edits could not carry anything
    /// across. Strings, constants and bodies without their numeric constants still identify them.
    /// </summary>
    private static byte[] TransformedBuild(int seed, string classType, string constType, string enumType, string[] methodNames)
    {
        var random = new Random(seed);
        var lab = new IlLab("Obf");
        lab.Module.Mvid = new Guid(seed, 0, 0, [1, 2, 3, 4, 5, 6, 7, 8]); // each build its own
        var worker = lab.NewType("", classType);
        string[] texts = ["https://api.example.test/v2/upload", "Upload failed: {0}", "settings.json corrupt", "retry-after", "X-Session-Token"];
        for (int i = 0; i < texts.Length; i++)
        {
            // filler: ldc.i4 <random>; stloc; ldloc; pop — then the real work
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
    public void RenamedTypesOfATransformedRebuildAreMatchedByContent()
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

    /// <summary>
    /// After an async method was stubbed, the decompiler showed its closure class (&lt;&gt;c__DisplayClass45_0) as a nested
    /// type, whose names do not parse as C#: every later C# patch of the class failed (Docker Desktop's installer). The
    /// patcher's source escapes such names.
    /// </summary>
    [Fact]
    public void CSharpPatchesWorkNextToAnOrphanedClosureClass()
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
        // Without [CompilerGenerated] the decompiler always shows it, as it does when it falls back to decompiling a
        // type member by member.
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

    /// <summary>
    /// The decompiled declaration is compiled as a separate assembly that references the target, so its members that
    /// override or use the target's internals failed: "internal override" (CS0115) and "protected internal override"
    /// (CS0507) of base members in the target, internal members using its internal types (CS0051-CS0053). Found in
    /// Newtonsoft.Json, CoseSignTool and PowerShell; the reference copy of the target now grants the patch assembly access
    /// to its internals.
    /// </summary>
    [Fact]
    public void CSharpPatchesCompileWhenTheTypeOverridesInternalsOfItsAssembly()
    {
        using var env = new Env(RealPackages.Lib("newtonsoft.json", "13.0.4", "netstandard2.0", "Newtonsoft.Json.dll"));
        var result = env.Edit(() => env.Edits.PatchMethodCSharp(env.One("Newtonsoft.Json.Linq.JTokenWriter::WriteValue(char)"),
            "base.WriteValue(value);", dryRun: true, default));
        Assert.Contains("compiled OK", result, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// A missing strong-named dependency is replaced by a stand-in without a public key, which the target's reference
    /// (name, version and token) did not bind to: C# patches using its types failed with CS0012 (Microsoft.CodeAnalysis.CSharp).
    /// </summary>
    [Fact]
    public void CSharpPatchesBindToTheStandInOfAStrongNamedDependency()
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

    /// <summary>
    /// The reference copy of the target got [InternalsVisibleTo] through an assembly reference to the core library; for
    /// the core library itself (System.Private.CoreLib, a Unity mscorlib) that left Roslyn without one (CS0518).
    /// </summary>
    [Fact]
    public void CSharpPatchesCompileInTheCoreLibrary()
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

    /// <summary>
    /// A netstandard library's closure has the runtime's System.Private.CoreLib (through a framework dependency) and the
    /// System.Memory package, which define the same types: every C# patch using spans failed with CS0433 (System.Text.Json).
    /// </summary>
    [Fact]
    public void CSharpPatchesOfANetStandardLibraryCompileAgainstOneCopyOfTheSpanTypes()
    {
        using var env = new Env(RealPackages.Lib("system.text.json", "10.0.1", "netstandard2.0", "System.Text.Json.dll"));
        var result = env.Edit(() => env.Edits.PatchMethodCSharp(env.One("System.Text.Json.JsonDocument::Dispose"),
            "var span = MemoryExtensions.AsSpan(new byte[2]); span[0] = 1;", dryRun: true, default));
        Assert.Contains("compiled OK", result, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// A reference naming the core library as version 65535.65535.65535.65535 (any version) made every patch using its types
    /// fail CS1705: it seemed to need a newer core library than the one compiled against (an obfuscated .NET Framework app).
    /// </summary>
    [Fact]
    public void CSharpPatchesCompileAgainstAReferenceNamingTheCoreLibraryWithAnyVersion()
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

    /// <summary>
    /// A .NET Standard 2.0 library's System.Runtime.InteropServices bound to the runtime facade, which put System.Private.CoreLib
    /// beside netstandard: the engine looked ExceptionDispatchInfo up there, so await in catch showed as catch (object) (System.Text.Json).
    /// </summary>
    [Fact]
    public void AwaitInCatchOfANetStandardLibraryDecompilesAsCatchException()
    {
        using var env = new Env(RealPackages.Lib("system.text.json", "10.0.1", "netstandard2.0", "System.Text.Json.dll"));
        var code = env.Decompile("System.Text.Json.Serialization.Metadata.JsonTypeInfo`1::SerializeAsync(PipeWriter, T, int, CancellationToken, object)");
        Assert.Contains("await state.DisposePendingDisposablesOnExceptionAsync()", code);
        Assert.DoesNotContain("catch (object", code);
    }

    /// <summary>
    /// References are imported with their internals, and a global-namespace type bound before the decompiled file's
    /// usings: an internal global 'Exception' in a .NET Framework assembly took every 'catch (Exception)' (CS0155; Greenshot).
    /// </summary>
    [Fact]
    public void CSharpPatchesBindUsingsBeforeInternalGlobalTypesOfReferences()
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

    /// <summary>
    /// References are imported with their internals, so an internal type of the target and a same-named internal type of
    /// another reference (System.SR in Microsoft.VisualBasic.Core and Microsoft.Win32.Registry) failed every C# patch
    /// using it with CS0433. Between two other references, the one the target references by that name wins.
    /// </summary>
    [Trait("Speed", "Slow")]
    [Fact]
    public void CSharpPatchesBindSameNamedInternalTypesToTheAssemblyTheTargetUses()
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

    /// <summary>
    /// A .NET 2.0 library with its own Func&lt;T, TResult&gt; compiled against mscorlib 4 made every patch of a type using it fail
    /// with CS0104 (ambiguous with System.Func); the target's own type is the one its code meant.
    /// </summary>
    [Trait("Speed", "Slow")]
    [Fact]
    public void CSharpPatchesPreferTheTargetsOwnTypeOverANewerFrameworkTypeOfTheSameName()
    {
        using var env = new Env(RealPackages.Lib("Newtonsoft.Json", "13.0.1", "net20", "Newtonsoft.Json.dll"));
        Assert.Contains("compiled OK", env.Edit(() => env.Edits.PatchMethodCSharp(env.One("Newtonsoft.Json.Utilities.ThreadSafeStore`2::Get"),
            "return _creator(key);", dryRun: true, default)));
    }

    /// <summary>
    /// ImmutableList&lt;T&gt;'s interfaces (from the target) return the target's ImmutableList&lt;T&gt;, which its decompiled copy
    /// cannot (CS0738): every patch in the type failed. The copy is compiled without those interfaces and their explicit stubs.
    /// </summary>
    [Trait("Speed", "Slow")]
    [Fact]
    public void CSharpPatchesCompileInATypeWhoseInterfacesReturnTheType()
    {
        using var env = new Env(RealPackages.Lib("System.Collections.Immutable", "1.3.1", "netstandard1.0", "System.Collections.Immutable.dll"));
        Assert.Contains("compiled OK", env.Edit(() => env.Edits.PatchMethodCSharp(env.One("System.Collections.Immutable.ImmutableList`1/Node::CopyTo(int, T[], int, int)"),
            "throw new System.InvalidOperationException();", dryRun: true, default)));
    }

    /// <summary>
    /// Labels spell System.Decimal as Decimal and the decompiled source as decimal, so a patch of one of several same-count
    /// overloads taking a decimal (JsonConvert.ToString(decimal)) failed: "none match by parameter types".
    /// </summary>
    [Trait("Speed", "Slow")]
    [Fact]
    public void CSharpPatchesFindDecimalOverloads()
    {
        using var env = new Env(RealPackages.Lib("Newtonsoft.Json", "13.0.1", "netstandard2.0", "Newtonsoft.Json.dll"));
        Assert.Contains("compiled OK", env.Edit(() => env.Edits.PatchMethodCSharp(env.One("Newtonsoft.Json.JsonConvert::ToString(decimal)"), "return \"d\";", dryRun: true, default)));
    }

    /// <summary>
    /// Two references with an internal System.SR, neither public nor used by the target: none was hidden, so SR in code of
    /// namespace App.Sub (usings inside it) was ambiguous instead of the target's App.SR (System.Web.SR in System.Web.Security).
    /// </summary>
    [Trait("Speed", "Slow")]
    [Fact]
    public void CSharpPatchesBindTypesOfEnclosingNamespacesBeforeImportedOnes()
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

    /// <summary>
    /// The CS0433 retry read [NonVersionable] as a type named NonVersionable, so an attribute the target and mscorlib both define
    /// kept failing (System.Collections.Immutable 1.3.1); a public framework type the target defines again was never hidden
    /// (Lazy&lt;T&gt; of NUnit 3 for .NET 3.5, compiled against mscorlib 4).
    /// </summary>
    [Trait("Speed", "Slow")]
    [Fact]
    public void CSharpPatchesBindAttributesAndRedefinedFrameworkTypesToTheTarget()
    {
        using (var env = new Env(RealPackages.Lib("System.Collections.Immutable", "1.3.1", "netstandard1.0", "System.Collections.Immutable.dll")))
            Assert.Contains("compiled OK", env.Edit(() => env.Edits.PatchMethodCSharp(env.One("System.Collections.Immutable.ImmutableArray`1::IndexOf(T, int, int)"),
                "return -1;", dryRun: true, default)));
        using (var env = new Env(RealPackages.Lib("NUnit", "3.14.0", "net35", "nunit.framework.dll")))
            Assert.Contains("compiled OK", env.Edit(() => env.Edits.PatchMethodCSharp(env.One("NUnit.Framework.Constraints.Constraint::ToString()"),
                "return \"x\";", dryRun: true, default)));
    }

    /// <summary>
    /// The decompiled types were made public in the compiled copy, so an internal type deriving from or exposing another
    /// internal type of the target failed every C# patch with CS0060 or CS0053 (Newtonsoft.Json's JSON path classes).
    /// </summary>
    [Trait("Speed", "Slow")]
    [Fact]
    public void CSharpPatchesCompileWhenAnInternalTypeUsesInternalTypesOfItsAssembly()
    {
        using var env = new Env(RealPackages.Lib("newtonsoft.json", "13.0.4", "netstandard2.0", "Newtonsoft.Json.dll"));
        const string member = "public static int Twice(int x) { return x * 2; }";
        Assert.Contains("compiled OK", env.Edit(() => env.Edits.AddMembersCSharp(env.One("Newtonsoft.Json.Linq.JsonPath.ScanFilter"), member, dryRun: true, default)));
        Assert.Contains("compiled OK", env.Edit(() => env.Edits.AddMembersCSharp(env.One("Newtonsoft.Json.Linq.JsonPath.JPath"), member, dryRun: true, default)));
    }

    /// <summary>
    /// Member labels left out generic arity, so JsonConvert::DeserializeObject&lt;T&gt;(string) and DeserializeObject(string)
    /// had one label: diff_edits could not resolve an edit of either, and a replay on another build was ambiguous or
    /// reported the target as renamed to itself. Scripts saved before labels carried the arity still replay.
    /// </summary>
    [Fact]
    public void GenericOverloadsHaveTheirOwnLabelsInDiffsAndReplays()
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

    /// <summary>
    /// A script from before arity labels replayed on another build without the source build loaded: the bare label
    /// Read(string) named both Read(string) and Read&lt;T&gt;(string) and failed as ambiguous; the recorded token picks one.
    /// </summary>
    [Fact]
    public void LegacyEditScriptsPickBetweenOverloadsOfOneLabelByTheRecordedToken()
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

    /// <summary>
    /// apply_edits onto a transformed rebuild matched targets against the source build as edited: after the script's
    /// own stub, that body no longer resembled its counterpart (now renamed), so the replay failed and rolled back.
    /// </summary>
    [Fact]
    public void EditsReplayOntoATransformedRebuildAfterTheScriptEditedItsSourceBuild()
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

    /// <summary>
    /// Saving an edited signed assembly drops its Authenticode signature and leaves a strong-name signature that no longer
    /// matches; both happened without a word. Found on PDFelement's signed Office add-in.
    /// </summary>
    [Fact]
    public void SavingAnEditedSignedAssemblySaysWhatHappensToItsSignatures()
    {
        var path = RealPackages.Lib("newtonsoft.json", "13.0.4", "netstandard2.0", "Newtonsoft.Json.dll");
        using var dir = new TempDir();
        using var env = new Env(path);
        env.Edit(() => env.Edits.StubMethod(env.One("Newtonsoft.Json.JsonConvert::ToString(bool)"), "\"x\""));
        var result = env.Workspace.Read(() => env.Edits.Save(env.Fixture, dir.File("Newtonsoft.Json.dll"), overwrite: false));
        Assert.Contains("strong-name signed", result);
        using var pe = new System.Reflection.PortableExecutable.PEReader(File.OpenRead(path));
        Assert.Equal(pe.PEHeaders.PEHeader!.CertificateTableDirectory.Size > 0, result.Contains("Authenticode-signed"));

        using var clean = new Env(path);
        Assert.DoesNotContain("Signatures:", clean.Workspace.Read(() => clean.Edits.Save(clean.Fixture, dir.File("Unedited.dll"), overwrite: false)));
    }

    [Fact]
    public void StaticConstructorDeclarationSaysStaticOnce()
    {
        var lab = new IlLab("Ctors");
        var cctor = lab.StaticConstructor(lab.Type, IlLab.Ret());
        Assert.Equal("private static P()", Format.Method(cctor));
        Assert.Equal("static P()", Format.Method(cctor, withModifiers: false));
    }

    [Trait("Speed", "Slow")]
    [Fact]
    public async Task MissingRequiredArgumentIsAClearToolError()
    {
        await using var client = await McpProtocolTests.StartServerAsync("--load", Env.FixturePath);
        var result = await client.CallToolAsync("decompile_member", new Dictionary<string, object?>());
        // The first block is the readable error; the second repeats it as JSON.
        var text = result.Content.OfType<ModelContextProtocol.Protocol.TextContentBlock>().First().Text;
        Assert.True(result.IsError);
        Assert.Equal("Error (invalid_argument) in decompile_member: missing required parameter 'member'.", text);
        Assert.Equal("member", McpProtocolTests.ErrorJson(result).GetProperty("details").GetProperty("parameter").GetString());
    }

    [Fact]
    public void ADirectoryPassedForAFileGetsAnExplainingError()
    {
        using var dir = new TempDir();
        using var env = new Env();
        var inspection = new Corvus.Services.Analysis.InspectionService(env.Workspace);
        var error = Assert.Throws<ToolError>(() => inspection.Summarize(null, dir.Path, default)).Message;
        Assert.Contains("is a directory", error);
    }

    [Trait("Speed", "Slow")]
    [Fact]
    public void CSharpPatchesCompileForANetAppThatUsesANetStandardLibrary()
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
