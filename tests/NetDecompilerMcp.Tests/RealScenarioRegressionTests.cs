using dnlib.DotNet;
using dnlib.DotNet.Emit;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Tests;

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
        Assert.False(NetDecompilerMcp.Services.MetadataUtil.IsSameMethod(container, ctor));
        var sameType = new MemberRefUser(lib.Module, ".ctor", MethodSig.CreateInstance(lib.T.Void),
            new TypeRefUser(lib.Module, "RefApp", "ViewModel", new AssemblyRefUser("RefApp")));
        Assert.True(NetDecompilerMcp.Services.MetadataUtil.IsSameMethod(sameType, ctor));
    }

    /// <summary>
    /// A protected assembly (Babel / Goliath here) with metadata the decompiler's reader rejects: the module name's
    /// string offset past the heap, and a custom attribute whose constructor coded index is invalid. dnlib reads both
    /// leniently. Every decompile and get_il failed with an internal BadImageFormatException; the decompiler now works
    /// on a normalized copy with the same tokens, and says so.
    /// </summary>
    [Fact]
    public void ProtectedMetadataIsDecompiledFromANormalizedCopy()
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
    /// Obfuscators name members with zero-width and bidi characters (U+202E reverses the rest of the line). Tool output
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

    [Fact]
    public async Task MissingRequiredArgumentIsAClearToolError()
    {
        await using var client = await McpProtocolTests.StartServerAsync("--load", Env.FixturePath);
        var result = await client.CallToolAsync("decompile_member", new Dictionary<string, object?>());
        var text = string.Join("\n", result.Content.OfType<ModelContextProtocol.Protocol.TextContentBlock>().Select(c => c.Text));
        Assert.True(result.IsError);
        Assert.Equal("Missing required parameter 'member' for decompile_member.", text);
    }

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
