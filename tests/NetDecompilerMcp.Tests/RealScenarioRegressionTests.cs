using dnlib.DotNet;
using dnlib.DotNet.Emit;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Tests;

/// <summary>Defects found by running the server against real applications, each reduced to a fixture.</summary>
public sealed class RealScenarioRegressionTests
{
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

    [Fact]
    public async Task MissingRequiredArgumentIsAClearToolError()
    {
        await using var client = await McpProtocolTests.StartServerAsync("--load", Env.FixturePath);
        var result = await client.CallToolAsync("decompile_member", new Dictionary<string, object?>());
        var text = string.Join("\n", result.Content.OfType<ModelContextProtocol.Protocol.TextContentBlock>().Select(c => c.Text));
        Assert.True(result.IsError);
        Assert.Equal("Missing required parameter 'member' for decompile_member.", text);
    }
}
