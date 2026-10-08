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
}
