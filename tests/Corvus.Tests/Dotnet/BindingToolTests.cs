using Corvus.Services;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Corvus.Tests;

/// <summary>get_assembly_info view=bindings projects the binding map with the unknowns kept.</summary>
public class BindingToolTests
{
    private static string Fixture(TempDir dir, bool emptyBinder, bool unnamed = false, bool second = false)
    {
        var module = new ModuleDefUser("Fixture.dll", Guid.NewGuid(), new AssemblyRefUser("System.Runtime", new Version(8, 0, 0, 0))) { Kind = ModuleKind.Dll };
        new AssemblyDefUser("Fixture", new Version(1, 0, 0, 0)).Modules.Add(module);
        var objectRef = new TypeRefUser(module, "System", "Object", module.CorLibTypes.AssemblyRef);
        var subject = new TypeDefUser("Fixture", "Subject", objectRef);
        var binder = new TypeDefUser("Fixture", "SubjectWrap", objectRef);
        module.Types.Add(subject);
        module.Types.Add(binder);
        MethodDefUser Add(string name)
        {
            var m = new MethodDefUser(name, MethodSig.CreateStatic(module.CorLibTypes.Void), MethodAttributes.Public | MethodAttributes.Static) { Body = new CilBody() };
            m.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            binder.Methods.Add(m);
            return m;
        }
        var impl = Add("Alpha");
        var register = Add("Register");
        var ins = register.Body.Instructions;
        ins.Clear();
        if (!emptyBinder)
        {
            var host = new TypeRefUser(module, "Fixture", "Host", module.CorLibTypes.AssemblyRef);
            var add = new MemberRefUser(module, "Add", MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Object), host);
            ins.Add(OpCodes.Ldtoken.ToInstruction(subject));
            ins.Add(OpCodes.Pop.ToInstruction());
            ins.Add(unnamed ? OpCodes.Ldnull.ToInstruction() : OpCodes.Ldstr.ToInstruction("alpha"));
            ins.Add(OpCodes.Ldnull.ToInstruction());
            ins.Add(OpCodes.Ldftn.ToInstruction(impl));
            ins.Add(OpCodes.Call.ToInstruction(add));
            if (second)
            {
                ins.Add(OpCodes.Ldstr.ToInstruction("beta"));
                ins.Add(OpCodes.Ldnull.ToInstruction());
                ins.Add(OpCodes.Ldftn.ToInstruction(Add("Beta")));
                ins.Add(OpCodes.Call.ToInstruction(add));
            }
        }
        ins.Add(OpCodes.Ret.ToInstruction());
        var path = dir.File("Fixture.dll");
        module.Write(path);
        return path;
    }

    private static string Bindings(Env env, string path, string view = "bindings")
    {
        var asm = env.Workspace.Load(path);
        return env.Workspace.Read(() => new AssemblyReport(env.Workspace, new AotMetadataService(env.Workspace)).Build(asm, view, out _));
    }

    [Fact]
    public void A_binder_is_listed_with_its_script_name_target_and_bound_type()
    {
        using var dir = new TempDir();
        using var env = new Env();
        var text = Bindings(env, Fixture(dir, emptyBinder: false));

        Assert.Contains("Script bindings: 1", text);
        Assert.Contains("alpha -> ", text);
        Assert.Contains("Fixture.SubjectWrap::Alpha", text);
        Assert.Contains("[Fixture.Subject]  in Fixture.SubjectWrap", text);
    }

    [Fact]
    public void A_binder_with_no_readable_registration_is_reported_as_unknown()
    {
        using var dir = new TempDir();
        using var env = new Env();
        var text = Bindings(env, Fixture(dir, emptyBinder: true));

        Assert.Contains("Script bindings: 0", text);
        Assert.Contains("no readable registration (unknown): Fixture.SubjectWrap", text);
    }

    [Fact]
    public void A_registration_without_a_name_is_reported_as_unknown()
    {
        using var dir = new TempDir();
        using var env = new Env();
        var text = Bindings(env, Fixture(dir, emptyBinder: false, unnamed: true));

        Assert.Contains("registered without a name (unknown): ", text);
    }

    [Fact]
    public void Other_views_leave_the_bindings_out()
    {
        using var dir = new TempDir();
        using var env = new Env();
        var text = Bindings(env, Fixture(dir, emptyBinder: false, second: true), "all");

        Assert.DoesNotContain("Script bindings", text);
    }
}
