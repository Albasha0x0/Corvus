using Corvus.Core;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Corvus.Tests;

/// <summary>The binding map joins script names to managed methods through generated binder classes.</summary>
public class BindingMapTests
{
    private static (ModuleDefUser Module, TypeDefUser Type) NewModule(string binderName)
    {
        var module = new ModuleDefUser("Fixture.dll", Guid.NewGuid(), new AssemblyRefUser("System.Runtime", new Version(8, 0, 0, 0))) { Kind = ModuleKind.Dll };
        new AssemblyDefUser("Fixture", new Version(1, 0, 0, 0)).Modules.Add(module);
        var objectRef = new TypeRefUser(module, "System", "Object", module.CorLibTypes.AssemblyRef);
        var subject = new TypeDefUser("Fixture", "Subject", objectRef);
        module.Types.Add(subject);
        var binder = new TypeDefUser("Fixture", binderName, objectRef);
        module.Types.Add(binder);
        return (module, binder);
    }

    private static MethodDefUser Method(TypeDef owner, string name)
    {
        var method = new MethodDefUser(name, MethodSig.CreateStatic(owner.Module.CorLibTypes.Void), MethodAttributes.Public | MethodAttributes.Static)
        {
            Body = new CilBody(),
        };
        method.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        owner.Methods.Add(method);
        return method;
    }

    private static MethodDefUser Register(TypeDef binder, params (string? Name, MethodDef Target)[] entries) =>
        Register(binder, "Register", entries);

    private static MethodDefUser Register(TypeDef binder, string methodName, params (string? Name, MethodDef Target)[] entries)
    {
        var module = binder.Module;
        var delegateRef = new TypeRefUser(module, "System", "Action", module.CorLibTypes.AssemblyRef);
        var ctor = new MemberRefUser(module, ".ctor",
            MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.Object, module.CorLibTypes.IntPtr), delegateRef);
        var add = new MemberRefUser(module, "Add",
            MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Object), new TypeRefUser(module, "Fixture", "Host", module.CorLibTypes.AssemblyRef));
        var register = Method(binder, methodName);
        var body = register.Body;
        body.Instructions.Clear();
        var subject = binder.Module.Types.First(t => t.Name == "Subject");
        body.Instructions.Add(OpCodes.Ldtoken.ToInstruction(subject));
        body.Instructions.Add(OpCodes.Pop.ToInstruction());
        foreach (var (name, target) in entries)
        {
            if (name != null) body.Instructions.Add(OpCodes.Ldstr.ToInstruction(name));
            body.Instructions.Add(OpCodes.Ldnull.ToInstruction());
            body.Instructions.Add(OpCodes.Ldftn.ToInstruction(target));
            body.Instructions.Add(OpCodes.Newobj.ToInstruction(ctor));
            body.Instructions.Add(OpCodes.Call.ToInstruction(add));
        }
        body.Instructions.Add(OpCodes.Ret.ToInstruction());
        return register;
    }

    [Fact]
    public void A_binder_maps_each_script_name_to_its_managed_method()
    {
        var (module, binder) = NewModule("SubjectWrap");
        Register(binder, ("Alpha", Method(binder, "Alpha")), ("Beta", Method(binder, "BetaImpl")));

        var map = BindingMap.Read(module);

        Assert.Equal(["Alpha", "Beta"], map.Bindings.Select(b => b.ScriptName));
        Assert.Contains("BetaImpl", map.Bindings[1].Target);
        Assert.All(map.Bindings, b => Assert.Equal("Fixture.Subject", b.BoundType));
        Assert.All(map.Bindings, b => Assert.Equal("Fixture.SubjectWrap", b.Binder));
        Assert.Empty(map.Unnamed);
        Assert.Empty(map.Empty);
    }

    [Fact]
    public void A_method_registered_without_a_name_is_listed_as_unnamed()
    {
        var (module, binder) = NewModule("SubjectWrap");
        Register(binder, ("Alpha", Method(binder, "Alpha")), (null, Method(binder, "Hidden")));

        var map = BindingMap.Read(module);

        Assert.Single(map.Bindings);
        Assert.Contains("Hidden", Assert.Single(map.Unnamed));
    }

    [Fact]
    public void A_binder_without_registrations_is_reported_as_empty()
    {
        var (module, binder) = NewModule("SubjectWrap");
        Method(binder, "Helper");

        var map = BindingMap.Read(module);

        Assert.Empty(map.Bindings);
        Assert.Equal(["Fixture.SubjectWrap"], map.Empty);
    }

    [Fact]
    public void A_class_without_the_binder_suffix_is_ignored()
    {
        var (module, plain) = NewModule("SubjectBinder");
        Register(plain, ("Alpha", Method(plain, "Alpha")));

        var map = BindingMap.Read(module);

        Assert.Empty(map.Bindings);
        Assert.Empty(map.Empty);
    }

    [Fact]
    public void A_name_before_a_call_does_not_name_a_later_method()
    {
        var (module, binder) = NewModule("SubjectWrap");
        var register = Register(binder, ("Alpha", Method(binder, "Alpha")));
        var add = (IMethod)register.Body.Instructions.First(i => i.OpCode.Code == Code.Call).Operand;
        var list = register.Body.Instructions;
        list.Insert(list.Count - 1, OpCodes.Ldstr.ToInstruction("Stale"));
        list.Insert(list.Count - 1, OpCodes.Call.ToInstruction(add));
        list.Insert(list.Count - 1, OpCodes.Ldnull.ToInstruction());
        list.Insert(list.Count - 1, OpCodes.Ldftn.ToInstruction(Method(binder, "Hidden")));

        var map = BindingMap.Read(module);

        Assert.Equal(["Alpha"], map.Bindings.Select(b => b.ScriptName));
        Assert.Contains("Hidden", Assert.Single(map.Unnamed));
    }

    [Fact]
    public void A_name_loaded_for_another_purpose_does_not_name_a_later_method()
    {
        var (module, binder) = NewModule("SubjectWrap");
        var register = Method(binder, "Register");
        var list = register.Body.Instructions;
        list.Clear();
        var ctor = new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void),
            new TypeRefUser(module, "System", "Exception", module.CorLibTypes.AssemblyRef));
        list.Add(OpCodes.Ldstr.ToInstruction("message"));
        list.Add(OpCodes.Newobj.ToInstruction(ctor));
        list.Add(OpCodes.Pop.ToInstruction());
        list.Add(OpCodes.Ldnull.ToInstruction());
        list.Add(OpCodes.Ldftn.ToInstruction(Method(binder, "Hidden")));
        list.Add(OpCodes.Ret.ToInstruction());

        var map = BindingMap.Read(module);

        Assert.Empty(map.Bindings);
        Assert.Contains("Hidden", Assert.Single(map.Unnamed));
    }

    [Fact]
    public void A_registrar_without_a_type_token_has_no_bound_type()
    {
        var (module, binder) = NewModule("SubjectWrap");
        var register = Register(binder, ("Alpha", Method(binder, "Alpha")));
        register.Body.Instructions.RemoveAt(0);
        register.Body.Instructions.RemoveAt(0);

        var map = BindingMap.Read(module);

        Assert.Null(Assert.Single(map.Bindings).BoundType);
    }

    [Fact]
    public void The_bound_type_is_the_nearest_type_token_before_the_registration()
    {
        var (module, binder) = NewModule("SubjectWrap");
        var other = new TypeDefUser("Fixture", "Other", binder.BaseType);
        module.Types.Add(other);
        var register = Register(binder, ("Alpha", Method(binder, "Alpha")));
        register.Body.Instructions.Insert(2, OpCodes.Ldtoken.ToInstruction(other));
        register.Body.Instructions.Insert(3, OpCodes.Pop.ToInstruction());

        var map = BindingMap.Read(module);

        Assert.Equal("Fixture.Other", Assert.Single(map.Bindings).BoundType);
    }

    [Fact]
    public void Registrars_are_told_apart_by_full_name()
    {
        var (module, binder) = NewModule("SubjectWrap");
        Register(binder, "RegisterOne", ("Alpha", Method(binder, "Alpha")));
        Register(binder, "RegisterTwo", ("Beta", Method(binder, "Beta")));

        var map = BindingMap.Read(module);

        Assert.Contains("RegisterOne", map.Bindings[0].Registrar);
        Assert.Contains("RegisterTwo", map.Bindings[1].Registrar);
        Assert.Contains("Fixture.SubjectWrap", map.Bindings[0].Registrar);
    }

    [Fact]
    public void A_type_named_exactly_the_suffix_is_ignored()
    {
        var (module, binder) = NewModule("Wrap");
        Register(binder, ("Alpha", Method(binder, "Alpha")));

        var map = BindingMap.Read(module);

        Assert.Empty(map.Bindings);
        Assert.Empty(map.Empty);
    }

    [Fact]
    public void An_empty_binder_is_not_mixed_up_with_another_binders_bindings()
    {
        var (module, first) = NewModule("SubjectWrap");
        Register(first, ("Alpha", Method(first, "Alpha")));
        var second = new TypeDefUser("Fixture", "WidgetWrap", first.BaseType);
        module.Types.Add(second);
        Method(second, "Helper");

        var map = BindingMap.Read(module);

        Assert.Equal(["Alpha"], map.Bindings.Select(b => b.ScriptName));
        Assert.Equal(["Fixture.WidgetWrap"], map.Empty);
    }

    [Fact]
    public void A_nested_type_of_a_binder_is_read_for_the_outer_binder()
    {
        var (module, binder) = NewModule("SubjectWrap");
        var nested = new TypeDefUser("", "Closure", binder.BaseType);
        binder.NestedTypes.Add(nested);
        Register(nested, ("Alpha", Method(binder, "Alpha")));

        var map = BindingMap.Read(module);

        Assert.Equal("Fixture.SubjectWrap", Assert.Single(map.Bindings).Binder);
        Assert.Empty(map.Empty);
    }

    [Fact]
    public void A_method_body_without_instructions_is_reported_as_unreadable()
    {
        var (module, binder) = NewModule("SubjectWrap");
        Method(binder, "Broken").Body.Instructions.Clear();

        var map = BindingMap.Read(module);

        Assert.Contains("Broken", Assert.Single(map.Unreadable));
        Assert.Empty(map.Empty);
    }
}
