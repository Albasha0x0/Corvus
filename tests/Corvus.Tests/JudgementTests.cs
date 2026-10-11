using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Corvus.Tests;

/// <summary>Decompiler cleanups apply only where they provably preserve behavior.</summary>
public class JudgementTests : IDisposable
{
    private readonly TempDir _dir = new();
    public void Dispose() => _dir.Dispose();

    /// <summary>Constructors that store before calling the base constructor (IL that C# cannot write).</summary>
    private string StoreBeforeBase()
    {
        var bytes = ReferenceResolutionTests.Compile("Order", """
            public class Base { public Base() { Init(); } protected virtual void Init() { } }
            public class Plain { public Plain() { } }
            // fields: the engine shows these as a primary constructor with field initializers
            public class FieldUnsafe : Base { public int Seen; private int f; public FieldUnsafe(int x) { f = x; } protected override void Init() { Seen = f; } }
            public class FieldSafe : Plain { private int f; public FieldSafe(int x) { f = x; } public int F => f; }
            // property setters: the engine writes base._002Ector(...) after them
            public class SetterUnsafe : Base { public int Seen; public int P { get; set; } public SetterUnsafe(int x) { P = x; } protected override void Init() { Seen = P; } }
            public class SetterSafe : Plain { public int P { get; set; } public SetterSafe(int x) { P = x; } }
            """);
        var module = ModuleDefMD.Load(bytes);
        foreach (var name in new[] { "FieldUnsafe", "FieldSafe", "SetterUnsafe", "SetterSafe" })
        {
            var ctor = module.Find(name, false)!.FindInstanceConstructors().Single();
            var il = ctor.Body.Instructions;
            // Move the stores before the base constructor call.
            int call = il.ToList().FindIndex(i => i.OpCode == OpCodes.Call && i.Operand is IMethod { Name.String: ".ctor" });
            var stores = il.Skip(call + 1).TakeWhile(i => i.OpCode != OpCodes.Ret).ToList();
            foreach (var i in stores) il.Remove(i);
            for (int k = 0; k < stores.Count; k++) il.Insert(k, stores[k]);
        }
        var path = _dir.File("Order.dll");
        module.Write(path);
        return path;
    }

    [Fact]
    public void ConstructorView_ShowsWhatRunsBeforeTheBaseConstructor()
    {
        using var env = new Env(StoreBeforeBase());
        var view = env.Decompile("FieldSafe::.ctor");
        Assert.Contains("a primary constructor: they run as part of this constructor, before the base constructor", view);
        Assert.Contains("class FieldSafe(int x) : Plain", view);
        Assert.Contains("private int f = x;", view);
        Assert.DoesNotContain("public int F", view); // unrelated members are trimmed
    }

    [Fact]
    public void BaseConstructorReorder_OnlyWhenTheBaseCannotObserveIt()
    {
        using var env = new Env(StoreBeforeBase());
        // Plain's constructor calls nothing overridable: the store can move after it.
        var safe = env.Decompile("SetterSafe");
        Assert.Contains(": base()", safe);
        Assert.DoesNotContain("_002Ector", safe);
        // Base's constructor calls the overridden Init, which reads P: compiled order is kept.
        var risky = env.Decompile("SetterUnsafe");
        Assert.DoesNotContain(": base()", risky);
        Assert.Matches(@"P = x;[\s\S]*base\.", risky);
        // Field stores become primary-constructor initializers in either case.
        Assert.Contains("class FieldUnsafe(int x) : Base", env.Decompile("FieldUnsafe"));
    }
}
