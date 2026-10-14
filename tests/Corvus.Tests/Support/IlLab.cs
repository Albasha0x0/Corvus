using System.Runtime.Loader;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Corvus.Tests;

/// <summary>
/// A module built with dnlib for IL-level tests: static methods with hand-written bodies, structs and helper types, then
/// written to an image that the runtime can execute next to the in-memory module the engine analyses.
/// </summary>
internal sealed class IlLab
{
    public ModuleDefUser Module { get; }
    public TypeDefUser Type { get; }
    public ICorLibTypes T => Module.CorLibTypes;

    public IlLab(string name = "Lab")
    {
        Module = new ModuleDefUser(name + ".dll", new Guid("6c1b0f42-0d6e-4c25-9a77-3e5f3c1d2b10"), AssemblyRefUser.CreateMscorlibReferenceCLR40())
        {
            Kind = ModuleKind.Dll,
            RuntimeVersion = dnlib.DotNet.MD.MDHeaderRuntimeVersion.MS_CLR_40,
        };
        new AssemblyDefUser(name, new Version(1, 0, 0, 0)).Modules.Add(Module);
        Type = NewType("Lab", "P", abstractSealed: true);
    }

    public TypeDefUser NewType(string ns, string name, bool abstractSealed = false, ITypeDefOrRef? baseType = null, bool beforeFieldInit = true)
    {
        var attributes = TypeAttributes.Public | TypeAttributes.Class | (abstractSealed ? TypeAttributes.Abstract | TypeAttributes.Sealed : 0) |
                         (beforeFieldInit ? TypeAttributes.BeforeFieldInit : 0);
        var type = new TypeDefUser(ns, name, baseType ?? T.Object.TypeDefOrRef) { Attributes = attributes };
        Module.Types.Add(type);
        return type;
    }

    public TypeDefUser NewStruct(string name, params (string Name, TypeSig Type)[] fields)
    {
        var s = new TypeDefUser("Lab", name, T.GetTypeRef("System", "ValueType"))
        {
            Attributes = TypeAttributes.Public | TypeAttributes.SequentialLayout | TypeAttributes.Sealed | TypeAttributes.BeforeFieldInit,
        };
        foreach (var (n, t) in fields) s.Fields.Add(new FieldDefUser(n, new FieldSig(t), FieldAttributes.Public));
        Module.Types.Add(s);
        return s;
    }

    public FieldDefUser StaticField(TypeDef owner, string name, TypeSig type, bool readOnly)
    {
        var f = new FieldDefUser(name, new FieldSig(type), FieldAttributes.Public | FieldAttributes.Static | (readOnly ? FieldAttributes.InitOnly : 0));
        owner.Fields.Add(f);
        return f;
    }

    /// <summary>A static method of <paramref name="owner"/> (default: the lab type) with the given body.</summary>
    public MethodDefUser Method(string name, TypeSig ret, TypeSig[] parameters, IEnumerable<Instruction> code, TypeSig[]? locals = null,
        TypeDef? owner = null, IEnumerable<ExceptionHandler>? handlers = null)
    {
        var m = new MethodDefUser(name, MethodSig.CreateStatic(ret, parameters), MethodImplAttributes.IL | MethodImplAttributes.Managed,
            MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.HideBySig);
        for (int p = 0; p < parameters.Length; p++) m.ParamDefs.Add(new ParamDefUser("a" + p, (ushort)(p + 1)));
        (owner ?? Type).Methods.Add(m);
        m.Body = new CilBody { InitLocals = true };
        foreach (var l in locals ?? []) m.Body.Variables.Add(new Local(l));
        foreach (var i in code) m.Body.Instructions.Add(i);
        foreach (var h in handlers ?? []) m.Body.ExceptionHandlers.Add(h);
        return m;
    }

    public MethodDefUser Method(string name, TypeSig ret, params Instruction[] code) => Method(name, ret, [], code);

    public MethodDefUser StaticConstructor(TypeDef owner, params Instruction[] code)
    {
        var m = new MethodDefUser(".cctor", MethodSig.CreateStatic(T.Void), MethodImplAttributes.IL | MethodImplAttributes.Managed,
            MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.HideBySig | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName);
        owner.Methods.Add(m);
        m.Body = new CilBody();
        foreach (var i in code) m.Body.Instructions.Add(i);
        return m;
    }

    public byte[] Write()
    {
        using var ms = new MemoryStream();
        Module.Write(ms);
        return ms.ToArray();
    }

    public static Instruction Ldc(int v) => OpCodes.Ldc_I4.ToInstruction(v);
    public static Instruction Op(OpCode op) => op.ToInstruction();
    public static Instruction Ret() => OpCodes.Ret.ToInstruction();

    /// <summary>An image loaded in a collectible context, to run its static methods.</summary>
    public sealed class LabRunner : IDisposable
    {
        private readonly AssemblyLoadContext _context = new(null, isCollectible: true);
        private readonly System.Reflection.Assembly _assembly;

        public LabRunner(byte[] image) => _assembly = _context.LoadFromStream(new MemoryStream(image));

        /// <summary>The method's result, or the exception it throws (JIT rejection of invalid IL included).</summary>
        public (object? Value, Exception? Error) Call(string type, string method, params object?[] args)
        {
            try
            {
                var m = _assembly.GetType(type, throwOnError: true)!.GetMethod(method, System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static)!;
                return (m.Invoke(null, args), null);
            }
            catch (System.Reflection.TargetInvocationException ex) when (ex.InnerException is TypeInitializationException { InnerException: { } inner })
            {
                return (null, inner);
            }
            catch (System.Reflection.TargetInvocationException ex)
            {
                return (null, ex.InnerException);
            }
        }

        /// <summary>JIT-compiles a static method without running it: the exception for invalid IL, or null.</summary>
        public Exception? Prepare(string type, string method)
        {
            try
            {
                var m = _assembly.GetType(type, throwOnError: true)!.GetMethod(method, System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static)!;
                System.Runtime.CompilerServices.RuntimeHelpers.PrepareMethod(m.MethodHandle);
                return null;
            }
            catch (Exception ex)
            {
                return ex;
            }
        }

        public void Dispose() => _context.Unload();
    }
}
