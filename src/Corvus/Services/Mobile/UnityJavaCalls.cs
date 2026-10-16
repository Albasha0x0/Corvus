using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Corvus.Services.Mobile;

/// <summary>
/// One use of Java from Unity C#: <paramref name="Class"/> is a JNI class name (pkg/Outer$Inner); <paramref name="Member"/> the method or field
/// named by string (null for a class use); <paramref name="Arity"/> the argument count when the object[] is built in place;
/// <paramref name="Signature"/> a JNI signature passed to AndroidJNI. Kind: call, call_static, get, set, get_static, set_static, new, proxy, jni.
/// </summary>
public sealed record UnityJavaCall(MethodDef Caller, string? Class, string? Member, string Kind, int? Arity, string? Signature);

/// <summary>
/// Finds the Java classes, methods and fields Unity C# reaches by string: AndroidJavaClass / AndroidJavaObject construction,
/// Call / CallStatic / Get / Set / GetStatic / SetStatic, AndroidJavaProxy interfaces, and AndroidJNI class and method lookups.
/// A linear walk of each method's IL tracks strings, object[] lengths and Java objects through the stack, locals and fields.
/// </summary>
public static class UnityJavaCalls
{
    private static readonly HashSet<string> JavaTypes = ["UnityEngine.AndroidJavaObject", "UnityEngine.AndroidJavaClass", "UnityEngine.AndroidJavaProxy", "UnityEngine.AndroidJNI", "UnityEngine.AndroidJNIHelper"];

    private sealed record Val(string? Str = null, string? JavaClass = null, int? Int = null, int? ArrayLength = null);

    private static readonly Val Unknown = new();

    /// <summary>The Java uses of a module; empty when it references none of Unity's Java bridge types.</summary>
    public static List<UnityJavaCall> Scan(ModuleDef module, CancellationToken ct)
    {
        var calls = new List<UnityJavaCall>();
        if (!module.GetTypeRefs().Any(t => JavaTypes.Contains(t.FullName)) && !module.GetTypes().Any(t => JavaTypes.Contains(t.FullName))) return calls;
        var fields = new Dictionary<IField, string>(FieldComparer.Instance);
        var methods = module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody).ToList();
        // the first pass learns which fields hold a Java object of a known class, the second records the uses
        foreach (var m in methods) Walk(m, fields, null);
        foreach (var m in methods)
        {
            ct.ThrowIfCancellationRequested();
            Walk(m, fields, calls);
        }
        return calls;
    }

    /// <summary>A Java class name as written in C# (com.example.Foo, com/example/Foo) in JNI form.</summary>
    public static string JniClass(string name) => name.Trim().Replace('.', '/');

    private static void Walk(MethodDef method, Dictionary<IField, string> fields, List<UnityJavaCall>? calls)
    {
        var body = method.Body;
        var stack = new List<Val>();
        var locals = new Dictionary<int, Val>();
        Val Pop() { if (stack.Count == 0) return Unknown; var v = stack[^1]; stack.RemoveAt(stack.Count - 1); return v; }
        List<Val> PopN(int n) { var list = new List<Val>(); for (int i = 0; i < n; i++) list.Insert(0, Pop()); return list; }
        void Record(string? cls, string? member, string kind, int? arity, string? signature) =>
            calls?.Add(new UnityJavaCall(method, cls is { Length: > 0 } ? JniClass(cls) : null, member, kind, arity, signature));
        var targets = new HashSet<Instruction>(body.Instructions.SelectMany(i => i.Operand switch
        {
            Instruction t => [t],
            Instruction[] ts => ts,
            _ => [],
        }));
        foreach (var h in body.ExceptionHandlers) if (h.HandlerStart != null) targets.Add(h.HandlerStart);

        foreach (var ins in body.Instructions)
        {
            if (targets.Contains(ins)) stack.Clear(); // a join: what is on the stack is no longer known
            switch (ins.OpCode.Code)
            {
                case Code.Ldstr: stack.Add(new Val(Str: (string)ins.Operand)); continue;
                case Code.Ldc_I4: case Code.Ldc_I4_S: case Code.Ldc_I4_0: case Code.Ldc_I4_1: case Code.Ldc_I4_2: case Code.Ldc_I4_3: case Code.Ldc_I4_4:
                case Code.Ldc_I4_5: case Code.Ldc_I4_6: case Code.Ldc_I4_7: case Code.Ldc_I4_8: case Code.Ldc_I4_M1:
                    stack.Add(new Val(Int: ins.GetLdcI4Value())); continue;
                case Code.Newarr: stack.Add(new Val(ArrayLength: Pop().Int)); continue;
                case Code.Dup: { var v = Pop(); stack.Add(v); stack.Add(v); continue; }
                case Code.Stloc: case Code.Stloc_S: case Code.Stloc_0: case Code.Stloc_1: case Code.Stloc_2: case Code.Stloc_3:
                    locals[ins.GetLocal(body.Variables)?.Index ?? -1] = Pop(); continue;
                case Code.Ldloc: case Code.Ldloc_S: case Code.Ldloc_0: case Code.Ldloc_1: case Code.Ldloc_2: case Code.Ldloc_3:
                    stack.Add(locals.GetValueOrDefault(ins.GetLocal(body.Variables)?.Index ?? -1, Unknown)); continue;
                case Code.Stfld: case Code.Stsfld:
                {
                    var v = Pop();
                    if (ins.OpCode.Code == Code.Stfld) Pop();
                    if (v.JavaClass != null && ins.Operand is IField f) fields[f] = v.JavaClass;
                    continue;
                }
                case Code.Ldfld: case Code.Ldsfld:
                    if (ins.OpCode.Code == Code.Ldfld) Pop();
                    stack.Add(ins.Operand is IField lf && fields.TryGetValue(lf, out var held) ? new Val(JavaClass: held) : Unknown);
                    continue;
                case Code.Newobj: case Code.Call: case Code.Callvirt:
                    if (ins.Operand is IMethod callee) { Invoke(ins.OpCode.Code, callee); continue; }
                    break;
            }
            ins.CalculateStackUsage(method.HasReturnType, out int pushes, out int pops);
            if (pops < 0) stack.Clear(); else PopN(pops);
            for (int i = 0; i < pushes; i++) stack.Add(Unknown);
            if (ins.OpCode.FlowControl is FlowControl.Branch or FlowControl.Return or FlowControl.Throw) stack.Clear();
        }

        void Invoke(Code code, IMethod callee)
        {
            var sig = callee.MethodSig;
            int count = sig?.Params.Count ?? 0;
            bool hasThis = sig?.HasThis == true && code != Code.Newobj;
            var args = PopN(count + (hasThis ? 1 : 0));
            var self = hasThis ? args[0] : Unknown;
            var parameters = hasThis ? args.Skip(1).ToList() : args;
            var type = callee.DeclaringType?.FullName ?? "";
            bool returns = code == Code.Newobj || sig?.RetType.ElementType != ElementType.Void;
            Val result = Unknown;
            if (type == "System.Array" && callee.Name == "Empty") result = new Val(ArrayLength: 0); // params with no arguments
            if (JavaTypes.Contains(type))
            {
                var name = callee.Name.String;
                string? First() => parameters.Count > 0 ? parameters[0].Str : null;
                switch (type, name)
                {
                    case ("UnityEngine.AndroidJavaClass" or "UnityEngine.AndroidJavaObject", ".ctor") when First() is { } cls:
                        result = new Val(JavaClass: JniClass(cls));
                        Record(cls, null, "new", parameters.Count > 1 ? parameters[^1].ArrayLength : null, null);
                        break;
                    case ("UnityEngine.AndroidJavaProxy", ".ctor") when First() is { } iface:
                        Record(iface, null, "proxy", null, null);
                        break;
                    case (_, "Call" or "CallStatic" or "Get" or "Set" or "GetStatic" or "SetStatic") when First() is { } member:
                        var kind = name switch { "Call" => "call", "CallStatic" => "call_static", "Get" => "get", "Set" => "set", "GetStatic" => "get_static", _ => "set_static" };
                        Record(self.JavaClass, member, kind, kind.StartsWith("call", StringComparison.Ordinal) && parameters.Count > 1 ? parameters[^1].ArrayLength : null, null);
                        break;
                    case ("UnityEngine.AndroidJNI", "FindClass") when First() is { } jni:
                        result = new Val(JavaClass: JniClass(jni));
                        Record(jni, null, "jni", null, null);
                        break;
                    case ("UnityEngine.AndroidJNI" or "UnityEngine.AndroidJNIHelper", "GetMethodID" or "GetStaticMethodID" or "GetFieldID" or "GetStaticFieldID")
                        when parameters.Count >= 2 && parameters[1].Str is { } member:
                        Record(parameters[0].JavaClass, member, "jni", null, parameters.Count >= 3 ? parameters[2].Str : null);
                        break;
                }
            }
            if (returns) stack.Add(result);
        }
    }

    private sealed class FieldComparer : IEqualityComparer<IField>
    {
        public static readonly FieldComparer Instance = new();
        public bool Equals(IField? x, IField? y) => x?.FullName == y?.FullName;
        public int GetHashCode(IField obj) => obj.FullName.GetHashCode(StringComparison.Ordinal);
    }
}
