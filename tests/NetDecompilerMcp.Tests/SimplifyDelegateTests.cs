using System.Runtime.Loader;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using NetDecompilerMcp.Services.Simplify;
using SymbolKind = NetDecompilerMcp.Core.SymbolKind;

namespace NetDecompilerMcp.Tests;

/// <summary>
/// simplify_methods, calls through delegate fields: the evaluator runs the fields' type initializers (method groups,
/// and reflection-based initializers as SmartAssembly emits them: field names that encode the target's token, resolved
/// through a ModuleHandle into Delegate.CreateDelegate or a DynamicMethod) and the call sites call the targets directly.
/// The fixture runs before and after.
/// </summary>
public sealed class SimplifyDelegateTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private const string Alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345";

    private const string Source = """
        using System;
        using System.IO;
        using System.Reflection;
        using System.Reflection.Emit;

        namespace Proxies
        {
            public static class Targets
            {
                public static int Add(int a, int b) => a + b;
                public static int Neg(int a) => -a;
                internal static string Decrypt(int k) => new string((char)('a' + k), 3);
            }

            public class Box
            {
                public int V;
                public Box(int v) { V = v; }
                public int Get() => V;
                public virtual int Twice() => V * 2;
            }

            public sealed class Box2 : Box
            {
                public Box2(int v) : base(v) { }
                public override int Twice() => V * 3;
            }

            // Method groups in a type initializer.
            public static class Direct
            {
                private static readonly Func<int, int, int> AddF = Targets.Add;
                private static readonly Func<string, bool> ExistsF = File.Exists;
                public static int UseAdd(int x) => AddF(x, 5) + AddF(1, x);
                public static bool UseExists(int x) => ExistsF("does-not-exist-" + x.ToString());
            }

            internal delegate int IntIntInt(int a, int b);
            internal delegate int IntInt(int a);
            internal delegate int ObjInt(object box);
            internal delegate string StrDelegate(int k);

            // SmartAssembly-style: each field's name encodes its target's token (base 58, least significant digit
            // first; '~' first for callvirt).
            internal static class ProxyInit
            {
                private static readonly char[] Digits = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345".ToCharArray();
                private static ModuleHandle Handle = typeof(ProxyInit).Module.ModuleHandle;

                public static void Init(Type type)
                {
                    FieldInfo[] fields = type.GetFields(BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.GetField);
                    for (int i = 0; i < fields.Length; i++)
                    {
                        FieldInfo field = fields[i];
                        string name = field.Name;
                        bool virt = false;
                        int token = 0;
                        for (int k = name.Length - 1; k >= 0; k--)
                        {
                            char c = name[k];
                            if (c == '~') { virt = true; break; }
                            for (int j = 0; j < 58; j++)
                            {
                                if (Digits[j] == c) { token = token * 58 + j; break; }
                            }
                        }
                        MethodInfo method;
                        try
                        {
                            method = (MethodInfo)MethodBase.GetMethodFromHandle(Handle.ResolveMethodHandle(token + 0x06000000));
                        }
                        catch
                        {
                            continue;
                        }
                        Delegate value;
                        if (method.IsStatic)
                        {
                            value = Delegate.CreateDelegate(field.FieldType, method);
                        }
                        else
                        {
                            ParameterInfo[] parameters = method.GetParameters();
                            Type[] types = new Type[parameters.Length + 1];
                            types[0] = typeof(object);
                            for (int k = 0; k < parameters.Length; k++) types[k + 1] = parameters[k].ParameterType;
                            var dynamic = new DynamicMethod(string.Empty, method.ReturnType, types, type, true);
                            ILGenerator il = dynamic.GetILGenerator();
                            il.Emit(OpCodes.Ldarg_0);
                            if (types.Length > 1) il.Emit(OpCodes.Ldarg_1);
                            if (types.Length > 2) il.Emit(OpCodes.Ldarg_2);
                            il.Emit(OpCodes.Tailcall);
                            il.Emit(virt ? OpCodes.Callvirt : OpCodes.Call, method);
                            il.Emit(OpCodes.Ret);
                            value = dynamic.CreateDelegate(field.FieldType);
                        }
                        field.SetValue(null, value);
                    }
                }

                // SmartAssembly-style string delegates: Decrypt(k - the field's row number).
                public static void InitStrings(Type type)
                {
                    foreach (FieldInfo field in type.GetFields(BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.GetField))
                    {
                        if ((object)field.FieldType != typeof(StrDelegate)) continue;
                        var dynamic = new DynamicMethod(string.Empty, typeof(string), new Type[] { typeof(int) }, type.Module, true);
                        ILGenerator il = dynamic.GetILGenerator();
                        il.Emit(OpCodes.Ldarg_0);
                        il.Emit(OpCodes.Ldc_I4, field.MetadataToken & 0xFFFFFF);
                        il.Emit(OpCodes.Sub);
                        il.Emit(OpCodes.Call, typeof(Targets).GetMethod("Decrypt", BindingFlags.Static | BindingFlags.NonPublic));
                        il.Emit(OpCodes.Ret);
                        field.SetValue(null, dynamic.CreateDelegate(typeof(StrDelegate)));
                    }
                }
            }

            public static class Calls
            {
                static Calls() { ProxyInit.Init(typeof(Calls)); }

                internal static IntIntInt P_Add;
                internal static IntInt P_Neg;
                internal static ObjInt P_Get;
                internal static ObjInt V_Twice;

                public static int UseAdd(int x) => P_Add(x, 7);
                public static int UseNeg(int x) => P_Neg(P_Add(x, 1));
                public static int UseGet(int x) => P_Get(new Box(x));
                public static int UseTwice(int x) => V_Twice(new Box2(x)) + V_Twice(new Box(x));
            }

            public static class Strings
            {
                static Strings() { ProxyInit.InitStrings(typeof(Strings)); }

                internal static StrDelegate S;

                public static string Use(int x) => S(x) + S(4);
            }

            // Not provable: written outside the initializer, visible to other assemblies, bound to an object.
            public static class Unprovable
            {
                internal static Func<int, int> Swapped = Targets.Neg;
                public static Func<int, int> Visible = Targets.Neg;
                private static readonly Func<int> Bound = new Box(3).Get;

                public static void Swap(Func<int, int> f) => Swapped = f;
                public static int UseSwapped(int x) => Swapped(x);
                public static int UseVisible(int x) => Visible(x);
                public static int UseBound(int x) => Bound() + x;
            }
        }
        """;

    /// <summary>The fixture, with each SmartAssembly-style field renamed to its target's encoded token.</summary>
    private string Fixture()
    {
        var path = _dir.File("Proxies.dll");
        if (File.Exists(path)) return path;
        var references = ((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!).Split(Path.PathSeparator)
            .Where(p => p.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)).Select(p => MetadataReference.CreateFromFile(p));
        var compilation = CSharpCompilation.Create("Proxies", [CSharpSyntaxTree.ParseText(Source)], references,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary, optimizationLevel: OptimizationLevel.Release));
        using var ms = new MemoryStream();
        var result = compilation.Emit(ms);
        Assert.True(result.Success, string.Join("\n", result.Diagnostics.Where(d => d.Severity == DiagnosticSeverity.Error)));

        using var module = ModuleDefMD.Load(ms.ToArray());
        MethodDef Target(string type, string name) => module.Find("Proxies." + type, false)!.FindMethod(name);
        var targets = new Dictionary<string, (MethodDef Method, bool Virtual)>
        {
            ["P_Add"] = (Target("Targets", "Add"), false),
            ["P_Neg"] = (Target("Targets", "Neg"), false),
            ["P_Get"] = (Target("Box", "Get"), false),
            ["V_Twice"] = (Target("Box", "Twice"), true),
        };
        foreach (var field in module.Find("Proxies.Calls", false)!.Fields)
        {
            if (!targets.TryGetValue(field.Name, out var t)) continue;
            uint rid = t.Method.Rid;
            var name = "";
            do { name += Alphabet[(int)(rid % 58)]; rid /= 58; } while (rid > 0);
            field.Name = (t.Virtual ? "~" : "") + name;
        }
        module.Write(path);
        return path;
    }

    private static string Simplify(Env env, string symbol, bool dryRun = false)
    {
        var sym = env.One(symbol);
        var options = SimplifyOptions.Parse(null, null, null);
        return dryRun
            ? env.Workspace.Read(() => env.Edits.SimplifyMethods(sym.Assembly, sym, options, true, default))
            : env.Edit(() => env.Edits.SimplifyMethods(sym.Assembly, sym, options, false, default));
    }

    private static List<Instruction> Body(Env env, string method) => env.Def<MethodDef>(method, SymbolKind.Method).Body.Instructions.ToList();

    private static object? Run(byte[] image, string type, string method, params object?[] args)
    {
        var context = new AssemblyLoadContext(null, isCollectible: true);
        try
        {
            var asm = context.LoadFromStream(new MemoryStream(image));
            return asm.GetType(type, throwOnError: true)!.GetMethod(method)!.Invoke(null, args);
        }
        finally
        {
            context.Unload();
        }
    }

    private static readonly int[] Inputs = [0, 3, -4, 100];

    [Theory]
    [InlineData("Proxies.Direct", "UseAdd", 2, "Proxies.Targets::Add(int, int)")]
    [InlineData("Proxies.Direct", "UseExists", 1, "System.IO.File::Exists(string)")]
    [InlineData("Proxies.Calls", "UseAdd", 1, "Proxies.Targets::Add(int, int)")]
    [InlineData("Proxies.Calls", "UseNeg", 2, "Proxies.Targets::Neg(int)")]
    [InlineData("Proxies.Calls", "UseGet", 1, "Proxies.Box::Get()")]
    [InlineData("Proxies.Calls", "UseTwice", 2, "Proxies.Box::Twice()")]
    public void CallsThroughDelegateFieldsCallTheTarget(string type, string method, int calls, string target)
    {
        using var env = new Env(Fixture());
        var report = Simplify(env, $"{type}::{method}");
        Assert.Contains("1 of 1 method(s) changed", report);
        Assert.Equal(calls, report.Split('\n').Count(l => l.Contains("  resolved ")));
        Assert.Contains($".Invoke -> {target} at IL_", report);
        Assert.DoesNotContain("delegate-target", report);

        var code = Body(env, $"{type}::{method}");
        Assert.DoesNotContain(code, i => i.Operand is IMethod { Name.String: "Invoke" } || i.OpCode.Code == Code.Ldsfld);
        var image = env.Fixture.GetImageBytes();
        foreach (var x in Inputs)
            Assert.Equal(Run(env.Fixture.OriginalBytes, type, method, x), Run(image, type, method, x));
    }

    [Fact]
    public void VirtualTargetsStayVirtual()
    {
        using var env = new Env(Fixture());
        Simplify(env, "Proxies.Calls::UseTwice");
        var calls = Body(env, "Proxies.Calls::UseTwice").Where(i => i.Operand is IMethod { Name.String: "Twice" }).ToList();
        Assert.Equal(2, calls.Count);
        Assert.All(calls, c => Assert.Equal(Code.Callvirt, c.OpCode.Code));
        Assert.Contains("new Box2(x).Twice() + new Box(x).Twice()", env.Decompile("Proxies.Calls::UseTwice"));
    }

    [Fact]
    public void StringDelegatesBecomeCallsAndThenLiterals()
    {
        using var env = new Env(Fixture());
        var report = Simplify(env, "Proxies.Strings::Use");
        Assert.Contains("resolved Proxies.Strings::S.Invoke -> Proxies.Targets::Decrypt(int) (after ldc.i4", report);
        var csharp = env.Decompile("Proxies.Strings::Use");
        Assert.DoesNotContain("S(", csharp);
        Assert.Contains("Targets.Decrypt(", csharp); // S(x): x - rid, not constant
        var image = env.Fixture.GetImageBytes();
        foreach (var x in new[] { 1, 5, 9 })
            Assert.Equal(Run(env.Fixture.OriginalBytes, "Proxies.Strings", "Use", x), Run(image, "Proxies.Strings", "Use", x));
        // S(4) has a constant argument: Decrypt(4 - rid) is evaluated to its string.
        var rid = (int)env.Def<FieldDef>("Proxies.Strings::S", SymbolKind.Field).Rid;
        Assert.Contains(new string((char)('a' + 4 - rid), 3), csharp);
    }

    [Fact]
    public void NavigationFollowsCallsThroughDelegateFields()
    {
        // The original IL calls Invoke; references, callees and the call graph show the method the delegate calls.
        using var env = new Env(Fixture());
        var refs = env.Workspace.Read(() => env.References.FindReferences(env.One("Proxies.Targets::Add"), true, 100, default));
        var through = refs.Items.Where(r => r.Kind == "delegate").Select(r => $"{((MethodDef)r.Where).Name} {r.Detail}").ToList();
        Assert.Contains(through, s => s.StartsWith("UseAdd via Proxies.Calls::", StringComparison.Ordinal));
        Assert.Contains(through, s => s.StartsWith("UseNeg via Proxies.Calls::", StringComparison.Ordinal));
        Assert.Contains(through, s => s.StartsWith("UseAdd via Proxies.Direct::AddF", StringComparison.Ordinal));

        var callees = env.Workspace.Read(() => env.References.FindCallees(env.Def<MethodDef>("Proxies.Calls::UseTwice", SymbolKind.Method)));
        Assert.Equal(2, callees.Count(c => c.Target == "Proxies.Box::Twice()" && c.OpCode.StartsWith("callvirt via Proxies.Calls::~", StringComparison.Ordinal)));

        var graph = new NetDecompilerMcp.Services.CallGraphService(env.Workspace);
        var tree = env.Workspace.Read(() => graph.Tree(env.Fixture, env.Def<MethodDef>("Proxies.Targets::Neg", SymbolKind.Method), callers: true, 2, 50, false, default));
        Assert.Contains("Proxies.Calls::UseNeg", tree);
        Assert.Contains("via Proxies.Calls::", tree);
    }

    [Theory]
    [InlineData("UseSwapped", "Swapped", "reads mutable static field Proxies.Unprovable::Swapped")]
    [InlineData("UseVisible", "Visible", "reads mutable static field Proxies.Unprovable::Visible")]
    [InlineData("UseBound", "Bound", "creates a delegate bound to an object")]
    public void UnprovableDelegateCallsAreKeptAndReported(string method, string field, string why)
    {
        using var env = new Env(Fixture());
        var before = string.Join("\n", Body(env, "Proxies.Unprovable::" + method));
        var report = Simplify(env, "Proxies.Unprovable::" + method);
        Assert.Contains("Not rewritten (the code is kept; the other passes still apply):", report);
        Assert.Matches($@"call through Proxies\.Unprovable::{field} at IL_\w{{4}}: .*{System.Text.RegularExpressions.Regex.Escape(why)}.* \[delegate-target\]", report);
        Assert.Equal(before, string.Join("\n", Body(env, "Proxies.Unprovable::" + method)));
    }
}
