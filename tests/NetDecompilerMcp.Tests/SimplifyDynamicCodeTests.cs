using System.Runtime.Loader;
using dnlib.DotNet;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using NetDecompilerMcp.Services.Simplify;
using SymbolKind = NetDecompilerMcp.Core.SymbolKind;

namespace NetDecompilerMcp.Tests;

/// <summary>
/// The two ways to build a dynamic method's code, ILGenerator.Emit and DynamicILInfo.SetCode with tokens from
/// GetTokenFor, are modelled alike: the same delegates built either way resolve and fold the same, and code outside
/// the modelled subset (locals, branches) is kept either way. The fixture runs before and after.
/// </summary>
public sealed class SimplifyDynamicCodeTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private const string Source = """
        using System;
        using System.Reflection;
        using System.Reflection.Emit;

        namespace Dyn
        {
            internal delegate int IntIntInt(int a, int b);
            internal delegate string StrDelegate(int k);

            public static class Targets
            {
                public static int Add(int a, int b) => a + b;
                internal static string Decode(int k) => new string((char)('a' + k), 3);
            }

            internal static class Build
            {
                internal static readonly MethodInfo AddM = typeof(Targets).GetMethod("Add");
                internal static readonly MethodInfo DecodeM = typeof(Targets).GetMethod("Decode", BindingFlags.Static | BindingFlags.NonPublic);

                // ldarg.0 [ldarg.1] [ldc.i4 k; sub] tail. call target; ret
                internal static Delegate Gen(Type type, Type ret, Type[] args, MethodInfo target, int subtract)
                {
                    var dm = new DynamicMethod(string.Empty, ret, args, typeof(Build).Module, true);
                    ILGenerator il = dm.GetILGenerator();
                    il.Emit(OpCodes.Ldarg_0);
                    if (args.Length > 1) il.Emit(OpCodes.Ldarg_1);
                    if (subtract != 0)
                    {
                        il.Emit(OpCodes.Ldc_I4, subtract);
                        il.Emit(OpCodes.Sub);
                    }
                    il.Emit(OpCodes.Tailcall);
                    il.Emit(OpCodes.Call, target);
                    il.Emit(OpCodes.Ret);
                    return dm.CreateDelegate(type);
                }

                // The same code as bytes.
                internal static Delegate Info(Type type, Type ret, Type[] args, MethodInfo target, int subtract)
                {
                    var dm = new DynamicMethod(string.Empty, ret, args, typeof(Build).Module, true);
                    DynamicILInfo info = dm.GetDynamicILInfo();
                    var code = new byte[32];
                    int n = 0;
                    code[n++] = 0x02;
                    if (args.Length > 1) code[n++] = 0x03;
                    if (subtract != 0)
                    {
                        code[n++] = 0x20;
                        n = Put(code, n, subtract);
                        code[n++] = 0x59;
                    }
                    code[n++] = 0xFE;
                    code[n++] = 0x14;
                    code[n++] = 0x28;
                    n = Put(code, n, info.GetTokenFor(target.MethodHandle));
                    code[n++] = 0x2A;
                    var exact = new byte[n];
                    Array.Copy(code, exact, n);
                    info.SetCode(exact, 8);
                    info.SetLocalSignature(new byte[] { 0x07, 0x00 });
                    return dm.CreateDelegate(type);
                }

                // Outside the modelled subset: a local (stloc.0; ldloc.0) or a branch (br.s +0).
                internal static Delegate GenLocal()
                {
                    var dm = new DynamicMethod(string.Empty, typeof(int), new[] { typeof(int), typeof(int) }, typeof(Build).Module, true);
                    ILGenerator il = dm.GetILGenerator();
                    il.DeclareLocal(typeof(int));
                    il.Emit(OpCodes.Ldarg_0);
                    il.Emit(OpCodes.Stloc_0);
                    il.Emit(OpCodes.Ldloc_0);
                    il.Emit(OpCodes.Ldarg_1);
                    il.Emit(OpCodes.Call, AddM);
                    il.Emit(OpCodes.Ret);
                    return dm.CreateDelegate(typeof(IntIntInt));
                }

                internal static Delegate InfoLocal()
                {
                    var dm = new DynamicMethod(string.Empty, typeof(int), new[] { typeof(int), typeof(int) }, typeof(Build).Module, true);
                    DynamicILInfo info = dm.GetDynamicILInfo();
                    var code = new byte[] { 0x02, 0x0A, 0x06, 0x03, 0x28, 0, 0, 0, 0, 0x2A };
                    Put(code, 5, info.GetTokenFor(AddM.MethodHandle));
                    info.SetCode(code, 8);
                    info.SetLocalSignature(new byte[] { 0x07, 0x01, 0x08 });
                    return dm.CreateDelegate(typeof(IntIntInt));
                }

                internal static Delegate GenBranch()
                {
                    var dm = new DynamicMethod(string.Empty, typeof(int), new[] { typeof(int), typeof(int) }, typeof(Build).Module, true);
                    ILGenerator il = dm.GetILGenerator();
                    Label next = il.DefineLabel();
                    il.Emit(OpCodes.Br_S, next);
                    il.MarkLabel(next);
                    il.Emit(OpCodes.Ldarg_0);
                    il.Emit(OpCodes.Ldarg_1);
                    il.Emit(OpCodes.Call, AddM);
                    il.Emit(OpCodes.Ret);
                    return dm.CreateDelegate(typeof(IntIntInt));
                }

                internal static Delegate InfoBranch()
                {
                    var dm = new DynamicMethod(string.Empty, typeof(int), new[] { typeof(int), typeof(int) }, typeof(Build).Module, true);
                    DynamicILInfo info = dm.GetDynamicILInfo();
                    var code = new byte[] { 0x2B, 0x00, 0x02, 0x03, 0x28, 0, 0, 0, 0, 0x2A };
                    Put(code, 5, info.GetTokenFor(AddM.MethodHandle));
                    info.SetCode(code, 8);
                    info.SetLocalSignature(new byte[] { 0x07, 0x00 });
                    return dm.CreateDelegate(typeof(IntIntInt));
                }

                private static int Put(byte[] b, int n, int v)
                {
                    b[n] = (byte)v;
                    b[n + 1] = (byte)(v >> 8);
                    b[n + 2] = (byte)(v >> 16);
                    b[n + 3] = (byte)(v >> 24);
                    return n + 4;
                }
            }

            public static class ViaGen
            {
                private static readonly IntIntInt Add = (IntIntInt)Build.Gen(typeof(IntIntInt), typeof(int), new[] { typeof(int), typeof(int) }, Build.AddM, 0);
                private static readonly StrDelegate Str = (StrDelegate)Build.Gen(typeof(StrDelegate), typeof(string), new[] { typeof(int) }, Build.DecodeM, 3);
                public static int UseAdd(int x) => Add(x, 7);
                public static string UseStr(int x) => Str(x) + Str(5);
            }

            public static class ViaGenLocal
            {
                private static readonly IntIntInt Local = (IntIntInt)Build.GenLocal();
                public static int UseLocal(int x) => Local(x, 1);
            }

            public static class ViaGenBranch
            {
                private static readonly IntIntInt Branch = (IntIntInt)Build.GenBranch();
                public static int UseBranch(int x) => Branch(x, 2);
            }

            public static class ViaInfo
            {
                private static readonly IntIntInt Add = (IntIntInt)Build.Info(typeof(IntIntInt), typeof(int), new[] { typeof(int), typeof(int) }, Build.AddM, 0);
                private static readonly StrDelegate Str = (StrDelegate)Build.Info(typeof(StrDelegate), typeof(string), new[] { typeof(int) }, Build.DecodeM, 3);
                public static int UseAdd(int x) => Add(x, 7);
                public static string UseStr(int x) => Str(x) + Str(5);
            }

            public static class ViaInfoLocal
            {
                private static readonly IntIntInt Local = (IntIntInt)Build.InfoLocal();
                public static int UseLocal(int x) => Local(x, 1);
            }

            public static class ViaInfoBranch
            {
                private static readonly IntIntInt Branch = (IntIntInt)Build.InfoBranch();
                public static int UseBranch(int x) => Branch(x, 2);
            }
        }
        """;

    private string Fixture()
    {
        var path = _dir.File("Dyn.dll");
        if (File.Exists(path)) return path;
        File.WriteAllBytes(path, Roslyn.Release("Dyn", Source));
        return path;
    }

    private static object? Run(byte[] image, string type, string method, object arg)
    {
        var context = new AssemblyLoadContext(null, isCollectible: true);
        try
        {
            var asm = context.LoadFromStream(new MemoryStream(image));
            return asm.GetType(type, throwOnError: true)!.GetMethod(method)!.Invoke(null, [arg]);
        }
        finally
        {
            context.Unload();
        }
    }

    private static string Simplify(Env env, string symbol) =>
        env.Edit(() => env.Edits.SimplifyMethods(env.One(symbol).Assembly, env.One(symbol), SimplifyOptions.Parse(null, null, null), false, default));

    private static string Body(Env env, string method) =>
        string.Join("\n", env.Def<MethodDef>(method, SymbolKind.Method).Body.Instructions.Select(i => $"{i.OpCode} {i.Operand}"));

    [Theory]
    [InlineData("UseAdd", "resolved Dyn.ViaGen::Add.Invoke -> Dyn.Targets::Add(int, int) at IL_")]
    [InlineData("UseStr", "folded Dyn.Targets::Decode(int) -> \"ccc\"")]
    public void BothWaysResolveAndFoldAlike(string method, string expected)
    {
        using var env = new Env(Fixture());
        var gen = Simplify(env, "Dyn.ViaGen::" + method);
        var info = Simplify(env, "Dyn.ViaInfo::" + method);
        Assert.Contains(expected, gen);
        Assert.Equal(gen, info.Replace("ViaInfo", "ViaGen"));
        Assert.Equal(Body(env, "Dyn.ViaGen::" + method), Body(env, "Dyn.ViaInfo::" + method).Replace("ViaInfo", "ViaGen"));

        var image = env.Fixture.GetImageBytes();
        foreach (var x in new[] { 0, 4, 9 })
        {
            Assert.Equal(Run(env.Fixture.OriginalBytes, "Dyn.ViaGen", method, x), Run(image, "Dyn.ViaGen", method, x));
            Assert.Equal(Run(env.Fixture.OriginalBytes, "Dyn.ViaInfo", method, x), Run(image, "Dyn.ViaInfo", method, x));
        }
    }

    [Theory]
    [InlineData("UseLocal", "Local", "ILGenerator::DeclareLocal", "declares locals of a dynamic method (locals of dynamic methods are not modelled)")]
    [InlineData("UseBranch", "Branch", "ILGenerator::DefineLabel", "emits br.s with an operand the interpreter does not model")]
    public void CodeOutsideTheSubsetIsKeptEitherWay(string method, string field, string genWhy, string infoWhy)
    {
        using var env = new Env(Fixture());
        string gt = $"Dyn.ViaGen{field}", it = $"Dyn.ViaInfo{field}";
        var genBefore = Body(env, $"{gt}::{method}");
        var infoBefore = Body(env, $"{it}::{method}");
        var gen = Simplify(env, $"{gt}::{method}");
        var info = Simplify(env, $"{it}::{method}");
        Assert.Matches($@"call through {System.Text.RegularExpressions.Regex.Escape(gt)}::{field} at IL_\w{{4}}: .*{System.Text.RegularExpressions.Regex.Escape(genWhy)}.* \[delegate-target\]", gen);
        Assert.Matches($@"call through {System.Text.RegularExpressions.Regex.Escape(it)}::{field} at IL_\w{{4}}: .*{System.Text.RegularExpressions.Regex.Escape(infoWhy)}.* \[delegate-target\]", info);
        Assert.Equal(genBefore, Body(env, $"{gt}::{method}"));
        Assert.Equal(infoBefore, Body(env, $"{it}::{method}"));
    }
}
