using dnlib.DotNet;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Services;

namespace NetDecompilerMcp.Tests;

/// <summary>
/// export_il2cpp_symbols on a module shaped like a dumper's dummy DLL: generic instances laid out where the dumpers
/// write offset 0, static fields, fixed buffers, C and C++ keywords, and C prototypes in the scripts and script.json.
/// </summary>
public sealed class Il2CppLayoutTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private const string Source = """
        using System;
        namespace Il2CppDummyDll
        {
            public class FieldOffsetAttribute : Attribute { public string Offset; }
            public class AddressAttribute : Attribute { public string RVA; public string Offset; public string VA; }
        }
        namespace Game
        {
            using Il2CppDummyDll;
            public struct Vec { [FieldOffset(Offset = "0x0")] public float x; [FieldOffset(Offset = "0x4")] public float y; [FieldOffset(Offset = "0x8")] public float z; }
            // Generic definitions: the dumpers give their fields offset 0.
            public struct Pair<T> { [FieldOffset(Offset = "0x0")] public bool hasValue; [FieldOffset(Offset = "0x0")] public T value; }
            public class Base<T> { [FieldOffset(Offset = "0x0")] public int Count; [FieldOffset(Offset = "0x0")] public T Item; }
            public class Derived : Base<Vec> { [FieldOffset(Offset = "0x20")] public int Own; }
            public class Holder
            {
                [FieldOffset(Offset = "0x10")] public Pair<bool> flag;
                [FieldOffset(Offset = "0x12")] public bool after;
                [FieldOffset(Offset = "0x18")] public Pair<long> wide;
                [FieldOffset(Offset = "0x28")] public int @class;
                [FieldOffset(Offset = "0x2C")] public int asm;
                [FieldOffset(Offset = "0x8")] public static int Counter;
                [FieldOffset(Offset = "0x0")] public static Holder Instance;
                [Address(RVA = "0x1000", Offset = "0x400", VA = "0x180001000")]
                public Pair<bool> Get(Vec v, ref int n, Holder other) { return default; }
                [Address(RVA = "0x1100", Offset = "0x500", VA = "0x180001100")]
                public static void Reset() { }
            }
            public unsafe struct Buffered { [FieldOffset(Offset = "0x0")] public int Length; [FieldOffset(Offset = "0x4")] public fixed byte Data[24]; }
            public class UsesBuffer { [FieldOffset(Offset = "0x10")] public Buffered buffer; [FieldOffset(Offset = "0x2C")] public int next; }
        }
        """;

    private string Export()
    {
        var image = Roslyn.Compile("Game", Source, new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary, allowUnsafe: true));
        // The dumpers write type arguments as classes, value types included.
        using (var module = ModuleDefMD.Load(image))
        {
            var derived = module.Find("Game.Derived", false)!;
            var baseInst = (GenericInstSig)((TypeSpec)derived.BaseType).TypeSig;
            baseInst.GenericArguments[0] = new ClassSig(((TypeDefOrRefSig)baseInst.GenericArguments[0]).TypeDefOrRef);
            module.Write(_dir.File("Game.dll"));
        }
        using var ws = new AssemblyWorkspace(new ServerOptions { BackgroundIndexing = false, WatchFiles = false });
        ws.Load(_dir.File("Game.dll"));
        var result = ws.Read(() => new Il2CppExporter(new Il2CppService(ws)).Export(ws.Assemblies, _dir.Path, "all", "game", default));
        Assert.Equal(2, result.Methods);
        return File.ReadAllText(_dir.File("game.h"));
    }

    private static string Struct(string header, string name)
    {
        int start = header.IndexOf($"struct {name} {{", StringComparison.Ordinal);
        Assert.True(start >= 0, $"no struct {name}");
        return header[start..(header.IndexOf("};", start, StringComparison.Ordinal) + 2)];
    }

    [Fact]
    public void GenericValueTypeInstancesAreLaidOutAndEmbedded()
    {
        var header = Export();
        Assert.Contains("nd_u8 hasValue;  /* 0x0 bool (computed) */", Struct(header, "Game_Pair_1_bool_"));
        Assert.Contains("nd_u8 value;  /* 0x1 bool (computed) */", Struct(header, "Game_Pair_1_bool_"));
        // long aligns to 8: the instance is 16 bytes, with an explicit tail.
        var wide = Struct(header, "Game_Pair_1_long_");
        Assert.Contains("nd_i64 value;  /* 0x8 long (computed) */", wide);
        var holder = Struct(header, "Game_Holder");
        Assert.Contains("struct Game_Pair_1_bool_ flag;  /* 0x10 Pair<bool> */", holder);
        Assert.Contains("nd_u8 after;  /* 0x12 bool */", holder); // kept: the instance is 2 bytes, not a pointer
        Assert.Contains("struct Game_Pair_1_long_ wide;  /* 0x18 Pair<long> */", holder);
        // No struct for an open definition: its dumped offsets are all 0.
        Assert.DoesNotContain("struct Game_Pair_1 {", header);
        Assert.DoesNotContain("struct Game_Base_1 {", header);
    }

    [Fact]
    public void FieldsOfAGenericBaseInstanceAreLaidOutBeforeTheDerivedClass()
    {
        var derived = Struct(Export(), "Game_Derived");
        Assert.Contains("nd_i32 Count;  /* 0x10 int (computed) */", derived);
        Assert.Contains("struct Game_Vec Item;  /* 0x14 Vec (computed) */", derived);
        Assert.Contains("nd_i32 Own;  /* 0x20 int */", derived);
    }

    [Fact]
    public void StaticFieldsFixedBuffersAndKeywords()
    {
        var header = Export();
        var statics = Struct(header, "Game_Holder_StaticFields");
        Assert.Contains("nd_ptr Instance;  /* 0x0 Holder */", statics);
        Assert.Contains("nd_i32 Counter;  /* 0x8 int */", statics);
        var holder = Struct(header, "Game_Holder");
        Assert.Contains("nd_i32 class_;", holder);
        Assert.Contains("nd_i32 asm_;", holder);
        Assert.Contains("nd_u8 Data[0x18];  /* 0x4 <Data>e__FixedBuffer */", Struct(header, "Game_Buffered"));
        Assert.Contains("nd_i32 next;  /* 0x2C int */", Struct(header, "Game_UsesBuffer"));
        Assert.Contains("#pragma pack(push, 1)", header);
    }

    [Fact]
    public void ScriptsAndJsonCarryCPrototypes()
    {
        Export();
        const string get = "struct Game_Pair_1_bool_ Game_Holder__Get(struct Game_Holder* __this, struct Game_Vec v, nd_i32* n, nd_ptr other, nd_ptr method);";
        var ida = File.ReadAllText(_dir.File("game_ida.py"));
        Assert.Contains(get, ida);
        Assert.Contains("void Game_Holder__Reset(nd_ptr method);", ida);
        Assert.Contains("idc.SetType(ea, prototype)", ida);
        Assert.True(ida.IndexOf("parse_decls", StringComparison.Ordinal) < ida.IndexOf("SetType", StringComparison.Ordinal), "the header is imported before the prototypes");
        Assert.Contains("ApplyFunctionSignatureCmd", File.ReadAllText(_dir.File("game_ghidra.py")));
        Assert.Contains($"\"Signature\": \"{get}\"", File.ReadAllText(_dir.File("game_script.json")));
    }

    private const string Clang = @"C:\Program Files\LLVM\bin\clang.exe";

    [Fact]
    public void HeaderAndPrototypesCompileAsCAndCpp()
    {
        var header = Export();
        if (!File.Exists(Clang)) return;
        var prototypes = File.ReadAllLines(_dir.File("game_ida.py")).Where(l => l.StartsWith("    (0x", StringComparison.Ordinal))
            .Select(l => l[(l.LastIndexOf(", \"", StringComparison.Ordinal) + 3)..l.LastIndexOf("\")", StringComparison.Ordinal)]);
        File.WriteAllText(_dir.File("check.h"), header + "\n" + string.Join("\n", prototypes) + "\n");
        foreach (var lang in new[] { "c", "c++" })
        {
            var (code, output) = Tools.Run(Clang, $"-fsyntax-only -x {lang} \"{_dir.File("check.h")}\"");
            Assert.True(code == 0, $"{lang}: {output}");
        }
    }
}
