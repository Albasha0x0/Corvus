using System.Diagnostics;
using dnlib.DotNet;
using System.Text.RegularExpressions;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;

namespace Corvus.Tests;

/// <summary>A missing dependency is stubbed from its usage so decompilation and export still work.</summary>
public class MissingReferenceTests : IDisposable
{
    private readonly TempDir _dir = new();
    public void Dispose() => _dir.Dispose();

    private const string Library = """
        using System;
        namespace Lib
        {
            public struct Point { public int X, Y; public Point(int x, int y) { X = x; Y = y; } public int Length => X + Y; }
            public enum Mode { Off, On, Auto }
            public interface IShape { double Area(); string Name { get; } }
            public delegate void Changed(object sender, int value);
            public class LibException : Exception { public LibException(string m) : base(m) { } }
            [AttributeUsage(AttributeTargets.All)] public class TagAttribute : Attribute { public TagAttribute(string name) { } }
            public interface IEvent { }
            public static class Events { public static void Raise<T>(in T e) where T : struct, IEvent { } }
            public abstract class Widget
            {
                public string Title { get; set; } = "";
                public event Changed OnChanged;
                public static int Count;
                protected virtual int Measure(int width) => width;
                public void Fire(int v) => OnChanged?.Invoke(this, v);
                public Box<T> Wrap<T>(T value) => new Box<T> { Value = value };
            }
            public class Box<T> { public T Value; }
        }
        """;

    private const string App = """
        using System;
        using Lib;
        namespace App
        {
            public struct Moved : IEvent { public int Distance; }
            [Tag("panel")]
            public sealed class Panel : Widget, IShape
            {
                public double Area() => 1.0;
                public string Name => Title;
                protected override int Measure(int width) => width * 2;

                public int Use(Point p, Mode mode)
                {
                    Title = "panel " + p.Length;
                    Count++;
                    OnChanged += (s, v) => Console.WriteLine(v);
                    var box = Wrap(p);
                    Events.Raise(new Moved { Distance = box.Value.X });
                    try { if (mode == Mode.Auto) throw new LibException("auto"); }
                    catch (LibException e) { Title = e.Message; }
                    return box.Value.Y + Measure(p.X);
                }
            }
        }
        """;

    private static byte[] Compile(string name, string source, params byte[][] references)
    {
        return Roslyn.Compile(name, source,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary, optimizationLevel: OptimizationLevel.Release),
            references.Select(r => MetadataReference.CreateFromImage(r)));
    }

    [Trait("Speed", "Slow")]
    [Fact]
    public void MissingDependency_IsRebuiltFromUse_SoTheRestDecompilesAndBuilds()
    {
        var lib = Compile("Lib", Library);
        var app = _dir.File("App.dll");
        File.WriteAllBytes(app, Compile("App", App, lib)); // Lib.dll is not written: missing
        using var env = new Env(app);

        Assert.Matches(@"Lib, Version=0\.0\.0\.0.*\[not found; stub built from what the loaded code uses \(\d+ types, \d+ members\)\]", env.Report.Build(env.Fixture));

        var code = env.Decompile("App.Panel");
        Assert.DoesNotContain("missing references", code);
        Assert.DoesNotContain("get_Title", code);         // a property, not an accessor call
        Assert.DoesNotContain("add_OnChanged", code);     // an event
        Assert.Contains("Title = \"panel \" + p.Length;", code);
        Assert.Contains("OnChanged += ", code);
        Assert.Contains("protected override int Measure(int width)", code);
        Assert.Contains("if (mode == (Mode)2)", code);  // enum member names are not recoverable from usage
        Assert.Contains("OnChanged += (object s, int v) =>", code); // a delegate type: the lambda comes back
        Assert.DoesNotContain("__ldftn", code);
        Assert.Contains("catch (LibException ", code);

        // The export references the stub and builds.
        var out_ = _dir.File("export");
        var result = env.Decompiler.ExportProject(env.Fixture, out_, null, default);
        Assert.True(File.Exists(Path.Combine(out_, "lib", "Lib.dll")));
        Assert.Contains("not found on the machine that exported this project", File.ReadAllText(result.ProjectFile!));
        var (exitCode, output) = Tools.Dotnet(null, "build", result.ProjectFile!, "-nologo", "-clp:NoSummary;ErrorsOnly");
        Assert.True(exitCode == 0, string.Join("\n", Regex.Matches(output, @"[^\\/\r\n]+\.cs\(\d+,\d+\): error [^\r\n]*").Select(m => m.Value).Distinct()));
    }

    /// <summary>
    /// An exported project of MediatR (MediatR.Contracts missing) did not build: the stub left out types named only by
    /// [assembly: TypeForwardedTo], and its ref readonly property lacked [IsReadOnly], so C# rejected it (CS0570).
    /// </summary>
    [Fact]
    public void MissingDependency_StubHasForwardedTypesAndReadOnlyRefs()
    {
        var lib = Compile("Lib", """
            namespace Lib
            {
                public class Moved { }
                public interface IMarker<T> { }
                public struct Unit { private static readonly Unit _value; public static ref readonly Unit Value => ref _value; }
            }
            """);
        var app = _dir.File("App.dll");
        File.WriteAllBytes(app, Compile("App", """
            [assembly: System.Runtime.CompilerServices.TypeForwardedTo(typeof(Lib.Moved))]
            [assembly: System.Runtime.CompilerServices.TypeForwardedTo(typeof(Lib.IMarker<>))]
            namespace App { public class Uses { public Lib.Unit Get() => Lib.Unit.Value; } }
            """, lib));
        using var env = new Env(app);
        var stub = Corvus.Core.ReferenceStubs.Build("Lib", null, [env.Fixture]);
        Assert.NotNull(stub);
        using var module = dnlib.DotNet.ModuleDefMD.Load(stub.Value.Image);
        Assert.NotNull(module.Find("Lib.Moved", isReflectionName: false));
        Assert.NotNull(module.Find("Lib.IMarker`1", isReflectionName: false));
        Compile("Consumer", """
            [assembly: System.Runtime.CompilerServices.TypeForwardedTo(typeof(Lib.Moved))]
            public class C { public Lib.Unit Get() => Lib.Unit.Value; }
            """, stub.Value.Image);
    }

    /// <summary>
    /// Building one stub read the owner's attributes, whose enum argument resolved the other missing assembly, whose stub
    /// read the same attribute list again: dnlib's list lock is not re-entrant (LockException on LINQPad and Codist).
    /// </summary>
    [Fact]
    public void TwoMissingDependencies_ThroughEnumAttributeArguments_OnOneOwner()
    {
        var a = Compile("LibA", "namespace LibA { public enum ModeA { Off, On } }");
        var b = Compile("LibB", "namespace LibB { public enum ModeB { Low, High } }");
        var app = _dir.File("App.dll");
        File.WriteAllBytes(app, Compile("App", """
            using System;
            namespace App
            {
                public sealed class UsesAttribute : Attribute { public UsesAttribute(LibA.ModeA a, LibB.ModeB b) { } }
                [Uses(LibA.ModeA.On, LibB.ModeB.High)]
                public class Owner { public LibA.ModeA A; public LibB.ModeB B; }
            }
            """, a, b));
        using var env = new Env(app);

        var report = env.Report.Build(env.Fixture);
        Assert.Matches(@"LibA, .*\[not found; stub built", report);
        Assert.Matches(@"LibB, .*\[not found; stub built", report);
        Assert.Contains("[Uses(", env.Decompile("App.Owner"));
        // Both resolve now that no build is in progress: the nested miss was not cached.
        var owner = env.Def<TypeDef>("App.Owner");
        Assert.All(owner.Fields, f => Assert.NotNull(f.FieldType.ToTypeDefOrRef().ResolveTypeDef()));
    }

    [Fact]
    public void LocalFunction_CapturedByLambdas_IsNotLost()
    {
        var path = _dir.File("Local.dll");
        File.WriteAllBytes(path, Compile("Local", """
            using System;
            public class Party
            {
                public Action? Confirm;
                public int Sent;
                public void Join(int room, bool ask)
                {
                    int target = room * 10;
                    bool flag = !ask;
                    if (flag) { DoTransit(); return; }
                    Confirm = () => { if (target > 0) DoTransit(); };
                    void DoTransit() { Sent += target; Console.WriteLine(target + this.Sent); }
                }
            }
            """));
        using var env = new Env(path);
        var code = env.Decompile("Party::Join");
        Assert.Contains("void DoTransit()", code);
        Assert.Contains("Sent += target;", code);
        Assert.DoesNotContain("<>", code);
        Assert.DoesNotContain("DisplayClass", code);
    }
}
