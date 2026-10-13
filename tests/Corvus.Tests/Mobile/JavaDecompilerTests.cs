using System.Text.Json.Nodes;
using Corvus.Core;
using Corvus.Services.Mobile;
using static Corvus.Tests.AndroidSamples;

namespace Corvus.Tests;

/// <summary>decompile_java against a stand-in JADX server (the fake tool) and, with CORVUS_JAVA_DECOMPILER, the real one.</summary>
[Collection(ExternalToolEnvironmentCollection.Name)]
public sealed class JavaDecompilerTests(Xunit.Abstractions.ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly FakeTool _fake = new();

    public void Dispose()
    {
        _fake.Dispose();
        _dir.Dispose();
    }

    private string Apk() => Save(_dir, "app.apk", AndroidSamples.Apk(30, ("classes.dex", Dex())));

    private (JavaDecompilerService Service, EnvironmentScope Env) Fake()
    {
        var jar = Path.Combine(_fake.Directory, "jadx-headless-mcp-0.7.1-all.jar");
        File.WriteAllBytes(jar, [0x50, 0x4B, 3, 4]);
        _fake.Set("mcp", new JsonObject
        {
            ["get_methods_of_class"] = FakeTool.Json(new { items = new[] { new { name = "compute", signature = "compute(int): int" }, new { name = "compute", signature = "compute(String): int" } } }),
        });
        var env = new EnvironmentScope().Set("CORVUS_JAVA", _fake.CopyAs("java")).Set("CORVUS_JAVA_DECOMPILER", jar);
        return (new JavaDecompilerService(new DexService()) { Environment = _fake.Environment }, env);
    }

    [Fact]
    public async Task ClassesAndExactOverloads_OneSessionPerPackage()
    {
        var (service, env) = Fake();
        using (env)
        using (service)
        {
            var apk = Apk();
            Assert.Equal($"// {Main} (JADX)\n// source of com.example.app.Main", await service.Decompile(apk, "com.example.app.Main", true, default));
            var text = await service.Decompile(apk, "com.example.app.Main::compute(String)", true, default);
            Assert.StartsWith($"// {ComputeString} (JADX, java, overload 2 of 2 matched by parameter types)", text);
            Assert.Contains("compute overload 1", text);
            Assert.Contains("overload 1 of 2", await service.Decompile(apk, ComputeInt, false, default));
            var calls = _fake.Calls.OfType<JsonObject>().ToList();
            Assert.Single(calls, c => (string?)c["tool"] == "load_apk");
            Assert.Equal(apk, (string?)calls.First(c => (string?)c["tool"] == "load_apk")["arguments"]!["path"]);
            Assert.False((bool)calls.Last(c => (string?)c["tool"] == "get_method_body")["arguments"]!["smali_fallback"]!);
            Assert.Single(_fake.ArgumentLists, a => a.Contains("-jar")); // one server process

            Assert.Equal(ErrorCode.NotFound, (await Assert.ThrowsAsync<ToolError>(() => service.Decompile(apk, "Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I", true, default))).Code);
            Assert.Equal(ErrorCode.Ambiguous, (await Assert.ThrowsAsync<ToolError>(() => service.Decompile(apk, "com.example.app.Main::compute", true, default))).Code);
        }
    }

    /// <summary>A package with a member class, an anonymous class and a lambda class, which JADX writes inside other code.</summary>
    private string NestedApk()
    {
        var b = new DexBuilder();
        var outer = b.Class("Lp/Outer;", 1, source: "Outer.java");
        outer.Method("run", "V", [], 1, Asm.NewInstance(0, "Lp/Outer$1;"), Asm.ReturnVoid()).Registers = 2;
        outer.Method("make", "V", [], 1, Asm.NewInstance(0, "Lp/L;"), Asm.ReturnVoid()).Registers = 2;
        var named = b.Class("Lp/Outer$Named;", 9, source: "Outer.java");
        named.Annotations.Add(("Ldalvik/annotation/EnclosingClass;", 2, [("value", "Lp/Outer;")]));
        named.Annotations.Add(("Ldalvik/annotation/InnerClass;", 2, [("accessFlags", 9), ("name", "Named")]));
        var anonymous = b.Class("Lp/Outer$1;", 0x10, source: "Outer.java");
        anonymous.Annotations.Add(("Ldalvik/annotation/EnclosingMethod;", 2, [("value", "Lp/Outer;->run()V")]));
        anonymous.Annotations.Add(("Ldalvik/annotation/InnerClass;", 2, [("accessFlags", 0), ("name", null!)]));
        anonymous.Method("a", "V", [], 1, Asm.ReturnVoid()).Registers = 1;
        b.Class("Lp/L;", 0x1011, source: "Outer.java");
        return Save(_dir, "nested.apk", AndroidSamples.Apk(30, ("classes.dex", b.Build())));
    }

    [Fact]
    public async Task NestedClasses_ComeFromWhereJadxWritesThem()
    {
        var (service, env) = Fake();
        using (env)
        using (service)
        {
            _fake.Set("mcp", new JsonObject
            {
                ["get_class_source"] = new JsonObject
                {
                    ["p.Outer"] = "package p;\r\n\r\npublic class Outer {\r\n\r\n    /* loaded from: classes.dex */\r\n    public static class Named {\r\n        void f() { String s = \"}\"; }\r\n    }\r\n\r\n    void run() { }\r\n}\r\n",
                    ["p.Outer$Named"] = "",
                    ["*"] = "!class not found",
                },
                ["get_method_body"] = new JsonObject { ["p.Outer$1"] = "!class did not resolve", ["*"] = "{\"mode\":\"java\",\"body\":\"    void host() { }\"}" },
            });
            var apk = NestedApk();
            Assert.Equal("// Lp/Outer$Named; (JADX, from the source of Lp/Outer;)\n/* loaded from: classes.dex */\npublic static class Named {\n    void f() { String s = \"}\"; }\n}",
                await service.Decompile(apk, "p.Outer$Named", true, default));
            Assert.Equal("// Lp/Outer$1; is an anonymous class inside Lp/Outer;->run()V; JADX writes it there:\n// Lp/Outer;->run()V (JADX, java)\n    void host() { }",
                await service.Decompile(apk, "Lp/Outer$1;", true, default));
            Assert.StartsWith("// Lp/L; is a lambda class inside Lp/Outer;->make()V;", await service.Decompile(apk, "p.L", true, default));
            Assert.StartsWith("// Lp/Outer$1;->a()V: in a class JADX writes elsewhere\n// Lp/Outer$1; is an anonymous class", await service.Decompile(apk, "Lp/Outer$1;->a()V", true, default));
        }
    }

    /// <summary>A jar of .class files goes to JADX by name, without a DEX index.</summary>
    [Fact]
    public async Task ClassFileJar_DecompilesByName()
    {
        var (service, env) = Fake();
        using (env)
        using (service)
        {
            var jar = Save(_dir, "lib.jar", ContainerFixtures.Zip(("p/A.class", [0xCA, 0xFE, 0xBA, 0xBE])));
            Assert.Equal("// p.A (JADX)\n// source of p.A", await service.Decompile(jar, "p.A", true, default));
            Assert.StartsWith("// p.A::compute(String) (JADX, java, overload 2 of 2)", await service.Decompile(jar, "p.A::compute(String)", true, default));
            Assert.StartsWith("// p.A::compute(I) (JADX, java, overload 1 of 2)", await service.Decompile(jar, "Lp/A;->compute(I)", true, default));
            Assert.Equal(ErrorCode.NotFound, (await Assert.ThrowsAsync<ToolError>(() => service.Decompile(jar, "p.A::compute(long)", true, default))).Code);
        }
    }

    [Fact]
    public async Task SmaliFallbackHint_NamesOurParameter()
    {
        var (service, env) = Fake();
        using (env)
        using (service)
        {
            _fake.Set("mcp", new JsonObject { ["get_class_source"] = "// (Java body was an anti-decompile stub; showing smali. Pass smali_fallback=false for the partial Java.)\n.class public Lx;" });
            var text = await service.Decompile(Apk(), "com.example.app.Main", true, default);
            Assert.Contains("Pass javaOnly=true for the partial Java.", text);
            Assert.DoesNotContain("smali_fallback", text);
        }
    }

    /// <summary>decompile_java asks JADX for smali where Java fails unless javaOnly (the default of the former smaliFallback=true).</summary>
    [Trait("Speed", "Slow")]
    [Fact]
    public async Task DecompileJava_SmaliFallbackByDefault_JavaOnlyTurnsItOff()
    {
        var (service, env) = Fake();
        using (env)
        using (service)
        {
            var dex = new DexService();
            var tools = new Corvus.Tools.AndroidTools(new AndroidPackageService(), dex, service, new JavaDotNetMap(new AssemblyWorkspace(), dex), new JniBindings(dex),
                new OutputPager(new ServerOptions()));
            var apk = Apk();
            bool Sent() => (bool)_fake.Calls.OfType<JsonObject>().Last(c => (string?)c["tool"] == "get_class_source")["arguments"]!["smali_fallback"]!;
            await tools.DecompileJava(apk, "com.example.app.Main");
            Assert.True(Sent());
            await tools.DecompileJava(apk, "com.example.app.Main", javaOnly: true);
            Assert.False(Sent());
        }
    }

    [Fact]
    public async Task ServerCrash_IsProviderUnavailable_AndTheNextCallStartsAgain()
    {
        var (service, env) = Fake();
        using (env)
        using (service)
        {
            var apk = Apk();
            _fake.Set("crashOnLoad", true);
            var error = await Assert.ThrowsAsync<ToolError>(() => service.Decompile(apk, "com.example.app.Main", true, default));
            Assert.Equal(ErrorCode.ProviderUnavailable, error.Code);
            Assert.Contains("exited", error.Message);
            _fake.Set("crashOnLoad", false);
            Assert.Contains("source of", await service.Decompile(apk, "com.example.app.Main", true, default));
        }
    }

    [Fact]
    public async Task WithoutJadx_NamesTheVariable()
    {
        using var env = new EnvironmentScope().Set("CORVUS_JAVA_DECOMPILER", Path.Combine(_dir.Path, "missing.jar"));
        using var service = new JavaDecompilerService(new DexService());
        var error = await Assert.ThrowsAsync<ToolError>(() => service.Decompile(Apk(), "com.example.app.Main", true, default));
        Assert.Equal(ErrorCode.ProviderUnavailable, error.Code);
        Assert.Contains("disassemble_dex", error.Message);
        Assert.Contains("CORVUS_JAVA_DECOMPILER", error.Remediation);
        // Not configured: the same call cannot succeed until the setting changes.
        Assert.False(error.Retryable);
        Assert.Contains("\"retryable\":false", error.ToJson());
        Assert.Contains("\"reason\":\"not_configured\"", error.ToJson());
    }

    /// <summary>The real JADX server (CORVUS_JAVA_DECOMPILER) decompiles the sample and picks the overload asked for.</summary>
    [Trait("Speed", "Slow")]
    [RequiresRealDataFact("CORVUS_JAVA_DECOMPILER")]
    public async Task RealJadx()
    {
        using var service = new JavaDecompilerService(new DexService());
        var apk = Apk();
        var cls = await service.Decompile(apk, "com.example.app.Helper", true, default);
        output.WriteLine(cls);
        Assert.Contains("class Helper", cls);
        Assert.Contains("Log.d(\"Example\"", cls);
        var method = await service.Decompile(apk, ComputeString, true, default);
        output.WriteLine(method);
        Assert.Contains("length()", method);
        Assert.DoesNotContain("COUNT", method);
        var other = await service.Decompile(apk, ComputeInt, true, default);
        Assert.Contains("COUNT", other);
    }
}
