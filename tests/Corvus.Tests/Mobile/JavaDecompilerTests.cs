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
        return (new JavaDecompilerService(new DexService()) { Environment = _fake.Environment, Cache = new JavaSourceCache(_dir.File("java-cache")) }, env);
    }

    /// <summary>
    /// A later server answers from the disk cache without starting JADX, hashing the package or indexing its DEX, under
    /// 50 ms; a changed package is decompiled again.
    /// </summary>
    [Fact]
    [Trait(PerfBudget.Trait, PerfBudget.Timing)]
    public async Task The_disk_cache_answers_a_later_server_without_JADX()
    {
        var (first, env) = Fake();
        using (env)
        {
            var apk = Apk();
            string cold;
            using (first) cold = await first.Decompile(apk, "com.example.app.Main", true, default);
            int starts = _fake.ArgumentLists.Count(a => a.Contains("-jar"));
            int hashed = first.Cache!.InputsHashed;
            var dex = new DexService();
            using var second = new JavaDecompilerService(dex) { Environment = _fake.Environment, Cache = first.Cache };
            // The JIT's first pass.
            await second.Decompile(apk, "com.example.app.Main", true, default);
            var before = MachineLoad.Factor();
            // The read's cost is the best of 5 calls: one call can also hold a blocking GC or a descheduled thread that
            // the suite beside it causes (up to 420 ms on a 3-core macOS runner, where the read's median is 0.4 ms).
            var best = TimeSpan.MaxValue;
            for (int i = 0; i < 5; i++)
            {
                var watch = System.Diagnostics.Stopwatch.StartNew();
                var warm = await second.Decompile(apk, "com.example.app.Main", true, default);
                best = TimeSpan.FromTicks(Math.Min(best.Ticks, watch.Elapsed.Ticks));
                Assert.Equal(cold, warm);
            }
            var (_, load) = MachineLoad.Budget(TimeSpan.FromMilliseconds(50), before, MachineLoad.Factor());
            Assert.Equal(starts, _fake.ArgumentLists.Count(a => a.Contains("-jar")));
            Assert.Equal(hashed, first.Cache.InputsHashed);
            Assert.Empty(dex.Cached());
            PerfBudget.Time("mobile/java-disk-cache-warm", best, TimeSpan.FromMilliseconds(50), output, load);
            File.SetLastWriteTimeUtc(apk, DateTime.UtcNow.AddMinutes(1));
            File.AppendAllText(apk, "x");
            _fake.Set("crashOnLoad", true);
            await Assert.ThrowsAsync<ToolError>(() => second.Decompile(apk, "com.example.app.Main", true, default));
        }
    }

    [Fact]
    public async Task Classes_and_exact_overloads_share_one_session_per_package()
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
            // One server process.
            Assert.Single(_fake.ArgumentLists, a => a.Contains("-jar"));

            Assert.Equal(ErrorCode.NotFound, (await Assert.ThrowsAsync<ToolError>(() => service.Decompile(apk, "Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I", true, default))).Code);
            Assert.Equal(ErrorCode.Ambiguous, (await Assert.ThrowsAsync<ToolError>(() => service.Decompile(apk, "com.example.app.Main::compute", true, default))).Code);
        }
    }

    [Fact]
    public async Task Mapping_resolves_original_names_and_heads_the_source_with_a_count()
    {
        var (service, env) = Fake();
        using (env)
        using (service)
        {
            var mapping = _dir.File("mapping.txt");
            File.WriteAllText(mapping, "com.example.Original -> com.example.app.Main:\n    int realCompute(int) -> compute\n");
            var text = await service.Decompile(Apk(), "com.example.Original", true, default, mapping);
            Assert.Equal($"// original names from mapping.txt: 0 identifier(s) replaced\n// {Main} (JADX)\n// source of com.example.app.Main", text);
        }
    }

    /// <summary>An R8-shaped package (two classes in package a, overloads all named a, a field and a class both named b) and its mapping.</summary>
    private (string Apk, string Mapping) Obfuscated()
    {
        var b = new DexBuilder();
        var client = b.Class("La/a;", 1).Field("a", "Ljava/lang/String;", 1).Field("b", "I", 9);
        client.Method("<init>", "V", [], 1, Asm.Invoke(0x70, "Ljava/lang/Object;-><init>()V", 0), Asm.ReturnVoid()).Registers = 1;
        client.Method("a", "I", ["La/b;"], 1,
            Asm.Invoke(0x6e, "La/b;->a()Ljava/lang/String;", 3),
            Asm.Op11x(0x0c, 0),
            Asm.Invoke(0x71, "La/b;->a(Ljava/lang/String;)V", 0),
            Asm.Instance(0x54, 1, 2, "La/a;->a:Ljava/lang/String;"),
            Asm.Invoke(0x71, "La/b;->a(Ljava/lang/String;)V", 1),
            Asm.Static(0x60, 0, "La/a;->b:I"),
            Asm.Return(0x0f, 0)).Registers = 4;
        client.Method("a", "V", ["I"], 9, Asm.Static(0x67, 0, "La/a;->b:I"), Asm.ReturnVoid()).Registers = 1;
        var request = b.Class("La/b;", 1).Field("a", "Ljava/lang/String;", 1);
        request.Method("<init>", "V", [], 1, Asm.Invoke(0x70, "Ljava/lang/Object;-><init>()V", 0), Asm.ReturnVoid()).Registers = 1;
        request.Method("a", "Ljava/lang/String;", [], 1, Asm.Instance(0x54, 0, 1, "La/b;->a:Ljava/lang/String;"), Asm.Return(0x11, 0)).Registers = 2;
        request.Method("a", "V", ["Ljava/lang/String;"], 9, Asm.ReturnVoid()).Registers = 1;
        var mapping = _dir.File("r8-mapping.txt");
        File.WriteAllText(mapping, """
            com.example.net.ApiClient -> a.a:
                java.lang.String baseUrl -> a
                int retries -> b
                1:3:int send(com.example.net.Request) -> a
                void setRetries(int) -> a
            com.example.net.Request -> a.b:
                java.lang.String url -> a
                java.lang.String path() -> a
                void log(java.lang.String) -> a
            """.Replace("\r\n", "\n"));
        return (Save(_dir, "r8.apk", AndroidSamples.Apk(30, ("classes.dex", b.Build()))), mapping);
    }

    /// <summary>The real JADX server's source of an R8-shaped class, with the mapping's names put into it.</summary>
    [Permit("reference-tool")]
    [Trait("Speed", "Slow")]
    [RequiresRealDataFact("CORVUS_JAVA_DECOMPILER")]
    public async Task Real_JADX_writes_mapping_names_into_the_source()
    {
        using var service = new JavaDecompilerService(new DexService());
        var (apk, mapping) = Obfuscated();
        var text = await service.Decompile(apk, "a.a", true, default, mapping);
        output.WriteLine(text);
        Assert.Contains("public class ApiClient {", text);
        Assert.Contains("Request.log(bVar.path());", text);
        Assert.Contains("Request.log(this.baseUrl);", text);
        Assert.Contains("return retries;", text);
        var request = await service.Decompile(apk, "a.b", true, default, mapping);
        Assert.Contains("return this.url;", request);
        var method = await service.Decompile(apk, "com.example.net.ApiClient::send", true, default, mapping);
        Assert.Contains("public int send(Request bVar) {", method);
    }

    /// <summary>
    /// JADX's text of an R8-shaped class (as the real server writes it, with its own f0a for a field) gets the mapping's names:
    /// overloads told apart by declared parameter types and by the calls of the method around them, a field and a class both
    /// named b told apart by the member after them; a call whose candidates disagree stays as written and is named in the header.
    /// </summary>
    [Fact]
    public async Task Mapping_names_go_into_the_Java_text()
    {
        var (service, env) = Fake();
        using (env)
        using (service)
        {
            _fake.Set("mcp", new JsonObject
            {
                ["get_class_source"] = new JsonObject
                {
                    ["a.a"] = """
                        package a;

                        import java.util.List;

                        /* JADX INFO: loaded from: classes.dex */
                        public class a {
                            public static int b;

                            /* JADX INFO: renamed from: a, reason: collision with root package name */
                            public String f0a;

                            static {
                                a(5);
                            }

                            public static void a(int i) {
                                b = i;
                            }

                            public int a(b bVar) {
                                b.a(bVar.a());
                                b.a(this.f0a);
                                String s = "a.a b.a";
                                return b;
                            }
                        }
                        """,
                    ["*"] = "!class not found",
                },
            });
            var (apk, mapping) = Obfuscated();
            var text = await service.Decompile(apk, "a.a", true, default, mapping);
            Assert.Equal("// original names from r8-mapping.txt: 15 identifier(s) replaced; kept as JADX wrote them (ambiguous): a (setRetries | send | log)",
                text[..text.IndexOf('\n')]);
            Assert.Contains("package com.example.net;", text);
            Assert.Contains("public class ApiClient {", text);
            Assert.Contains("public static int retries;", text);
            Assert.Contains("public String baseUrl;", text);
            Assert.Contains("        a(5);", text);
            Assert.Contains("public static void setRetries(int i) {\n        retries = i;", text);
            Assert.Contains("public int send(Request bVar) {\n        Request.log(bVar.path());\n        Request.log(this.baseUrl);", text);
            Assert.Contains("String s = \"a.a b.a\";\n        return retries;", text);
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
    public async Task Nested_classes_come_from_where_JADX_writes_them()
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
    public async Task Class_file_jar_decompiles_by_name()
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

    /// <summary>engine=vineflower gets the class with its nested classes and the jar as a library; DEX code stays JADX's.</summary>
    [Fact]
    public async Task Vineflower_decompiles_class_files_with_their_nested_classes()
    {
        var vineflower = Path.Combine(_fake.Directory, "vineflower-1.11.2.jar");
        File.WriteAllBytes(vineflower, [0x50, 0x4B, 3, 4]);
        using var env = new EnvironmentScope().Set("CORVUS_JAVA", _fake.CopyAs("java")).Set("CORVUS_JAVA_DECOMPILER2", vineflower);
        using var service = new JavaDecompilerService(new DexService()) { Environment = _fake.Environment, Cache = new JavaSourceCache(_dir.File("java-cache")) };
        var shape = JvmClassTests.Shape();
        var jar = Save(_dir, "lib.jar", ContainerFixtures.Zip(("p/Shape.class", shape), ("p/Shape$1.class", shape), ("p/Other.class", shape)));
        var text = await service.Decompile(jar, "p.Shape::m(int)", true, default, engine: JavaDecompilerService.Vineflower);
        Assert.StartsWith("// p.Shape (Vineflower)\n// p.Shape::m(int): Vineflower writes whole classes; the class follows\n// vineflower: p/Shape$1.class p/Shape.class\n// options: ", text);
        Assert.Contains("-e=" + jar, text);
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() =>
            service.Decompile(Apk(), "com.example.app.Main", true, default, engine: JavaDecompilerService.Vineflower))).Code);
    }

    [Fact]
    public async Task The_smali_fallback_hint_names_our_parameter()
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

    /// <summary>decompile_java asks JADX for smali where Java fails unless javaOnly.</summary>
    [Permit("reference-tool")]
    [Trait("Speed", "Slow")]
    [Fact]
    public async Task Decompile_Java_smali_fallback_by_default_Java_only_turns_it_off()
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
    public async Task Server_crash_is_provider_unavailable_and_the_next_call_starts_again()
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
    public async Task Without_JADX_names_the_variable()
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

    /// <summary>The real Vineflower (CORVUS_JAVA_DECOMPILER2) decompiles a class of a jar.</summary>
    [Permit("reference-tool")]
    [Trait("Speed", "Slow")]
    [RequiresRealDataFact("CORVUS_JAVA_DECOMPILER2")]
    public async Task Real_Vineflower_decompiles_a_class_of_a_jar()
    {
        using var service = new JavaDecompilerService(new DexService()) { Cache = null };
        var jar = Save(_dir, "lib.jar", ContainerFixtures.Zip(("p/Shape.class", JvmClassTests.Shape())));
        var text = await service.Decompile(jar, "p.Shape", true, default, engine: JavaDecompilerService.Vineflower);
        output.WriteLine(text);
        Assert.StartsWith("// p.Shape (Vineflower)\npackage p;", text);
        Assert.Contains("public class Shape {", text);
        Assert.Contains("\"a\\nb\"", text);
    }

    /// <summary>The real JADX server (CORVUS_JAVA_DECOMPILER) decompiles the sample and picks the overload asked for.</summary>
    [Permit("reference-tool")]
    [Trait("Speed", "Slow")]
    [RequiresRealDataFact("CORVUS_JAVA_DECOMPILER")]
    public async Task Real_JADX_decompiles_the_sample_and_picks_the_overload()
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
