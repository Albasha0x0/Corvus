using System.Text.Json.Nodes;
using Corvus.Core.Mobile;
using Corvus.Services.Mobile;
using static Corvus.Tests.AndroidSamples;

namespace Corvus.Tests;

/// <summary>decompile_java simplified=true: decoder calls in Java text replaced by the strings their fold sites evaluate to.</summary>
[Collection(ExternalToolEnvironmentCollection.Name)]
public sealed class JavaStringFoldTests : IDisposable
{
    private const string Dec = "Lp/Dec;", Main = "Lp/Main;", S = "Ljava/lang/String;", Sb = "Ljava/lang/StringBuilder;";
    private const string Rev = Dec + "->r(Ljava/lang/String;)Ljava/lang/String;";

    private readonly TempDir _dir = new();
    private readonly FakeTool _fake = new();

    public void Dispose()
    {
        _fake.Dispose();
        _dir.Dispose();
    }

    private static void Method(DexBuilder.ClassDef c, string name, string[] parameters, int registers, params DexInsn[] code) =>
        c.Method(name, S, parameters, 9, code).Registers = registers;

    /// <summary>Dec.r reverses its argument; Main.hello, Main.quoted and Main.twice call it with constants, Main.use with its own parameter.</summary>
    private static byte[] Fixture()
    {
        var b = new DexBuilder();
        Method(b.Class(Dec), "r", [S], 2,
            Asm.NewInstance(0, Sb), Asm.Invoke(0x70, Sb + "-><init>(Ljava/lang/String;)V", 0, 1), Asm.Invoke(0x6e, Sb + "->reverse()Ljava/lang/StringBuilder;", 0),
            Asm.Op11x(0x0c, 0), Asm.Invoke(0x6e, Sb + "->toString()Ljava/lang/String;", 0), Asm.Op11x(0x0c, 0), Asm.Return(0x11, 0));
        var main = b.Class(Main);
        Method(main, "hello", [], 1, Asm.ConstString(0, "olleh"), Asm.Invoke(0x71, Rev, 0), Asm.Op11x(0x0c, 0), Asm.Return(0x11, 0));
        Method(main, "quoted", [], 1, Asm.ConstString(0, "\n\"q\\"), Asm.Invoke(0x71, Rev, 0), Asm.Op11x(0x0c, 0), Asm.Return(0x11, 0));
        Method(main, "twice", [], 1,
            Asm.ConstString(0, "a"), Asm.Invoke(0x71, Rev, 0), Asm.Op11x(0x0c, 0), Asm.ConstString(0, "bc"), Asm.Invoke(0x71, Rev, 0), Asm.Op11x(0x0c, 0), Asm.Return(0x11, 0));
        Method(main, "use", [S], 1, Asm.Invoke(0x71, Rev, 0), Asm.Op11x(0x0c, 0), Asm.Return(0x11, 0));
        return b.Build();
    }

    private (IReadOnlyList<DexFoldSite> Sites, HashSet<string> Scope) Sites(params string[] methods)
    {
        var index = DexIndex.Load(Save(_dir, "app.dex", Fixture()), Core.AnalysisLimits.Default, default);
        var folding = DexStringFolding.For(index);
        return ([.. methods.SelectMany(m => folding.Method(index.Methods[index.ResolveMethod(Main + "->" + m)]))], [Main]);
    }

    [Fact]
    public void A_decoder_call_is_replaced_by_its_string_literal()
    {
        var (sites, scope) = Sites("hello");
        var r = JavaStringFold.Apply("String hello() {\n    return Dec.r(\"olleh\");\n}", sites, scope);
        Assert.Equal("String hello() {\n    return \"hello\";\n}", r.Text);
        Assert.Equal((1, 0), (r.Folded, r.Unknown));
        Assert.Equal("// simplified: 1 strings folded, 0 unknown", r.Header);
    }

    [Fact]
    public void A_quote_and_a_newline_in_a_value_are_escaped()
    {
        var (sites, scope) = Sites("quoted");
        var r = JavaStringFold.Apply("return p.Dec.r(\"x\");", sites, scope);
        Assert.Equal("return \"\\\\q\\\"\\n\";", r.Text);
        Assert.Equal("\"\\u00e9\\u0001\"", JavaStringFold.Literal("\u00e9\u0001"));
    }

    [Fact]
    public void A_call_that_cannot_be_bound_stays_and_is_counted_unknown()
    {
        var (sites, scope) = Sites("hello", "use", "twice");
        // Two calls in the text but one is outside the sites' methods: counts
        // differ, nothing binds.
        var text = "a() { return Dec.r(\"olleh\"); }\nb() { return Dec.r(s); }\n";
        var r = JavaStringFold.Apply(text, sites, scope);
        Assert.Equal(text, r.Text);
        Assert.Equal((0, 2), (r.Folded, r.Unknown));
        var (one, scope1) = Sites("use");
        var arg = JavaStringFold.Apply("return Dec.r(s);", one, scope1);
        Assert.Equal(("return Dec.r(s);", 0, 1), (arg.Text, arg.Folded, arg.Unknown));
    }

    [Fact]
    public void Calls_in_several_methods_are_bound_by_their_declaration()
    {
        var (sites, scope) = Sites("hello", "twice");
        var text = "String twice() {\n  return Dec.r(\"a\") + Dec.r(\"cb\");\n}\nString hello() {\n  return Dec.r(\"olleh\");\n}\n";
        var r = JavaStringFold.Apply(text, sites, scope);
        Assert.Equal("String twice() {\n  return \"a\" + \"cb\";\n}\nString hello() {\n  return \"hello\";\n}\n", r.Text);
        Assert.Equal(3, r.Folded);
    }

    [Fact]
    public void A_string_literal_and_a_comment_with_the_call_text_are_left()
    {
        var (sites, scope) = Sites("hello");
        var text = "// Dec.r(\"x\")\nString s = \"Dec.r(1)\";\nreturn Dec.r(\"olleh\");";
        Assert.Equal("// Dec.r(\"x\")\nString s = \"Dec.r(1)\";\nreturn \"hello\";", JavaStringFold.Apply(text, sites, scope).Text);
    }

    private (JavaDecompilerService Service, EnvironmentScope Env, string Apk) Fake(string source)
    {
        var fake = _fake;
        var jar = Path.Combine(fake.Directory, "jadx-headless-mcp-0.7.1-all.jar");
        File.WriteAllBytes(jar, [0x50, 0x4B, 3, 4]);
        fake.Set("mcp", new JsonObject { ["get_class_source"] = source });
        var env = new EnvironmentScope().Set("CORVUS_JAVA", fake.CopyAs("java")).Set("CORVUS_JAVA_DECOMPILER", jar);
        return (new JavaDecompilerService(new DexService()) { Environment = fake.Environment, Cache = null }, env,
            Save(_dir, "app.apk", AndroidSamples.Apk(30, ("classes.dex", Fixture()))));
    }

    [Fact]
    public async Task Output_without_simplified_is_unchanged()
    {
        var (service, env, apk) = Fake("class Main { String hello() { return Dec.r(\"olleh\"); } }");
        using (env)
        using (service)
        {
            var plain = await service.Decompile(apk, "p.Main", true, default);
            Assert.Contains("Dec.r(\"olleh\")", plain);
            Assert.DoesNotContain("simplified", plain);
            var folded = await service.Decompile(apk, "p.Main", true, default, simplified: true);
            Assert.StartsWith("// simplified: ", folded);
            Assert.Equal(plain, await service.Decompile(apk, "p.Main", true, default));
        }
    }

    [Fact]
    public void A_smali_fallback_is_left_unchanged()
    {
        Assert.True(JavaStringFold.IsSmali(".class public Lp/Main;\n.super Ljava/lang/Object;"));
        Assert.True(JavaStringFold.IsSmali("// Lp/Main;->hello()Ljava/lang/String; (JADX, smali)\n.method"));
        Assert.False(JavaStringFold.IsSmali("// Lp/Main; (JADX)\nclass Main {}"));
    }

    /// <summary>The real JADX server's source of the fixture class, with the decoder calls shown as literals.</summary>
    [Permit("reference-tool")]
    [Trait("Speed", "Slow")]
    [RequiresRealDataFact("CORVUS_JAVA_DECOMPILER")]
    public async Task Real_JADX_source_shows_a_decoder_call_as_a_literal()
    {
        using var service = new JavaDecompilerService(new DexService());
        var text = await service.Decompile(Save(_dir, "app.apk", AndroidSamples.Apk(30, ("classes.dex", Fixture()))), "p.Main", true, default, simplified: true);
        Assert.StartsWith("// simplified: ", text);
        Assert.Contains("\"hello\"", text);
    }
}
