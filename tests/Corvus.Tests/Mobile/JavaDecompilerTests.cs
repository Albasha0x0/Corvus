using System.Text.Json.Nodes;
using Corvus.Core;
using Corvus.Services.Mobile;
using static Corvus.Tests.AndroidSamples;

namespace Corvus.Tests;

/// <summary>decompile_java against a stand-in JADX server (the fake tool) and, with NDM_JAVA_DECOMPILER, the real one.</summary>
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
        var env = new EnvironmentScope().Set("NDM_JAVA", _fake.CopyAs("java")).Set("NDM_JAVA_DECOMPILER", jar);
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

    [Fact]
    public async Task SmaliFallbackHint_NamesOurParameter()
    {
        var (service, env) = Fake();
        using (env)
        using (service)
        {
            _fake.Set("mcp", new JsonObject { ["get_class_source"] = "// (Java body was an anti-decompile stub; showing smali. Pass smali_fallback=false for the partial Java.)\n.class public Lx;" });
            var text = await service.Decompile(Apk(), "com.example.app.Main", true, default);
            Assert.Contains("Pass smaliFallback=false for the partial Java.", text);
            Assert.DoesNotContain("smali_fallback", text);
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
        using var env = new EnvironmentScope().Set("NDM_JAVA_DECOMPILER", Path.Combine(_dir.Path, "missing.jar"));
        using var service = new JavaDecompilerService(new DexService());
        var error = await Assert.ThrowsAsync<ToolError>(() => service.Decompile(Apk(), "com.example.app.Main", true, default));
        Assert.Equal(ErrorCode.ProviderUnavailable, error.Code);
        Assert.Contains("disassemble_dex", error.Message);
        Assert.Contains("NDM_JAVA_DECOMPILER", error.Remediation);
    }

    /// <summary>The real JADX server (NDM_JAVA_DECOMPILER) decompiles the sample and picks the overload asked for.</summary>
    [Trait("Speed", "Slow")]
    [RequiresRealDataFact("NDM_JAVA_DECOMPILER")]
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
