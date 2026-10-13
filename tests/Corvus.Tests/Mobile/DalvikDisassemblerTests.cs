using Corvus.Core;
using Corvus.Core.Mobile;
using Corvus.Native.Providers;
using Corvus.Services.Mobile;
using static Corvus.Tests.AndroidSamples;

namespace Corvus.Tests;

/// <summary>Smali output of the Dalvik disassembler, and (with CORVUS_DEX_DISASSEMBLER) the same text as baksmali's.</summary>
[Collection(ExternalToolEnvironmentCollection.Name)]
public sealed class DalvikDisassemblerTests(Xunit.Abstractions.ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly DexService _dex = new();

    public void Dispose() => _dir.Dispose();

    private string Apk() => Save(_dir, "app.apk", AndroidSamples.Apk(30, ("classes.dex", Dex())));

    [Fact]
    public void Method_ResolvesOperands_ParametersLinesAndLabels()
    {
        var apk = Apk();
        var onCreate = _dex.Disassemble(apk, Main + "->onCreate(Landroid/os/Bundle;)V", false, default);
        Assert.Equal("""
            # Lcom/example/app/Main;->onCreate(Landroid/os/Bundle;)V in classes.dex
            .method protected onCreate(Landroid/os/Bundle;)V
                .registers 3
                .param p1, "savedInstanceState"    # Landroid/os/Bundle;

                .line 10
                invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V

                .line 11
                const-string v0, "https://api.example.com/v1"

                .line 12
                iput-object v0, p0, Lcom/example/app/Main;->name:Ljava/lang/String;

                .line 13
                invoke-static {v0}, Lcom/example/app/Helper;->log(Ljava/lang/String;)V

                return-void
            .end method

            """.Replace("\r\n", "\n"), onCreate);

        var compute = _dex.Disassemble(apk, "com.example.app.Main::compute(int)", false, default);
        Assert.Contains("    sget v0, Lcom/example/app/Main;->COUNT:I\n", compute);
        Assert.Contains("    if-eqz v0, :cond_8\n", compute);
        Assert.Contains("    :cond_8\n    return p1\n", compute);
        Assert.Contains("iget-object v0, p0, Lcom/example/app/Main;->name:Ljava/lang/String;", compute);
        Assert.DoesNotContain("length()I", compute); // the other overload is never included

        var pick = _dex.Disassemble(apk, Main + "->pick(I)I", false, default);
        Assert.Contains("    packed-switch p0, :pswitch_data_8\n", pick);
        Assert.Contains("    const/4 v0, -0x1\n", pick);
        Assert.Contains("    :pswitch_5\n    const/high16 v0, 0x3f800000    # 1.0f\n", pick);
        Assert.Contains("    :pswitch_data_8\n    .packed-switch 0xa\n        :pswitch_5\n        :pswitch_3\n    .end packed-switch\n", pick);

        var guarded = _dex.Disassemble(apk, Main + "->guarded()V", false, default);
        Assert.Contains("    :try_start_0\n    invoke-static {v0}, Lcom/example/app/Helper;->log(Ljava/lang/String;)V\n    :try_end_3\n" +
                        "    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_3} :catch_4\n    .catchall {:try_start_0 .. :try_end_3} :catchall_4\n", guarded);
        Assert.Contains("    :catch_4\n    :catchall_4\n    move-exception v0\n", guarded);
        var data = _dex.Disassemble(apk, Main + "->data()V", true, default);
        Assert.Contains("    fill-array-data v0, :array_4    # 0000: 0026 0004 0000\n", data);
        Assert.Contains("    .array-data 4\n        0x1\n        -0x2\n        0x7fffffff\n    .end array-data\n", data);
        Assert.Contains(".method public native abstractLike()V\n.end method", _dex.Disassemble(apk, Main + "->abstractLike()V", false, default));
    }

    [Fact]
    public void Class_FieldsAnnotationsAndEveryMethod()
    {
        var text = _dex.Disassemble(Apk(), "com.example.app.Main", false, default);
        Assert.StartsWith("# Lcom/example/app/Main; in classes.dex: 8 methods (symbol=<id> disassembles one)\n#   Lcom/example/app/Main;-><init>()V  4 units\n", text);
        Assert.Contains("\n.class public Lcom/example/app/Main;\n.super Landroid/app/Activity;\n.source \"Main.java\"\n", text);
        Assert.Contains(".annotation system Ldalvik/annotation/MemberClasses;\n    value = {\n        \"Lcom/example/app/Main$Inner;\"\n    }\n.end annotation\n", text);
        Assert.Contains("# static fields\n.field public static final COUNT:I = 0x7\n", text);
        Assert.Contains("# instance fields\n.field private name:Ljava/lang/String;\n", text);
        Assert.Contains("# direct methods\n.method public constructor <init>()V\n", text);
        Assert.Contains("# virtual methods\n", text);
        Assert.Equal(8, text.Split(".end method").Length - 1);
    }

    [Fact]
    public void Errors_AmbiguousOverloads_FrameworkMethods_BadFormat()
    {
        var apk = Apk();
        Assert.Equal(ErrorCode.Ambiguous, Assert.Throws<ToolError>(() => _dex.Disassemble(apk, "com.example.app.Main::compute", false, default)).Code);
        var framework = Assert.Throws<ToolError>(() => _dex.Disassemble(apk, "Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I", false, default));
        Assert.Contains("not defined in it", framework.Message);
    }

    /// <summary>baksmali 2.5 (CORVUS_DEX_DISASSEMBLER, its jar) writes the same text for every class of the sample, and of the first DEX of CORVUS_ANDROID_PACKAGE.</summary>
    [Trait("Speed", "Slow")]
    [RequiresRealDataFact("CORVUS_DEX_DISASSEMBLER")]
    public void MatchesBaksmali()
    {
        var dexPath = Save(_dir, "classes.dex", Dex());
        Compare(dexPath, File.ReadAllBytes(dexPath), all: true);
        if (RealData.Get(RealData.AndroidPackage) is { } package)
        {
            using var p = AndroidPackage.Open(package);
            var first = p.Read(p.DexFiles[0])!;
            Compare(Save(_dir, "real.dex", first), first, all: false);
        }
    }

    private void Compare(string dexPath, byte[] bytes, bool all)
    {
        var tool = ExternalTools.DexDisassembler;
        var outDir = _dir.File("smali-" + Path.GetFileNameWithoutExtension(dexPath));
        var command = ExternalTools.Command(tool, ExternalTools.Locate(tool)!.Value.Path, ExternalTools.Arguments(tool, "disassemble", ("out", outDir), ("dex", dexPath)))!.Value;
        var run = ExternalTools.Run(command.Exe, command.Args, TimeSpan.FromMinutes(5), 1 << 20, default);
        Assert.True(run.ExitCode == 0, run.Stderr);
        var dex = DexFile.Read(bytes, "x.dex");
        var disassembler = new DalvikDisassembler(dex);
        int compared = 0, differ = 0;
        foreach (var c in dex.Classes)
        {
            var file = Path.Combine([outDir, .. c.Descriptor[1..^1].Split('/')]) + ".smali";
            if (!File.Exists(file)) continue;
            // baksmali's comments on synthetic accessors are not produced.
            var expected = string.Join('\n', File.ReadAllText(file).Replace("\r\n", "\n").Split('\n')
                .Where(l => !System.Text.RegularExpressions.Regex.IsMatch(l, @"^\s+# (invokes|getter for|setter for|operator for|\+\+operator for|--operator for):"))).TrimEnd();
            var actual = disassembler.Class(c).TrimEnd();
            compared++;
            if (expected == actual) continue;
            differ++;
            if (differ <= 12)
            {
                var e = expected.Split('\n');
                var a = actual.Split('\n');
                int line = Enumerable.Range(0, Math.Min(e.Length, a.Length)).FirstOrDefault(k => e[k] != a[k], Math.Min(e.Length, a.Length));
                output.WriteLine($"{c.Descriptor} line {line + 1}:\n  baksmali: {(line < e.Length ? e[line] : "<end>")}\n  ours:     {(line < a.Length ? a[line] : "<end>")}");
                if (differ == 1 && all) output.WriteLine($"--- baksmali\n{expected}\n--- ours\n{actual}");
            }
        }
        output.WriteLine($"{dexPath}: {compared - differ} of {compared} classes identical");
        Assert.True(compared > 0);
        Assert.Equal(0, differ);
    }
}
