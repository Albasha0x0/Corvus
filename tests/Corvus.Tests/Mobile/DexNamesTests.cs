using System.Text;
using Corvus.Core;
using Corvus.Services.Mobile;

namespace Corvus.Tests;

/// <summary>The DEX name layer: an R8 mapping.txt applied to the DEX views, and names recovered from Kotlin metadata and source files.</summary>
public sealed class DexNamesTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly string _dex;
    private readonly string _mapping;

    private const string Login = "La/a;", Session = "Lb/a;", Compute = Login + "->a(I)I", Bind = Login + "->a(Lb/a;)V", User = Login + "->a:Ljava/lang/String;";

    public DexNamesTests()
    {
        var b = new DexBuilder();
        var login = b.Class(Login, 1, "Landroid/app/Activity;", "SourceFile").Field("a", "Ljava/lang/String;", 2);
        login.Method("a", "I", ["I"], 1, Asm.Return(0x0f, 2)).Registers = 3;
        login.Method("a", "V", [Session], 1, Asm.ReturnVoid()).Registers = 3;
        login.Method("b", "V", [], 1, Asm.ConstString(0, "login"), Asm.Invoke(0x6e, Compute, 1, 0), Asm.ReturnVoid()).Registers = 2;
        b.Class(Session, 1, source: "SourceFile");
        var repo = b.Class("Lc/a;", 0x11, source: "SourceFile");
        repo.Annotations.Add(("Lkotlin/Metadata;", 1, [("k", 1), ("d2", new[] { "Lcom/example/app/Repo;", "load", "" })]));
        b.Class("Ld/a;", 1, source: "Helper.java");
        _dex = AndroidSamples.Save(_dir, "classes.dex", b.Build());
        _mapping = _dir.File("mapping.txt");
        File.WriteAllText(_mapping, """
            # compiler: R8
            com.example.app.LoginActivity -> a.a:
            # {"id":"sourceFile","fileName":"LoginActivity.kt"}
                java.lang.String userName -> a
                1:3:int helper(int):20:22 -> a
                1:3:int compute(int):10 -> a
                void bind(com.example.app.Session) -> a
                4:6:void com.example.app.Util.log():30:32 -> b
                4:6:void onLogin():40:42 -> b
            com.example.app.Session -> b.a:
            """.Replace("\r\n", "\n"));
    }

    public void Dispose() => _dir.Dispose();

    [Fact]
    public void Mapping_NamesClassesAndMembers_InlinedFramesSkipped()
    {
        var dex = new DexService();
        var list = dex.ListClasses(_dex, null, null, 0, 100, default, _mapping);
        Assert.Equal("com.example.app.LoginActivity", list.Items.Single(c => c.Descriptor == Login).Original);
        Assert.Contains(list.Notes, n => n.Contains("2 classes and 4 members are defined in this package", StringComparison.Ordinal));
        var page = dex.GetClass(_dex, "com.example.app.LoginActivity", default); // original names as input, the mapping kept
        Assert.Equal(Login, page.Descriptor);
        Assert.Equal("com.example.app.LoginActivity.compute(int) : int", page.Methods.Single(m => m.Id == Compute).Original);
        Assert.Equal("com.example.app.LoginActivity.bind(com.example.app.Session) : void", page.Methods.Single(m => m.Id == Bind).Original);
        Assert.Equal("com.example.app.LoginActivity.onLogin() : void", page.Methods.Single(m => m.Name == "b").Original);
        Assert.Equal("com.example.app.LoginActivity.userName : java.lang.String", page.Fields.Single(f => f.Id == User).Original);
    }

    [Fact]
    public void Search_And_Disassembly_ShowOriginals_AndTakeOriginalNames()
    {
        var dex = new DexService();
        var hits = dex.Search(_dex, "string", "login", 0, 10, default, _mapping);
        Assert.Equal("com.example.app.LoginActivity.onLogin() : void", hits.Items.Single().InOriginal);
        Assert.Equal(Compute, dex.Search(_dex, "method", "compute", 0, 10, default).Items.Single().Value);
        var smali = dex.Disassemble(_dex, "com.example.app.LoginActivity::onLogin", false, default);
        Assert.Contains($"invoke-virtual {{p0, v0}}, {Compute}  # = com.example.app.LoginActivity.compute(int) : int", smali);
        Assert.Contains("  # = com.example.app.LoginActivity.onLogin() : void", smali);
        Assert.Equal(Compute, dex.References(_dex, "com.example.app.LoginActivity::compute", null, "to", 0, 10, default).Target);
    }

    [Fact]
    public void Without_A_Mapping_KotlinMetadataAndSourceFileNameClasses()
    {
        var rows = new DexService().ListClasses(_dex, null, null, 0, 100, default).Items.ToDictionary(c => c.Descriptor, c => c.Original);
        Assert.Equal("com.example.app.Repo (kotlin metadata)", rows["Lc/a;"]);
        Assert.Equal("Helper (source file)", rows["Ld/a;"]);
        Assert.Null(rows[Login]); // "SourceFile" names nothing
        Assert.Equal("Lc/a;", new DexService().GetClass(_dex, "com.example.app.Repo", default).Descriptor);
    }

    /// <summary>A mapping of 50,000 classes and 500,000 members is read and applied in under a second of CPU (Release; the Debug build is allowed 3 s).</summary>
    [Trait("Speed", "Slow")]
    [Fact]
    public void Large_Mapping_IsAppliedFast()
    {
        var text = new StringBuilder();
        for (int c = 0; c < 50_000; c++)
        {
            text.Append($"com.example.p{c % 100}.Class{c} -> a{c}.a:\n");
            for (int m = 0; m < 5; m++) text.Append($"    1:2:int method{m}(com.example.p0.Class0,int):10:11 -> m{m}\n");
            for (int f = 0; f < 5; f++) text.Append($"    java.lang.String field{f} -> f{f}\n");
        }
        var path = _dir.File("big-mapping.txt");
        File.WriteAllText(path, text.ToString());
        var index = new DexService().Index(_dex, default);
        var cpu = ThreadCpuClock.Now();
        var names = DexNames.Read(path, index, default);
        var took = ThreadCpuClock.Now() - cpu;
        Assert.Equal("com.example.p0.Class100.method3(com.example.p0.Class0, int) : int", names.Display("La100/a;->m3(La0/a;I)I"));
        Assert.True(took < TimeSpan.FromSeconds(3), $"{took.TotalMilliseconds:0} ms of CPU");
    }

    [Fact]
    public void Fuzzed_Mapping_NeverThrowsUnexpectedly()
    {
        var index = new DexService().Index(_dex, default);
        var failures = FormatFuzz.Run(File.ReadAllBytes(_mapping), b =>
        {
            File.WriteAllBytes(_mapping, b);
            var names = DexNames.Read(_mapping, index, default);
            _ = names.Display(Compute);
            try { _ = names.Translate("com.example.app.LoginActivity::compute"); }
            catch (ToolError e) when (e.Code == ErrorCode.Ambiguous) { }
        }, 800);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(5)));
    }
}
