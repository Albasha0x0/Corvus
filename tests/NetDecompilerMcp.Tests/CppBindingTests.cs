using dnlib.DotNet;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Services;

namespace NetDecompilerMcp.Tests;

public class CppBindingTests : IDisposable
{
    private readonly Env _env = new();
    public void Dispose() => _env.Dispose();

    private string Generate(string type, string? only = null, bool inherited = false) =>
        new CppBindingGenerator().Generate(_env.Fixture, _env.Def<TypeDef>(type, SymbolKind.Type), only?.Split(','), inherited);

    [Fact]
    public void GeneratesHostApiBinding()
    {
        var code = Generate("Player");
        Assert.Contains("klass = h->FindClass(\"TestFixture\", \"Fixture.Game\", \"Player\");", code);
        Assert.Contains("m_healthOff = h->FieldOffset(klass, \"_health\");", code);
        Assert.Contains("m_playerCountStaticOff = h->StaticFieldOffset(klass, \"PlayerCount\");", code);
        Assert.Contains("m_static = h->GetStaticFieldData(klass);", code);
        Assert.Contains("int32_t Health(const HostApi* h, const void* obj) const { return ReadField<int32_t>(h, obj, m_healthOff); }", code);
        Assert.Contains("h->GetMethod(klass, \"CheckLicense\", 0);", code);
        Assert.Contains("return CallValue<bool>(h, m_getIsAlive, obj);", code);
        Assert.Contains("namespace plugin {", code);
    }

    [Fact]
    public void OverloadsUseExactSignaturesAndFiltersWork()
    {
        var code = Generate("Shop", "Apply,_gold");
        Assert.Contains("GetMethodExact(h, klass, \"Apply\", \"Int32\")", code);
        Assert.Contains("GetMethodExact(h, klass, \"Apply\", \"String\")", code);
        Assert.Contains("_gold", code);
        Assert.DoesNotContain("Buy", code);
        Assert.Throws<ToolError>(() => Generate("Shop", "NoSuchMember"));
        Assert.Throws<ToolError>(() => Generate("Container"));
        Assert.Contains("GetMethodInHierarchy", Generate("Boss", inherited: true));
    }

    private const string ModHostPlugin = @"C:\work\ModHost\plugin";
    private const string ClangPlusPlus = @"C:\Program Files\LLVM\bin\clang++.exe";

    /// <summary>The generated code compiles against ModHost's real headers.</summary>
    [RequiresPathFact(ModHostPlugin)]
    public void CompilesAgainstModHostHeaders()
    {
        if (!File.Exists(ClangPlusPlus)) return;
        using var dir = new TempDir();
        foreach (var type in new[] { "Player", "Shop", "Boss" })
        {
            File.WriteAllText(dir.File(type + ".h"), Generate(type, inherited: true));
            File.WriteAllText(dir.File(type + ".cpp"), $"#include \"{type}.h\"\nint main() {{ plugin::{type}Binding b; return b.Resolved() ? 0 : 1; }}\n");
            var (code, text) = Tools.Run(ClangPlusPlus, $"-std=c++20 -fsyntax-only -I \"{ModHostPlugin}\" -I \"{dir.Path}\" \"{dir.File(type + ".cpp")}\"");
            Assert.True(code == 0, text);
        }
    }
}
