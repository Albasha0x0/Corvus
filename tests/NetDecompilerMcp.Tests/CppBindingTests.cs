using dnlib.DotNet;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Services;

namespace NetDecompilerMcp.Tests;

public class CppBindingTests : IDisposable
{
    private readonly Env _env = new();
    public void Dispose() => _env.Dispose();

    private string Generate(string type, string? only = null, bool inherited = false, string style = "mono") =>
        new CppBindingGenerator().Generate(_env.Fixture, _env.Def<TypeDef>(type, SymbolKind.Type), only?.Split(','), inherited, style);

    private const string ClangPlusPlus = @"C:\Program Files\LLVM\bin\clang++.exe";

    // ------------------------------------------------------------------ style "mono" (default)

    [Fact]
    public void GeneratesMonoEmbeddingApiBinding()
    {
        var code = Generate("Player");
        Assert.Contains("klass = FindClass(api, \"TestFixture\", \"Fixture.Game\", \"Player\");", code);
        Assert.Contains("m_healthOff = FieldOffset(api, klass, \"_health\");", code);
        Assert.Contains("m_playerCountStaticOff = FieldOffset(api, klass, \"PlayerCount\");", code);
        Assert.Contains("m_static = StaticData(api, klass);", code);
        Assert.Contains("int32_t Health(const void* obj) const { return Read<int32_t>(obj, m_healthOff); }", code);
        Assert.Contains("bool SetHealth(void* obj, int32_t value) const { return Write<int32_t>(obj, m_healthOff, value); }", code);
        Assert.Contains("api.class_get_method_from_name(klass, \"CheckLicense\", 0);", code);
        Assert.Contains("return CallValue<bool>(api, m_getIsAlive, obj);", code);
        Assert.Contains("get(class_from_name, \"mono_class_from_name\");", code);
        Assert.Contains("namespace monobind {", code);
        Assert.DoesNotContain("HostApi", code);
        Assert.DoesNotContain("#include \"", code); // only standard headers
    }

    [Fact]
    public void Mono_OverloadsByToken_NestedTypesThroughTheirOuterClass()
    {
        var shop = Generate("Shop", "Apply,_gold");
        var overloads = _env.Def<TypeDef>("Shop", SymbolKind.Type).Methods.Where(m => m.Name == "Apply").ToList();
        Assert.Equal(2, overloads.Count);
        foreach (var m in overloads)
            Assert.Contains($"MethodByToken(api, klass, 0x{m.MDToken.Raw:X8});", shop);
        Assert.Contains("regenerate this header when the assembly changes", shop);
        Assert.DoesNotContain("Buy", shop);

        var nested = Generate("Player+Inventory");
        Assert.Contains("klass = FindNested(api, FindClass(api, \"TestFixture\", \"Fixture.Game\", \"Player\"), \"Inventory\");", nested);

        Assert.Contains("MethodInHierarchy(api, klass, ", Generate("Boss", inherited: true));
        Assert.Contains("instance offsets include the object header", Generate("Vec2"));
    }

    [Fact]
    public void ErrorsAreClear()
    {
        Assert.Contains("NoSuchMember", Assert.Throws<ToolError>(() => Generate("Shop", "NoSuchMember")).Message);
        Assert.Contains("is generic", Assert.Throws<ToolError>(() => Generate("Container")).Message);
        Assert.Contains("Unknown style 'il2cpp'", Assert.Throws<ToolError>(() => Generate("Player", style: "il2cpp")).Message);
    }

    /// <summary>Every mono-style header compiles on its own, and several of them together in one translation unit.</summary>
    [Fact]
    public void MonoBindingsCompile()
    {
        if (!File.Exists(ClangPlusPlus)) return;
        using var dir = new TempDir();
        var types = new[] { "Player", "Shop", "Boss", "Player+Inventory", "Vec2", "Entity" };
        var includes = new List<string>();
        foreach (var type in types)
        {
            var file = type.Replace('+', '_') + ".h";
            File.WriteAllText(dir.File(file), Generate(type, inherited: true));
            includes.Add($"#include \"{file}\"");
        }
        File.WriteAllText(dir.File("all.cpp"), string.Join("\n", includes) + """

            static void* Lookup(const char*) { return nullptr; }
            int main() {
                monobind::MonoApi api;
                bool loaded = api.Load(Lookup);
                monobind::PlayerBinding player;
                monobind::InventoryBinding inventory;
                return loaded && player.Resolved() && inventory.Resolved() ? 0 : 1;
            }
            """);
        var (code, text) = Tools.Run(ClangPlusPlus, $"-std=c++17 -fsyntax-only -Wall -Wextra -Werror -I \"{dir.Path}\" \"{dir.File("all.cpp")}\"");
        Assert.True(code == 0, text);
    }

    // ------------------------------------------------------------------ style "hostapi"

    [Fact]
    public void GeneratesHostApiBinding()
    {
        var code = Generate("Player", style: "hostapi");
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
    public void HostApi_OverloadsUseExactSignaturesAndFiltersWork()
    {
        var code = Generate("Shop", "Apply,_gold", style: "hostapi");
        Assert.Contains("GetMethodExact(h, klass, \"Apply\", \"Int32\")", code);
        Assert.Contains("GetMethodExact(h, klass, \"Apply\", \"String\")", code);
        Assert.Contains("_gold", code);
        Assert.DoesNotContain("Buy", code);
        Assert.Contains("GetMethodInHierarchy", Generate("Boss", inherited: true, style: "hostapi"));
    }

    /// <summary>The hostapi output compiles against a real HostApi framework's headers (NDM_HOSTAPI_INCLUDE_DIR).</summary>
    [RequiresRealDataFact(RealData.HostApiIncludeDir)]
    public void HostApiBindingsCompileAgainstRealHeaders()
    {
        if (!File.Exists(ClangPlusPlus)) return;
        var include = RealData.Path(RealData.HostApiIncludeDir);
        using var dir = new TempDir();
        foreach (var type in new[] { "Player", "Shop", "Boss" })
        {
            File.WriteAllText(dir.File(type + ".h"), Generate(type, inherited: true, style: "hostapi"));
            File.WriteAllText(dir.File(type + ".cpp"), $"#include \"{type}.h\"\nint main() {{ plugin::{type}Binding b; return b.Resolved() ? 0 : 1; }}\n");
            var (code, text) = Tools.Run(ClangPlusPlus, $"-std=c++20 -fsyntax-only -I \"{include}\" -I \"{dir.Path}\" \"{dir.File(type + ".cpp")}\"");
            Assert.True(code == 0, text);
        }
    }
}
