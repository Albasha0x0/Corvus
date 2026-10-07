using dnlib.DotNet;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Mcp;
using NetDecompilerMcp.Tools;

namespace NetDecompilerMcp.Tests;

/// <summary>Details the full sweep found: constants in array data, paging, extension signatures, resources, previews.</summary>
public class ToolDetailTests : IDisposable
{
    private readonly Env _env = new();
    public void Dispose() => _env.Dispose();

    [Fact]
    public void Constants_AreFoundInArrayInitializerData()
    {
        using var dir = new TempDir();
        var path = dir.File("Sha.dll");
        File.WriteAllBytes(path, ReferenceResolutionTests.Compile("Sha", """
            public static class Sha256
            {
                private static readonly uint[] K = { 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5 };
                public static uint Round(int i) => K[i];
            }
            public static class Sha512
            {
                private static readonly ulong[] K = { 0x428a2f98d728ae22UL, 0x7137449123ef65cdUL, 0xb5c0fbcfec4d3b2fUL };
                public static ulong Round(int i) => K[i];
            }
            public static class Spans
            {
                public static System.ReadOnlySpan<uint> Table => new uint[] { 1, 2, 0xb5c0fbcf };
            }
            public static class Bytes
            {
                private static readonly byte[] B = { 0xcf, 0xfb, 0xc0, 0xb5, 0, 0, 0, 0 };
                public static byte At(int i) => B[i];
            }
            """));
        using var env = new Env(path);
        var hits = env.Search.SearchConstants("0xB5C0FBCF", env.Workspace.Assemblies, 50, default).Items
            .ToDictionary(h => h.Owner.DeclaringType.Name.String, h => h.Kind);
        Assert.StartsWith("array initializer element [2] of uint[] (data ", hits["Sha256"]);
        Assert.StartsWith("array initializer element [2] (high half) of ulong[] (data ", hits["Sha512"]);
        Assert.StartsWith("array initializer element [2] of uint[] (data ", hits["Spans"]);
        Assert.False(hits.ContainsKey("Bytes")); // four bytes of a byte[] are not a 32-bit value
        Assert.Equal(3, hits.Count);
        Assert.Empty(env.Search.SearchConstants("0x1234", env.Workspace.Assemblies, 50, default).Items); // small values: IL / consts only
    }

    [Fact]
    public void Constants_RealSha2Tables_WhenPresent()
    {
        var bc = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".nuget", "packages", "bouncycastle.cryptography", "2.6.2", "lib", "net6.0", "BouncyCastle.Cryptography.dll");
        if (!File.Exists(bc)) return;
        using var env = new Env(bc);
        var kinds = env.Search.SearchConstants("0x428A2F98", env.Workspace.Assemblies, 50, default).Items
            .Select(h => $"{h.Owner.DeclaringType.Name}: {h.Kind}").ToList();
        Assert.Contains(kinds, k => k.StartsWith("LongDigest: array initializer element [0] (high half) of ulong[]"));
        Assert.Contains(kinds, k => k.StartsWith("Sha224Digest: array initializer element [0] of uint[]"));
    }

    [Fact]
    public async Task FindOverrides_Pages()
    {
        var tools = new ReferenceTools(_env.Workspace, _env.References, _env.Pager);
        var all = await tools.FindOverrides("Fixture.Game.Entity::Score");
        Assert.Contains("Fixture.Game.Player::Score()", all);
        Assert.Contains("Fixture.Game.Boss::Score()", all);
        var first = await tools.FindOverrides("Fixture.Game.Entity::Score", limit: 1);
        Assert.Contains("(showing 1-1)", first);
        Assert.Contains("[More: call again with offset=1]", first);
    }

    [Fact]
    public void ExtensionMethods_ShowThis()
    {
        using var dir = new TempDir();
        var path = dir.File("Ext.dll");
        File.WriteAllBytes(path, ReferenceResolutionTests.Compile("Ext", "public static class E { public static int Twice(this int x) => x * 2; }"));
        using var env = new Env(path);
        Assert.Equal("public static int Twice(this int x)", Format.Method(env.Def<MethodDef>("E::Twice")));
        Assert.Equal("int Twice(int x)", Format.Method(env.Def<MethodDef>("E::Twice"), withModifiers: false));
    }

    [Fact]
    public void IlResource_GivesEveryOverload()
    {
        var resources = new DecompilerResources(_env.Workspace, _env.Decompiler, _env.Report);
        var il = resources.IL(_env.Fixture.Id, "Fixture.Game.Player::TakeDamage", default);
        Assert.Contains("Player::TakeDamage(int)", il);
        Assert.Contains("Player::TakeDamage(int, string)", il);
    }

    [Fact]
    public void StubDryRun_NumbersTheInstructions()
    {
        var preview = _env.Edits.StubMethod(_env.One("Player::CheckLicense"), "true", dryRun: true);
        Assert.Contains("IL_0000: ldc.i4 1", preview);
        Assert.Contains("IL_0005: ret", preview); // real offsets, not IL_0000 for every line
    }
}
