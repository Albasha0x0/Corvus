using dnlib.DotNet;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>Tool details: constants in array data, paging, extension signatures, IL resources, previews.</summary>
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
        Assert.Empty(env.Search.SearchConstants("0x1234", env.Workspace.Assemblies, 50, default).Items);
    }

    [Fact]
    public void Constants_SmallValues_AreFoundInArraysOfTheirOwnType()
    {
        using var dir = new TempDir();
        var path = dir.File("Tables.dll");
        File.WriteAllBytes(path, ReferenceResolutionTests.Compile("Tables", """
            public static class SBox
            {
                private static readonly byte[] Box = { 0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x7B };
                private static readonly short[] Steps = { -3, 1000, -3, 7, 9, 11, 13, 15 };
                private static readonly double[] Weights = { 0.25, 3.14, 2.5, 1.0 };
                public static int Get(int i) => Box[i] + Steps[i % 8] + (int)Weights[i % 4];
            }
            """));
        using var env = new Env(path);
        string Kind(string value) => Assert.Single(env.Search.SearchConstants(value, env.Workspace.Assemblies, 50, default).Items,
            h => h.Kind.StartsWith("array initializer", StringComparison.Ordinal)).Kind;
        Assert.StartsWith("array initializer elements [3], [8] of byte[]", Kind("0x7B"));
        Assert.StartsWith("array initializer elements [0], [2] of short[]", Kind("-3"));
        Assert.StartsWith("array initializer element [1] of double[]", Kind("3.14"));
        // Values that do not fit the element type are not matched.
        Assert.DoesNotContain(env.Search.SearchConstants("1000", env.Workspace.Assemblies, 50, default).Items, h => h.Kind.Contains("byte[]"));
    }

    [Fact]
    public void Constants_RealSha2Tables()
    {
        var bc = RealPackages.Lib("BouncyCastle.Cryptography", "2.6.2", "net6.0", "BouncyCastle.Cryptography.dll");
        using var env = new Env(bc);
        // Checks what is found, not how fast: a starved macOS CI runner once needed over 180 s for 0.3 s of work.
        env.Search.TimeLimit = Timeout.InfiniteTimeSpan;
        var kinds = env.Search.SearchConstants("0x428A2F98", env.Workspace.Assemblies, 50, default).Items
            .Select(h => $"{h.Owner.DeclaringType.Name}: {h.Kind}").ToList();
        Assert.Contains(kinds, k => k.StartsWith("LongDigest: array initializer element [0] (high half) of ulong[]"));
        // SHA-224 and SHA-256 share one data field: each method using it is reported.
        Assert.Contains(kinds, k => k.StartsWith("Sha224Digest: array initializer element [0] of uint[]"));
        Assert.Contains(kinds, k => k.StartsWith("Sha256Digest: array initializer element [0] of uint[]"));
    }

    [Fact]
    public async Task Overrides_Page()
    {
        var tools = new ReferenceTools(_env.Workspace, _env.References);
        var all = await tools.FindReferences("Fixture.Model.Entity::Score", kind: "overrides");
        Assert.Contains("Fixture.Model.Account::Score()", all);
        Assert.Contains("Fixture.Model.PremiumAccount::Score()", all);
        var first = await tools.FindReferences("Fixture.Model.Entity::Score", kind: "overrides", limit: 1);
        Assert.Contains("(showing 1-1)", first);
        Assert.Contains("[More: offset=1]", first);
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
        var il = resources.IL(_env.Fixture.Id, "Fixture.Model.Account::Charge", default);
        Assert.Contains("Account::Charge(int)", il);
        Assert.Contains("Account::Charge(int, string)", il);
    }

    [Fact]
    public void StubDryRun_NumbersTheInstructions()
    {
        var preview = _env.Edits.StubMethod(_env.One("Account::CheckPreview"), "true", dryRun: true);
        Assert.Contains("IL_0000: ldc.i4 1", preview);
        Assert.Contains("IL_0005: ret", preview); // real offsets, not IL_0000 for every line
    }
}
