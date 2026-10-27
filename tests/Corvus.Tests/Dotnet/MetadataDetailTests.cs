using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>Metadata detail on real packages: FieldRVA data, attribute arguments, Portable PDB sequence points.</summary>
public sealed class MetadataDetailTests
{
    private static string BouncyCastle => RealPackages.Lib("BouncyCastle.Cryptography", "2.6.2", "net6.0", "BouncyCastle.Cryptography.dll");

    [Fact]
    public async Task Field_RVA_data_shows_bytes_readers_and_typed_elements()
    {
        using var env = new Env(BouncyCastle);
        const string table = "<PrivateImplementationDetails>::74EF7306E7452D6859B6463CE496B8DF30925F69E1B2969E1F3F34BBC9C6AF04";
        var text = await new BrowseTools(env.Workspace, env.References, env.Pager).GetTypeInfo(table, limit: 1);
        Assert.Contains("initial data: 256 bytes at RVA 0x", text);
        Assert.Contains("(bytes match), SHA-256 74ef7306e7452d6859b6463ce496b8df30925f69e1b2969e1f3f34bbc9c6af04", text);
        Assert.Contains("read by Org.BouncyCastle.Crypto.Digests.Sha256Digest::.cctor() @IL_", text);
        Assert.Contains("as uint[64]: 0x428A2F98, 0x71374491,", text);
        Assert.Contains("0x0000  98 2f 8a 42", text);
        Assert.Contains("[More: offset=1]", text);
    }

    [Fact]
    public async Task Attribute_arguments_split_flags_enums()
    {
        using var env = new Env(RealPackages.Lib("NLog", "6.1.4", "netstandard2.0", "NLog.dll"));
        var text = await new BrowseTools(env.Workspace, env.References, env.Pager).GetAttributes("JetBrains.Annotations.MeansImplicitUseAttribute");
        Assert.Contains("[AttributeUsage(AttributeTargets.Class | AttributeTargets.Parameter | AttributeTargets.GenericParameter)]", text);
    }

    [Fact]
    public async Task Get_IL_source_places_PDB_lines_at_IL_offsets()
    {
        using var env = new Env(RealPackages.Lib("Mono.Cecil", "0.11.3", "netstandard2.0", "Mono.Cecil.dll"));
        var text = await new DecompileTools(env.Workspace, env.Decompiler, env.Pager).GetIL("Mono.Cecil.ModuleDefinition::ReadModule(string, ReaderParameters)", source: true);
        Assert.Contains("(id matches the image); SourceLink maps 138 documents", text);
        Assert.Contains("// line 1082:4-1082:136 in https://raw.githubusercontent.com/jbevain/cecil/e9a4815fdb102a3bc87a606c6e9ee5f61c00414a/Mono.Cecil/ModuleDefinition.cs\n\tIL_0000: ldarg.0", text);
        Assert.Contains("[1] class [netstandard]System.IO.MemoryStream memory", text);
        Assert.Contains("// hidden", text);
    }
}
