using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Services;
using NetDecompilerMcp.Services.Analysis;
using NetDecompilerMcp.Tools;

namespace NetDecompilerMcp.Tests;

/// <summary>Invalid (encrypted) method bodies are detected and flagged by every tool that reads them.</summary>
public class IlHealthTests : IDisposable
{
    private readonly TempDir _dir = new();
    public void Dispose() => _dir.Dispose();

    /// <summary>Overwrites the bodies of the selected types' methods with bytes that are not IL.</summary>
    private static byte[] Corrupt(byte[] image, Func<string, bool> declaringType)
    {
        var copy = (byte[])image.Clone();
        using var pe = new PEReader(new MemoryStream(image));
        var md = pe.GetMetadataReader();
        var rng = new Random(7);
        foreach (var handle in md.MethodDefinitions)
        {
            var def = md.GetMethodDefinition(handle);
            if (def.RelativeVirtualAddress == 0 || !declaringType(md.GetString(md.GetTypeDefinition(def.GetDeclaringType()).Name))) continue;
            int offset = FileOffset(pe, def.RelativeVirtualAddress);
            byte header = copy[offset];
            (int codeStart, int codeSize) = (header & 3) == 2
                ? (offset + 1, header >> 2)                                  // tiny header
                : (offset + 12, BitConverter.ToInt32(copy, offset + 4));     // fat header
            // Simulated encryption: random bytes starting with an unused opcode.
            for (int i = 0; i < codeSize; i++) copy[codeStart + i] = (byte)rng.Next(256);
            copy[codeStart] = 0xA6;
        }
        return copy;
    }

    private static int FileOffset(PEReader pe, int rva)
    {
        foreach (var s in pe.PEHeaders.SectionHeaders)
            if (rva >= s.VirtualAddress && rva < s.VirtualAddress + Math.Max(s.VirtualSize, s.SizeOfRawData))
                return rva - s.VirtualAddress + s.PointerToRawData;
        throw new InvalidOperationException("RVA outside sections");
    }

    private string WriteCopy(string folder, byte[] image)
    {
        var dir = _dir.File(folder);
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, Path.GetFileName(Env.FixturePath));
        File.WriteAllBytes(path, image);
        return path;
    }

    [Fact]
    public void TheInstalledRuntime_HasNoInvalidBodies()
    {
        // False-positive guard over the running runtime's assemblies (R2R images still carry IL).
        var dir = Path.GetDirectoryName(typeof(object).Assembly.Location)!;
        int bodies = 0;
        var flagged = new List<string>();
        foreach (var file in Directory.EnumerateFiles(dir, "*.dll"))
        {
            var balance = IlHealth.Assess(File.ReadAllBytes(file));
            bodies += balance.Bodies;
            if (balance.Invalid > 0) flagged.Add($"{Path.GetFileName(file)} {balance.Invalid}/{balance.Bodies}");
        }
        Assert.True(bodies > 50_000, $"{bodies} bodies");
        Assert.Empty(flagged);
        Assert.Equal(0, IlHealth.Assess(File.ReadAllBytes(Env.FixturePath)).Invalid);
        Assert.Equal(0, IlHealth.Assess([1, 2, 3]).Bodies); // not a PE: nothing, no exception
    }

    [Fact]
    public void SomeBodiesInvalid_FlaggedInInfoAndDecompilation()
    {
        var path = WriteCopy("partial", Corrupt(File.ReadAllBytes(Env.FixturePath), t => t == "Account"));
        using var env = new Env(path);
        var balance = env.Fixture.BodyHealth;
        Assert.InRange(balance.Invalid, 3, balance.Bodies - 1);
        Assert.False(balance.MostlyInvalid);
        Assert.True(balance.IsInvalid(env.Def<dnlib.DotNet.MethodDef>("Fixture.Model.Account::CheckLicense")));
        Assert.False(balance.IsInvalid(env.Def<dnlib.DotNet.MethodDef>("Fixture.Model.Entity::Score")));

        var info = env.Workspace.Read(() => env.Report.Build(env.Fixture));
        Assert.Matches($@"IL: {balance.Invalid} of {balance.Bodies} method bodies are not valid IL \(e\.g\. .*Account", info);
        Assert.Contains("// Warning: this method body is not valid IL", env.Decompile("Fixture.Model.Account::CheckLicense"));
        Assert.DoesNotContain("not valid IL", env.Decompile("Fixture.Model.Entity::Score"));
        Assert.StartsWith("// Warning: ", env.Workspace.Read(() =>
            env.Decompiler.DecompileType(env.Fixture, env.Def<dnlib.DotNet.TypeDef>("Fixture.Model.Account", SymbolKind.Type), default)));
    }

    /// <summary>Searches, reference lookups and build comparisons say how many bodies they could not read in full.</summary>
    [Fact]
    public async Task SomeBodiesInvalid_SearchesAndComparisonsSayWhatWasSkipped()
    {
        var path = WriteCopy("skipped", Corrupt(File.ReadAllBytes(Env.FixturePath), t => t == "Account"));
        using var env = new Env(path);
        int invalid = env.Fixture.BodyHealth.Invalid;
        var note = $"Skipped: {invalid} method bodies not valid IL ({env.Fixture.Id} {invalid}), read only up to the first invalid instruction";
        var search = new SearchTools(env.Workspace, env.Search, env.Il2Cpp, env.Il2CppStrings, env.Pager);
        Assert.Contains(note, await search.SearchStrings("license"));
        Assert.Contains(note, await search.SearchStrings("no such text anywhere"));
        Assert.Contains(note, await search.SearchConstants("12345678"));
        Assert.Contains(note, await search.SearchIL("ldstr *"));
        Assert.Contains(note, await new ReferenceTools(env.Workspace, env.References, env.Pager).FindReferences("Fixture.Model.Entity"));
        Assert.DoesNotContain("Skipped:", await search.SearchSymbols("Account"));

        using var clean = new Env();
        var corrupt = clean.Workspace.Load(path);
        var compare = new CompareTools(clean.Workspace, new AssemblyComparer(clean.Workspace), clean.Pager);
        Assert.Contains($"Skipped: {invalid} method bodies of the new build ({corrupt.Id}) are not valid IL (encrypted?) and were not compared",
            await compare.CompareAssemblies(clean.Fixture.Id, corrupt.Id));
        Assert.Contains($"Skipped: 0 old and {invalid} new method bodies are not valid IL and were not compared",
            await compare.FindCounterpart("Fixture.Model.Account", clean.Fixture.Id, corrupt.Id));
        Assert.DoesNotContain("Skipped:", await new SearchTools(clean.Workspace, clean.Search, clean.Il2Cpp, clean.Il2CppStrings, clean.Pager)
            .SearchStrings("license", assembly: clean.Fixture.Id));
    }

    [Fact]
    public void AllBodiesInvalid_ReportedAsEncryptedEverywhere()
    {
        var clean = File.ReadAllBytes(Env.FixturePath);
        var path = WriteCopy("encrypted", Corrupt(clean, _ => true));
        using var env = new Env(Env.FixturePath);
        var encrypted = env.Workspace.Load(path);
        Assert.True(encrypted.BodyHealth.MostlyInvalid);
        Assert.Equal(encrypted.BodyHealth.Bodies, encrypted.BodyHealth.Invalid);
        Assert.Contains("Load the decrypted image", env.Workspace.Read(() => env.Report.Build(encrypted)));

        // compare_assemblies does not report invalid bodies as real changes.
        var cmp = env.Workspace.Read(() => new AssemblyComparer(env.Workspace).Compare(env.Fixture, encrypted, default));
        var bodies = cmp.Types.SelectMany(t => t.Members).Where(m => m.Change == "body").ToList();
        Assert.NotEmpty(bodies);
        Assert.All(bodies, m => Assert.Equal("new body not valid IL (encrypted?); not comparable", m.Detail));

        var summary = new InspectionService(env.Workspace).Summarize(null, path, default);
        var one = Assert.Single(summary.Assemblies);
        Assert.Contains(one.Notes, n => n.Contains("method bodies are not valid IL"));
        Assert.Contains("Method bodies are not valid IL (encrypted or dumped before decryption)", one.Highlights);
    }

    [Fact]
    public void Validator_EdgeCases()
    {
        static bool Valid(params byte[] il) => IlHealth.IsValid(il);
        Assert.True(Valid(0x2A));                         // ret
        Assert.True(Valid(0x00, 0x7A));                   // nop; throw
        Assert.True(Valid(0x2B, 0xFE));                   // br.s -2 (an endless loop ends with a branch)
        Assert.True(Valid(0x16, 0x45, 1, 0, 0, 0, 0, 0, 0, 0, 0x2A)); // ldc.i4.0; switch(1 target); ret
        Assert.True(Valid(0xFE, 0x1A));                   // rethrow
        Assert.True(Valid(0xDC));                         // endfinally
        Assert.False(Valid());                            // empty
        Assert.False(Valid(0x00));                        // falls off the end
        Assert.False(Valid(0xA6, 0x2A));                  // unused opcode
        Assert.False(Valid(0x20, 0x01, 0x02));            // ldc.i4 with a truncated operand
        Assert.False(Valid(0x45, 0xFF, 0xFF, 0xFF, 0x7F)); // switch with an impossible count
        Assert.False(Valid(0x2A, 0xFE));                  // a lone two-byte prefix at the end
    }
}
