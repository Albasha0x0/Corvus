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
            if (balance.InvalidClauseCount > 0) flagged.Add($"{Path.GetFileName(file)}: {balance.InvalidClauseCount} exception clauses, e.g. {balance.InvalidClauses.First().Value[0]}");
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

    // ldarg.0; call 0x0A000001; stloc.0; leave.s IL_000e; pop; ldc.i4.m1; stloc.0; leave.s IL_000e; ldloc.0; ret
    private static readonly byte[] TryCatchIl = [0x02, 0x28, 1, 0, 0, 0x0A, 0x0A, 0xDE, 0x05, 0x26, 0x15, 0x0A, 0xDE, 0x00, 0x06, 0x2A];

    [Fact]
    public void ExceptionClauses_FlagsExtentsBoundariesAndFilterOrder()
    {
        static List<string> Issues(byte[] il, params IlHealth.Clause[] clauses) => IlHealth.ClauseIssues(il, clauses);
        static IlHealth.Clause Catch(int tryLength = 9, int handler = 9, int handlerLength = 5, bool typed = true, int flags = 0, int filter = -1) =>
            new(flags, 0, tryLength, handler, handlerLength, filter, typed);

        Assert.Empty(Issues(TryCatchIl, Catch(), Catch(flags: 2, typed: false), Catch(flags: 4, typed: false)));
        Assert.Equal(["clause 0 (flags 0x3): flags are not catch (0), filter (1), finally (2) or fault (4)"], Issues(TryCatchIl, Catch(flags: 3)));
        Assert.Equal(["clause 0 (catch): try range ends inside an instruction (IL_0008)"], Issues(TryCatchIl, Catch(tryLength: 8)));
        Assert.Equal(["clause 0 (catch): handler range starts inside an instruction (IL_0002)"], Issues(TryCatchIl, Catch(handler: 2, handlerLength: 4)));
        Assert.Equal(["clause 0 (catch): handler range IL_0009+0x14 leaves the code (0x10 bytes)"], Issues(TryCatchIl, Catch(handlerLength: 20)));
        Assert.Equal(["clause 0 (catch): catch clause without a catch type"], Issues(TryCatchIl, Catch(typed: false)));
        // A handler that runs to the end of the code ends on a boundary.
        Assert.Empty(Issues(TryCatchIl, Catch(handlerLength: 7)));
        // Filters: the filter block starts on an instruction before its handler.
        Assert.Empty(Issues(TryCatchIl, Catch(flags: 1, handler: 10, handlerLength: 4, filter: 9, typed: false)));
        Assert.Equal(["clause 0 (filter): filter at IL_0009 does not start on an instruction before its handler (IL_0009)"],
            Issues(TryCatchIl, Catch(flags: 1, filter: 9, typed: false)));
        Assert.Equal(["clause 0 (filter): filter at IL_0002 does not start on an instruction before its handler (IL_000A)"],
            Issues(TryCatchIl, Catch(flags: 1, handler: 10, handlerLength: 4, filter: 2, typed: false)));
        // Only the bad clause of several is reported, with its index.
        Assert.Equal(["clause 1 (catch): try range ends inside an instruction (IL_0008)"], Issues(TryCatchIl, Catch(), Catch(tryLength: 8)));

        // volatile. ldsfld 0x04000001; pop; ret: the prefix and the instruction it modifies are one boundary.
        byte[] prefixed = [0xFE, 0x13, 0x7E, 1, 0, 0, 4, 0x26, 0x2A];
        Assert.Empty(Issues(prefixed, new IlHealth.Clause(2, 0, 7, 7, 1, -1, false)));
        Assert.Equal(["clause 0 (finally): try range starts inside an instruction (IL_0002)"], Issues(prefixed, new IlHealth.Clause(2, 2, 5, 7, 1, -1, false)));
        // Invalid IL: clauses are not checked (the body is reported as invalid instead).
        Assert.Empty(IlHealth.ClauseIssues([0xA6, 0x2A], [Catch(flags: 3)]));
    }

    /// <summary>A try range shortened by one byte in the file is reported by get_assembly_info and get_il; the body itself stays valid IL.</summary>
    [Fact]
    public async Task ExceptionClause_OffAnInstructionBoundary_ReportedInInfoAndIl()
    {
        var lab = new IlLab();
        var parse = new dnlib.DotNet.MemberRefUser(lab.Module, "Parse", dnlib.DotNet.MethodSig.CreateStatic(lab.T.Int32, lab.T.String), lab.T.Int32.TypeDefOrRef);
        var end = dnlib.DotNet.Emit.OpCodes.Ldloc_0.ToInstruction();
        var code = new List<dnlib.DotNet.Emit.Instruction>
        {
            dnlib.DotNet.Emit.OpCodes.Ldarg_0.ToInstruction(), dnlib.DotNet.Emit.OpCodes.Call.ToInstruction(parse), dnlib.DotNet.Emit.OpCodes.Stloc_0.ToInstruction(),
            dnlib.DotNet.Emit.OpCodes.Leave_S.ToInstruction(end),
            dnlib.DotNet.Emit.OpCodes.Pop.ToInstruction(), dnlib.DotNet.Emit.OpCodes.Ldc_I4_M1.ToInstruction(), dnlib.DotNet.Emit.OpCodes.Stloc_0.ToInstruction(),
            dnlib.DotNet.Emit.OpCodes.Leave_S.ToInstruction(end),
            end, IlLab.Ret(),
        };
        var handler = new dnlib.DotNet.Emit.ExceptionHandler(dnlib.DotNet.Emit.ExceptionHandlerType.Catch)
        {
            TryStart = code[0], TryEnd = code[4], HandlerStart = code[4], HandlerEnd = code[8], CatchType = lab.T.GetTypeRef("System", "FormatException"),
        };
        lab.Method("Parse", lab.T.Int32, [lab.T.String], code, [lab.T.Int32], handlers: [handler]);
        var image = lab.Write();

        using (var pe = new PEReader(new MemoryStream(image)))
        {
            var md = pe.GetMetadataReader();
            var def = md.GetMethodDefinition(md.MethodDefinitions.Single(h => md.GetString(md.GetMethodDefinition(h).Name) == "Parse"));
            int at = FileOffset(pe, def.RelativeVirtualAddress);
            Assert.Equal(3, image[at] & 3); // fat header
            int section = (at + 12 + BitConverter.ToInt32(image, at + 4) + 3) & ~3;
            Assert.Equal(1, image[section]); // small exception section; its first clause follows the 4-byte header
            Assert.Equal(9, image[section + 8]); // try length
            image[section + 8] = 8;
        }
        var path = WriteCopy("clause", image);
        using var env = new Env(path);
        Assert.Equal(0, env.Fixture.BodyHealth.Invalid);
        Assert.Equal(1, env.Fixture.BodyHealth.InvalidClauseCount);

        const string issue = "clause 0 (catch): try range ends inside an instruction (IL_0008)";
        AssemblyReport.Summary summary = null!;
        var info = env.Workspace.Read(() => env.Report.Build(env.Fixture, out summary));
        Assert.Contains($"Exception clauses: 1 invalid in 1 method(s) (e.g. Lab.P::Parse(string) {issue})", info);
        Assert.Equal(1, summary.InvalidExceptionClauses);
        Assert.Contains($"// invalid exception clause: {issue}\n", await new DecompileTools(env.Workspace, env.Decompiler, env.Pager).GetIL("Lab.P::Parse"));
    }
}
