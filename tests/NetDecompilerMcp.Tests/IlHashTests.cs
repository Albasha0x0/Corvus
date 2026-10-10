using dnlib.DotNet;
using dnlib.DotNet.Emit;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Services;
using NetDecompilerMcp.Tools;

namespace NetDecompilerMcp.Tests;

/// <summary>The normalized IL hash (docs/il-hash.md): the documented test vector, and what does and does not change it.</summary>
public class IlHashTests : IDisposable
{
    private readonly TempDir _dir = new();
    public void Dispose() => _dir.Dispose();

    /// <summary>The test vector of docs/il-hash.md.</summary>
    private const string VectorCanonical = """
        ilhash 1
        locals System.Int32
        initlocals 1
        ldarg a:0
        call m:System.Int32 System.Int32::Parse(System.String)
        stloc v:0
        leave @8
        pop
        ldc.i4 i:-1
        stloc v:0
        leave @8
        ldloc v:0
        ldstr s:"done\u000a"
        pop
        ret
        catch @0 @4 @4 @8 t:System.FormatException

        """;

    private const string VectorHash = "21807e13787c7f6e0a872a4b4d1741c054fc0de4727a67d8b55ea0dc0b26fffa";

    /// <summary>
    /// Lab.P::Parse(string): <c>try { V_0 = int.Parse(a0); } catch (FormatException) { V_0 = -1; } ldstr "done\n"; pop; return V_0;</c>
    /// written with short forms, or with long forms and <paramref name="padding"/> extra members in front (other tokens).
    /// </summary>
    private string Vector(bool longForms = false, int padding = 0, string text = "done\n")
    {
        var lab = new IlLab();
        for (int i = 0; i < padding; i++)
        {
            lab.Method("Pad" + i, lab.T.Int32, IlLab.Ldc(i), IlLab.Ret());
            lab.Module.Types.Add(new TypeDefUser("Lab", "Filler" + i, lab.T.Object.TypeDefOrRef));
        }
        var parse = new MemberRefUser(lab.Module, "Parse", MethodSig.CreateStatic(lab.T.Int32, lab.T.String), lab.T.Int32.TypeDefOrRef);
        var end = longForms ? OpCodes.Ldloc.ToInstruction(new Local(lab.T.Int32)) : OpCodes.Ldloc_0.ToInstruction();
        var code = new List<Instruction>
        {
            longForms ? OpCodes.Ldarg.ToInstruction(new Parameter(0)) : OpCodes.Ldarg_0.ToInstruction(),
            OpCodes.Call.ToInstruction(parse),
            longForms ? OpCodes.Stloc.ToInstruction(new Local(lab.T.Int32)) : OpCodes.Stloc_0.ToInstruction(),
            (longForms ? OpCodes.Leave : OpCodes.Leave_S).ToInstruction(end),
            OpCodes.Pop.ToInstruction(),
            longForms ? OpCodes.Ldc_I4.ToInstruction(-1) : OpCodes.Ldc_I4_M1.ToInstruction(),
            longForms ? OpCodes.Stloc.ToInstruction(new Local(lab.T.Int32)) : OpCodes.Stloc_0.ToInstruction(),
            (longForms ? OpCodes.Leave : OpCodes.Leave_S).ToInstruction(end),
            end,
            OpCodes.Ldstr.ToInstruction(text),
            OpCodes.Pop.ToInstruction(),
            IlLab.Ret(),
        };
        var handler = new ExceptionHandler(ExceptionHandlerType.Catch)
        {
            TryStart = code[0], TryEnd = code[4], HandlerStart = code[4], HandlerEnd = code[8],
            CatchType = lab.T.GetTypeRef("System", "FormatException"),
        };
        var method = lab.Method("Parse", lab.T.Int32, [lab.T.String], code, [lab.T.Int32], handlers: [handler]);
        // The long forms name their local and argument objects; point them at the method's own.
        foreach (var i in method.Body.Instructions)
            if (i.Operand is Local) i.Operand = method.Body.Variables[0];
            else if (i.Operand is Parameter) i.Operand = method.Parameters[0];

        var dir = _dir.File($"v{longForms}{padding}{text.Length}");
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, "Lab.dll");
        File.WriteAllBytes(path, lab.Write());
        return path;
    }

    private static (string Canonical, string? Hash) HashOf(Env env, string method) => env.Workspace.Read(() =>
    {
        var m = env.Def<MethodDef>(method);
        return (IlHash.Canonical(FastIlReader.Read(env.Fixture, m)!), IlHash.Of(env.Fixture, m));
    });

    [Fact]
    public void TestVector()
    {
        using var env = new Env(Vector());
        var (canonical, hash) = HashOf(env, "Lab.P::Parse");
        Assert.Equal(VectorCanonical.ReplaceLineEndings("\n"), canonical);
        Assert.Equal(VectorHash, hash);
    }

    [Fact]
    public void ShortAndLongFormsAndOtherTokens_SameHash_OtherLiteral_OtherHash()
    {
        using var shortForms = new Env(Vector());
        using var longForms = new Env(Vector(longForms: true, padding: 3));
        using var otherText = new Env(Vector(text: "done!"));
        var expected = HashOf(shortForms, "Lab.P::Parse").Hash;
        // Instruction forms and metadata tokens differ (padding shifts every token); the hash does not.
        Assert.NotEqual(shortForms.Workspace.Read(() => Format.Token(shortForms.Def<MethodDef>("Lab.P::Parse"))),
            longForms.Workspace.Read(() => Format.Token(longForms.Def<MethodDef>("Lab.P::Parse"))));
        Assert.Equal(expected, HashOf(longForms, "Lab.P::Parse").Hash);
        Assert.NotEqual(expected, HashOf(otherText, "Lab.P::Parse").Hash);
    }

    /// <summary>The same code compiled with its members in another order (every token differs): the same hashes.</summary>
    [Trait("Speed", "Slow")]
    [Fact]
    public void RebuildWithOtherTokens_SameHashes()
    {
        string[] members =
        [
            "public static int Twice(int x) => x * 2;",
            "public static string Name<T>(System.Collections.Generic.List<T> items) => items.Count > 0 ? items[0]!.ToString()! : \"none\";",
            "public int Field;",
            "public int Sum(int[] values) { int s = Field; foreach (var v in values) { try { s = checked(s + Twice(v)); } catch (System.OverflowException) { return -1; } } return s; }",
            "public static int Pick(int k) { switch (k) { case 0: return 10; case 1: return 20; case 2: return 30; case 3: return 45; default: return Twice(k); } }",
        ];
        string Source(IEnumerable<string> order) => "public class Filler { public void A() { } }\npublic class C {\n" + string.Join("\n", order) + "\n}";
        Dictionary<string, string?> Hashes(string name, string source)
        {
            var dir = _dir.File(name);
            Directory.CreateDirectory(dir);
            var path = Path.Combine(dir, "Rebuild.dll");
            File.WriteAllBytes(path, Roslyn.Release("Rebuild", source));
            using var env = new Env(path);
            return env.Workspace.Read(() => env.Def<TypeDef>("C", SymbolKind.Type).Methods.ToDictionary(m => m.Name.String, m => IlHash.Of(env.Fixture, m)));
        }
        var first = Hashes("a", Source(members));
        var second = Hashes("b", Source(members.Reverse()).Replace("public void A() { }", "public void A() { } public void B() { }"));
        Assert.Equal(5, first.Count); // with the constructor
        Assert.All(first, h => Assert.NotNull(h.Value));
        Assert.Equal(first, second);
    }

    /// <summary>An edited assembly is read through dnlib instead of the fast reader: untouched bodies keep their hash.</summary>
    [Fact]
    public void EditedAssembly_UntouchedBodiesKeepTheirHash()
    {
        using var env = new Env();
        var methods = env.Workspace.Read(() => env.Fixture.Module.GetTypes().SelectMany(t => t.Methods).ToList());
        var before = env.Workspace.Read(() => methods.ToDictionary(m => m, m => IlHash.Of(env.Fixture, m)));
        Assert.True(before.Values.Count(h => h != null) > 50);
        var stubbed = env.Def<MethodDef>("Fixture.Model.Account::Score");
        env.Edit(() => env.Edits.StubMethod(env.One("Fixture.Model.Account::Score"), "5"));
        Assert.True(env.Fixture.IsDirty);
        var after = env.Workspace.Read(() => methods.ToDictionary(m => m, m => IlHash.Of(env.Fixture, m)));
        Assert.NotEqual(before[stubbed], after[stubbed]);
        Assert.Empty(methods.Where(m => m != stubbed && before[m] != after[m]).Select(m => m.FullName));
    }

    [Fact]
    public async Task GetIL_ShowsTheHashOfEachMethod()
    {
        using var env = new Env(Vector());
        var tools = new DecompileTools(env.Workspace, env.Decompiler, env.Pager);
        var method = await tools.GetIL("Lab.P::Parse");
        Assert.Matches($@"// IL hash: {VectorHash[..16]}  raw IL SHA-256: [0-9a-f]{{16}}\n", method);
        var type = await tools.GetIL("Lab.P");
        Assert.Matches($@"// IL hash: {VectorHash[..16]}  raw IL SHA-256: [0-9a-f]{{16}}  Parse\(string\)\n", type);
    }

    /// <summary>The raw IL SHA-256 covers exactly the code bytes after the fat header, and changes with the tokens where the normalized hash does not.</summary>
    [Fact]
    public async Task RawIlSha256_IsOverTheExactCodeBytes()
    {
        var path = Vector();
        var bytes = File.ReadAllBytes(path);
        using var env = new Env(path);
        var parse = env.Def<MethodDef>("Lab.P::Parse");
        int at = FileOffset(bytes, (uint)parse.RVA);
        Assert.Equal(3, bytes[at] & 3); // fat header: 12 bytes, code size at +4
        int size = BitConverter.ToInt32(bytes, at + 4);
        Assert.Equal(0x16, size);
        var expected = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(bytes.AsSpan(at + 12, size)));
        using (var reader = IlHash.RawReader(env.Fixture))
            Assert.Equal(expected, IlHash.RawSha256(reader, parse));
        Assert.Contains($"// IL hash: {VectorHash[..16]}  raw IL SHA-256: {expected[..16]}\n",
            await new DecompileTools(env.Workspace, env.Decompiler, env.Pager).GetIL("Lab.P::Parse"));

        // decompile_member provenance=true: both hashes in full, with the build's identity.
        var decompile = new DecompileTools(env.Workspace, env.Decompiler, env.Pager);
        var pinned = await decompile.DecompileMember("Lab.P::Parse", provenance: true);
        Assert.Contains($"// Provenance: SHA-256 {env.Fixture.OriginalSha256}, MVID {env.Fixture.Module.Mvid}\n", pinned);
        Assert.Contains($"//   Lab.P::Parse(string)  token {Format.Token(parse)}\n//     IL hash {VectorHash}  raw IL SHA-256 {expected}\n", pinned);
        Assert.Contains("int.Parse", pinned);
        Assert.DoesNotContain("Provenance", await decompile.DecompileMember("Lab.P::Parse"));
        Assert.StartsWith("// Provenance: SHA-256 ", await decompile.DecompileMember("Lab.P", provenance: true));

        using var other = new Env(Vector(longForms: true, padding: 3));
        var moved = other.Def<MethodDef>("Lab.P::Parse");
        using var otherReader = IlHash.RawReader(other.Fixture);
        Assert.Equal(VectorHash, other.Workspace.Read(() => IlHash.Of(other.Fixture, moved)));
        Assert.NotEqual(expected, IlHash.RawSha256(otherReader, moved));
    }

    private static int FileOffset(byte[] image, uint rva)
    {
        var headers = new System.Reflection.PortableExecutable.PEHeaders(new MemoryStream(image));
        var s = headers.SectionHeaders.Single(h => rva >= h.VirtualAddress && rva < h.VirtualAddress + h.VirtualSize);
        return (int)(rva - s.VirtualAddress + s.PointerToRawData);
    }
}
