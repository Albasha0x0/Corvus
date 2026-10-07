using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Tests;

public class IlPatchTests : IDisposable
{
    private readonly Env _env = new();
    public void Dispose() => _env.Dispose();

    private string Patch(string symbol, string il, string mode = "replace", bool dryRun = false) =>
        _env.Edit(() => _env.Edits.PatchMethodIL(_env.One(symbol), il, mode, dryRun));

    [Fact]
    public void HandWrittenILWithLabelsAndFrameworkCalls()
    {
        Patch("Secret::Validate", """
            ldarg.0                       // key
            call System.String::IsNullOrEmpty(string)
            brtrue.s fail
            ldc.i4.1
            ret
            fail:
            ldc.i4.0
            ret
            """);
        Assert.Contains("IsNullOrEmpty(key)", _env.Decompile("Secret::Validate"));
        Assert.True(_env.Fixture.IsDirty);
    }

    [Fact]
    public void RoundTripsEditedGetIlOutput()
    {
        var il = _env.Decompiler.Disassemble(_env.Fixture, _env.One("Player::TakeDamage(int, string)").Member, default);
        Patch("Player::TakeDamage(int, string)", il.Replace("\"hit by \"", "\"struck by \""));
        Assert.Contains("\"struck by \" + source", _env.Decompile("Player::TakeDamage(int, string)"));
    }

    [Fact]
    public void RoundTripsGenericAndLambdaHeavyMethod()
    {
        // MethodSpec (Enumerable.Where<int>), cached lambda field, ldftn, delegate ctor — all via token comments.
        var il = _env.Decompiler.Disassemble(_env.Fixture, _env.One("Player::SumPositive").Member, default);
        Patch("Player::SumPositive", il);
        Assert.Contains("v > 0", _env.Decompile("Player::SumPositive"));
    }

    [Fact]
    public void ResolvesMembersBySymbolAcrossTypes()
    {
        Patch("Player::CheckLicense", """
            ldstr "anything"
            call Fixture.Game.Secret::Validate(string)
            pop
            ldarg.0
            call Fixture.Game.Player::get_IsAlive()
            ret
            """);
        var code = _env.Decompile("Player::CheckLicense");
        Assert.Contains("Secret.Validate(\"anything\")", code);
        Assert.Contains("IsAlive", code);
    }

    [Fact]
    public void PrependKeepsOriginalAndBranchesIntoIt()
    {
        Patch("Player::TakeDamage(int)", """
            ldarg.1
            ldc.i4.0
            bge IL_0000
            ret
            """, mode: "prepend");
        var code = _env.Decompile("Player::TakeDamage(int)");
        Assert.Contains("if (amount >= 0)", code);
        Assert.Contains("_health -= amount", code);
    }

    [Fact]
    public void FieldsArgumentsLocalsSwitchAndTypes()
    {
        Patch("Player::Score", """
            .local int
            ldarg.0
            ldfld Fixture.Game.Player::_health
            stloc 0
            ldloc V_0
            switch (zero, one)
            ldc.i4 0x10
            ret
            zero:
            ldc.i4.0
            ret
            one:
            ldsfld Fixture.Game.Player::PlayerCount
            ret
            """);
        var code = _env.Decompile("Player::Score");
        Assert.Contains("switch", code);
        Assert.Contains("PlayerCount", code);
    }

    [Fact]
    public void DryRunLeavesOriginalUntouchedIncludingPrepend()
    {
        var before = _env.Decompiler.Disassemble(_env.Fixture, _env.One("Player::TakeDamage(int)").Member, default);
        Assert.StartsWith("Dry run", Patch("Player::TakeDamage(int)", "ldarg.1\nldc.i4.0\nbge IL_0000\nret", "prepend", dryRun: true));
        Assert.StartsWith("Dry run", Patch("Player::Score", ".local int\nldc.i4 0x10\nstloc 0\nldloc 0\nret", dryRun: true));
        Assert.False(_env.Fixture.IsDirty);
        Assert.Equal(before, _env.Decompiler.Disassemble(_env.Fixture, _env.One("Player::TakeDamage(int)").Member, default));
    }

    [Theory]
    [InlineData("ldc.i4.1\nadd\nret", "Stack imbalance")]
    [InlineData("frobnicate\nret", "unknown opcode")]
    [InlineData("ldc.i4.1", "must end with ret")]
    [InlineData("br nowhere\nret", "undefined label")]
    [InlineData("a:\na:\nret", "defined twice")]
    [InlineData("call Nope.Missing::Thing()\nret", "cannot resolve")]
    [InlineData("ldarg 9\nret", "out of range")]
    [InlineData("ldloc 5\nret", "does not exist")]
    [InlineData("ldstr unquoted\nret", "quoted string")]
    [InlineData("ret 5", "takes no operand")]
    [InlineData(".try {\nret", "exception-handling")]
    [InlineData("", "No IL instructions")]
    public void RejectsBadILWithoutTouchingTheMethod(string il, string expected)
    {
        var ex = Assert.Throws<ToolError>(() => Patch("Player::Score", il));
        Assert.Contains(expected, ex.Message);
        Assert.False(_env.Fixture.IsDirty);
    }

    [Fact]
    public void PatchedAssemblySavesAndReloads()
    {
        Patch("Secret::Validate", "ldc.i4.1\nret");
        using var dir = new TempDir();
        _env.Edits.Save(_env.Fixture, dir.File("p.dll"), false);
        using var reloaded = new Env(dir.File("p.dll"));
        Assert.Contains("return true;", reloaded.Decompile("Secret::Validate"));
    }
}

public class CSharpPatchTests : IDisposable
{
    private readonly Env _env = new(withConsumer: true);
    public void Dispose() => _env.Dispose();

    private string Patch(string symbol, string code, bool dryRun = false) =>
        _env.Edit(() => _env.Edits.PatchMethodCSharp(_env.One(symbol), code, dryRun, default));

    /// <summary>
    /// An internal value type in the signature (like a library's internal copy of a framework reader type): the helper
    /// method compiled in a separate assembly must not be more accessible than that type (CS0051), so valid patches use
    /// the helper path and invalid ones report only their own errors.
    /// </summary>
    [Fact]
    public void InternalTypesInSignatures_CompileAndReportOnlyRealErrors()
    {
        using var dir = new TempDir();
        var path = dir.File("Internals.dll");
        File.WriteAllBytes(path, InspectionTests.Compile("Internals", """
            internal struct RowReader
            {
                public int Position;
                public string Text;

                public bool TryNext(string key, out string value)
                {
                    value = key;
                    return Position < Text.Length;
                }

                internal static int Skip(ref RowReader reader, int count) => reader.Position += count;
            }
            """));
        using var env = new Env(path);
        string PatchHere(string symbol, string code, bool dryRun = false) =>
            env.Edit(() => env.Edits.PatchMethodCSharp(env.One(symbol), code, dryRun, default));

        PatchHere("RowReader::TryNext", "value = key + \"!\"; return false;");
        Assert.Contains("key + \"!\"", env.Decompile("RowReader::TryNext"));
        PatchHere("RowReader::Skip", "return reader.Position - count;");
        Assert.Contains("reader.Position - count", env.Decompile("RowReader::Skip"));

        var outParam = Assert.Throws<ToolError>(() => PatchHere("RowReader::TryNext", "return true;", dryRun: true));
        Assert.Contains("CS0177", outParam.Message);
        Assert.DoesNotContain("CS0051", outParam.Message);
        Assert.Contains("1 error(s)", outParam.Message);
        var badReturn = Assert.Throws<ToolError>(() => PatchHere("RowReader::Skip", "return \"text\";", dryRun: true));
        Assert.Contains("CS0029", badReturn.Message);
        Assert.DoesNotContain("CS0051", badReturn.Message);
    }

    [Fact]
    public void ReplacesBodyUsingPrivateStateAndInternalTypes()
    {
        // _health is private to Player; Secret is internal to the assembly: both must be accessible.
        Patch("Player::CheckLicense", """
            if (_health <= 0)
                return false;
            return Secret.Validate("LICENSE-OVERRIDE-0001");
            """);
        var code = _env.Decompile("Player::CheckLicense");
        Assert.Contains("_health <= 0", code);
        Assert.Contains("LICENSE-OVERRIDE-0001", code);
        Assert.True(_env.Fixture.IsDirty);
    }

    [Fact]
    public void WorksOnMethodsWithInitializersExpressionBodiesAndOverloads()
    {
        Patch("Shop::PriceOf(string, int)", "return PriceOf(item) * quantity - Discount;");
        Assert.Contains("- Discount", _env.Decompile("Shop::PriceOf(string, int)"));
        Patch("Shop::Buy", "{ _gold += 1; return true; }");
        Assert.Contains("_gold++", _env.Decompile("Shop::Buy"));
    }

    [Fact]
    public void ConstructorsAccessorsAndStatics()
    {
        Patch("Player::.ctor", "Name = name.ToUpperInvariant(); PlayerCount += 10;");
        Assert.Contains("ToUpperInvariant", _env.Decompile("Player::.ctor"));

        Patch("Player::set_Health", "_health = value < 0 ? 0 : value;");
        Assert.Matches(@"value (<|>=) 0", _env.Decompiler.DecompileType(_env.Fixture, (dnlib.DotNet.TypeDef)_env.One("Player", SymbolKind.Type).Member, default));

        Patch("Shop::get_Gold", "return _gold * 2;"); // expression-bodied property
        Patch("Shop::Create", "var s = new Shop(); s.Discount = 50; return s;");
        Assert.Contains("Discount = 50", _env.Decompile("Shop::Create"));
    }

    [Fact]
    public void GenericMethod()
    {
        Patch("Shop::Pick", "return second;");
        Assert.Contains("return second;", _env.Decompile("Shop::Pick"));
    }

    [Fact]
    public void PatchInOtherAssemblyReferencingFixture()
    {
        Patch("Consumer.Arena::Total", "return entity.Score() + 1;");
        Assert.Contains("entity.Score() + 1", _env.Decompile("Consumer.Arena::Total"));
    }

    [Fact]
    public void DryRunCompilesButChangesNothing()
    {
        var result = Patch("Player::CheckLicense", "return true;", dryRun: true);
        Assert.StartsWith("Dry run — compiled OK", result);
        Assert.False(_env.Fixture.IsDirty);
    }

    [Fact]
    public void CompileErrorsPointAtUserCode()
    {
        var ex = Assert.Throws<ToolError>(() => Patch("Player::CheckLicense", "return doesNotExist;"));
        Assert.Contains("CS0103", ex.Message);
        Assert.Contains("your code line 1", ex.Message);
        Assert.False(_env.Fixture.IsDirty);
        Assert.Throws<ToolError>(() => Patch("Player::CheckLicense", "return 5;")); // wrong type
        Assert.Throws<ToolError>(() => Patch("Player::CheckLicense", "public void X() {}")); // not statements
        Assert.Throws<ToolError>(() => Patch("Player::CheckLicense", "   "));
    }

    [Fact]
    public void UnsupportedTargetsExplainAlternatives()
    {
        var auto = Assert.Throws<ToolError>(() => Patch("Shop::get_Discount", "return 1;"));
        Assert.Contains("auto-property", auto.Message);
        Assert.Contains("patch_method_il", auto.Message);
        Assert.Throws<ToolError>(() => Patch("Entity::Tick", "return;"));                 // abstract
        Assert.Contains("field-like event", Assert.Throws<ToolError>(() => Patch("Player::add_Died", "return;")).Message);
    }

    [Fact]
    public void PatchedCodeSavesAndRunsCorrectly()
    {
        Patch("Shop::PriceOf(string)", "return item.Length * 100;");
        Patch("Player::.ctor", "Name = name.ToUpperInvariant();");
        Patch("Player::set_Health", "_health = value < 0 ? 0 : value;");
        using var dir = new TempDir();
        var path = dir.File("TestFixture.dll");
        _env.Edits.Save(_env.Fixture, path, false);

        // Execute the patched assembly in an isolated load context to prove the IL is valid at runtime.
        var context = new System.Runtime.Loader.AssemblyLoadContext("patched", isCollectible: true);
        try
        {
            var asm = context.LoadFromStream(new MemoryStream(File.ReadAllBytes(path)));
            var shop = Activator.CreateInstance(asm.GetType("Fixture.Game.Shop")!)!;
            var price = shop.GetType().GetMethod("PriceOf", [typeof(string)])!.Invoke(shop, ["sword"]);
            Assert.Equal(500, price);
            var buy = shop.GetType().GetMethod("Buy")!.Invoke(shop, ["sword"]);
            Assert.Equal(true, buy); // untouched method still works, and the field initializers ran

            var playerType = asm.GetType("Fixture.Game.Player")!;
            var player = Activator.CreateInstance(playerType, "bob")!;
            Assert.Equal("BOB", (string)playerType.GetField("Name")!.GetValue(player)!);
            Assert.Equal(100, (int)playerType.GetProperty("Health")!.GetValue(player)!); // initializer kept in the patched ctor
            playerType.GetProperty("Health")!.SetValue(player, -5);
            Assert.Equal(0, (int)playerType.GetProperty("Health")!.GetValue(player)!);
        }
        finally
        {
            context.Unload();
        }
    }
}
