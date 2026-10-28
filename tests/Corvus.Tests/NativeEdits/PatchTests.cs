using Corvus.Core;

namespace Corvus.Tests;

public class IlPatchTests : IDisposable
{
    private readonly Env _env = new();
    public void Dispose() => _env.Dispose();

    private string Patch(string symbol, string il, string mode = "replace", bool dryRun = false) =>
        _env.Edit(() => _env.Edits.PatchMethodIL(_env.One(symbol), il, mode, dryRun));

    [Fact]
    public void Hand_written_IL_with_labels_and_framework_calls_applies()
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
        Assert.Contains("IsNullOrEmpty(code)", _env.Decompile("Secret::Validate"));
        Assert.True(_env.Fixture.IsDirty);
    }

    [Fact]
    public void Round_trips_edited_get_IL_output()
    {
        var il = _env.Decompiler.Disassemble(_env.Fixture, _env.One("Account::Charge(int, string)").Member, default);
        Patch("Account::Charge(int, string)", il.Replace("\"charged by \"", "\"billed by \""));
        Assert.Contains("\"billed by \" + source", _env.Decompile("Account::Charge(int, string)"));
    }

    [Fact]
    public void Round_trips_generic_and_lambda_heavy_method()
    {
        // MethodSpec, cached lambda field, ldftn and delegate ctor round-trip via token comments.
        var il = _env.Decompiler.Disassemble(_env.Fixture, _env.One("Account::SumPositive").Member, default);
        Patch("Account::SumPositive", il);
        Assert.Contains("v > 0", _env.Decompile("Account::SumPositive"));
    }

    [Fact]
    public void Resolves_members_by_symbol_across_types()
    {
        Patch("Account::CheckPreview", """
            ldstr "anything"
            call Fixture.Model.Secret::Validate(string)
            pop
            ldarg.0
            call Fixture.Model.Account::get_IsActive()
            ret
            """);
        var code = _env.Decompile("Account::CheckPreview");
        Assert.Contains("Secret.Validate(\"anything\")", code);
        Assert.Contains("IsActive", code);
    }

    [Fact]
    public void Prepend_keeps_original_and_branches_into_it()
    {
        Patch("Account::Charge(int)", """
            ldarg.1
            ldc.i4.0
            bge IL_0000
            ret
            """, mode: "prepend");
        var code = _env.Decompile("Account::Charge(int)");
        Assert.Contains("if (amount >= 0)", code);
        Assert.Contains("_balance -= amount", code);
    }

    [Fact]
    public void IL_with_fields_arguments_locals_and_a_switch_applies()
    {
        Patch("Account::Score", """
            .local int
            ldarg.0
            ldfld Fixture.Model.Account::_balance
            stloc 0
            ldloc V_0
            switch (zero, one)
            ldc.i4 0x10
            ret
            zero:
            ldc.i4.0
            ret
            one:
            ldsfld Fixture.Model.Account::AccountCount
            ret
            """);
        var code = _env.Decompile("Account::Score");
        Assert.Contains("switch", code);
        Assert.Contains("AccountCount", code);
    }

    [Fact]
    public void Dry_run_leaves_original_untouched_including_prepend()
    {
        var before = _env.Decompiler.Disassemble(_env.Fixture, _env.One("Account::Charge(int)").Member, default);
        Assert.StartsWith("Dry run", Patch("Account::Charge(int)", "ldarg.1\nldc.i4.0\nbge IL_0000\nret", "prepend", dryRun: true));
        Assert.StartsWith("Dry run", Patch("Account::Score", ".local int\nldc.i4 0x10\nstloc 0\nldloc 0\nret", dryRun: true));
        Assert.False(_env.Fixture.IsDirty);
        Assert.Equal(before, _env.Decompiler.Disassemble(_env.Fixture, _env.One("Account::Charge(int)").Member, default));
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
    public void Rejects_bad_IL_without_touching_the_method(string il, string expected)
    {
        var ex = Assert.Throws<ToolError>(() => Patch("Account::Score", il));
        Assert.Contains(expected, ex.Message);
        Assert.False(_env.Fixture.IsDirty);
    }
}

public class CSharpPatchTests : IDisposable
{
    private readonly Env _env = new(withConsumer: true);
    public void Dispose() => _env.Dispose();

    private string Patch(string symbol, string code, bool dryRun = false) =>
        _env.Edit(() => _env.Edits.PatchMethodCSharp(_env.One(symbol), code, dryRun, default));

    /// <summary>Internal types in the signature must not cause CS0051 in the separately compiled helper.</summary>
    [Fact]
    public void Internal_types_in_signatures_compile_and_report_only_real_errors()
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
    public void Replaces_body_using_private_state_and_internal_types()
    {
        // _balance is private and Secret is internal: both must be accessible.
        Patch("Account::CheckPreview", """
            if (_balance <= 0)
                return false;
            return Secret.Validate("PREVIEW-OVERRIDE-0001");
            """);
        var code = _env.Decompile("Account::CheckPreview");
        Assert.Contains("_balance <= 0", code);
        Assert.Contains("PREVIEW-OVERRIDE-0001", code);
        Assert.True(_env.Fixture.IsDirty);
    }

    [Trait("Speed", "Slow")]
    [Fact]
    public void Methods_with_initializers_expression_bodies_and_overloads_take_patches()
    {
        Patch("Shop::PriceOf(string, int)", "return PriceOf(item) * quantity - Discount;");
        Assert.Contains("- Discount", _env.Decompile("Shop::PriceOf(string, int)"));
        Patch("Shop::Buy", "{ _credit += 1; return true; }");
        Assert.Contains("_credit++", _env.Decompile("Shop::Buy"));
    }

    [Trait("Speed", "Slow")]
    [Fact]
    public void Constructors_accessors_and_statics_take_patches()
    {
        Patch("Account::.ctor", "Name = name.ToUpperInvariant(); AccountCount += 10;");
        Assert.Contains("ToUpperInvariant", _env.Decompile("Account::.ctor"));

        Patch("Account::set_Balance", "_balance = value < 0 ? 0 : value;");
        Assert.Matches(@"value (<|>=) 0", _env.Decompiler.DecompileType(_env.Fixture, (dnlib.DotNet.TypeDef)_env.One("Account", SymbolKind.Type).Member, default));

        Patch("Shop::get_Credit", "return _credit * 2;"); // expression-bodied property
        Patch("Shop::Create", "var s = new Shop(); s.Discount = 50; return s;");
        Assert.Contains("Discount = 50", _env.Decompile("Shop::Create"));
    }

    [Fact]
    public void A_generic_method_takes_a_patch()
    {
        Patch("Shop::Pick", "return second;");
        Assert.Contains("return second;", _env.Decompile("Shop::Pick"));
    }

    [Fact]
    public void A_method_of_a_referencing_assembly_takes_a_patch()
    {
        Patch("Consumer.Branch::Total", "return entity.Score() + 1;");
        Assert.Contains("entity.Score() + 1", _env.Decompile("Consumer.Branch::Total"));
    }

    [Fact]
    public void Compile_errors_point_at_user_code()
    {
        var ex = Assert.Throws<ToolError>(() => Patch("Account::CheckPreview", "return doesNotExist;"));
        Assert.Contains("CS0103", ex.Message);
        Assert.Contains("your code line 1", ex.Message);
        Assert.False(_env.Fixture.IsDirty);
        Assert.Throws<ToolError>(() => Patch("Account::CheckPreview", "return 5;")); // wrong type
        Assert.Throws<ToolError>(() => Patch("Account::CheckPreview", "public void X() {}")); // not statements
        Assert.Throws<ToolError>(() => Patch("Account::CheckPreview", "   "));
    }

    [Fact]
    public void Unsupported_targets_explain_alternatives()
    {
        var auto = Assert.Throws<ToolError>(() => Patch("Shop::get_Discount", "return 1;"));
        Assert.Contains("auto-property", auto.Message);
        Assert.Contains("patch_method_il", auto.Message);
        Assert.Throws<ToolError>(() => Patch("Entity::Tick", "return;"));                 // abstract
        Assert.Contains("field-like event", Assert.Throws<ToolError>(() => Patch("Account::add_Closed", "return;")).Message);
    }

    [Fact]
    public void Patched_code_saves_and_runs_correctly()
    {
        Patch("Shop::PriceOf(string)", "return item.Length * 100;");
        Patch("Account::.ctor", "Name = name.ToUpperInvariant();");
        Patch("Account::set_Balance", "_balance = value < 0 ? 0 : value;");
        using var dir = new TempDir();
        var path = dir.File("TestFixture.dll");
        _env.Edits.Save(_env.Fixture, path, false);

        // Run in an isolated load context to prove the IL is valid at runtime.
        var context = new System.Runtime.Loader.AssemblyLoadContext("patched", isCollectible: true);
        try
        {
            var asm = context.LoadFromStream(new MemoryStream(File.ReadAllBytes(path)));
            var shop = Activator.CreateInstance(asm.GetType("Fixture.Model.Shop")!)!;
            var price = shop.GetType().GetMethod("PriceOf", [typeof(string)])!.Invoke(shop, ["pen"]);
            Assert.Equal(300, price);
            var buy = shop.GetType().GetMethod("Buy")!.Invoke(shop, ["pen"]);
            Assert.Equal(true, buy); // untouched method works and field initializers ran

            var accountType = asm.GetType("Fixture.Model.Account")!;
            var account = Activator.CreateInstance(accountType, "bob")!;
            Assert.Equal("BOB", (string)accountType.GetField("Name")!.GetValue(account)!);
            Assert.Equal(100, (int)accountType.GetProperty("Balance")!.GetValue(account)!); // initializer kept in the patched ctor
            accountType.GetProperty("Balance")!.SetValue(account, -5);
            Assert.Equal(0, (int)accountType.GetProperty("Balance")!.GetValue(account)!);
        }
        finally
        {
            context.Unload();
        }
    }
}
