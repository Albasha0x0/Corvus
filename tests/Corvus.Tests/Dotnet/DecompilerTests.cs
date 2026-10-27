using dnlib.DotNet;
using Corvus.Core;

namespace Corvus.Tests;

public class DecompilerTests : IDisposable
{
    private readonly Env _env = new();
    public void Dispose() => _env.Dispose();

    [Fact]
    public void Decompiles_type_with_nested_types()
    {
        var code = _env.Decompiler.DecompileType(_env.Fixture, _env.Def<TypeDef>("Account"), default);
        Assert.Contains("public class Account : Entity, IChargeable", code);
        Assert.Contains("Charge(int amount, string source)", code);
        Assert.Contains("class Inventory", code);
        Assert.Contains("public const int MaxBalance = 100;", code);
    }

    [Theory]
    [InlineData("Account::LoadAsync", "await Task.Delay(1)")]
    [InlineData("Account::Range", "yield return 1")]
    [InlineData("Account::SumPositive", "v > 0")]
    [InlineData("Account::Balance", "get")]
    [InlineData("Account::get_Balance", "public int Balance")] // an accessor alone was a bare block
    [InlineData("Account::add_Closed", "event EventHandler")]
    [InlineData("Account::Closed", "event EventHandler")]
    [InlineData("Account::_balance", "private int _balance")]
    [InlineData("Account::.ctor", "AccountCount++")]
    [InlineData("Vec2::Length", "MathF.Sqrt")]
    public void Decompiles_members_back_to_source(string symbol, string expected) =>
        Assert.Contains(expected, _env.Decompile(symbol));

    [Theory]
    [InlineData("Team", "Red = 1")]
    [InlineData("IChargeable", "interface IChargeable")]
    [InlineData("Vec2", "struct Vec2")]
    [InlineData("Container", "where T : class")]
    public void Decompiles_every_type_kind(string type, string expected) =>
        Assert.Contains(expected, _env.Decompiler.DecompileType(_env.Fixture, _env.Def<TypeDef>(type, SymbolKind.Type), default));

    [Fact]
    public void Disassembles_with_tokens_and_offsets()
    {
        var il = _env.Decompiler.Disassemble(_env.Fixture, _env.One("Account::CheckPreview").Member, default);
        Assert.Contains("ldstr \"PREVIEW-CODE-42\"", il);
        Assert.Contains("IL_0000", il);
        Assert.Matches(@"/\* 06[0-9A-F]{6} \*/", il);
    }

    [Fact]
    public void Disassembles_types_fields_properties_events()
    {
        foreach (var (symbol, directive) in new[] { ("Account", ".class"), ("Account::_balance", ".field"), ("Account::Balance", ".property"), ("Account::Closed", ".event") })
            Assert.Contains(directive, _env.Decompiler.Disassemble(_env.Fixture, _env.One(symbol).Member, default));
    }

    [Fact]
    public void Exports_project_with_progress_and_refuses_non_empty_directory()
    {
        using var dir = new TempDir();
        var progress = new List<string>();
        var result = _env.Decompiler.ExportProject(_env.Fixture, dir.Path, (_, _, s) => progress.Add(s), default);
        Assert.NotNull(result.ProjectFile);
        Assert.True(result.FileCount > 3);
        Assert.Empty(result.FailedTypes);
        Assert.Contains(Directory.EnumerateFiles(dir.Path, "*.cs", SearchOption.AllDirectories), f => f.EndsWith("Account.cs"));
        Assert.Throws<ToolError>(() => _env.Decompiler.ExportProject(_env.Fixture, dir.Path, null, default));
    }

    [Fact]
    public void Assembly_attributes_decompile() =>
        Assert.Contains("TargetFramework", _env.Decompiler.DecompileAssemblyAttributes(_env.Fixture, default));

    [Fact]
    public void Caller_cancellation_is_not_a_tool_error()
    {
        using var env = new Env();
        var decompiler = new Services.DecompilerService(env.Workspace, new ServerOptions());
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        // Caller cancellation is not converted to a ToolError.
        Assert.ThrowsAny<OperationCanceledException>(() => decompiler.DecompileType(env.Fixture, env.Def<TypeDef>("Account"), cts.Token));
    }

    [Fact]
    public void Assembly_report_covers_identity_PE_and_references()
    {
        var report = _env.Report.Build(_env.Fixture);
        foreach (var expected in new[] { "Id: TestFixture", "Target framework", "PE32", "Sections:", ".text", "Metadata streams", "References:", "System.Runtime", "AOT metadata: 2 methods" })
            Assert.Contains(expected, report);
    }

    /// <summary>A constructor with nothing stored before its base call is shown alone; one with field initializers in its type.</summary>
    [Fact]
    public void Constructors_without_initializers_are_shown_alone()
    {
        var alone = _env.Decompile("PremiumAccount::.ctor");
        Assert.DoesNotContain("they run as part of this constructor", alone);
        Assert.Contains("base(\"PremiumAccount\")", alone);
        var inContext = _env.Decompile("Fixture.Model.Account::.ctor");
        Assert.Contains("field initializers: they run as part of this constructor", inContext);
        Assert.Contains("_balance = 100", inContext);
    }

    /// <summary>A simplified view with nothing to simplify decompiles the loaded assembly as it is.</summary>
    [Fact]
    public void Simplified_view_without_changes_is_the_plain_decompile()
    {
        var member = _env.One("Account::CheckPreview").Member;
        var simplified = _env.Workspace.Read(() => _env.Decompiler.DecompileSimplified(_env.Fixture, [member], new Corvus.Services.Simplify.SimplifyOptions(), default));
        var plain = _env.Workspace.Read(() => _env.Decompiler.DecompileMembers(_env.Fixture, [member], default));
        Assert.StartsWith("// Simplified view (", simplified);
        Assert.Contains(": 0 of 1 method(s) simplified", simplified);
        Assert.EndsWith(plain, simplified);
    }

    // The XML doc file beside the assembly is held open with no sharing, so any read of it fails.
    [Fact]
    public void A_type_decompiles_whole_without_reading_the_xml_doc_file_beside_it()
    {
        using var dir = new TempDir();
        var path = dir.File("Documented.dll");
        File.WriteAllBytes(path, Roslyn.Release("Documented", "namespace Docs { /// <summary>Adds.</summary>\npublic class Adder { public int Add(int a, int b) => a + b; } }"));
        File.WriteAllText(dir.File("Documented.xml"), "<?xml version=\"1.0\"?><doc><members><member name=\"T:Docs.Adder\"><summary>Adds.</summary></member></members></doc>");
        using var held = new FileStream(dir.File("Documented.xml"), FileMode.Open, FileAccess.Read, FileShare.None);
        using var ws = new AssemblyWorkspace();
        var asm = ws.Load(path);
        var code = ws.Read(() => new Corvus.Services.DecompilerService(ws, new ServerOptions()).DecompileType(asm, asm.Module.Find("Docs.Adder", false)!, default));
        Assert.DoesNotContain("decompilation failed", code);
        Assert.Contains("public int Add(int a, int b)", code);
    }

    /// <summary>A write that changes no assembly keeps the decompiler's type systems; an edit of the assembly replaces its own.</summary>
    [Fact]
    public void Type_systems_outlive_writes_that_change_no_assembly()
    {
        var first = _env.Workspace.Read(() => _env.Decompiler.GetTypeSystem(_env.Fixture));
        _env.Workspace.Write(() => 0);
        Assert.Same(first, _env.Workspace.Read(() => _env.Decompiler.GetTypeSystem(_env.Fixture)));
        _env.Edit(() => _env.Edits.StubMethod(_env.One("Account::Score"), "3"));
        Assert.NotSame(first, _env.Workspace.Read(() => _env.Decompiler.GetTypeSystem(_env.Fixture)));
    }
}
