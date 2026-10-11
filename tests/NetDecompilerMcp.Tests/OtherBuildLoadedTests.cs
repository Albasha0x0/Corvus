using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Tests;

/// <summary>With another build of the assembly loaded (as for update_to_new_build), names in the assembly being worked on stay unambiguous.</summary>
public sealed class OtherBuildLoadedTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly Env _env = new();

    public OtherBuildLoadedTests()
    {
        var copy = _dir.File(Path.GetFileName(Env.FixturePath));
        File.Copy(Env.FixturePath, copy);
        _env.Workspace.Load(copy);
    }

    public void Dispose()
    {
        _env.Dispose();
        _dir.Dispose();
    }

    [Fact]
    public void IlOperandsBindToThePatchedAssembly()
    {
        var describe = SymbolResolver.ResolveOne(_env.Workspace, _env.Fixture.Id, "Fixture.Model.Shop::Describe");
        var result = _env.Edit(() => _env.Edits.PatchMethodIL(describe,
            "ldarg.0\nldstr \"pen\"\ncall instance int32 Fixture.Model.Shop::PriceOf(string)\npop\nldstr \"x\"\nret", "replace", true));
        Assert.Contains("PriceOf", result);
    }
}
