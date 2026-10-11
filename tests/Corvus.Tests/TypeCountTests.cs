using System.Text.RegularExpressions;
using Corvus.Core;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>Every tool that counts types agrees: all types, nested included, &lt;Module&gt; excluded.</summary>
public class TypeCountTests : IDisposable
{
    private readonly Env _env = new();
    public void Dispose() => _env.Dispose();

    [Fact]
    public async Task InfoNamespacesAndListTypes_Agree()
    {
        var browse = new BrowseTools(_env.Workspace, _env.References, _env.Pager);
        var expected = _env.Workspace.Read(() => _env.Fixture.Module.GetTypes().Count(t => t.FullName != "<Module>"));
        var nested = _env.Workspace.Read(() => _env.Fixture.Module.GetTypes().Count(t => t.DeclaringType != null));
        Assert.True(nested > 0); // the fixture has nested types (Account.Inventory, compiler-generated closures)

        var info = _env.Workspace.Read(() => _env.Report.Build(_env.Fixture));
        Assert.Contains($"Types: {expected} ({nested} nested)", info);

        var namespaces = await browse.ListNamespaces();
        var counts = Regex.Matches(namespaces, @"^  \S+  \((\d+)\)", RegexOptions.Multiline).Select(m => int.Parse(m.Groups[1].Value)).ToList();
        Assert.Equal(expected, counts.Sum());
        var namespaceCount = int.Parse(Regex.Match(namespaces, @"\] (\d+) namespace").Groups[1].Value);
        Assert.Contains($"Namespaces: {namespaceCount} ", info);
        Assert.DoesNotContain("<Module>", namespaces);

        Assert.StartsWith($"{expected} types", await browse.ListTypes(limit: 1));
        Assert.Equal(expected, _env.Workspace.Read(() => MetadataUtil.CountedTypes(_env.Fixture.Module).Count)); // list_assemblies, load_assembly

        // per namespace: list_namespaces' count is what list_types lists for it
        var model = int.Parse(Regex.Match(namespaces, @"^  Fixture\.Model  \((\d+)\)", RegexOptions.Multiline).Groups[1].Value);
        Assert.StartsWith($"{model} types", await browse.ListTypes(@namespace: "Fixture.Model", limit: 1));
    }
}
