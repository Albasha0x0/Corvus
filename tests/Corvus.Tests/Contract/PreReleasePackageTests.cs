namespace Corvus.Tests;

/// <summary>The shipped projects resolve no pre-release package but the exceptions THIRD-PARTY-NOTICES.md names.</summary>
public class PreReleasePackageTests
{
    private static readonly string[] Exceptions = ["Samboy063.LibCpp2IL", "Samboy063.WasmDisassembler", "Microsoft.CodeAnalysis.Analyzers"];

    [Fact]
    public void Only_the_named_pre_release_packages_ship()
    {
        var notices = File.ReadAllText(Path.Combine(DocsTests.RepoRoot(), "THIRD-PARTY-NOTICES.md"));
        foreach (var project in LockFileTests.Shipped)
            foreach (var (target, packages) in LockFileTests.LockTargets(project))
                foreach (var (name, entry) in packages!.AsObject())
                {
                    if ((string?)entry!["resolved"] is not { } resolved || !resolved.Contains('-', StringComparison.Ordinal)) continue;
                    Assert.True(Exceptions.Contains(name), $"{project}: {target} resolves pre-release {name} {resolved}");
                    Assert.Contains($"{name} `{resolved}`", notices, StringComparison.Ordinal);
                }
    }
}
