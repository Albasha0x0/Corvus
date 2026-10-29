using System.Text.RegularExpressions;

namespace Corvus.Services.Web.Packages;

public static partial class PackageReview
{
    // NuGet matches tools/ paths without regard to case; install and uninstall
    // may sit in a target framework folder.
    private static readonly Regex NugetScript = R(@"(?i)^tools/(?:init|(?:[^/]+/)?(?:install|uninstall))\.ps1$");

    /// <summary>
    /// The .nuspec at the package root, or null when the files are no NuGet
    /// package.
    /// </summary>
    private static string? Nuspec(PackageFiles files) =>
        files.Paths.Where(p => !p.Contains('/') && p.EndsWith(".nuspec", StringComparison.OrdinalIgnoreCase)).Order(StringComparer.Ordinal).FirstOrDefault();

    private static PackageReport? Nuget(PackageFiles files, CancellationToken ct)
    {
        var nuspec = Nuspec(files)!;
        var xml = files.Text(nuspec) ?? "";
        string? Element(string name) => Regex.Match(xml, $@"<{name}>\s*([^<]+?)\s*</{name}>", RegexOptions.NonBacktracking) is { Success: true } m ? m.Groups[1].Value : null;
        var findings = new List<PackageFinding>();
        var scripts = new List<PackageScript>();
        foreach (var path in files.Paths.Where(p => NugetScript.IsMatch(p)).Order(StringComparer.Ordinal))
        {
            var file = Path.GetFileName(path).ToLowerInvariant();
            var when = file switch
            {
                "init.ps1" => "each time the solution opens",
                "install.ps1" => "when the package is installed",
                _ => "when the package is removed",
            };
            scripts.Add(new PackageScript(path, $"run by the Package Manager Console {when}", file != "uninstall.ps1"));
            // Visual Studio runs these for packages.config projects only, so the
            // script alone is info; the code rules below set the level.
            findings.Add(new PackageFinding("package/install-script", "info", "install script", $"{path}: run by the Package Manager Console {when}", path));
            // A script over the read limits is already named in the not-read list.
            if (files.Text(path) is not { } code) continue;
            findings.AddRange(Scan(path, code, install: true, ct));
            if (NetworkCommand.IsMatch(code))
                findings.Add(new PackageFinding("package/install-network-tool", "noteworthy", "install script", $"{path} runs a network tool", path));
        }
        var binaries = Binaries(files);
        return new PackageReport("nuget", Element("id"), Element("version"))
        {
            Publisher = Element("authors"), Description = Clip(Element("description")), Scripts = scripts,
            Dependencies = Regex.Count(xml, @"<dependency\s", RegexOptions.NonBacktracking),
            // Assemblies are what a NuGet package carries, so they are listed,
            // not a finding.
            Binaries = binaries.Count > 0 ? binaries : null, Findings = findings,
        };
    }
}
