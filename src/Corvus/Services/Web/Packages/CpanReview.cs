using System.Text.Json;
using System.Text.RegularExpressions;

namespace Corvus.Services.Web.Packages;

public static partial class PackageReview
{
    private static readonly string[] CpanInstallers = ["Makefile.PL", "Build.PL"];

    private static readonly Regex PerlName = R(@"\b(NAME|module_name|dist_name)\s*=>\s*['""]([^'""\n]+)['""]");
    private static readonly Regex PerlVersion = R(@"\b(VERSION|dist_version)\s*=>\s*['""]([^'""\n]+)['""]");

    /// <summary>
    /// The Makefile.PL or Build.PL at the package root or one folder down; the
    /// shallowest wins. Null when there is none.
    /// </summary>
    private static string? CpanInstaller(PackageFiles files) =>
        CpanInstallers.Select(n => Root(files, n)).Where(p => p != null && p.Count(c => c == '/') <= 1)
            .OrderBy(p => p!.Count(c => c == '/')).ThenBy(p => p, StringComparer.Ordinal).FirstOrDefault();

    private static PackageReport? Cpan(PackageFiles files, CancellationToken ct)
    {
        var root = Folder(CpanInstaller(files)!);
        var findings = new List<PackageFinding>();
        var scripts = new List<PackageScript>();
        var notes = new List<string>();
        string? first = null;
        foreach (var name in CpanInstallers)
        {
            var path = root + name;
            if (!files.Has(path)) continue;
            first ??= path;
            // The CPAN client runs the installer with perl while installing.
            scripts.Add(new PackageScript(name, $"perl {name}", true));
            findings.Add(new PackageFinding("package/install-script", "info", "install script", $"{name}: perl runs it when the distribution is installed", path));
            if (files.Text(path) is { } code) findings.AddRange(Scan(path, code, install: true, ct));
            else notes.Add($"{name} was not read (see partial)");
        }
        string? pkgName = null, version = null, author = null, abstractText = null;
        int deps = 0;
        bool metaRead = false;
        if (Json(files, root + "META.json") is { ValueKind: JsonValueKind.Object } meta)
        {
            metaRead = true;
            pkgName = Str(meta, "name");
            version = Str(meta, "version");
            abstractText = Str(meta, "abstract");
            if (meta.TryGetProperty("author", out var a) && a.ValueKind == JsonValueKind.Array)
                author = a.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString()).FirstOrDefault();
            if (meta.TryGetProperty("prereqs", out var p) && p.ValueKind == JsonValueKind.Object
                && p.TryGetProperty("runtime", out var rt) && rt.ValueKind == JsonValueKind.Object
                && rt.TryGetProperty("requires", out var req) && req.ValueKind == JsonValueKind.Object)
                deps = req.EnumerateObject().Count();
            else notes.Add("META.json lists no runtime prerequisites; dependencies unknown");
        }
        else if (files.Container == "file") notes.Add("META.json not read (single file); dependencies unknown");
        else notes.Add("META.json absent or unreadable; dependencies unknown");
        if ((pkgName == null || version == null) && first != null && files.Text(first) is { } text)
        {
            var fromInstaller = false;
            if (pkgName == null && PerlName.Match(text) is { Success: true } n) { pkgName = n.Groups[2].Value; fromInstaller = true; }
            if (version == null && PerlVersion.Match(text) is { Success: true } v) { version = v.Groups[2].Value; fromInstaller = true; }
            if (fromInstaller) notes.Add(metaRead ? "name or version read from the installer" : "name and version read from the installer");
            if (pkgName == null || version == null) notes.Add("name or version not found in the installer; unknown");
        }
        var binaries = Binaries(files);
        if (binaries.Count > 0) findings.Add(new PackageFinding("package/binary", "review", "binary", $"{binaries.Count} native or executable file(s): {string.Join(", ", binaries.Take(5))}", binaries[0]));
        return new PackageReport("cpan", pkgName, version)
        {
            Publisher = author, Description = Clip(abstractText), Scripts = scripts, Dependencies = deps,
            Binaries = binaries.Count > 0 ? binaries : null, Findings = findings, Notes = notes,
        };
    }
}
