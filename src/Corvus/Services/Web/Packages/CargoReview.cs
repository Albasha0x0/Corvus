namespace Corvus.Services.Web.Packages;

public static partial class PackageReview
{
    private static PackageReport? Cargo(PackageFiles files, CancellationToken ct)
    {
        var manifestPath = CargoManifest(files)!;
        var root = Folder(manifestPath);
        if (files.Text(manifestPath) is not { } toml)
            return new PackageReport("cargo", null, null) { Notes = [$"{manifestPath} was not read (see partial): name, build script and dependencies unknown"] };
        var tree = TomlTree.Parse(toml, out var skipped);
        var notes = new List<string>();
        var findings = new List<PackageFinding>();
        var scripts = new List<PackageScript>();
        if (skipped > 0) notes.Add($"{manifestPath}: {skipped} line(s) not valid TOML, skipped; build script and dependencies may be incomplete");
        var package = tree["package"];
        // Cargo builds build.rs, or the file package.build names, before
        // compiling the crate; build = false turns it off, true keeps build.rs.
        var build = package?["build"];
        string? script = build is { Text: "false" } ? null
            : build is { Text: { Length: > 0 } named } && named != "true" ? named
            : files.Has(root + "build.rs") ? "build.rs" : null;
        if (script != null)
        {
            var target = Resolve(root, script);
            scripts.Add(new PackageScript("build", script, true));
            // The default build.rs is already reported by the repository pass.
            if (script != "build.rs")
                findings.Add(new PackageFinding("package/cargo-build-script", "review", "build step", $"Cargo build script {script}: cargo runs it on the machine that compiles the crate", manifestPath));
            if (files.Text(target) is { } code) findings.AddRange(Scan(target, code, install: true, ct));
            else if (files.Has(target)) notes.Add($"build script {script} was not read (see partial)");
            else notes.Add($"build script {script}, which the package does not hold");
        }
        if (tree["lib"]?["proc-macro"] is { Text: "true" })
            findings.Add(new PackageFinding("package/proc-macro", "info", "build step", "a procedural macro crate: its code runs inside the compiler of every crate that uses it", manifestPath));
        int buildDeps = tree["build-dependencies"]?.Props?.Count ?? 0;
        if (buildDeps > 0) notes.Add($"{buildDeps} build dependenc{(buildDeps == 1 ? "y" : "ies")}: their code also runs in the build script's compile step");
        var binaries = Binaries(files);
        if (binaries.Count > 0) findings.Add(new PackageFinding("package/binary", "review", "binary", $"{binaries.Count} native or executable file(s): {string.Join(", ", binaries.Take(5))}", binaries[0]));
        if (package?["name"]?.Text is { } crate && CloseTo(crate, PopularNames.Crates) is { } popular)
            findings.Add(new PackageFinding("package/close-name", scripts.Any(s => s.AtInstall) ? "noteworthy" : "review", "name", $"the name '{crate}' is close to the popular package '{popular}'"));
        var authors = package?["authors"]?.Items?.FirstOrDefault()?.Text;
        return new PackageReport("cargo", package?["name"]?.Text, package?["version"]?.Text)
        {
            Publisher = authors, Description = Clip(package?["description"]?.Text), Repository = package?["repository"]?.Text,
            Scripts = scripts, Dependencies = tree["dependencies"]?.Props?.Count ?? 0, Binaries = binaries.Count > 0 ? binaries : null, Findings = findings, Notes = notes,
        };
    }

    /// <summary>The Cargo.toml at the package root or one top folder down; null when none.</summary>
    private static string? CargoManifest(PackageFiles files) =>
        Root(files, "Cargo.toml") is { } m && m.Count(c => c == '/') <= 1 ? m : null;
}
