using System.Text.RegularExpressions;
using System.Xml;

namespace Corvus.Services.Web.Packages;

public static partial class PackageReview
{
    private const int MaxBuildFiles = 500, MaxHookLines = 400;

    // What runs each hook, from githooks(5).
    private static readonly Dictionary<string, string> HookEvents = new(StringComparer.Ordinal)
    {
        ["pre-commit"] = "commit", ["prepare-commit-msg"] = "commit", ["commit-msg"] = "commit", ["post-commit"] = "commit",
        ["pre-merge-commit"] = "merge", ["post-merge"] = "merge and pull", ["post-checkout"] = "checkout, switch and clone",
        ["pre-rebase"] = "rebase", ["post-rewrite"] = "rebase and amend", ["pre-push"] = "push", ["pre-auto-gc"] = "automatic gc",
        ["reference-transaction"] = "every ref update", ["fsmonitor-watchman"] = "every status", ["post-index-change"] = "every index write",
        ["applypatch-msg"] = "am", ["pre-applypatch"] = "am", ["post-applypatch"] = "am", ["sendemail-validate"] = "send-email",
    };

    // git-config(1) keys whose value git runs as a command, and when.
    private static readonly (Regex Key, string When, bool Noteworthy)[] ConfigCommands =
    [
        (new(@"^core\.fsmonitor$"), "on every status, which editors run when the folder opens", true),
        (new(@"^filter\.[^.]+\.(smudge|process)$"), "on checkout of the files .gitattributes assigns to the filter", true),
        (new(@"^filter\.[^.]+\.clean$"), "when files the filter covers are staged", false),
        (new(@"^core\.hookspath$"), "sets the folder git runs hooks from", false),
        (new(@"^core\.(sshcommand|pager|editor|askpass)$|^sequence\.editor$|^gpg\.program$|^credential\.helper$"), "when git needs it", false),
        (new(@"^diff\.([^.]+\.)?(external|textconv|command)$|^merge\.[^.]+\.driver$"), "on diff or merge", false),
        (new(@"^alias\."), "when the alias is used", false),
    ];

    // Targets a Visual Studio design-time build runs, so hooks on them run when the project opens.
    private static readonly HashSet<string> DesignTimeTargets = new(StringComparer.OrdinalIgnoreCase)
    {
        "CoreCompile", "Compile", "BeforeCompile", "ResolveReferences", "ResolveAssemblyReferences", "ResolveProjectReferences",
        "CollectPackageReferences", "PrepareForBuild", "_CheckForInvalidConfigurationAndPlatform",
    };

    private static readonly Regex GradleExec = new(@"\bexec\s*\{|\bcommandLine\b|\bProcessBuilder\b|Runtime\.getRuntime\(\)\.exec|""\s*\.execute\(\)", RegexOptions.Compiled);
    private static readonly Regex CMakeExec = new(@"\bexecute_process\s*\(", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    /// <summary>What a repository runs on open, checkout or build (git, dev container, direnv, build files); null when none.</summary>
    internal static AgentReview? RepositoryHooks(PackageFiles files, CancellationToken ct)
    {
        var review = new AgentReview([], [], []);
        var paths = files.Paths.Where(p => !p.Contains("node_modules/", StringComparison.Ordinal)).Order(StringComparer.Ordinal).ToList();
        foreach (var path in paths.Where(p => p == ".git/config" || p.EndsWith("/.git/config", StringComparison.Ordinal)).Take(1)) GitConfig(files, path, review, ct);
        foreach (var path in paths.Where(p => Regex.IsMatch(p, @"(^|/)\.git/hooks/[^/]+$") && !p.EndsWith(".sample", StringComparison.Ordinal)))
            GitHook(files, path, "a clone never carries hooks, so this copy had them added", true, review, ct);
        foreach (var path in paths.Where(p => Regex.IsMatch(p, @"(^|/)\.husky/[^/_][^/]*$") && HookEvents.ContainsKey(p[(p.LastIndexOf('/') + 1)..])))
            GitHook(files, path, "husky installs it on npm install", false, review, ct);
        foreach (var path in paths.Where(p => Regex.IsMatch(p, @"(^|/)(\.devcontainer/([^/]+/)?devcontainer\.json|\.devcontainer\.json)$")))
            DevContainer(files, path, review, ct);
        foreach (var path in paths.Where(p => p == ".envrc" || p.EndsWith("/.envrc", StringComparison.Ordinal)).Take(10))
        {
            review.Entries.Add(new AgentEntry("direnv", ".envrc", Clip(FirstCommand(files.Text(path)), 160), path));
            review.Findings.Add(new PackageFinding("review", "repository hook", "direnv runs .envrc on entering the folder once it is allowed", path));
            if (files.Text(path) is { } text) ScanCommand(text, ".envrc", path, 1, review, ct);
        }
        var build = paths.Where(IsBuildFile).ToList();
        if (build.Count > MaxBuildFiles) review.Notes.Add($"{build.Count} build files; the first {MaxBuildFiles} by path are read, the others' build steps are unknown");
        foreach (var path in build.Take(MaxBuildFiles))
        {
            ct.ThrowIfCancellationRequested();
            if (files.Text(path) is not { } text)
            {
                review.Notes.Add($"{path}: not read ({files.Size(path):N0} bytes); its build steps are unknown");
                continue;
            }
            var name = path[(path.LastIndexOf('/') + 1)..];
            if (name == "build.rs") CargoBuildScript(path, text, review, ct);
            else if (name.StartsWith("build.gradle", StringComparison.Ordinal) || name.StartsWith("settings.gradle", StringComparison.Ordinal)) Gradle(path, text, review, ct);
            else if (name == "gradle-wrapper.properties") GradleWrapper(path, text, review);
            else if (name == "CMakeLists.txt" || name.EndsWith(".cmake", StringComparison.Ordinal)) CMake(path, text, review, ct);
            else MsBuild(path, text, review, ct);
        }
        return review.Entries.Count > 0 || review.Findings.Count > 0 || review.Notes.Count > 0 ? review : null;
    }

    private static bool IsBuildFile(string path)
    {
        var name = path[(path.LastIndexOf('/') + 1)..];
        var ext = Path.GetExtension(name).ToLowerInvariant();
        return ext is ".csproj" or ".vbproj" or ".fsproj" or ".vcxproj" or ".proj" or ".props" or ".targets"
            || name is "build.rs" or "build.gradle" or "build.gradle.kts" or "settings.gradle" or "settings.gradle.kts" or "gradle-wrapper.properties" or "CMakeLists.txt"
            || ext == ".cmake";
    }

    /// <summary>The first line of a script that is not a shebang, comment or blank; null when there is none.</summary>
    private static string? FirstCommand(string? text) =>
        text?.Split('\n').Select(l => l.Trim()).FirstOrDefault(l => l.Length > 0 && !l.StartsWith('#'));

    // --- git ---

    private static void GitConfig(PackageFiles files, string path, AgentReview review, CancellationToken ct)
    {
        if (files.Text(path) is not { } text)
        {
            review.Notes.Add($"{path}: not read; the commands it sets are unknown");
            return;
        }
        string section = "";
        int line = 0;
        foreach (var raw in text.Split('\n'))
        {
            line++;
            var l = raw.Trim();
            if (l.Length == 0 || l[0] is '#' or ';') continue;
            if (l[0] == '[')
            {
                // [section "subsection"]: the section is case-insensitive, the subsection is not.
                var m = Regex.Match(l, @"^\[\s*([\w.-]+)(?:\s+""((?:[^""\\]|\\.)*)"")?\s*\]");
                section = m.Success ? m.Groups[1].Value.ToLowerInvariant() + (m.Groups[2].Success ? "." + m.Groups[2].Value : "") : "";
                continue;
            }
            int eq = l.IndexOf('=');
            if (eq <= 0 || section.Length == 0) continue;
            var key = section + "." + l[..eq].Trim().ToLowerInvariant();
            var value = l[(eq + 1)..].Trim().Trim('"');
            var hit = ConfigCommands.FirstOrDefault(c => c.Key.IsMatch(key));
            if (hit.Key == null || key.StartsWith("alias.", StringComparison.Ordinal) && !value.StartsWith('!')) continue;
            if (key == "core.fsmonitor" && value is "true" or "false") continue;
            review.Entries.Add(new AgentEntry("git config", key, Clip(value, 200), path, line));
            review.Findings.Add(new PackageFinding(hit.Noteworthy ? "noteworthy" : "review", "repository hook", $"git config {key} runs {hit.When}: {Clip(value, 200)}", path, line));
            ScanCommand(value, "git config " + key, path, line, review, ct);
        }
    }

    private static void GitHook(PackageFiles files, string path, string origin, bool noteworthy, AgentReview review, CancellationToken ct)
    {
        var name = path[(path.LastIndexOf('/') + 1)..];
        var when = HookEvents.GetValueOrDefault(name, "git commands");
        var text = files.Text(path);
        review.Entries.Add(new AgentEntry("git hook", name, Clip(FirstCommand(text), 160), path));
        review.Findings.Add(new PackageFinding(noteworthy ? "noteworthy" : "review", "repository hook", $"git hook {name} runs on {when}; {origin}", path));
        if (text != null) ScanCommand(string.Join('\n', text.Split('\n').Take(MaxHookLines)), "git hook " + name, path, 1, review, ct);
        else review.Notes.Add($"{path}: not read; what the hook runs is unknown");
    }

    // --- dev containers ---

    private static void DevContainer(PackageFiles files, string path, AgentReview review, CancellationToken ct)
    {
        if (Tree(files, path, review.Notes) is not { } config) return;
        foreach (var key in new[] { "initializeCommand", "onCreateCommand", "updateContentCommand", "postCreateCommand", "postStartCommand", "postAttachCommand" })
        {
            if (config[key] is not { } value) continue;
            // A command is a string, an array of arguments, or an object of named commands run in parallel.
            var commands = value.Props is { } named
                ? named.Select(p => (Name: $"{key} ({p.Name})", Command: Command(p.Value), p.Value.Line)).ToList()
                : [(Name: key, Command: Command(value), value.Line)];
            bool host = key == "initializeCommand";
            foreach (var (name, command, line) in commands.Where(c => c.Command != null))
            {
                review.Entries.Add(new AgentEntry("dev container", name, Clip(command), path, line));
                review.Findings.Add(new PackageFinding(host ? "noteworthy" : "review", "repository hook",
                    (host ? $"{name} runs on the host before the dev container is built: " : $"{name} runs in the dev container: ") + Clip(command, 200), path, line));
                ScanCommand(command!, name, path, line, review, ct);
            }
        }

        static string? Command(JsonTree v) => v.Text ?? (v.Items is { } args ? string.Join(" ", args.Select(a => a.Text ?? "")) : null);
    }

    // --- build files ---

    private static void MsBuild(string path, string text, AgentReview review, CancellationToken ct)
    {
        var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, IgnoreComments = true };
        var initial = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        string? target = null;
        bool designTime = false;
        try
        {
            using var reader = XmlReader.Create(new StringReader(text), settings);
            var info = (IXmlLineInfo)reader;
            while (reader.Read())
            {
                if (reader.NodeType == XmlNodeType.EndElement && reader.LocalName == "Target") target = null;
                if (reader.NodeType != XmlNodeType.Element) continue;
                switch (reader.LocalName)
                {
                    case "Project":
                        foreach (var t in (reader.GetAttribute("InitialTargets") ?? "").Split(';', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)) initial.Add(t);
                        break;
                    case "Target":
                        target = reader.GetAttribute("Name") ?? "(no name)";
                        var hooked = $"{reader.GetAttribute("BeforeTargets")};{reader.GetAttribute("AfterTargets")}".Split(';', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
                        designTime = initial.Contains(target) || hooked.Any(DesignTimeTargets.Contains);
                        if (reader.IsEmptyElement) target = null;
                        break;
                    case "Exec" when target != null && reader.GetAttribute("Command") is { } command:
                        review.Entries.Add(new AgentEntry("build step", target, Clip(command), path, info.LineNumber));
                        review.Findings.Add(new PackageFinding(designTime ? "noteworthy" : "review", "build step",
                            $"MSBuild target {target} runs {Clip(command, 200)}" + (designTime ? "; the design-time build runs it when Visual Studio opens the project" : " at build"), path, info.LineNumber));
                        ScanCommand(command, "target " + target, path, info.LineNumber, review, ct);
                        break;
                    case "UsingTask" when reader.GetAttribute("TaskFactory") is { } factory && factory.Contains("CodeTaskFactory", StringComparison.Ordinal):
                        var task = reader.GetAttribute("TaskName") ?? "(no name)";
                        review.Entries.Add(new AgentEntry("build step", task, factory, path, info.LineNumber));
                        review.Findings.Add(new PackageFinding("noteworthy", "build step", $"inline MSBuild task {task} ({factory}) compiles and runs code at build", path, info.LineNumber));
                        break;
                }
            }
        }
        catch (XmlException ex)
        {
            review.Notes.Add($"{path}: not valid XML ({ex.Message}); build steps after line {ex.LineNumber} are unknown");
        }
    }

    private static void CargoBuildScript(string path, string text, AgentReview review, CancellationToken ct)
    {
        review.Entries.Add(new AgentEntry("build step", "build.rs", null, path));
        review.Findings.Add(new PackageFinding("review", "build step", "Cargo build script: cargo runs it before compiling, and rust-analyzer when the folder opens", path));
        foreach (var f in Scan(path, text, install: true, ct, peel: false))
            if (f.Level == "noteworthy") review.Findings.Add(f with { Detail = "build.rs: " + f.Detail });
    }

    private static void Gradle(string path, string text, AgentReview review, CancellationToken ct)
    {
        var lines = text.Split('\n');
        for (int i = 0; i < lines.Length; i++)
        {
            if (!GradleExec.IsMatch(lines[i])) continue;
            var command = Clip(lines[i].Trim(), 200)!;
            review.Entries.Add(new AgentEntry("build step", path[(path.LastIndexOf('/') + 1)..], command, path, i + 1));
            review.Findings.Add(new PackageFinding("review", "build step", $"Gradle script starts a process; IDE sync runs it when the project opens: {command}", path, i + 1));
            ScanCommand(lines[i], "Gradle script", path, i + 1, review, ct);
        }
    }

    private static void GradleWrapper(string path, string text, AgentReview review)
    {
        var lines = text.Split('\n');
        for (int i = 0; i < lines.Length; i++)
        {
            var m = Regex.Match(lines[i], @"^\s*distributionUrl\s*=\s*(\S+)");
            if (!m.Success) continue;
            var url = m.Groups[1].Value.Replace(@"\:", ":", StringComparison.Ordinal);
            if (Regex.IsMatch(url, @"^https://services\.gradle\.org/distributions/")) return;
            review.Entries.Add(new AgentEntry("build step", "gradle wrapper", url, path, i + 1));
            review.Findings.Add(new PackageFinding("noteworthy", "build step", $"the Gradle wrapper downloads and runs its build tool from {Clip(url, 200)}, not services.gradle.org", path, i + 1));
        }
    }

    private static void CMake(string path, string text, AgentReview review, CancellationToken ct)
    {
        var lines = text.Split('\n');
        for (int i = 0; i < lines.Length; i++)
        {
            if (!CMakeExec.IsMatch(lines[i])) continue;
            var command = Clip(lines[i].Trim(), 200)!;
            review.Entries.Add(new AgentEntry("build step", path[(path.LastIndexOf('/') + 1)..], command, path, i + 1));
            review.Findings.Add(new PackageFinding("review", "build step", $"CMake runs a process at configure: {command}", path, i + 1));
            ScanCommand(lines[i], "CMake", path, i + 1, review, ct);
        }
    }
}
