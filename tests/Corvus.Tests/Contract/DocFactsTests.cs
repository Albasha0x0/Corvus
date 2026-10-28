using System.Text;
using System.Text.RegularExpressions;
using Corvus.Setup;

namespace Corvus.Tests;

/// <summary>Facts the README and docs state that the code decides: clients, release targets, commands, variables, version, links, examples and tool names.</summary>
public partial class DocFactsTests
{
    private static readonly string Root = DocsTests.RepoRoot();

    private static string Read(string relative) => File.ReadAllText(Path.Combine(Root, relative)).ReplaceLineEndings("\n");

    /// <summary>The user-facing Markdown: README, community files, docs and the skill.</summary>
    private static IEnumerable<string> MarkdownFiles() =>
        new[] { "README.md", "CONTRIBUTING.md", "SECURITY.md" }
            .Concat(Directory.EnumerateFiles(Path.Combine(Root, "docs"), "*.md").Select(f => Path.GetRelativePath(Root, f)))
            .Concat(SampleDocsTests.Pages().Select(f => Path.GetRelativePath(Root, f)))
            .Concat(RecipePages())
            .Concat(Directory.EnumerateFiles(Path.Combine(Root, "skills"), "*.md", SearchOption.AllDirectories).Select(f => Path.GetRelativePath(Root, f)))
            .Select(f => f.Replace('\\', '/'));

    [Fact]
    public void The_installation_guide_names_every_client()
    {
        var env = new SetupHome();
        try
        {
            var names = ClientCatalog.All(env.Env(os: HostOs.Windows)).Select(c => c.Name).ToList();
            var sentence = SupportedClients().Match(Read("docs/installation.md"));
            Assert.True(sentence.Success, "docs/installation.md has no 'Supported clients:' sentence");
            var listed = sentence.Groups[1].Value.ReplaceLineEndings(" ").Split([", ", " and "], StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
            Assert.Equal(names.Order(StringComparer.Ordinal), listed.Order(StringComparer.Ordinal));
        }
        finally { env.Dispose(); }
    }

    [Fact]
    public void Release_targets_match_the_release_workflow()
    {
        var rids = Rid().Matches(Read(".github/workflows/release.yml")).Select(m => m.Groups[1].Value).ToHashSet(StringComparer.Ordinal);
        Assert.Equal(8, rids.Count);
        foreach (var file in new[] { "README.md", "docs/installation.md" })
        {
            var named = RidName().Matches(Read(file)).Select(m => m.Value).ToHashSet(StringComparer.Ordinal);
            Assert.True(named.IsSubsetOf(rids), $"{file} names targets the release does not build: {string.Join(", ", named.Except(rids))}");
        }
        var readme = RidName().Matches(Read("README.md")).Select(m => m.Value).ToHashSet(StringComparer.Ordinal);
        Assert.True(rids.IsSubsetOf(readme), $"README.md does not name release targets {string.Join(", ", rids.Except(readme))}");
    }

    [Fact]
    public void Commands_are_documented()
    {
        var cli = Read("docs/cli.md");
        foreach (var command in ToolCli.Commands.Where(c => c != "help"))
            Assert.True(cli.Contains($"| `{command}", StringComparison.Ordinal), $"docs/cli.md has no row for {command}");
        var install = Read("docs/installation.md");
        foreach (var command in SetupCli.Words.Where(w => w is not ("help" or "version" or "doctor")))
            Assert.True(install.Contains($"corvus {command}", StringComparison.Ordinal), $"docs/installation.md does not describe {command}");
        // Rows of the command table name real commands.
        var section = cli[cli.IndexOf("## Commands", StringComparison.Ordinal)..];
        section = section[..section.IndexOf("\n## ", 3, StringComparison.Ordinal)];
        foreach (Match row in CommandRow().Matches(section))
        {
            var word = row.Groups[1].Value;
            Assert.True(word == "<tool>" || ToolCli.Commands.Contains(word), $"docs/cli.md lists unknown command {word}");
        }
    }

    [Fact]
    public void Every_environment_variable_is_documented()
    {
        var read = Directory.EnumerateFiles(Path.Combine(Root, "src"), "*.cs", SearchOption.AllDirectories)
            .SelectMany(f => VariableLiteral().Matches(File.ReadAllText(f)).Select(m => m.Groups[1].Value))
            .ToHashSet(StringComparer.Ordinal);
        Assert.NotEmpty(read);
        var docs = Read("docs/configuration.md");
        var missing = read.Where(v => !Regex.IsMatch(docs, $@"\b{v}\b")).Order(StringComparer.Ordinal).ToList();
        Assert.True(missing.Count == 0, $"variables read in src/ but not in docs/configuration.md: {string.Join(", ", missing)}");
    }

    [Fact]
    public void Every_server_option_is_documented()
    {
        var options = new[] { "Core/ServerOptions.cs", "Core/Toolsets.cs", "Core/ClientProfiles.cs" }
            .SelectMany(f => OptionLiteral().Matches(File.ReadAllText(Path.Combine(Root, "src", "Corvus", f))).Select(m => m.Groups[1].Value))
            .ToHashSet(StringComparer.Ordinal);
        Assert.Contains("--allow-live", options);
        var rows = Read("docs/configuration.md");
        var missing = options.Where(o => !rows.Contains($"| `{o}", StringComparison.Ordinal)).Order(StringComparer.Ordinal).ToList();
        Assert.True(missing.Count == 0, $"server options without a row in docs/configuration.md: {string.Join(", ", missing)}");
    }

    [Fact]
    public void Release_notes_head_the_project_version()
    {
        var version = ProjectVersion().Match(Read("src/Corvus/Corvus.csproj")).Groups[1].Value;
        var first = ReleaseHeading().Match(Read("docs/release-notes.md"));
        Assert.True(first.Success, "docs/release-notes.md has no '## <version>' heading");
        // The notes of the release being cut lead: release.ps1 bumps the project version after the suite passes.
        Assert.True(Version.Parse(first.Groups[1].Value) >= Version.Parse(version), $"the notes head {first.Groups[1].Value}, older than the project's {version}");
    }

    [Fact]
    public void Doc_links_resolve()
    {
        var problems = new List<string>();
        foreach (var file in MarkdownFiles())
        {
            var text = Read(file);
            foreach (Match link in Link().Matches(text))
            {
                var target = link.Groups[1].Value;
                if (target.Contains("://", StringComparison.Ordinal) || target.StartsWith("mailto:", StringComparison.Ordinal)) continue;
                var (path, anchor) = target.IndexOf('#') is var hash and >= 0 ? (target[..hash], target[(hash + 1)..]) : (target, "");
                var resolved = path.Length == 0 ? Path.Combine(Root, file) : Path.GetFullPath(Path.Combine(Root, Path.GetDirectoryName(file)!, path));
                if (!File.Exists(resolved) && !Directory.Exists(resolved)) problems.Add($"{file}: {target} (no such file)");
                else if (anchor.Length > 0 && resolved.EndsWith(".md", StringComparison.OrdinalIgnoreCase)
                         && !Heading().Matches(File.ReadAllText(resolved)).Any(h => Slug(h.Groups[1].Value) == anchor))
                    problems.Add($"{file}: {target} (no such heading)");
            }
        }
        Assert.True(problems.Count == 0, string.Join("\n", problems));
    }

    /// <summary>GitHub's heading anchor: lower case, punctuation dropped, spaces as dashes.</summary>
    private static string Slug(string heading)
    {
        var sb = new StringBuilder();
        foreach (var c in heading.Trim().ToLowerInvariant())
            if (char.IsLetterOrDigit(c) || c is '-' or '_') sb.Append(c);
            else if (c == ' ') sb.Append('-');
        return sb.ToString();
    }

    [Fact]
    public void Command_line_examples_use_real_tools_and_parameters()
    {
        var problems = new List<string>();
        int checkedCalls = 0;
        foreach (var file in MarkdownFiles())
            foreach (Match call in CliCall().Matches(Read(file)))
            {
                var word = call.Groups[1].Value;
                if (ToolCli.FindTool(word) is not { } tool) continue;
                checkedCalls++;
                var declared = ToolCli.Parameters(tool).Select(p => p.Name).ToHashSet(StringComparer.Ordinal);
                foreach (Match assignment in Assignment().Matches(call.Groups[2].Value))
                    if (!declared.Contains(assignment.Groups[1].Value))
                        problems.Add($"{file}: {word} has no parameter {assignment.Groups[1].Value}");
            }
        Assert.True(checkedCalls >= 5, $"only {checkedCalls} example calls found");
        Assert.True(problems.Count == 0, string.Join("\n", problems));
    }

    /// <summary>The recipes under docs/recipes, relative to the repository root.</summary>
    private static IEnumerable<string> RecipePages() =>
        Directory.EnumerateFiles(Path.Combine(Root, "docs", "recipes"), "*.md").Select(f => Path.GetRelativePath(Root, f).Replace('\\', '/')).Order(StringComparer.Ordinal);

    [Fact]
    public void Recipes_run_real_commands_with_real_options()
    {
        // A recipe's other tools are checked by running it once; its Corvus command lines are checked here.
        var options = new[] { "Setup/CliArgs.cs", "Core/ServerOptions.cs", "Core/Toolsets.cs", "Core/ClientProfiles.cs" }
            .SelectMany(f => OptionLiteral().Matches(Read("src/Corvus/" + f)).Select(m => m.Groups[1].Value))
            .ToHashSet(StringComparer.Ordinal);
        var pages = RecipePages().ToList();
        Assert.True(pages.Count >= 3, $"only {pages.Count} recipes");
        var problems = new List<string>();
        foreach (var page in pages)
        {
            var text = Read(page);
            var calls = CliCall().Matches(text).ToList();
            if (calls.Count == 0) problems.Add($"{page}: runs no corvus command");
            foreach (Match call in calls)
            {
                var word = call.Groups[1].Value;
                if (ToolCli.FindTool(word) == null && !ToolCli.Commands.Contains(word)) { problems.Add($"{page}: corvus has no command {word}"); continue; }
                problems.AddRange(OptionWord().Matches(call.Groups[2].Value).Select(o => o.Groups[1].Value).Where(o => !options.Contains(o))
                    .Select(o => $"{page}: corvus {word} has no option {o}"));
            }
            // An argument list written for another tool (a Velociraptor execve argv) quotes each option.
            foreach (Match argv in Argv().Matches(text))
                problems.AddRange(OptionLiteral().Matches(argv.Value).Select(o => o.Groups[1].Value).Where(o => !options.Contains(o))
                    .Select(o => $"{page}: corvus has no option {o}"));
        }
        Assert.True(problems.Count == 0, string.Join("\n", problems));
    }

    [Fact]
    public void Docs_name_only_registered_tools()
    {
        // Prompt names read like tools; list_changed is a notification.
        var tools = ToolCli.CatalogTools.Concat(ToolCli.CatalogPrompts).Select(t => (string)t["name"]!).ToHashSet(StringComparer.Ordinal);
        string[] notTools = ["dump_from_memory", "list_changed"];
        foreach (var file in new[] { "README.md", "docs/cli.md", "docs/faq.md", "docs/troubleshooting.md", "docs/installation.md" }
                     .Concat(SampleDocsTests.Pages().Select(f => Path.GetRelativePath(Root, f).Replace('\\', '/'))))
        {
            var unknown = McpProtocolTests.UnknownTools(Read(file), tools, notTools);
            Assert.True(unknown.Count == 0, $"{file} names tools that do not exist: {string.Join(", ", unknown)}");
        }
    }

    private static readonly string[] Translations = ["README.zh-CN.md", "README.ja.md"];

    /// <summary>What a translation keeps from its source: heading levels, links, code, table shape and numbers.</summary>
    private static (List<string> Headings, List<string> Links, List<string> Code, List<string> Tables, List<string> Numbers) Skeleton(string text)
    {
        var withoutBlocks = CodeBlock().Replace(text, "");
        var code = CodeBlock().Matches(text).Concat(InlineCode().Matches(withoutBlocks)).Select(m => m.Value).ToList();
        var prose = InlineCode().Replace(withoutBlocks, "");
        // The language line links the other two READMEs, so it differs by design.
        var links = Link().Matches(prose).Select(m => m.Groups[1].Value).Where(l => !IsReadme(l)).ToList();
        var tables = text.Split('\n').Where(l => l.StartsWith('|')).Select(l => $"{l.Count(c => c == '|')} bars").ToList();
        var numbers = Number().Matches(Link().Replace(prose, "")).Select(m => m.Value).Order(StringComparer.Ordinal).ToList();
        var headings = Heading().Matches(text).Select(m => m.Value[..m.Value.IndexOf(' ')]).ToList();
        return (headings, links, code, tables, numbers);
    }

    private static bool IsReadme(string link) => link.StartsWith("README", StringComparison.Ordinal);

    private static HashSet<string> ReadmeLinks(string file) =>
        Link().Matches(Read(file)).Select(m => m.Groups[1].Value).Where(IsReadme).ToHashSet(StringComparer.Ordinal);

    [Fact]
    public void The_translated_READMEs_keep_the_headings_links_code_tables_and_counts_of_README_md()
    {
        var source = Skeleton(Read("README.md"));
        foreach (var file in Translations)
        {
            var translated = Skeleton(Read(file));
            Assert.True(source.Headings.SequenceEqual(translated.Headings), $"{file}: heading levels differ from README.md");
            Assert.Equal(source.Links, translated.Links);
            Assert.Equal(source.Code, translated.Code);
            Assert.Equal(source.Tables, translated.Tables);
            Assert.Equal(source.Numbers, translated.Numbers);
            Assert.Equal(new[] { "README.md" }.Concat(Translations).Where(r => r != file).ToHashSet(), ReadmeLinks(file));
        }
        Assert.Equal(Translations.ToHashSet(), ReadmeLinks("README.md"));
    }

    [GeneratedRegex(@"Supported clients: ([^.]+)\.")]
    private static partial Regex SupportedClients();

    [GeneratedRegex(@"rid: ([a-z0-9-]+)")]
    private static partial Regex Rid();

    [GeneratedRegex(@"\b(?:win|linux-musl|linux|osx)-(?:x64|x86|arm64|arm)\b")]
    private static partial Regex RidName();

    [GeneratedRegex(@"^\| `([^` ]+)", RegexOptions.Multiline)]
    private static partial Regex CommandRow();

    [GeneratedRegex(@"""(CORVUS_[A-Z0-9_]+)""")]
    private static partial Regex VariableLiteral();

    [GeneratedRegex(@"""(--[a-z][a-z0-9-]+)""")]
    private static partial Regex OptionLiteral();

    [GeneratedRegex(@"<Version>([^<]+)</Version>")]
    private static partial Regex ProjectVersion();

    [GeneratedRegex(@"^## (\d+\.\d+\.\d+)", RegexOptions.Multiline)]
    private static partial Regex ReleaseHeading();

    [GeneratedRegex(@"\]\(([^)\s]+)\)")]
    private static partial Regex Link();

    [GeneratedRegex(@"^#+ (.+)$", RegexOptions.Multiline)]
    private static partial Regex Heading();

    /// <summary>A command line: corvus [call] word, then its arguments up to the end of the line, a backtick or a comment.</summary>
    [GeneratedRegex(@"corvus (?:call )?([a-z][a-z0-9_-]*)([^`\n#|]*)")]
    private static partial Regex CliCall();

    [GeneratedRegex(@"(?:^|\s)([A-Za-z_][A-Za-z0-9_]*):?=")]
    private static partial Regex Assignment();

    [GeneratedRegex(@"(?:^|\s)(--[a-z][a-z0-9-]*)")]
    private static partial Regex OptionWord();

    /// <summary>A quoted argument list that runs corvus batch: argv=[..., "batch", ...].</summary>
    [GeneratedRegex(@"argv=\[[^\]]*""batch""[^\]]*\]")]
    private static partial Regex Argv();

    [GeneratedRegex(@"^```[^\n]*\n.*?^```", RegexOptions.Multiline | RegexOptions.Singleline)]
    private static partial Regex CodeBlock();

    [GeneratedRegex(@"`[^`\n]+`")]
    private static partial Regex InlineCode();

    [GeneratedRegex(@"\d+(?:\.\d+)*")]
    private static partial Regex Number();
}
