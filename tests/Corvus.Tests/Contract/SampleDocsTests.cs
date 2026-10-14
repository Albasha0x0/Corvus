using System.Diagnostics;
using System.Text.RegularExpressions;
using Corvus.Setup;

namespace Corvus.Tests;

/// <summary>
/// The guides (docs/guides) and showcases (docs/showcase) run on the samples built from samples/. Their checked blocks
/// are executed in order and each output block must equal what the step prints now; CORVUS_UPDATE_DOCS=1 rewrites them.
/// </summary>
public partial class SampleDocsTests
{
    private static readonly string Root = DocsTests.RepoRoot();

    internal static IEnumerable<string> Pages() =>
        new[] { "guides", "showcase" }.Select(d => Path.Combine(Root, "docs", d)).Where(Directory.Exists)
            .SelectMany(d => Directory.EnumerateFiles(d, "*.md")).Order(StringComparer.Ordinal);

    /// <summary>A checked block: setup (commands, exit 0), batch (corvus batch steps), run (one program run) or output.</summary>
    internal sealed record Block(string Kind, string Options, int Start, int End, string Body);

    /// <summary>Each block is a <c>&lt;!-- check: kind --&gt;</c> line followed by a fenced block; Start..End are the fence's body lines.</summary>
    internal static List<Block> Blocks(string[] lines)
    {
        var blocks = new List<Block>();
        for (int i = 0; i < lines.Length; i++)
        {
            if (CheckLine().Match(lines[i]) is not { Success: true } m) continue;
            int open = i + 1;
            while (open < lines.Length && lines[open].Length == 0) open++;
            if (open >= lines.Length || !lines[open].StartsWith("```", StringComparison.Ordinal)) throw new FormatException($"line {i + 1}: no fenced block after the check");
            int close = open + 1;
            while (close < lines.Length && lines[close] != "```") close++;
            if (close >= lines.Length) throw new FormatException($"line {open + 1}: unclosed fence");
            blocks.Add(new Block(m.Groups[1].Value, m.Groups[2].Value.Trim(), open + 1, close, string.Join("\n", lines[(open + 1)..close])));
            i = close;
        }
        return blocks;
    }

    [Fact]
    public void PagesAreWellFormed()
    {
        var pages = Pages().ToList();
        Assert.True(pages.Count >= 5, $"only {pages.Count} guide and showcase pages");
        foreach (var page in pages)
        {
            var name = Path.GetRelativePath(Root, page);
            var blocks = Blocks(File.ReadAllLines(page));
            Assert.True(blocks.Any(b => b.Kind == "output"), $"{name} checks no output");
            for (int i = 0; i < blocks.Count; i++)
            {
                var b = blocks[i];
                switch (b.Kind)
                {
                    case "batch":
                        Assert.NotEmpty(ToolCli.ParseBatch(b.Body));
                        Assert.True(i + 1 < blocks.Count && blocks[i + 1].Kind == "output", $"{name}:{b.Start}: a batch block needs an output block next");
                        break;
                    case "run":
                        Assert.True(b.Body.Split('\n').Length == 1 && b.Body.StartsWith("dotnet samples/", StringComparison.Ordinal), $"{name}:{b.Start}: a run block is one 'dotnet samples/...' line");
                        Assert.True(i + 1 < blocks.Count && blocks[i + 1].Kind == "output", $"{name}:{b.Start}: a run block needs an output block next");
                        break;
                    case "setup":
                        Assert.All(b.Body.Split('\n'), l => Assert.StartsWith("dotnet ", l, StringComparison.Ordinal));
                        break;
                    case "output":
                        Assert.True(i > 0 && blocks[i - 1].Kind is "batch" or "run", $"{name}:{b.Start}: an output block follows a batch or run block");
                        break;
                    default:
                        Assert.Fail($"{name}:{b.Start}: unknown check '{b.Kind}'");
                        break;
                }
            }
        }
    }

    [Fact]
    [Trait("Speed", "Slow")]
    public async Task PagesMatchWhatTheStepsPrint()
    {
        bool update = Environment.GetEnvironmentVariable("CORVUS_UPDATE_DOCS") == "1";
        var stale = new List<string>();
        foreach (var page in Pages())
        {
            var lines = File.ReadAllLines(page);
            var labels = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var replacements = new List<(Block Output, string Text)>();
            string? last = null;
            foreach (var b in Blocks(lines))
            {
                switch (b.Kind)
                {
                    case "setup":
                        foreach (var command in b.Body.Split('\n'))
                        {
                            var (code, stdout, stderr) = await RunAsync(command);
                            Assert.True(code == 0, $"{command} failed ({code}):\n{stdout}\n{stderr}");
                        }
                        break;
                    case "batch":
                        last = await BatchAsync(b.Body, b.Options);
                        break;
                    case "run":
                        var (exit, output, error) = await RunAsync(b.Body);
                        last = output.ReplaceLineEndings("\n").TrimEnd('\n')
                            + string.Concat(error.ReplaceLineEndings("\n").Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(l => "\nstderr: " + l))
                            + $"\nexit code {exit}";
                        break;
                    case "output":
                        var text = Normalize(last!, labels);
                        if (text != b.Body) replacements.Add((b, text));
                        break;
                }
            }
            if (replacements.Count == 0) continue;
            var name = Path.GetRelativePath(Root, page);
            if (!update)
            {
                stale.AddRange(replacements.Select(r => $"{name}:{r.Output.Start}: expected\n{r.Text}\n--- found\n{r.Output.Body}"));
                continue;
            }
            var edited = lines.ToList();
            foreach (var (output, text) in replacements.OrderByDescending(r => r.Output.Start))
            {
                edited.RemoveRange(output.Start, output.End - output.Start);
                edited.InsertRange(output.Start, text.Split('\n'));
            }
            File.WriteAllText(page, string.Join("\n", edited) + "\n");
        }
        Assert.True(stale.Count == 0, "guide or showcase output is out of date (CORVUS_UPDATE_DOCS=1 rewrites it):\n" + string.Join("\n\n", stale));
    }

    /// <summary>Runs the steps in one in-process session, with the samples' paths made absolute; show=1,3 keeps those steps.</summary>
    private static async Task<string> BatchAsync(string steps, string options)
    {
        // Output folders must be new or empty; a page run again starts from none.
        foreach (var step in ToolCli.ParseBatch(steps))
            if (step.Arguments.TryGetValue("outputDirectory", out var dir) && dir?.ToString() is { } d && d.StartsWith("samples/", StringComparison.Ordinal) && d.Contains("/bin/", StringComparison.Ordinal)
                && Path.Combine(Root, d) is var full && Directory.Exists(full))
                Directory.Delete(full, recursive: true);
        var json = System.Text.Json.JsonSerializer.Serialize(Root.Replace('\\', '/') + "/")[1..^1];
        var (_, output, error) = await ToolCliTests.RunWithInput(steps.Replace("\"samples/", "\"" + json + "samples/", StringComparison.Ordinal), "batch", "-", "--no-index");
        var text = output.ReplaceLineEndings("\n").TrimEnd('\n') + (error.Length > 0 ? "\n" + error.ReplaceLineEndings("\n").TrimEnd('\n') : "");
        if (ShowOption().Match(options) is not { Success: true } show) return text;
        var keep = show.Groups[1].Value.Split(',').Select(int.Parse).ToHashSet();
        var sections = StepStart().Split(text).Where(s => s.Length > 0);
        return string.Join("\n", sections.Where(s => StepHeader().Match(s) is { Success: true } h && keep.Contains(int.Parse(h.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture)))
            .Select(s => s.TrimEnd('\n')));
    }

    /// <summary>Runs a 'dotnet ...' line from the repository root; arguments are split at spaces.</summary>
    private static async Task<(int Code, string Out, string Error)> RunAsync(string command)
    {
        var words = command.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var psi = new ProcessStartInfo("dotnet") { WorkingDirectory = Root, RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        foreach (var w in words.Skip(1)) psi.ArgumentList.Add(w);
        psi.Environment["DOTNET_CLI_UI_LANGUAGE"] = "en";
        // The SDK leaves random folders in its temporary folder: one of its own, deleted after the call.
        var temp = Directory.CreateTempSubdirectory("corvus-dotnet-").FullName;
        foreach (var name in new[] { "TMP", "TEMP", "TMPDIR" }) psi.Environment[name] = temp;
        try
        {
            using var p = Process.Start(psi)!;
            var stdout = p.StandardOutput.ReadToEndAsync();
            var stderr = p.StandardError.ReadToEndAsync();
            await p.WaitForExitAsync();
            return (p.ExitCode, await stdout, await stderr);
        }
        finally
        {
            try { Directory.Delete(temp, true); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
    }

    /// <summary>
    /// Output as the page shows it: repository paths relative with '/', and each SHA-256, GUID and bundle id replaced by
    /// a label numbered in order of first appearance on the page (equal values keep one label; builds change the values).
    /// </summary>
    internal static string Normalize(string text, Dictionary<string, string> labels)
    {
        var root = Path.TrimEndingDirectorySeparator(Root);
        foreach (var form in new[] { root.Replace("\\", "\\\\", StringComparison.Ordinal) + "\\\\", root + Path.DirectorySeparatorChar, root.Replace('\\', '/') + "/" })
            text = text.Replace(form, "", StringComparison.OrdinalIgnoreCase);
        text = SamplePath().Replace(text, m => m.Value.Replace("\\\\", "/", StringComparison.Ordinal).Replace('\\', '/'));
        string Label(Match m, string kind)
        {
            var key = m.Value.ToLowerInvariant();
            if (!labels.TryGetValue(key, out var label)) labels[key] = label = $"<{kind}-{labels.Values.Count(v => v.StartsWith("<" + kind + "-", StringComparison.Ordinal)) + 1}>";
            return label;
        }
        text = Sha256().Replace(text, m => Label(m, "sha256"));
        text = Guid().Replace(text, m => Label(m, "guid"));
        text = BundleId().Replace(text, m => Label(m, "bundle-id"));
        return string.Join("\n", text.ReplaceLineEndings("\n").Split('\n').Select(l => l.TrimEnd()));
    }

    [Fact]
    public void NormalizeLabelsValuesAndPaths()
    {
        var labels = new Dictionary<string, string>();
        var a = new string('a', 64);
        var path = Path.Combine(Root, "samples", "Notes", "v1", "bin", "Notes.dll");
        var text = Normalize($"{a} {a.ToUpperInvariant()} {new string('b', 64)} {path} 0f8fad5b-d9cb-469f-a165-70867728950e", labels);
        Assert.Equal("<sha256-1> <sha256-1> <sha256-2> samples/Notes/v1/bin/Notes.dll <guid-1>", text);
    }

    [GeneratedRegex(@"^<!-- check: ([a-z]+)\b([^>]*)-->$")]
    private static partial Regex CheckLine();

    [GeneratedRegex(@"show=([0-9,]+)")]
    private static partial Regex ShowOption();

    [GeneratedRegex(@"(?m)^(?==== \[)")]
    private static partial Regex StepStart();

    [GeneratedRegex(@"^=== \[(\d+)/\d+\]")]
    private static partial Regex StepHeader();

    [GeneratedRegex(@"samples(?:(?:\\\\|\\|/)[A-Za-z0-9._#-]+)+")]
    private static partial Regex SamplePath();

    /// <summary>A single-file bundle's id, which each publish draws anew.</summary>
    [GeneratedRegex(@"(?<=bundle v[0-9.]+, id )[A-Za-z0-9_-]+")]
    private static partial Regex BundleId();

    [GeneratedRegex(@"\b[0-9a-fA-F]{64}\b")]
    private static partial Regex Sha256();

    [GeneratedRegex(@"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")]
    private static partial Regex Guid();
}
