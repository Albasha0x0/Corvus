using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using Acornima.Ast;
using Corvus.Core;
using Corvus.Services.Web;

namespace Corvus.Services.Web.Packages;

public static partial class PackageReview
{
    private const int MaxToolDescriptions = 500, MaxSourceFiles = 200, MaxSourceBytes = 2 << 20;

    // Registry server.json, MCPB manifest.json and a saved tools/list response.
    internal static string? McpKind(string path)
    {
        var name = path[(path.LastIndexOf('/') + 1)..];
        if (name == "server.json") return "mcp registry";
        if (name == "manifest.json") return "mcp manifest";
        return name is "tools.json" or "tools-list.json" or "tools_list.json" ? "mcp tools" : null;
    }

    /// <summary>A folder with no agent configuration, for comparing against one that has.</summary>
    internal static readonly PackageReport EmptyAgentReport = new("repository", null, null) { Hosts = [] };

    /// <summary>The agent configuration entries and findings of a folder, with its endpoints empty so a comparison does not note them; null when the folder holds none.</summary>
    internal static PackageReport? ReviewAgentFolder(string root, CancellationToken ct)
    {
        var review = AgentConfig(PackageFiles.OpenAgentFolder(root, ct), standalone: true, ct);
        if (review == null) return null;
        return new PackageReport("repository", null, null) { Agents = review.Entries, Findings = review.Findings, Notes = review.Notes, Hosts = [] };
    }

    [GeneratedRegex(@"token|secret|passw(?:or)?d|api[_-]?key|credential|private[_-]?key|(?:^|[_-])o?auth(?:orization)?(?:[_-]|$)", RegexOptions.IgnoreCase | RegexOptions.NonBacktracking)]
    private static partial Regex SecretKey();

    // Package launchers: the argument that names the package, after these subcommands.
    private static readonly string[] Launchers = ["npx", "bunx", "pnpx", "uvx", "pipx", "docker", "podman", "deno"];

    private static readonly HashSet<string> ValueFlags = new(StringComparer.Ordinal)
    {
        "-e", "--env", "-v", "--volume", "--name", "--network", "-p", "--publish", "-w", "--workdir", "-u", "--user", "--mount", "--entrypoint",
        "--platform", "--env-file", "--from", "-p", "--package", "-c", "--call",
    };

    /// <summary>One server entry: its launcher, remote address and environment key names.</summary>
    private static void McpServer(string name, JsonTree server, string path, AgentReview review, CancellationToken ct)
    {
        var args = (server["args"]?.Items ?? []).Select(a => a.Text ?? "").ToList();
        var exe = server["command"]?.Text;
        var command = exe != null ? string.Join(" ", new[] { exe }.Concat(args)) : server["url"]?.Text;
        review.Entries.Add(new AgentEntry("mcp server", name, Clip(command), path, server.Line));
        if (command != null) ScanCommand(command, $"MCP server {name}", path, server.Line, review, ct);
        if (exe != null && Unpinned(exe, args) is { } package)
            review.Findings.Add(new PackageFinding("package/mcp-unpinned", "review", "agent configuration",
                $"MCP server {name} launches {Clip(package, 120)} without a pinned version", path, server.Line));
        if (server["url"]?.Text is { } url) McpRemote($"MCP server {name}", url, path, server.Line, review);
        var keys = (server["env"]?.Props ?? []).Select(p => p.Name).Where(k => SecretKey().IsMatch(k)).ToList();
        if (keys.Count > 0)
            review.Findings.Add(new PackageFinding("package/mcp-secret-env", "review", "agent configuration",
                $"MCP server {name} passes credential-named environment key(s) {Clip(string.Join(", ", keys), 200)}; values not shown", path, server.Line));
    }

    /// <summary>Review findings for a remote address that is plain HTTP or a raw IP address; loopback is ordinary.</summary>
    private static void McpRemote(string what, string url, string path, int line, AgentReview review)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https" or "ws" or "wss")) return;
        bool loopback = uri.IsLoopback || uri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase) || uri.Host.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase);
        if (loopback) return;
        if (uri.Scheme is "http" or "ws")
            review.Findings.Add(new PackageFinding("package/mcp-plain-http", "review", "agent configuration", $"{what} connects to {Clip(uri.Host, 120)} without TLS", path, line));
        if (IPAddress.TryParse(uri.Host.Trim('[', ']'), out _))
            review.Findings.Add(new PackageFinding("package/mcp-raw-address", "review", "agent configuration", $"{what} connects to the raw address {Clip(uri.Host, 120)}", path, line));
    }

    /// <summary>The package a launcher runs without a version, or null when it is pinned or <paramref name="exe"/> is no package launcher.</summary>
    internal static string? Unpinned(string exe, IReadOnlyList<string> args)
    {
        var tool = Path.GetFileNameWithoutExtension(exe.Replace('\\', '/').Split('/')[^1]).ToLowerInvariant();
        var list = args.ToList();
        if (tool is "npm" or "pnpm" or "yarn" or "bun")
        {
            if (list.Count == 0 || list[0] is not ("exec" or "dlx" or "x")) return null;
            list.RemoveAt(0);
            tool = "npx";
        }
        if (!Launchers.Contains(tool)) return null;
        if (tool is "docker" or "podman")
        {
            if (list.Count == 0 || list[0] != "run") return null;
            list.RemoveAt(0);
            var image = FirstOperand(list, skipFlagValues: true);
            if (image == null || image.Contains("@sha256:", StringComparison.Ordinal)) return null;
            var tag = image[(image.LastIndexOf('/') + 1)..];
            return tag.Contains(':') && !tag.EndsWith(":latest", StringComparison.Ordinal) ? null : image;
        }
        if (tool == "deno")
        {
            if (list.Count == 0 || list[0] != "run") return null;
            list.RemoveAt(0);
            var spec = FirstOperand(list, skipFlagValues: false);
            return spec != null && (spec.StartsWith("npm:", StringComparison.Ordinal) || spec.StartsWith("jsr:", StringComparison.Ordinal)) && !VersionPinned(spec[(spec.IndexOf(':') + 1)..])
                ? spec : null;
        }
        if (tool == "pipx") { if (list.Count == 0 || list[0] != "run") return null; list.RemoveAt(0); }
        int from = list.FindIndex(a => a is "--from" or "--package" or "-p");
        var package = from >= 0 && from + 1 < list.Count ? list[from + 1] : FirstOperand(list, skipFlagValues: true);
        if (package == null || package.Contains('/') && !package.StartsWith('@') || package.StartsWith('.')) return null;
        return VersionPinned(package) ? null : package;
    }

    private static string? FirstOperand(List<string> args, bool skipFlagValues)
    {
        for (int i = 0; i < args.Count; i++)
        {
            if (!args[i].StartsWith('-')) return args[i];
            if (skipFlagValues && ValueFlags.Contains(args[i]) && !args[i].Contains('=')) i++;
        }
        return null;
    }

    // A version is a number after "@" or "==" (a range or a tag such as latest is not a pin).
    private static bool VersionPinned(string package)
    {
        int at = package.IndexOf('@', package.StartsWith('@') ? 1 : 0);
        var version = at >= 0 ? package[(at + 1)..] : package.Contains("==", StringComparison.Ordinal) ? package[(package.IndexOf("==", StringComparison.Ordinal) + 2)..] : null;
        return version is { Length: > 0 } && char.IsAsciiDigit(version[0]);
    }

    // --- tool descriptions ---

    // A comment or hidden-character run in a description is text the person approving the tool does not see.
    private static void McpDescription(string label, string? text, int line, string path, AgentReview review, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(text)) return;
        var lines = text.Split('\n');
        for (int i = 0; i < lines.Length; i++)
            foreach (var f in HiddenOnLine(lines[i], ct).Where(f => f.Level == "noteworthy"))
                review.Findings.Add(f with { Detail = $"{label}: {f.Detail}", Path = path, Line = line });
        foreach (Match m in RenderedHidden().Matches(text))
        {
            var body = (m.Groups[1].Success ? m.Groups[1].Value : m.Groups[2].Value).Trim();
            if (body.Length == 0 || MarkupDirective().IsMatch(body)) continue;
            review.Findings.Add(new PackageFinding("package/mcp-hidden-description", "noteworthy", "hidden text",
                $"{label} holds a comment not shown when rendered: \"{Format.EscapeInvisible(Clip(Blanks().Replace(body, " "), 200)!)}\"", path, line));
        }
    }

    private static void McpTools(JsonTree? tools, string path, AgentReview review, CancellationToken ct)
    {
        int seen = 0;
        foreach (var tool in tools?.Items ?? [])
        {
            if (seen++ >= MaxToolDescriptions) { review.Notes.Add($"{path}: over {MaxToolDescriptions} tools, the rest not checked"); return; }
            var name = Clip(tool["name"]?.Text ?? "(unnamed)", 80);
            McpDescription($"tool {name} description", tool["description"]?.Text, tool["description"]?.Line ?? tool.Line, path, review, ct);
            foreach (var (param, schema) in (tool["inputSchema"] ?? tool["input_schema"])?["properties"]?.Props ?? [])
                McpDescription($"tool {name} parameter {Clip(param, 60)} description", schema["description"]?.Text, schema["description"]?.Line ?? schema.Line, path, review, ct);
        }
    }

    /// <summary>A saved tools/list response: a tools array, bare or under result.</summary>
    private static void McpToolsList(JsonTree root, string path, AgentReview review, CancellationToken ct)
    {
        var tools = root.Items != null ? root : root["tools"] ?? root["result"]?["tools"];
        if (tools?.Items == null) return;
        review.Entries.Add(new AgentEntry("mcp tools", path[(path.LastIndexOf('/') + 1)..], $"{tools.Items.Count} tool(s)", path, tools.Line));
        McpTools(tools, path, review, ct);
    }

    /// <summary>An MCPB manifest: its tools, prompts and launcher; other manifest.json files are not MCP.</summary>
    private static void McpManifest(JsonTree root, string path, AgentReview review, CancellationToken ct)
    {
        if (root["server"] == null) return;
        var name = root["name"]?.Text ?? "(unnamed)";
        if (root["server"]?["mcp_config"] is { } launch) McpServer(Clip(name, 80)!, launch, path, review, ct);
        McpDescription("manifest description", root["description"]?.Text, root["description"]?.Line ?? 1, path, review, ct);
        McpDescription("manifest long description", root["long_description"]?.Text, root["long_description"]?.Line ?? 1, path, review, ct);
        McpTools(root["tools"], path, review, ct);
        foreach (var prompt in root["prompts"]?.Items ?? [])
            McpDescription($"prompt {Clip(prompt["name"]?.Text ?? "(unnamed)", 80)} description", prompt["description"]?.Text, prompt["description"]?.Line ?? prompt.Line, path, review, ct);
    }

    /// <summary>A registry server.json: its description, remotes and package versions.</summary>
    private static void McpRegistry(JsonTree root, string path, AgentReview review, CancellationToken ct)
    {
        if (root["name"] == null || root["description"] == null && root["packages"] == null && root["remotes"] == null) return;
        var name = Clip(root["name"]!.Text ?? "(unnamed)", 80)!;
        review.Entries.Add(new AgentEntry("mcp server", name, Clip(root["remotes"]?.Items?.FirstOrDefault()?["url"]?.Text
            ?? root["packages"]?.Items?.FirstOrDefault()?["identifier"]?.Text), path, root.Line));
        McpDescription("server description", root["description"]?.Text, root["description"]?.Line ?? 1, path, review, ct);
        foreach (var remote in root["remotes"]?.Items ?? [])
            if (remote["url"]?.Text is { } url) McpRemote($"MCP server {name} remote", url, path, remote.Line, review);
        foreach (var package in root["packages"]?.Items ?? [])
        {
            var version = package["version"]?.Text;
            var id = package["identifier"]?.Text;
            if (id != null && (version == null || version == "latest"))
                review.Findings.Add(new PackageFinding("package/mcp-unpinned", "review", "agent configuration",
                    $"MCP server {name} lists package {Clip(id, 120)} without a pinned version", path, package.Line));
        }
    }

    // --- registrations in server source ---

    // A decorator registration: @server.tool(...) over a function, with the description keyword or the docstring.
    [GeneratedRegex(@"^[ \t]*@\w+(?:\.\w+)*\.(?:tool|prompt)\b(?:\(([^)]*)\))?[ \t]*\r?\n[ \t]*(?:async[ \t]+)?def[ \t]+(\w+)\([^)]*\)[^:\n]*:[ \t]*\r?\n[ \t]*(?:""""""(.*?)""""""|'''(.*?)''')?",
        RegexOptions.Singleline | RegexOptions.Multiline | RegexOptions.NonBacktracking)]
    private static partial Regex PythonRegistration();

    [GeneratedRegex(@"description[ \t]*=[ \t]*(?:""((?:[^""\\\n]|\\.)*)""|'((?:[^'\\\n]|\\.)*)')", RegexOptions.NonBacktracking)]
    private static partial Regex DescriptionKeyword();

    /// <summary>Descriptions in string literals passed to tool registration calls in JavaScript and Python source; TypeScript is not read.</summary>
    private static void McpSource(PackageFiles files, AgentReview review, CancellationToken ct)
    {
        int read = 0, typescript = 0;
        foreach (var path in files.Paths.Where(p => !p.Contains("node_modules/", StringComparison.Ordinal)).Order(StringComparer.Ordinal))
        {
            ct.ThrowIfCancellationRequested();
            var ext = Path.GetExtension(path).ToLowerInvariant();
            if (ext is not (".js" or ".mjs" or ".cjs" or ".py" or ".ts" or ".mts")) continue;
            if (files.Size(path) > MaxSourceBytes || files.Text(path) is not { } text) continue;
            if (ext == ".py" ? !text.Contains("mcp", StringComparison.OrdinalIgnoreCase) : !text.Contains("tool", StringComparison.OrdinalIgnoreCase)) continue;
            if (ext is ".ts" or ".mts")
            {
                if (JsRegistration().IsMatch(text)) typescript++;
                continue;
            }
            if (read++ >= MaxSourceFiles) { review.Notes.Add($"{path}: over {MaxSourceFiles} source files, the rest not checked for tool registrations"); break; }
            if (ext == ".py") PythonDescriptions(text, path, review, ct);
            else JsDescriptions(text, path, review, ct);
        }
        if (typescript > 0) review.Notes.Add($"{typescript} TypeScript file(s) register tools; tool descriptions in TypeScript source are not read");
    }

    [GeneratedRegex(@"\.(?:tool|registerTool|addTool)\(", RegexOptions.NonBacktracking)]
    private static partial Regex JsRegistration();

    private static void PythonDescriptions(string text, string path, AgentReview review, CancellationToken ct)
    {
        foreach (Match m in PythonRegistration().Matches(text))
        {
            ct.ThrowIfCancellationRequested();
            int line = 1 + text.AsSpan(0, m.Index).Count('\n');
            var function = m.Groups[2].Value;
            if (DescriptionKeyword().Match(m.Groups[1].Value) is { Success: true } kw)
                McpDescription($"tool {function} description", kw.Groups[1].Success ? kw.Groups[1].Value : kw.Groups[2].Value, line, path, review, ct);
            var doc = m.Groups[3].Success ? m.Groups[3].Value : m.Groups[4].Value;
            McpDescription($"tool {function} docstring", doc, line, path, review, ct);
        }
    }

    private static string? Literal(Node? node) => node switch
    {
        StringLiteral s => s.Value,
        TemplateLiteral { Expressions.Count: 0 } t => string.Concat(t.Quasis.Select(q => q.Value.Cooked ?? q.Value.Raw)),
        _ => null,
    };

    private static string? PropertyValue(ObjectExpression o, string name) =>
        o.Properties.OfType<Property>().FirstOrDefault(p => p.Key is Identifier { Name: var n } && n == name || p.Key is StringLiteral { Value: var v } && v == name) is { } p ? Literal(p.Value) : null;

    // server.tool(name, description, ...), registerTool(name, { description }, ...) and addTool({ name, description }).
    private static void JsDescriptions(string text, string path, AgentReview review, CancellationToken ct)
    {
        var notes = new List<string>();
        if (JsModules.Parse(text, notes) is not { } program) return;
        var stack = new Stack<Node>();
        stack.Push(program);
        while (stack.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            var node = stack.Pop();
            if (node is CallExpression { Callee: MemberExpression { Property: Identifier { Name: "tool" or "registerTool" or "addTool" or "prompt" or "registerPrompt" }, Computed: false } } call
                && call.Arguments.Count > 0)
            {
                string? name = Literal(call.Arguments[0]);
                string? description = call.Arguments.Count > 1 ? Literal(call.Arguments[1]) : null;
                if (call.Arguments.Count > 1 && call.Arguments[1] is ObjectExpression config) description = PropertyValue(config, "description");
                if (call.Arguments[0] is ObjectExpression first) { name = PropertyValue(first, "name"); description = PropertyValue(first, "description"); }
                if (description != null)
                    McpDescription($"tool {Clip(name ?? "(unnamed)", 80)} description", description, node.Location.Start.Line, path, review, ct);
            }
            foreach (var child in node.ChildNodes)
                if (child != null) stack.Push(child);
        }
    }
}
