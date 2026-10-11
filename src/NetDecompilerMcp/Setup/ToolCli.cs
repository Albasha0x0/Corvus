using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Mcp;

namespace NetDecompilerMcp.Setup;

/// <summary>The tool CLI's streams; Tty flags select indented JSON and a progress line.</summary>
internal sealed record CliIo(TextWriter Out, TextWriter Error, TextReader In, bool OutTty = false, bool ErrorTty = false);

/// <summary>
/// Every tool from the terminal with no per-tool code: commands and argument types come from the live catalog, and calls
/// run through an in-process server (<see cref="ToolSession"/>). Exit codes: <see cref="Exit"/>.
/// </summary>
internal static partial class ToolCli
{
    /// <summary>Exit codes, documented in docs/cli.md.</summary>
    public static class Exit
    {
        public const int Ok = 0;
        public const int ToolError = 1;
        public const int Usage = 2;
        public const int Environment = 3;
        public const int Timeout = 124;
        public const int Cancelled = 130;
    }

    /// <summary>The CLI's commands; any other first word that is not a setup command is a tool name.</summary>
    public static readonly string[] Commands = ["call", "tools", "describe", "help", "batch", "prompts", "prompt", "resources", "read", "completion"];

    private const string Program = "NetDecompilerMcp";

    /// <summary>Runs a CLI command with the console and Ctrl+C, or returns null when the arguments are not one.</summary>
    public static int? TryRun(string[] args)
    {
        if (!Handles(args)) return null;
        using var cancel = new CancellationTokenSource();
        ConsoleCancelEventHandler onCancel = (_, e) =>
        {
            // The first Ctrl+C cancels the call and waits for the tool to stop; a second one ends the process.
            if (cancel.IsCancellationRequested) return;
            e.Cancel = true;
            cancel.Cancel();
        };
        Console.CancelKeyPress += onCancel;
        try
        {
            var io = new CliIo(Console.Out, Console.Error, Console.In, !Console.IsOutputRedirected, !Console.IsErrorRedirected);
            return RunAsync(args, io, cancel.Token).GetAwaiter().GetResult();
        }
        finally { Console.CancelKeyPress -= onCancel; }
    }

    /// <summary>
    /// A CLI command, a tool name, or any other word that is not a setup command (reported as unknown); server options start
    /// with "-", so a server start never matches. "help" alone is the setup help.
    /// </summary>
    public static bool Handles(string[] args)
    {
        if (args.Length == 0 || args[0].StartsWith('-')) return false;
        if (args[0].Equals("help", StringComparison.OrdinalIgnoreCase)) return args.Length > 1 && !args[1].StartsWith('-');
        return !SetupCli.IsCommand(args[0]);
    }

    public static async Task<int> RunAsync(string[] args, CliIo io, CancellationToken cancellationToken)
    {
        try
        {
            var command = args[0].ToLowerInvariant();
            var rest = args.Skip(1).ToList();
            if (!Commands.Contains(command))
            {
                command = "call";
                rest = [.. args];
            }
            var a = CliArgs.Parse(rest);
            return command switch
            {
                "call" => await CallAsync(a, io, cancellationToken),
                "tools" => Tools(a, io),
                "batch" => await BatchAsync(a, io, cancellationToken),
                "prompts" => Prompts(a, io),
                "prompt" => await PromptAsync(a, io, cancellationToken),
                "resources" => await ResourcesAsync(a, io, cancellationToken),
                "read" => await ReadAsync(a, io, cancellationToken),
                "completion" => Completion(a, io),
                _ => Describe(a, io),
            };
        }
        catch (UsageException ex)
        {
            io.Error.WriteLine($"{ex.Message} Run: {Program} help");
            return Exit.Usage;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            io.Error.WriteLine("Cancelled.");
            return Exit.Cancelled;
        }
    }

    /// <summary>The catalog with every toolset, for names, schemas and descriptions; built once per process.</summary>
    private static readonly Lazy<(List<JsonNode> Tools, List<JsonNode> Prompts)> Catalog = new(() => Mcp.Catalog.OfThisBuild(Toolsets.All));

    public static IReadOnlyList<JsonNode> CatalogTools => Catalog.Value.Tools;
    public static IReadOnlyList<JsonNode> CatalogPrompts => Catalog.Value.Prompts;

    private static string NameOf(JsonNode node) => (string)node["name"]!;

    /// <summary>A tool by name; kebab-case and any letter case are accepted.</summary>
    public static JsonNode? FindTool(string name)
    {
        var normalized = name.Replace('-', '_');
        return CatalogTools.FirstOrDefault(t => NameOf(t).Equals(normalized, StringComparison.OrdinalIgnoreCase));
    }

    private static JsonNode? FindPrompt(string name)
    {
        var normalized = name.Replace('-', '_');
        return CatalogPrompts.FirstOrDefault(p => NameOf(p).Equals(normalized, StringComparison.OrdinalIgnoreCase));
    }

    private static JsonNode RequireTool(string name) => FindTool(name) ?? throw new UsageException(
        $"Unknown command or tool '{name}'." + Suggestion(name, CatalogTools.Select(NameOf)) + $" Tools: {Program} tools.");

    private static string Suggestion(string name, IEnumerable<string> names) =>
        ArgumentCheck.Suggest(name.Replace('-', '_'), [.. names]) is { Count: > 0 } s ? $" Did you mean {string.Join(" or ", s)}?" : "";

    // ---- call ----

    private static async Task<int> CallAsync(CliArgs a, CliIo io, CancellationToken cancellationToken)
    {
        if (a.Positionals.Count == 0) throw new UsageException("call needs a tool name.");
        if (a.Positionals.Count > 1) throw new UsageException($"Unexpected '{a.Positionals[1]}': tool arguments are name=value.");
        var tool = RequireTool(a.Positionals[0]);
        var name = NameOf(tool);
        if (a.Structured && tool["outputSchema"] is null) throw new UsageException($"{name} has no structured output; use --json.");
        var arguments = a.ToolArguments(tool["inputSchema"], io.In);
        var options = a.Server();
        await using var session = await ToolSession.StartAsync(options, cancellationToken);
        var result = await Invoke(session, name, arguments, io, cancellationToken);
        return result is null ? Exit.Usage : Print(name, result, a, io);
    }

    /// <summary>One tool call; null after reporting a protocol error (a tool the --toolsets leave out).</summary>
    private static async Task<CallToolResult?> Invoke(ToolSession session, string name, Dictionary<string, object?> arguments, CliIo io, CancellationToken cancellationToken)
    {
        IProgress<ProgressNotificationValue>? progress = io.ErrorTty ? new ProgressLine(io.Error) : null;
        try
        {
            var result = await session.Client.CallToolAsync(name, arguments, progress, cancellationToken: cancellationToken);
            if (progress is ProgressLine line) line.Clear();
            return result;
        }
        catch (McpProtocolException ex)
        {
            io.Error.WriteLine($"{name}: {ex.Message}");
            return null;
        }
    }

    /// <summary>Writes a result and returns its exit code: text to stdout (errors to stderr), notices to stderr.</summary>
    private static int Print(string tool, CallToolResult result, CliArgs a, CliIo io)
    {
        var (text, notices, error) = Split(result);
        bool isError = result.IsError == true;
        foreach (var notice in notices) io.Error.WriteLine(notice);
        if (a.Json)
        {
            var record = new JsonObject
            {
                ["tool"] = tool,
                ["isError"] = isError,
                ["text"] = text,
                ["structured"] = result.StructuredContent is { } s ? JsonNode.Parse(s.GetRawText()) : null,
                ["error"] = error,
            };
            io.Out.WriteLine(record.ToJsonString(JsonOptions(io)));
        }
        else if (isError) io.Error.WriteLine(text);
        else if (a.Structured && result.StructuredContent is { } structured)
            io.Out.WriteLine(JsonNode.Parse(structured.GetRawText())!.ToJsonString(JsonOptions(io)));
        else io.Out.WriteLine(text);
        return isError ? ExitCode(error) : Exit.Ok;
    }

    /// <summary>The text blocks (the error JSON block and workspace notices apart) and the parsed error record.</summary>
    public static (string Text, List<string> Notices, JsonNode? Error) Split(CallToolResult result)
    {
        var text = new StringBuilder();
        var notices = new List<string>();
        JsonNode? error = null;
        foreach (var block in result.Content)
        {
            if (block is not TextContentBlock t)
            {
                text.Append($"[{block.Type} content]\n");
                continue;
            }
            if (t.Text.StartsWith(ErrorResult.JsonMarker, StringComparison.Ordinal))
            {
                try { error = JsonNode.Parse(t.Text[ErrorResult.JsonMarker.Length..]); }
                catch (JsonException) { text.Append(t.Text); }
            }
            else if (t.Text.StartsWith("[workspace] ", StringComparison.Ordinal)) notices.AddRange(t.Text.TrimEnd().Split('\n'));
            else text.Append(t.Text);
        }
        return (text.ToString().TrimEnd('\n', '\r'), notices, error);
    }

    /// <summary>The exit code of an error result by its code: 2 usage, 3 environment, 124 timeout, else 1.</summary>
    public static int ExitCode(JsonNode? error) => (string?)error?["code"] switch
    {
        "invalid_argument" => Exit.Usage,
        "provider_unavailable" or "unsupported" => Exit.Environment,
        "timeout" => Exit.Timeout,
        _ => Exit.ToolError,
    };

    private static JsonSerializerOptions JsonOptions(CliIo io) => io.OutTty ? Indented : Compact;

    private static readonly JsonSerializerOptions Compact = new() { Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping };
    private static readonly JsonSerializerOptions Indented = new(Compact) { WriteIndented = true };

    /// <summary>Progress notifications as one updating stderr line.</summary>
    private sealed class ProgressLine(TextWriter error) : IProgress<ProgressNotificationValue>
    {
        private int _width;

        public void Report(ProgressNotificationValue value)
        {
            var line = value.Total is { } total ? $"[{value.Progress:0}/{total:0}] {value.Message}" : $"[{value.Progress:0}] {value.Message}";
            if (line.Length > 110) line = line[..110];
            lock (this)
            {
                error.Write("\r" + line.PadRight(_width));
                _width = line.Length;
            }
        }

        public void Clear()
        {
            lock (this)
            {
                if (_width > 0) error.Write("\r" + new string(' ', _width) + "\r");
                _width = 0;
            }
        }
    }

    // ---- tools, describe ----

    private static int Tools(CliArgs a, CliIo io)
    {
        if (a.Positionals.Count > 1) throw new UsageException("tools takes one filter.");
        var filter = a.Positionals.FirstOrDefault();
        var tools = CatalogTools.Where(t => filter == null || NameOf(t).Contains(filter, StringComparison.OrdinalIgnoreCase)
            || ((string?)t["description"] ?? "").Contains(filter, StringComparison.OrdinalIgnoreCase)).ToList();
        if (a.Json)
        {
            var rows = new JsonArray([.. tools.Select(t =>
            {
                var name = NameOf(t);
                var e = ToolEffects.Of(name);
                return (JsonNode)new JsonObject
                {
                    ["name"] = name, ["title"] = Title(t), ["toolset"] = Toolsets.FamilyOf(name), ["readOnly"] = e.ReadOnly,
                    ["destructive"] = e.Destructive, ["openWorld"] = e.OpenWorld, ["longRunning"] = e.LongRunning, ["summary"] = Summary(t),
                };
            })]);
            io.Out.WriteLine(rows.ToJsonString(JsonOptions(io)));
            return Exit.Ok;
        }
        foreach (var family in Toolsets.Families)
        {
            var members = tools.Where(t => Toolsets.FamilyOf(NameOf(t)) == family.Name).OrderBy(NameOf, StringComparer.Ordinal).ToList();
            if (members.Count == 0) continue;
            io.Out.WriteLine($"{family.Name}: {family.Description}");
            foreach (var t in members) io.Out.WriteLine($"  {NameOf(t),-28} {Flags(NameOf(t)),-12} {Summary(t)}");
            io.Out.WriteLine();
        }
        io.Out.WriteLine($"{tools.Count} tools. Details: {Program} describe <tool>. Call: {Program} <tool> name=value ...");
        return Exit.Ok;
    }

    private static string Title(JsonNode tool) => (string?)tool["title"] ?? (string?)tool["annotations"]?["title"] ?? NameOf(tool);

    /// <summary>read-only, edit or destructive, plus long for long-running tools.</summary>
    private static string Flags(string tool)
    {
        var e = ToolEffects.Of(tool);
        var kind = e.ReadOnly ? "read-only" : e.Destructive ? "destructive" : "edit";
        return e.LongRunning ? kind + ",long" : kind;
    }

    /// <summary>The description's first sentence, at most 100 characters.</summary>
    public static string Summary(JsonNode node)
    {
        var d = ((string?)node["description"] ?? "").Replace(ToolEffects.LongRunningSuffix, "", StringComparison.Ordinal).Trim().ReplaceLineEndings(" ");
        var end = d.IndexOf(". ", StringComparison.Ordinal);
        if (end > 0) d = d[..(end + 1)];
        return d.Length > 100 ? d[..97].TrimEnd() + "..." : d;
    }

    private static int Describe(CliArgs a, CliIo io)
    {
        if (a.Positionals.Count != 1) throw new UsageException("describe takes one tool or prompt name.");
        var name = a.Positionals[0];
        if (FindTool(name) is { } tool)
        {
            if (a.Json) io.Out.WriteLine(tool.ToJsonString(JsonOptions(io)));
            else io.Out.Write(DescribeTool(tool));
            return Exit.Ok;
        }
        if (FindPrompt(name) is { } prompt)
        {
            if (a.Json) io.Out.WriteLine(prompt.ToJsonString(JsonOptions(io)));
            else io.Out.Write(DescribePrompt(prompt));
            return Exit.Ok;
        }
        throw new UsageException($"Unknown tool or prompt '{name}'." + Suggestion(name, CatalogTools.Concat(CatalogPrompts).Select(NameOf)));
    }

    /// <summary>A tool's description, parameters, annotations, output summary and an example call.</summary>
    public static string DescribeTool(JsonNode tool)
    {
        var name = NameOf(tool);
        var e = ToolEffects.Of(name);
        var sb = new StringBuilder();
        sb.Append($"{name}: {Title(tool)}\n\n");
        sb.Append(((string?)tool["description"] ?? "").Trim()).Append("\n\n");
        var notes = new List<string> { e.ReadOnly ? "read-only" : "changes state" };
        if (e.Destructive) notes.Add("destructive");
        if (e.Idempotent) notes.Add("idempotent");
        if (e.OpenWorld) notes.Add("open-world");
        if (e.LongRunning) notes.Add("long-running");
        sb.Append($"Toolset: {Toolsets.FamilyOf(name) ?? "none"}. Annotations: {string.Join(", ", notes)}.\n\n");
        var parameters = Parameters(tool);
        sb.Append(parameters.Count == 0 ? "Parameters: none.\n" : "Parameters:\n");
        foreach (var p in parameters)
        {
            var facts = new List<string> { p.Type };
            if (p.Required) facts.Add("required");
            if (p.Default is { } def) facts.Add("default " + def);
            if (p.Values is { } values) facts.Add("one of " + values);
            sb.Append($"  {p.Name} ({string.Join(", ", facts)})\n");
            if (p.Description.Length > 0) sb.Append($"      {p.Description.ReplaceLineEndings(" ")}\n");
        }
        if (tool["outputSchema"]?["properties"] is JsonObject output)
            sb.Append($"\nStructured output: {string.Join(", ", output.Select(p => p.Key))} (--structured prints it).\n");
        sb.Append($"\nExample:\n  {Example(tool)}\n");
        return sb.ToString();
    }

    private static string DescribePrompt(JsonNode prompt)
    {
        var sb = new StringBuilder();
        sb.Append($"{NameOf(prompt)} (prompt): {(string?)prompt["title"] ?? NameOf(prompt)}\n\n{(string?)prompt["description"]}\n\n");
        var args = prompt["arguments"] as JsonArray ?? [];
        sb.Append(args.Count == 0 ? "Arguments: none.\n" : "Arguments:\n");
        foreach (var arg in args)
            sb.Append($"  {(string?)arg?["name"]}{((bool?)arg?["required"] == true ? " (required)" : "")}\n      {(string?)arg?["description"]}\n");
        return sb.ToString();
    }

    public sealed record Parameter(string Name, string Type, bool Required, string? Default, string? Values, string Description);

    /// <summary>The input schema's parameters, required ones first.</summary>
    public static List<Parameter> Parameters(JsonNode tool)
    {
        var schema = tool["inputSchema"];
        var required = (schema?["required"] as JsonArray)?.Select(n => (string?)n).OfType<string>().ToHashSet(StringComparer.Ordinal) ?? [];
        var list = new List<Parameter>();
        foreach (var (key, p) in schema?["properties"] as JsonObject ?? [])
        {
            var types = CliArgs.Types(p).Where(t => t != "null").ToList();
            var type = types.Count == 0 ? "any" : string.Join("|", types);
            if (type == "array" && CliArgs.Types(p?["items"]).FirstOrDefault(t => t != "null") is { } item) type = item + "[]";
            var values = p?["enum"] is JsonArray e ? string.Join(", ", e.Where(v => v is not null).Select(v => v!.ToJsonString().Trim('"'))) : null;
            var def = p?["default"] is { } d ? d.ToJsonString().Trim('"') : null;
            list.Add(new Parameter(key, type, required.Contains(key), def, values, ((string?)p?["description"] ?? "").Trim()));
        }
        return [.. list.OrderBy(p => !p.Required)];
    }

    /// <summary>A call line with the required parameters as placeholders.</summary>
    public static string Example(JsonNode tool)
    {
        var required = Parameters(tool).Where(p => p.Required).Select(p => $"{p.Name}=<{p.Type}>");
        return string.Join(" ", new[] { Program, NameOf(tool) }.Concat(required));
    }
}
