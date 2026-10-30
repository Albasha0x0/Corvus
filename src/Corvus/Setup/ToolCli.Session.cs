using System.Text.Json;
using System.Text.Json.Nodes;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;

namespace Corvus.Setup;

/// <summary>Commands that keep one session for several requests, or need a running server: batch, prompts, resources.</summary>
internal static partial class ToolCli
{
    public sealed record BatchStep(string Tool, Dictionary<string, object?> Arguments);

    /// <summary>Steps from a JSON array or JSON Lines ({"tool", "args"}; # lines are comments); every tool is checked before any runs.</summary>
    public static List<BatchStep> ParseBatch(string text)
    {
        var nodes = new List<JsonNode?>();
        try
        {
            if (text.TrimStart().StartsWith('[')) nodes.AddRange(JsonNode.Parse(text)!.AsArray());
            else
                foreach (var line in text.Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0 && !l.StartsWith('#')))
                    nodes.Add(JsonNode.Parse(line));
        }
        catch (JsonException ex) { throw new UsageException($"The batch is not valid JSON: {ex.Message}"); }
        var steps = new List<BatchStep>();
        foreach (var node in nodes)
        {
            if (node is not JsonObject o || o["tool"]?.GetValueKind() != JsonValueKind.String)
                throw new UsageException($"Batch step {steps.Count + 1}: expected {{\"tool\": \"name\", \"args\": {{...}}}}.");
            var tool = RequireTool((string)o["tool"]!);
            var args = new Dictionary<string, object?>(StringComparer.Ordinal);
            switch (o["args"] ?? o["arguments"])
            {
                case null: break;
                case JsonObject obj:
                    foreach (var (key, value) in obj) args[key] = value is null ? null : JsonSerializer.SerializeToElement(value);
                    break;
                default: throw new UsageException($"Batch step {steps.Count + 1}: args must be an object.");
            }
            steps.Add(new BatchStep(NameOf(tool), args));
        }
        return steps.Count > 0 ? steps : throw new UsageException("The batch has no steps.");
    }

    /// <summary>Runs the steps in one session; returns the first failed step's exit code, or 0; --stop-on-error stops there.</summary>
    private static async Task<int> BatchAsync(CliArgs a, CliIo io, CancellationToken cancellationToken)
    {
        if (a.BatchFile != null)
            return a.Json != a.JsonLines ? await FileBatchAsync(a, io, cancellationToken)
                : throw new UsageException("batch --file writes JSON: add --json for one document or --jsonl for one record per line.");
        var fileOption = a.Rules != null ? "--rules" : a.Recurse ? "--recurse" : a.FailOn != null ? "--fail-on" : a.AllowIncomplete ? "--allow-incomplete"
            : a.Extract != null ? "--extract" : a.Baseline != null ? "--baseline" : a.Report != null ? "--report" : a.Sarif != null ? "--sarif" : a.JsonLines ? "--jsonl"
            : a.Out != null ? "--out" : null;
        if (fileOption != null) throw new UsageException($"{fileOption} goes with batch --file.");
        if (a.Positionals.Count != 1) throw new UsageException("batch takes one file (- for stdin).");
        var source = a.Positionals[0];
        string text;
        try { text = source == "-" ? io.In.ReadToEnd() : File.ReadAllText(source); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException) { throw new UsageException($"Cannot read {source}: {ex.Message}"); }
        var steps = ParseBatch(text);
        await using var session = await ToolSession.StartAsync(a.Server(), cancellationToken);
        int exit = Exit.Ok;
        for (int i = 0; i < steps.Count; i++)
        {
            var step = steps[i];
            var result = await Invoke(session, step.Tool, step.Arguments, io, cancellationToken);
            int code = result is null ? Exit.Usage : result.IsError == true ? ExitCode(Split(result).Error) : Exit.Ok;
            if (result != null)
            {
                var (output, notices, error) = Split(result);
                foreach (var notice in notices) io.Error.WriteLine(notice);
                if (a.Json)
                {
                    var record = new JsonObject
                    {
                        ["step"] = i + 1,
                        ["tool"] = step.Tool,
                        ["isError"] = result.IsError == true,
                        ["text"] = output,
                        ["structured"] = result.StructuredContent is { } s ? JsonNode.Parse(s.GetRawText()) : null,
                        ["error"] = error,
                    };
                    io.Out.WriteLine(record.ToJsonString(Compact));
                }
                else
                {
                    io.Out.WriteLine($"=== [{i + 1}/{steps.Count}] {step.Tool}{(result.IsError == true ? " (error)" : "")}");
                    io.Out.WriteLine(output);
                }
            }
            if (code == Exit.Ok) continue;
            if (exit == Exit.Ok) exit = code;
            if (a.StopOnError)
            {
                io.Error.WriteLine($"Stopped at step {i + 1} of {steps.Count} (--stop-on-error).");
                break;
            }
        }
        return exit;
    }

    private static int Prompts(CliArgs a, CliIo io)
    {
        if (a.Positionals.Count > 0) throw new UsageException("prompts takes no names; describe <prompt> shows one.");
        if (a.Json)
        {
            io.Out.WriteLine(new JsonArray([.. CatalogPrompts.Select(p => p.DeepClone())]).ToJsonString(JsonOptions(io)));
            return Exit.Ok;
        }
        foreach (var p in CatalogPrompts)
        {
            var args = (p["arguments"] as JsonArray ?? []).Select(x => (string?)x?["name"] + ((bool?)x?["required"] == true ? "" : "?"));
            io.Out.WriteLine($"  {NameOf(p),-22} {Summary(p)}");
            if (args.Any()) io.Out.WriteLine($"  {"",-22} arguments: {string.Join(", ", args)}");
        }
        io.Out.WriteLine($"{CatalogPrompts.Count} prompts. Render one: {Program} prompt <name> name=value ...");
        return Exit.Ok;
    }

    /// <summary>A prompt's messages as text, for piping into any agent.</summary>
    private static async Task<int> PromptAsync(CliArgs a, CliIo io, CancellationToken cancellationToken)
    {
        if (a.Positionals.Count != 1) throw new UsageException("prompt takes one prompt name.");
        var prompt = FindPrompt(a.Positionals[0]) ?? throw new UsageException(
            $"Unknown prompt '{a.Positionals[0]}'." + Suggestion(a.Positionals[0], CatalogPrompts.Select(NameOf)) + $" Prompts: {Program} prompts.");
        var arguments = a.ToolArguments(null, io.In).ToDictionary(p => p.Key, p => (object?)(p.Value is JsonElement e && e.ValueKind == JsonValueKind.String ? e.GetString() : p.Value?.ToString()));
        await using var session = await ToolSession.StartAsync(a.Server(oneShot: true), cancellationToken);
        GetPromptResult result;
        try { result = await session.Client.GetPromptAsync(NameOf(prompt), arguments, cancellationToken: cancellationToken); }
        catch (McpProtocolException ex)
        {
            io.Error.WriteLine($"{NameOf(prompt)}: {ex.Message}");
            return Exit.Usage;
        }
        if (a.Json)
        {
            io.Out.WriteLine(JsonSerializer.SerializeToNode(result, McpJsonUtilities.DefaultOptions)!.ToJsonString(JsonOptions(io)));
            return Exit.Ok;
        }
        bool roles = result.Messages.Count > 1;
        foreach (var message in result.Messages)
        {
            if (roles) io.Out.WriteLine($"[{message.Role.ToString().ToLowerInvariant()}]");
            io.Out.WriteLine(message.Content is TextContentBlock t ? t.Text : $"[{message.Content.Type} content]");
        }
        return Exit.Ok;
    }

    private static async Task<int> ResourcesAsync(CliArgs a, CliIo io, CancellationToken cancellationToken)
    {
        if (a.Positionals.Count > 0) throw new UsageException("resources takes no names; read <uri> reads one.");
        await using var session = await ToolSession.StartAsync(a.Server(oneShot: true), cancellationToken);
        var resources = await session.Client.ListResourcesAsync(cancellationToken: cancellationToken);
        var templates = await session.Client.ListResourceTemplatesAsync(cancellationToken: cancellationToken);
        if (a.Json)
        {
            var record = new JsonObject
            {
                ["resources"] = new JsonArray([.. resources.Select(r => JsonSerializer.SerializeToNode(r.ProtocolResource, McpJsonUtilities.DefaultOptions))]),
                ["templates"] = new JsonArray([.. templates.Select(t => JsonSerializer.SerializeToNode(t.ProtocolResourceTemplate, McpJsonUtilities.DefaultOptions))]),
            };
            io.Out.WriteLine(record.ToJsonString(JsonOptions(io)));
            return Exit.Ok;
        }
        io.Out.WriteLine("Resources:");
        foreach (var r in resources) io.Out.WriteLine($"  {r.Uri,-44} {r.Description ?? r.Name}");
        io.Out.WriteLine("Templates:");
        foreach (var t in templates) io.Out.WriteLine($"  {t.UriTemplate,-44} {t.Description ?? t.Name}");
        io.Out.WriteLine($"Read one: {Program} read <uri> (with --load PATH for the assembly resources).");
        return Exit.Ok;
    }

    private static async Task<int> ReadAsync(CliArgs a, CliIo io, CancellationToken cancellationToken)
    {
        if (a.Positionals.Count != 1) throw new UsageException("read takes one resource URI.");
        await using var session = await ToolSession.StartAsync(a.Server(oneShot: true), cancellationToken);
        ReadResourceResult result;
        try { result = await session.Client.ReadResourceAsync(a.Positionals[0], cancellationToken: cancellationToken); }
        catch (McpProtocolException ex)
        {
            io.Error.WriteLine($"{a.Positionals[0]}: {ex.Message}");
            return Exit.ToolError;
        }
        if (a.Json)
        {
            io.Out.WriteLine(JsonSerializer.SerializeToNode(result, McpJsonUtilities.DefaultOptions)!.ToJsonString(JsonOptions(io)));
            return Exit.Ok;
        }
        foreach (var content in result.Contents)
            io.Out.WriteLine(content is TextResourceContents t ? t.Text : $"[binary content: {content.Uri}]");
        return Exit.Ok;
    }
}
