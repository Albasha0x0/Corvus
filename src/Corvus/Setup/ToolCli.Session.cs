using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;

namespace Corvus.Setup;

/// <summary>Commands that keep one session for several requests, or need a running server: batch, prompts, resources.</summary>
internal static partial class ToolCli
{
    public sealed record BatchStep(string Tool, Dictionary<string, object?> Arguments);

    // True when the text holds a backslash that starts no valid JSON escape.
    static bool HasInvalidEscape(string? text)
    {
        if (text == null) return false;
        for (int i = 0; i < text.Length; i++)
        {
            if (text[i] != '\\') continue;
            if (++i >= text.Length || "\"\\/bfnrtu".IndexOf(text[i]) < 0) return true;
        }
        return false;
    }

    // The line the reader named, so a hint reads one line and not the file.
    static string ErrorLine(string text, JsonException ex)
    {
        var lines = text.Split('\n');
        return ex.LineNumber is long n && n < lines.Length ? lines[n] : text;
    }

    // Reports a one-based line and a UTF-8 byte column; omits both when the reader gave none.
    static string BatchJsonError(JsonException ex, long line, int indent, string? source = null)
    {
        // The reader's zero-based position is replaced by the located form.
        var cut = ex.Message.IndexOf(" Path:", StringComparison.Ordinal);
        if (cut < 0) cut = ex.Message.IndexOf("LineNumber:", StringComparison.Ordinal);
        var reason = cut >= 0 ? ex.Message[..cut].TrimEnd() : ex.Message;
        var hint = HasInvalidEscape(source) ? " A Windows path takes / or a doubled backslash." : "";
        return ex.BytePositionInLine is long col
            ? $"The batch is not valid JSON at line {line}, byte column {col + indent + 1}: {reason}{hint}"
            : $"The batch is not valid JSON: {reason}{hint}";
    }

    /// <summary>
    /// Steps from a JSON array or JSON Lines; with <paramref name="invalid"/>,
    /// names and skips bad lines or entries instead of failing.
    /// </summary>
    public static List<BatchStep> ParseBatch(string text, List<string>? invalid = null)
    {
        var nodes = new List<(JsonNode? Node, string Label, int Order)>();
        var skipped = new List<(int Order, string Message)>();
        if (text.TrimStart().StartsWith('['))
        {
            try
            {
                int n = 0;
                foreach (var node in JsonNode.Parse(text)!.AsArray()) nodes.Add((node, $"entry {++n}", n));
            }
            catch (JsonException ex) { throw new UsageException(BatchJsonError(ex, (ex.LineNumber ?? 0) + 1, 0, ErrorLine(text, ex))); }
        }
        else
        {
            var fileLines = text.Split('\n');
            for (int i = 0; i < fileLines.Length; i++)
            {
                var line = fileLines[i].TrimEnd();
                var trimmed = line.TrimStart();
                if (trimmed.Length == 0 || trimmed.StartsWith('#')) continue;
                try { nodes.Add((JsonNode.Parse(trimmed), $"line {i + 1}", i + 1)); }
                catch (JsonException ex)
                {
                    // The reader's column is relative to the trimmed line.
                    var indent = Encoding.UTF8.GetByteCount(line.AsSpan(0, line.Length - trimmed.Length));
                    var message = BatchJsonError(ex, i + 1, indent, trimmed);
                    if (invalid == null) throw new UsageException(message);
                    skipped.Add((i + 1, $"line {i + 1}: {message}"));
                }
            }
        }
        var steps = new List<BatchStep>();
        foreach (var (node, label, order) in nodes)
        {
            try { steps.Add(ParseStep(node, invalid == null ? $"Batch step {steps.Count + 1}: " : "")); }
            catch (UsageException ex) when (invalid != null) { skipped.Add((order, $"{label}: {ex.Message}")); }
        }
        // Report skips in file order, whichever pass found them.
        if (invalid != null) invalid.AddRange(skipped.OrderBy(x => x.Order).Select(x => x.Message));
        return steps.Count > 0 ? steps : throw new UsageException(invalid is { Count: > 0 }
            ? "The batch has no valid steps. " + string.Join(" ", invalid) : "The batch has no steps.");
    }

    static BatchStep ParseStep(JsonNode? node, string prefix)
    {
        if (node is not JsonObject o || o["tool"]?.GetValueKind() != JsonValueKind.String)
            throw new UsageException($"{prefix}expected {{\"tool\": \"name\", \"args\": {{...}}}}.");
        var tool = RequireTool((string)o["tool"]!);
        var args = new Dictionary<string, object?>(StringComparer.Ordinal);
        switch (o["args"] ?? o["arguments"])
        {
            case null: break;
            case JsonObject obj:
                foreach (var (key, value) in obj) args[key] = value is null ? null : JsonSerializer.SerializeToElement(value);
                break;
            default: throw new UsageException($"{prefix}args must be an object.");
        }
        return new BatchStep(NameOf(tool), args);
    }

    /// <summary>The --json record of a step that got no result: an invalid_argument error with no text or structured content.</summary>
    internal static JsonObject RefusedStepRecord(int step, string tool, string state, long elapsedMs) => new()
    {
        ["step"] = step,
        ["tool"] = tool,
        ["isError"] = true,
        ["state"] = state,
        ["text"] = null,
        ["structured"] = null,
        ["error"] = new JsonObject
        {
            ["code"] = "invalid_argument",
            ["message"] = $"{tool} was refused with a protocol error; run corvus help to list the tool names.",
        },
        ["elapsedMs"] = elapsedMs,
    };

    /// <summary>
    /// Runs the steps in one session; returns the first failed step's exit
    /// code, or 2 if only --keep-going skipped lines, else 0.
    /// </summary>
    private static async Task<int> BatchAsync(CliArgs a, CliIo io, CancellationToken cancellationToken)
    {
        if (a.BatchFile != null && a.EvtxJsonl != null) return EvtxJsonl(a, io, cancellationToken);
        if (a.EvtxJsonl != null) throw new UsageException("--evtx-jsonl goes with batch --file.");
        if (a.BatchFile != null)
            return a.Json != a.JsonLines ? await FileBatchAsync(a, io, cancellationToken)
                : throw new UsageException("batch --file writes JSON: add --json for one document or --jsonl for one record per line.");
        var fileOption = a.Rules != null ? "--rules" : a.Recurse ? "--recurse" : a.FailOn != null ? "--fail-on" : a.AllowIncomplete ? "--allow-incomplete"
            : a.Extract != null ? "--extract" : a.DumpModules != null ? "--dump-modules" : a.PasswordFile != null ? "--password-file" : a.Baseline != null ? "--baseline" : a.Report != null ? "--report" : a.JsonLines ? "--jsonl"
            : a.Out != null ? "--out" : null;
        if (fileOption != null) throw new UsageException($"{fileOption} goes with batch --file.");
        if (a.Positionals.Count != 1) throw new UsageException("batch takes one file (- for stdin).");
        var source = a.Positionals[0];
        string text;
        try { text = source == "-" ? io.In.ReadToEnd() : File.ReadAllText(source); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException) { throw new UsageException($"Cannot read {source}: {ex.Message}"); }
        var invalid = new List<string>();
        var steps = ParseBatch(text, a.KeepGoing ? invalid : null);
        foreach (var message in invalid) io.Error.WriteLine($"Skipped {message}");
        var stepSeconds = StepSeconds(a.StepTimeout);
        var sarif = OutputPath("--sarif", a.Sarif);
        if (sarif != null && Directory.Exists(sarif)) throw new UsageException($"--sarif names a file, not a folder: {a.Sarif}.");
        var comparisons = new List<JsonObject>();
        var routed = RoutedSession(a, io);
        await using var session = routed == null ? await ToolSession.StartAsync(a.Server(), cancellationToken) : null;
        int exit = Exit.Ok;
        for (int i = 0; i < steps.Count; i++)
        {
            var step = steps[i];
            var started = System.Diagnostics.Stopwatch.GetTimestamp();
            CallToolResult? result;
            bool expired;
            try
            {
                (result, expired) = await WithStepLimit(stepSeconds, cancellationToken, ct => routed == null ? Invoke(session!, step.Tool, step.Arguments, io, ct) : InvokeRemote(routed, step.Tool, step.Arguments, io, ct));
            }
            catch (SessionUnreachableException ex)
            {
                io.Error.WriteLine(ex.Message);
                exit = Exit.Environment;
                break;
            }
            if (expired)
            {
                if (ReportStepTimeout(io, a.Json, i + 1, steps.Count, step.Tool, stepSeconds, a.StopOnError, ref exit)) break;
                continue;
            }
            var elapsedMs = Math.Max(1, (long)Math.Ceiling(System.Diagnostics.Stopwatch.GetElapsedTime(started).TotalMilliseconds));
            int code = result is null ? Exit.Usage : result.IsError == true ? ExitCode(Split(result).Error) : Exit.Ok;
            if (result != null && step.Tool == "compare_folders" && result.IsError != true && Structured(result) is JsonObject comparison) comparisons.Add(comparison);
            if (result == null)
            {
                if (a.Json)
                {
                    var failure = RefusedStepRecord(i + 1, step.Tool, StepState(code), elapsedMs);
                    io.Out.WriteLine(failure.ToJsonString(Compact));
                }
            }
            else
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
                        ["state"] = StepState(code),
                        ["text"] = output,
                        ["structured"] = result.StructuredContent is { } s ? JsonNode.Parse(s.GetRawText()) : null,
                        ["error"] = error,
                        ["elapsedMs"] = elapsedMs,
                    };
                    io.Out.WriteLine(record.ToJsonString(Compact));
                }
                else
                {
                    io.Out.WriteLine($"=== [{i + 1}/{steps.Count}] {step.Tool}{(code == Exit.Running ? " (running)" : result.IsError == true ? " (error)" : "")}");
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
        // The findings new in each compare_folders step, as one run.
        if (sarif != null) await File.WriteAllTextAsync(sarif, SarifLog.BuildDiff(comparisons, Directory.GetCurrentDirectory()).ToJsonString(Compact), CancellationToken.None);
        return exit == Exit.Ok && invalid.Count > 0 ? Exit.Usage : exit;
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
