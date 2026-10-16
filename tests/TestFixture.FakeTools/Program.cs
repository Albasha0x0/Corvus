using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

// Modes: "-version" answers like a JDK; "version" like adb; "... -jar vineflower*.jar ... <in> <out>" writes sources like Vineflower;
// "... -jar <jar> ..." serves MCP over stdio like the JADX server;
// anything else follows the rules of the JSON script named by ADB_FAKE_SCRIPT: the first rule whose "match" regex finds the
// joined arguments prints "stdout" ("repeat" times), "bytes" (base64, "repeat" times), "printEnv" (a variable) and "stderr",
// writes "file" (base64) to the last argument, and exits with "exit".
var script = Environment.GetEnvironmentVariable("ADB_FAKE_SCRIPT") is { Length: > 0 } path && File.Exists(path)
    ? JsonNode.Parse(File.ReadAllText(path))!.AsObject()
    : new JsonObject();
var log = script["log"]?.GetValue<string>();
if (log != null) File.AppendAllText(log, JsonSerializer.Serialize(args) + "\n");

if (args is ["-version"])
{
    Console.Error.WriteLine(script["javaVersion"]?.GetValue<string>() ?? "openjdk version \"21.0.2\" 2024-01-16");
    return 0;
}
if (args is ["version"])
{
    Console.WriteLine("Android Debug Bridge version 1.0.41");
    Console.WriteLine("Version 35.0.2-12147458");
    return 0;
}
if (args.Contains("-jar") && args.Any(a => Path.GetFileName(a).StartsWith("vineflower", StringComparison.Ordinal))) return Vineflower(args);
if (args.Contains("-jar")) return Jadx(script, log);

var joined = string.Join(' ', args);
foreach (var rule in script["rules"]?.AsArray() ?? [])
{
    if (!Regex.IsMatch(joined, rule!["match"]!.GetValue<string>())) continue;
    if (rule["sleepMs"]?.GetValue<int>() is { } sleep) Thread.Sleep(sleep);
    if (rule["file"]?.GetValue<string>() is { } file) File.WriteAllBytes(args[^1], Convert.FromBase64String(file));
    if (rule["printEnv"]?.GetValue<string>() is { } variable) Console.Out.Write(Environment.GetEnvironmentVariable(variable) ?? "<unset>");
    if (rule["stdout"]?.GetValue<string>() is { } text)
    {
        using var stdout = Console.OpenStandardOutput();
        var bytes = Encoding.UTF8.GetBytes(text);
        for (int i = 0, n = rule["repeat"]?.GetValue<int>() ?? 1; i < n; i++) stdout.Write(bytes);
    }
    if (rule["bytes"]?.GetValue<string>() is { } binary)
    {
        using var stdout = Console.OpenStandardOutput();
        var bytes = Convert.FromBase64String(binary);
        for (int i = 0, n = rule["repeat"]?.GetValue<int>() ?? 1; i < n; i++) stdout.Write(bytes);
    }
    if (rule["stderr"]?.GetValue<string>() is { } error) Console.Error.Write(error);
    return rule["exit"]?.GetValue<int>() ?? 0;
}
Console.Error.WriteLine($"fake tool: no rule for '{joined}'");
return 1;

// Like Vineflower's command line (... <input folder> <output folder>): one .java per top-level class, naming its classes and options.
static int Vineflower(string[] args)
{
    string input = args[^2], output = args[^1];
    foreach (var file in Directory.EnumerateFiles(input, "*.class", SearchOption.AllDirectories))
    {
        var relative = Path.GetRelativePath(input, file);
        if (Path.GetFileName(relative).Contains('$')) continue;
        var target = Path.Combine(output, Path.ChangeExtension(relative, ".java"));
        Directory.CreateDirectory(Path.GetDirectoryName(target)!);
        var nested = Directory.EnumerateFiles(input, "*.class", SearchOption.AllDirectories).Select(f => Path.GetRelativePath(input, f).Replace('\\', '/')).Order(StringComparer.Ordinal);
        File.WriteAllText(target, $"// vineflower: {string.Join(" ", nested)}\n// options: {string.Join(" ", args.Where(a => a.StartsWith('-') && a != "-jar"))}\n");
    }
    return 0;
}

static int Jadx(JsonObject script, string? log)
{
    var answers = script["mcp"]?.AsObject() ?? [];
    using var stdin = new StreamReader(Console.OpenStandardInput(), new UTF8Encoding(false));
    var stdout = new StreamWriter(Console.OpenStandardOutput(), new UTF8Encoding(false)) { AutoFlush = true, NewLine = "\n" };
    string? line;
    while ((line = stdin.ReadLine()) != null)
    {
        if (line.Length == 0) continue;
        var request = JsonNode.Parse(line)!.AsObject();
        if (request["id"] is not { } id) continue; // notifications
        var method = request["method"]!.GetValue<string>();
        JsonNode result;
        if (method == "initialize")
            result = new JsonObject
            {
                ["protocolVersion"] = "2025-06-18",
                ["capabilities"] = new JsonObject { ["tools"] = new JsonObject() },
                ["serverInfo"] = new JsonObject { ["name"] = "fake-jadx", ["version"] = "0.0" },
            };
        else
        {
            var name = request["params"]!["name"]!.GetValue<string>();
            var arguments = request["params"]!["arguments"]?.AsObject() ?? [];
            if (log != null) File.AppendAllText(log, JsonSerializer.Serialize(new { tool = name, arguments }) + "\n");
            if (name == "load_apk" && script["crashOnLoad"]?.GetValue<bool>() == true) Environment.Exit(3);
            // A canned answer is text, or an object of answers by class_name ("*" for the rest; "!" before a text marks an error).
            var key = arguments["class_name"]?.GetValue<string>() ?? "";
            string? canned = answers[name] switch
            {
                JsonValue v => v.GetValue<string>(),
                JsonObject byClass => (byClass[key] ?? byClass["*"])?.GetValue<string>(),
                _ => null,
            };
            bool failed = canned?.StartsWith('!') == true;
            if (failed) canned = canned![1..];
            string text = canned != null ? canned
                : name switch
                {
                    "load_apk" => """{"state":"LOADED","class_count":1}""",
                    "get_class_source" => $"// source of {arguments["class_name"]}",
                    "get_method_body" => JsonSerializer.Serialize(new
                    {
                        mode = "java",
                        fell_back = false,
                        overload_index = arguments["overload_index"]?.GetValue<int>() ?? 0,
                        body = $"// {arguments["class_name"]}.{arguments["method_name"]} overload {arguments["overload_index"]}",
                    }),
                    _ => "unknown tool",
                };
            result = new JsonObject { ["content"] = new JsonArray(new JsonObject { ["type"] = "text", ["text"] = text }), ["isError"] = failed || text == "unknown tool" };
        }
        stdout.WriteLine(new JsonObject { ["jsonrpc"] = "2.0", ["id"] = id.DeepClone(), ["result"] = result }.ToJsonString());
    }
    return 0;
}
