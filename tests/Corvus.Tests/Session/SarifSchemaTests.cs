using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Corvus.Setup;

namespace Corvus.Tests;

/// <summary>batch --sarif documents checked against the SARIF 2.1.0 schema.</summary>
public class SarifSchemaTests
{
    private static readonly JsonObject Schema =
        JsonNode.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Session", "sarif-schema-2.1.0.json")))!.AsObject();

    /// <summary>The schema errors of <paramref name="log"/>, empty when it is valid.</summary>
    private static List<string> Errors(JsonNode log)
    {
        var errors = new List<string>();
        // Round-trip so every value has the kind it serializes with.
        Check(JsonNode.Parse(log.ToJsonString()), Schema, "$", errors);
        return errors;
    }

    private static JsonObject Resolve(JsonObject schema)
    {
        if (schema["$ref"] is not JsonValue reference) return schema;
        JsonNode node = Schema;
        foreach (var part in ((string)reference!).TrimStart('#').Split('/', StringSplitOptions.RemoveEmptyEntries))
            node = node[part]!;
        return Resolve(node.AsObject());
    }

    // The draft-04 keywords the SARIF schema uses, and no others.
    private static void Check(JsonNode? value, JsonObject schema, string path, List<string> errors)
    {
        schema = Resolve(schema);
        if (schema["anyOf"] is JsonArray any)
        {
            if (!any.Any(s => Matches(value, s!.AsObject()))) errors.Add($"{path}: matches none of anyOf");
            return;
        }
        if (schema["oneOf"] is JsonArray one)
        {
            if (one.Count(s => Matches(value, s!.AsObject())) != 1) errors.Add($"{path}: does not match exactly one of oneOf");
            return;
        }
        if (schema["enum"] is JsonArray allowed && !allowed.Any(a => a!.ToJsonString() == value?.ToJsonString()))
            errors.Add($"{path}: {value?.ToJsonString()} is not in the enum");
        if (schema["type"] is { } type && !TypeMatches(value, type))
        {
            errors.Add($"{path}: expected type {type.ToJsonString()}");
            return;
        }
        switch (value)
        {
            case JsonObject obj:
                foreach (var name in schema["required"] as JsonArray ?? [])
                    if (!obj.ContainsKey((string)name!)) errors.Add($"{path}: missing required {name}");
                var properties = schema["properties"] as JsonObject;
                foreach (var (name, child) in obj)
                {
                    if (properties?[name] is JsonObject known) Check(child, known, $"{path}.{name}", errors);
                    else if (schema["additionalProperties"] is JsonValue flag && !(bool)flag) errors.Add($"{path}: unexpected property {name}");
                    else if (schema["additionalProperties"] is JsonObject extra) Check(child, extra, $"{path}.{name}", errors);
                }
                break;
            case JsonArray array:
                if (schema["minItems"] is { } min && array.Count < (int)min) errors.Add($"{path}: fewer than {min} items");
                if (schema["uniqueItems"] is JsonValue unique && (bool)unique
                    && array.Select(a => a?.ToJsonString()).Distinct().Count() != array.Count) errors.Add($"{path}: items are not unique");
                if (schema["items"] is JsonObject item)
                    for (int i = 0; i < array.Count; i++) Check(array[i], item, $"{path}[{i}]", errors);
                break;
            case JsonValue scalar when scalar.TryGetValue<string>(out var text):
                if (schema["pattern"] is { } pattern && !Regex.IsMatch(text, (string)pattern!)) errors.Add($"{path}: does not match {pattern}");
                if ((string?)schema["format"] is { } format && !FormatMatches(format, text)) errors.Add($"{path}: not a {format}");
                break;
            case JsonValue number when number.TryGetValue<double>(out var n):
                if (schema["minimum"] is { } lower && n < (double)lower) errors.Add($"{path}: below {lower}");
                if (schema["maximum"] is { } upper && n > (double)upper) errors.Add($"{path}: above {upper}");
                break;
        }
    }

    private static bool Matches(JsonNode? value, JsonObject schema)
    {
        var errors = new List<string>();
        Check(value, schema, "$", errors);
        return errors.Count == 0;
    }

    private static bool TypeMatches(JsonNode? value, JsonNode type)
    {
        if (type is JsonArray list) return list.Any(t => TypeMatches(value, t!));
        var isNumber = value is JsonValue v && v.GetValueKind() == System.Text.Json.JsonValueKind.Number;
        return (string)type! switch
        {
            "null" => value == null,
            "object" => value is JsonObject,
            "array" => value is JsonArray,
            "string" => value is JsonValue s && s.GetValueKind() == System.Text.Json.JsonValueKind.String,
            "boolean" => value is JsonValue b && b.GetValueKind() is System.Text.Json.JsonValueKind.True or System.Text.Json.JsonValueKind.False,
            "number" => isNumber,
            "integer" => isNumber && (double)value! is var d && d == Math.Floor(d),
            _ => false,
        };
    }

    private static bool FormatMatches(string format, string text) => format switch
    {
        "uri" => Uri.TryCreate(text, UriKind.Absolute, out _),
        "uri-reference" => Uri.TryCreate(text, UriKind.RelativeOrAbsolute, out _),
        "date-time" => DateTimeOffset.TryParse(text, out _),
        _ => true,
    };

    private static JsonObject Finding(string level, string rule, string key) =>
        new() { ["level"] = level, ["rule"] = rule, ["evidence"] = $"{rule} evidence", ["location"] = null, ["key"] = key };

    private static JsonObject RecordsDocument()
    {
        JsonObject Record(string path, params JsonObject[] findings) =>
            new() { ["file"] = new JsonObject { ["paths"] = new JsonArray(path) }, ["findings"] = new JsonArray([.. findings]) };
        return new JsonObject
        {
            ["file"] = new JsonObject { ["path"] = Path.GetFullPath("in") },
            ["complete"] = true,
            ["ruleTable"] = "2026-01",
            ["records"] = new JsonArray(
                Record("a b.zip!/d/e.txt", Finding("noteworthy", "package/collection-url", "k1"), Finding("info", "package/network", "k2")),
                Record("lib/c.js", Finding("review", "package/eval", "k3"))),
        };
    }

    private static JsonObject Comparison(params JsonObject[] rows) => new()
    {
        ["old"] = new JsonObject { ["path"] = "old", ["kind"] = "folder", ["complete"] = true },
        ["new"] = new JsonObject { ["path"] = Path.GetFullPath("new"), ["kind"] = "folder", ["complete"] = true },
        ["changes"] = new JsonArray([.. rows]),
    };

    private static JsonObject Row(string kind, string key, string? @new, string? rule) =>
        new() { ["kind"] = kind, ["key"] = key, ["old"] = null, ["new"] = @new, ["rule"] = rule };

    private static JsonObject[] DiffRows() =>
    [
        Comparison(
            Row("added", "package-lock.json: left-pad@1.0.0", "noteworthy: git https://example.invalid/x.git", "package/locked-source"),
            Row("added", "malcontent/net/download at lib/a.js", "noteworthy (critical): downloads", "malcontent/net/download"),
            Row("added", "package/index.js: eval", "review at lib/b.js:7", "package/eval"),
            Row("added", "package/in.zip!/x/y.js: eval", "review at in.zip!/x/y.js:3", "package/eval")),
    ];

    [Fact]
    public void A_records_document_validates_against_the_sarif_schema()
    {
        var log = SarifLog.Build(RecordsDocument(), Directory.GetCurrentDirectory());
        Assert.Equal(3, log["runs"]![0]!["results"]!.AsArray().Count);
        Assert.Empty(Errors(log));
    }

    [Fact]
    public void A_single_file_document_validates_against_the_sarif_schema()
    {
        var document = new JsonObject
        {
            ["file"] = new JsonObject { ["path"] = "run.ps1" },
            ["complete"] = true,
            ["findings"] = new JsonArray(Finding("review", "package/network", "k"), Finding("noteworthy", "package/eval", "k2")),
        };
        var log = SarifLog.Build(document, Directory.GetCurrentDirectory());
        Assert.Equal(2, log["runs"]![0]!["results"]!.AsArray().Count);
        Assert.Empty(Errors(log));
    }

    [Fact]
    public void A_diff_document_validates_against_the_sarif_schema()
    {
        var log = SarifLog.BuildDiff(DiffRows(), Directory.GetCurrentDirectory());
        Assert.Equal(4, log["runs"]![0]!["results"]!.AsArray().Count);
        Assert.Empty(Errors(log));
    }

    [Fact]
    public void A_cut_run_validates_against_the_sarif_schema()
    {
        var log = SarifLog.Build(RecordsDocument(), Directory.GetCurrentDirectory(), maxResults: 1);
        Assert.NotNull(log["runs"]![0]!["invocations"]);
        Assert.Empty(Errors(log));
        var cutDiff = SarifLog.BuildDiff(DiffRows(), Directory.GetCurrentDirectory(), maxResults: 2);
        Assert.NotNull(cutDiff["runs"]![0]!["invocations"]);
        Assert.Empty(Errors(cutDiff));
    }

    [Fact]
    public void An_empty_run_validates_against_the_sarif_schema()
    {
        var empty = new JsonObject { ["file"] = new JsonObject { ["path"] = "notes.txt" }, ["complete"] = true, ["findings"] = new JsonArray() };
        Assert.Empty(Errors(SarifLog.Build(empty, Directory.GetCurrentDirectory())));
        Assert.Empty(Errors(SarifLog.BuildDiff([], Directory.GetCurrentDirectory())));
    }

    [Fact]
    public void The_checker_rejects_a_result_without_a_message_and_a_bad_level()
    {
        var log = SarifLog.Build(RecordsDocument(), Directory.GetCurrentDirectory());
        var result = log["runs"]![0]!["results"]![0]!.AsObject();
        result.Remove("message");
        result["level"] = "severe";
        var errors = Errors(log);
        Assert.Contains(errors, e => e.Contains("missing required message"));
        Assert.Contains(errors, e => e.Contains("level") && e.Contains("enum"));
    }
}
