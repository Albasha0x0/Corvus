using System.IO.Compression;
using System.Text.Json;
using Json.Schema;
using Corvus.Core;
using Corvus.Services;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>The notes a STIX bundle carries for matched YARA rules and capa labels.</summary>
public sealed class StixMatchNotesTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly AssemblyWorkspace _workspace = new(new ServerOptions());

    public void Dispose()
    {
        _workspace.Dispose();
        _dir.Dispose();
    }

    // The OASIS bundle schema does not list note among its objects, so notes
    // are checked against note.json.
    private static readonly Lazy<(JsonSchema Bundle, JsonSchema Note)> Schemas = new(() =>
    {
        var root = Path.Combine(AppContext.BaseDirectory, "Containers", "StixSchemas");
        var options = new BuildOptions { SchemaRegistry = new SchemaRegistry() };
        JsonSchema? bundle = null, note = null;
        foreach (var file in Directory.EnumerateFiles(root, "*.json", SearchOption.AllDirectories).OrderBy(f => f.EndsWith("bundle.json", StringComparison.Ordinal)))
        {
            var schema = JsonSchema.FromFile(file, options);
            options.SchemaRegistry.Register(schema);
            if (file.EndsWith("bundle.json", StringComparison.Ordinal)) bundle = schema;
            if (file.EndsWith("note.json", StringComparison.Ordinal)) note = schema;
        }
        return (bundle!, note!);
    });

    private static void Valid(JsonSchema schema, string json)
    {
        using var doc = JsonDocument.Parse(json);
        var result = schema.Evaluate(doc.RootElement, new EvaluationOptions { OutputFormat = OutputFormat.List });
        Assert.True(result.IsValid, string.Join("\n", (result.Details ?? []).Where(d => d.Errors is { Count: > 0 })
            .SelectMany(d => d.Errors!.Select(e => $"{d.InstanceLocation} {d.EvaluationPath}: {e.Value}")).Take(20)));
    }

    private InspectionService.FileSummary Summary()
    {
        var app = InspectionTests.Compile("Marker", "public static class Marker { public static int One() => 1; }");
        var path = _dir.File("app.zip");
        using (var zip = ZipFile.Open(path, ZipArchiveMode.Create))
        using (var entry = zip.CreateEntry("bin/Marker.dll").Open())
            entry.Write(app);
        return new InspectionService(_workspace).Summarize(null, path, default, new FileViewOptions { Stix = true });
    }

    private static CapaReport Report(string state, params CapaLabel[] labels) =>
        new(state, "capa", true, "pe", labels, state == "matched" ? [] : ["capa is not set up"]);

    private static byte[] Write(InspectionService.FileSummary summary, CapaReport? capa, IReadOnlyList<StixBundle.Match>? yara = null, bool available = true)
    {
        var (matches, note) = StixBundle.CapaMatches(capa, available);
        return StixBundle.Write(summary, "1.0.0", DateTimeOffset.UnixEpoch, Guid.NewGuid(), Guid.NewGuid(), [.. matches, .. yara ?? []], note == null ? null : [note]);
    }

    private static List<JsonElement> Objects(byte[] bytes, string type) =>
        [.. JsonDocument.Parse(bytes).RootElement.GetProperty("objects").EnumerateArray().Where(o => o.GetProperty("type").GetString() == type)];

    [Fact]
    public void Each_matched_capa_label_is_a_note_that_refers_to_the_sample()
    {
        var summary = Summary();
        var labels = new[]
        {
            new CapaLabel("write file", "host-interaction/file-system", "function", [], [], [0x401000]),
            new CapaLabel("encode data", null, "file", [], [], []),
        };
        var bytes = Write(summary, Report("matched", labels));
        var notes = Objects(bytes, "note");
        var sample = Objects(bytes, "file").Single(f => f.GetProperty("name").GetString() == "app.zip").GetProperty("id").GetString();
        Assert.Equal(["encode data", "write file"], notes.Select(n => n.GetProperty("content").GetString()!.Split(' ')[2] + " " + n.GetProperty("content").GetString()!.Split(' ')[3]).ToArray());
        Assert.All(notes, n => Assert.Equal(sample, n.GetProperty("object_refs")[0].GetString()));
        Assert.Equal("0x401000", notes[1].GetProperty("x_corvus_locations")[0].GetString());
    }

    [Fact]
    public void Each_matched_yara_rule_is_a_note_with_its_paths()
    {
        var yara = new StixBundle.Match[]
        {
            new("yara", "rule_a", null, null, ["bin/a.dll"]),
            new("yara", "rule_a", null, null, ["bin/b.dll", "bin/a.dll"]),
        };
        var notes = Objects(Write(Summary(), null, yara, available: false), "note");
        var note = Assert.Single(notes);
        Assert.Contains("YARA rule rule_a", note.GetProperty("content").GetString());
        Assert.Equal(["bin/a.dll", "bin/b.dll"], note.GetProperty("x_corvus_locations").EnumerateArray().Select(l => l.GetString()!).ToArray());
    }

    [Fact]
    public void Note_ids_are_the_same_in_two_runs()
    {
        var summary = Summary();
        var report = Report("matched", new CapaLabel("write file", null, "function", [], [], []));
        string Id() => Objects(Write(summary, report), "note").Single().GetProperty("id").GetString()!;
        Assert.Equal(Id(), Id());
    }

    [Fact]
    public void A_capa_state_other_than_matched_adds_no_note_and_names_the_state()
    {
        var bytes = Write(Summary(), Report("not checked"));
        Assert.Empty(Objects(bytes, "note"));
        var description = Objects(bytes, "malware-analysis").Single().GetProperty("description").GetString();
        Assert.Contains("capa not run or unknown: not checked, capa is not set up.", description);
    }

    [Fact]
    public void Notes_past_the_cap_are_cut_and_the_cut_is_named()
    {
        var many = Enumerable.Range(0, StixBundle.MaxNotes + 5).Select(i => new StixBundle.Match("yara", $"rule_{i:D4}", null, null, [])).ToList();
        var bytes = Write(Summary(), null, many, available: false);
        Assert.Equal(StixBundle.MaxNotes, Objects(bytes, "note").Count);
        Assert.Contains("5 of 1,005", Objects(bytes, "malware-analysis").Single().GetProperty("description").GetString());
    }

    [Fact]
    public void A_bundle_with_notes_validates_against_the_STIX_2_1_schemas()
    {
        var bytes = Write(Summary(), Report("matched", new CapaLabel("write file", "host-interaction/file-system", "function", [], [], [0x401000])),
            [new StixBundle.Match("yara", "rule_a", null, null, ["bin/a.dll"])]);
        var root = System.Text.Json.Nodes.JsonNode.Parse(bytes)!;
        var objects = root["objects"]!.AsArray();
        var notes = objects.Where(o => (string?)o!["type"] == "note").Select(o => o!.ToJsonString()).ToList();
        foreach (var n in objects.Where(o => (string?)o!["type"] == "note").ToList()) objects.Remove(n);
        Assert.Equal(2, notes.Count);
        Assert.All(notes, n => Valid(Schemas.Value.Note, n));
        Valid(Schemas.Value.Bundle, root.ToJsonString());
    }
}
