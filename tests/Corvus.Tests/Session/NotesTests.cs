using System.Text.Json;
using System.Text.Json.Nodes;
using ModelContextProtocol.Protocol;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Native.Annotations;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>record_note / update_note / list_notes: persistence, partial updates, revision conflicts, anchors, filters, concurrent writers.</summary>
public sealed class NotesTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private NotesService Store() => new(new AnnotationStore(_dir.File("annotations")));

    private (NoteTools Tools, AssemblyWorkspace Workspace, NotesService Notes) Tools()
    {
        var options = new ServerOptions { BackgroundIndexing = false };
        var workspace = new AssemblyWorkspace(options);
        var store = new AnnotationStore(_dir.File("annotations"));
        var code = new NativeCodeService(workspace, options, annotations: store);
        var notes = new NotesService(store);
        return (new NoteTools(workspace, notes, code, new MinidumpService(workspace, code)), workspace, notes);
    }

    [Fact]
    public void RecordUpdateAndReadBack()
    {
        var store = Store();
        var note = store.Record("decoder at the second call", "hypothesis", null, NoteAnchor.Global, ["crypto", "crypto"], ["get_il x"], "tester");
        Assert.Matches("^n[a-z2-7]{8}$", note.Id);
        Assert.Equal((1, "open", "hypothesis"), (note.Revision, note.Status, note.Kind));
        Assert.Equal(["crypto"], note.Tags);

        var updated = store.Update(note.Id, 1, new NoteChange(Status: "confirmed", AppendText: "verified by stepping", AddTags: ["xor"], RemoveTags: ["CRYPTO"]));
        Assert.Equal(2, updated.Revision);
        Assert.Equal("confirmed", updated.Status);
        Assert.Equal("decoder at the second call\nverified by stepping", updated.Text);
        Assert.Equal(["xor"], updated.Tags);
        Assert.Equal("get_il x", Assert.Single(updated.Evidence).Text);

        // a fresh store (another process) reads the same note
        var read = Store().All().Single();
        Assert.Equal((updated.Id, updated.Revision, updated.Text, updated.Updated), (read.Id, read.Revision, read.Text, read.Updated));
        Assert.Equal(updated.Tags, read.Tags);
        Assert.Equal((0, 1), Store().Counts());
    }

    [Fact]
    public void StaleRevisionIsAConflictCarryingTheCurrentNote()
    {
        var store = Store();
        var note = store.Record("first", null, null, NoteAnchor.Global, null, null, null);
        store.Update(note.Id, 1, new NoteChange(Text: "second"));
        var error = Assert.Throws<ToolError>(() => Store().Update(note.Id, 1, new NoteChange(Status: "dropped")));
        Assert.Equal(ErrorCode.Conflict, error.Code);
        var current = (Note)error.Details!.GetType().GetProperty("current")!.GetValue(error.Details)!;
        Assert.Equal((2, "second", "open"), (current.Revision, current.Text, current.Status));
        Assert.Equal(ErrorCode.NotFound, Assert.Throws<ToolError>(() => store.Update("nzzzzzzzz", 1, new NoteChange())).Code);
        Assert.Equal(ErrorCode.InvalidArgument, Assert.Throws<ToolError>(() => store.Update(note.Id, 2, new NoteChange(Status: "closed"))).Code);
        Assert.Equal(ErrorCode.LimitExceeded, Assert.Throws<ToolError>(() => store.Record(new string('x', 4001), null, null, NoteAnchor.Global, null, null, null)).Code);
    }

    [Fact]
    public async Task ConcurrentWritersKeepEveryNote()
    {
        var anchor = new NoteAnchor(NoteAnchor.Native, Sha256: new string('a', 64), Rva: 0x1000, Label: "x@0x1000");
        var a = Store();
        var b = Store();
        await Task.WhenAll(
            Task.Run(() => { for (int i = 0; i < 40; i++) a.Record($"a{i}", null, null, anchor, null, null, null); }),
            Task.Run(() => { for (int i = 0; i < 40; i++) b.Record($"b{i}", null, null, anchor, null, null, null); }));
        Assert.Equal(80, Store().Read(anchor.StoreKey).Select(n => n.Id).Distinct().Count());
    }

    [Fact]
    public async Task DecompileOutputCountsOpenNotes()
    {
        using var env = new Env();
        var notes = new NotesService(new AnnotationStore(_dir.File("annotations")));
        var tools = new DecompileTools(env.Workspace, env.Decompiler, env.Pager, notes);
        Assert.DoesNotContain("// notes:", await tools.DecompileMember("Account::Score"));
        var score = env.One("Account::Score");
        var anchor = new NoteAnchor(NoteAnchor.DotNet, Sha256: env.Fixture.OriginalSha256, Mvid: env.Fixture.Module.Mvid!.ToString(), Token: score.Member.MDToken.Raw);
        notes.Record("capped at 100", null, null, anchor, null, null, null);
        notes.Record("old idea", null, "dropped", anchor, null, null, null);
        Assert.StartsWith($"// notes: 1 open (list_notes anchor=TestFixture:{Format.Token(score.Member)})", await tools.DecompileMember("Account::Score"));
        Assert.StartsWith("// notes: 1 open", await tools.DecompileMember("Fixture.Model.Account"));
        Assert.DoesNotContain("// notes:", await tools.DecompileMember("Account::Charge"));
    }

    [Fact]
    public async Task AnchorsResolveAndFilter()
    {
        var (tools, workspace, notes) = Tools();
        var image = McpProtocolTests.NativeSample(_dir);
        workspace.LoadAny(image);
        workspace.Load(Env.FixturePath);
        var native = workspace.FindNative("native.dll")!;

        var atFirst = await tools.RecordNote("entry point stub", anchor: "native.dll@First", tags: ["entry"]);
        Assert.Equal((NoteAnchor.Native, native.OriginalSha256), (atFirst.Anchor.Kind, atFirst.Anchor.Sha256));
        Assert.NotNull(atFirst.Anchor.Rva);
        var member = await tools.RecordNote("scores are capped", kind: "finding", anchor: "TestFixture:Account::Score");
        Assert.Equal(NoteAnchor.DotNet, member.Anchor.Kind);
        Assert.Equal(workspace.Get("TestFixture").Module.Mvid.ToString(), member.Anchor.Mvid);
        Assert.Equal(0x06000000u, member.Anchor.Token & 0xFF000000);
        var byToken = await tools.RecordNote("same member by token", anchor: $"TestFixture:0x{member.Anchor.Token:X8}");
        Assert.Equal(member.Anchor.Token, byToken.Anchor.Token);
        var file = await tools.RecordNote("packed?", kind: "question", anchor: "TestFixture");
        Assert.Equal(NoteAnchor.File, file.Anchor.Kind);
        await tools.RecordNote("global todo", kind: "todo");
        await Assert.ThrowsAsync<ToolError>(() => tools.RecordNote("x", anchor: "NoSuchThing:Foo"));

        async Task<NoteTools.NoteList> List(string? status = null, string? kind = null, string? anchor = null, string? tag = null, int offset = 0, int limit = 50)
        {
            var collector = ToolOutput.Collect();
            await tools.ListNotes(status, kind, anchor, tag, offset: offset, limit: limit);
            return Assert.IsType<NoteTools.NoteList>(collector.Value);
        }
        Assert.Equal(5, (await List()).Total);
        Assert.Equal(3, (await List(anchor: "TestFixture")).Total);
        Assert.Equal(2, (await List(anchor: "TestFixture:Account")).Total); // the type includes its members
        Assert.Equal(["entry point stub"], (await List(anchor: "native.dll@First")).Items.Select(n => n.Text));
        Assert.Equal(["packed?"], (await List(kind: "question")).Items.Select(n => n.Text));
        Assert.Equal(["entry point stub"], (await List(tag: "ENTRY")).Items.Select(n => n.Text));
        Assert.Equal(["global todo"], (await List(anchor: "global")).Items.Select(n => n.Text));

        await tools.UpdateNote(file.Id, 1, status: "answered", text: "not packed");
        Assert.Equal(4, (await List()).Total);
        Assert.Equal(["not packed"], (await List(status: "answered")).Items.Select(n => n.Text));
        var page = await List(status: "all", offset: 1, limit: 2);
        Assert.Equal((2, 5), (page.Items.Count, page.Total));
        var text = await tools.ListNotes(status: "all", offset: 1, limit: 2);
        Assert.Contains("5 notes (showing 2-3):\n  n", text);
        Assert.Contains("[More: offset=3]", text);
        Assert.Equal((4, 5), notes.Counts());
    }

    /// <summary>MB N1: an evidence entry names a call made here; its resultSha256 is filled in, and re-running the call reproduces it.</summary>
    [Fact]
    public async Task A_hypothesis_flips_when_its_linked_record_verifies_and_names_its_anchor()
    {
        await using var server = await InProcessServer.StartAsync();
        var sqlite = RealPackages.File("SQLitePCLRaw.lib.e_sqlite3", "2.1.11", "runtimes", "win-x64", "native", "e_sqlite3.dll");
        await server.Client.CallToolAsync("load_assembly", new Dictionary<string, object?> { ["path"] = sqlite });
        Assert.NotEqual(true, (await server.Client.CallToolAsync("disassemble", new Dictionary<string, object?> { ["image"] = "e_sqlite3.dll", ["address"] = "sqlite3_complete" })).IsError);

        async Task<JsonNode> Note(string tool, Dictionary<string, object?> args)
        {
            var r = await server.Client.CallToolAsync(tool, args);
            Assert.NotEqual(true, r.IsError);
            return JsonNode.Parse(r.StructuredContent!.Value.GetRawText())!;
        }
        string result = "last:1";
        async Task<JsonNode> Hypothesis(string anchor, string expect)
        {
            var n = await Note("record_note", new() { ["text"] = "checked against the listing", ["kind"] = "hypothesis", ["anchor"] = anchor,
                ["evidence"] = new object[] { new { result, expect } } });
            var linked = n["evidence"]![0]!;
            result = (string)linked["result"]!; // last:1 is kept under its content id
            Assert.Matches("^r-[0-9a-f]{12}$", result);
            Assert.Equal("disassemble", (string)linked["tool"]!);
            return await Note("update_note", new() { ["id"] = (string)n["id"]!, ["expectedRevision"] = 1, ["verify"] = true });
        }

        var confirmed = await Hypothesis("e_sqlite3.dll@sqlite3_complete", "supports");
        Assert.Equal("confirmed", (string)confirmed["status"]!);
        Assert.StartsWith("verified: same content", (string)confirmed["evidence"]![0]!["verdict"]!);
        Assert.Equal("refuted", (string)(await Hypothesis("e_sqlite3.dll@sqlite3_complete", "refutes"))["status"]!);
        // the record verifies but is about another function: the hypothesis stays open
        var open = await Hypothesis("e_sqlite3.dll@sqlite3_open_v2", "supports");
        Assert.Equal("open", (string)open["status"]!);
        Assert.StartsWith("does not name the note's anchor", (string)open["evidence"]![0]!["verdict"]!);
    }

    [Fact]
    public async Task EvidenceReRunsAndMatchesByResultSha256()
    {
        await using var server = await InProcessServer.StartAsync();
        var args = new Dictionary<string, object?> { ["assembly"] = "TestFixture", ["limit"] = 3 };
        var seen = await server.Client.CallToolAsync("list_types", args);
        string Sha(CallToolResult r) => (string)r.Meta![ToolOutput.ProvenanceKey]!["resultSha256"]!;
        var evidence = new object[] { new { tool = "list_types", args }, new { text = "seen in the debugger" }, new { tool = "list_types", args = new { assembly = "Nope" } } };
        var recorded = await server.Client.CallToolAsync("record_note", new Dictionary<string, object?>
        {
            ["text"] = "three types to start with", ["tags"] = new[] { "evidence", "test" }, ["evidence"] = evidence,
        });
        Assert.NotEqual(true, recorded.IsError);
        var note = JsonNode.Parse(recorded.StructuredContent!.Value.GetRawText())!;
        Assert.Equal(["evidence", "test"], note["tags"]!.AsArray().Select(t => (string)t!));
        var entries = note["evidence"]!.AsArray();
        Assert.Equal(Sha(seen), (string)entries[0]!["resultSha256"]!);
        Assert.Equal("seen in the debugger", (string)entries[1]!["text"]!);
        Assert.Null(entries[2]!["resultSha256"]); // no such call was made
        Assert.Contains("no earlier call here of list_types", (string)note["warnings"]![0]!);

        // A later check re-runs the recorded call: the same result has the same hash.
        var e = entries[0]!;
        var again = await server.Client.CallToolAsync((string)e["tool"]!, JsonSerializer.Deserialize<Dictionary<string, object?>>(e["args"]!.ToJsonString()));
        Assert.Equal((string)e["resultSha256"]!, ToolOutput.ResultSha256(again));
        Assert.Equal((string)e["resultSha256"]!, Sha(again));
        await server.Client.CallToolAsync("update_note", new Dictionary<string, object?> { ["id"] = (string)note["id"]!, ["expectedRevision"] = 1, ["status"] = "dropped" });
    }

    /// <summary>Note files from before evidence objects (corvus-notes/1, evidence as strings) read as text entries.</summary>
    [Fact]
    public void FormatOneEvidenceStringsReadAsText()
    {
        var store = Store();
        Directory.CreateDirectory(store.Root);
        File.WriteAllText(Path.Combine(store.Root, "global.json"), ("{'format':'corvus-notes/1','notes':[{'id':'nabcdefgh','kind':'finding','status':'open','text':'old','tags':['t'],'evidence':['get_il x']," +
            "'anchor':{'kind':'none'},'revision':1,'created':'2026-01-01T00:00:00Z','updated':'2026-01-01T00:00:00Z','author':null}]}").Replace('\'', '"'));
        var old = Assert.Single(store.All());
        Assert.Equal(new NoteEvidence(Text: "get_il x"), Assert.Single(old.Evidence));
        var updated = store.Update(old.Id, 1, new NoteChange(AddEvidence: [new NoteEvidence("get_il", new JsonObject { ["symbol"] = "A::B" })]));
        Assert.Equal(2, updated.Evidence.Count);
        Assert.Contains("\"format\": \"corvus-notes/3\"", File.ReadAllText(Path.Combine(store.Root, "global.json")));
        Assert.Equal(updated.Evidence[1].Args!.ToJsonString(), Store().All().Single().Evidence[1].Args!.ToJsonString());
        Assert.Equal(ErrorCode.InvalidArgument, Assert.Throws<ToolError>(() => NotesService.CheckEvidence([new NoteEvidence()])).Code);
        Assert.Equal(ErrorCode.InvalidArgument, Assert.Throws<ToolError>(() => NotesService.CheckEvidence([new NoteEvidence("x", ResultSha256: "abc")])).Code);
    }
}
