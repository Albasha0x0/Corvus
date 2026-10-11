using System.Text.Json;
using System.Text.RegularExpressions;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Annotations;
using NetDecompilerMcp.Native.Providers;
using NetDecompilerMcp.Native.Providers.Ida;
using NetDecompilerMcp.Services;
using NetDecompilerMcp.Tools;

namespace NetDecompilerMcp.Tests;

/// <summary>Type renames and deletions: kept in the user-type layer and sidecar, sent to a scripted engine, exported and migrated.</summary>
public sealed class NativeTypeEditTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly List<IDisposable> _owned = [];

    public void Dispose()
    {
        foreach (var d in _owned) d.Dispose();
        _dir.Dispose();
    }

    private static UserTypeLayer Seeded() => UserTypeLayer.Empty
        .WithDeclarations("struct Packet { int length; };\nstruct PacketSize { Packet *p; };")
        .WithType(0x2000, "Packet *").WithType(0x2100, "PacketSize")
        .WithLocal(new(0x1000, "v1", null, "pkt", "Packet *"))
        .WithStackVar(new(0x1000, 0x20, "buf", "Packet[2]"))
        .WithAnalysis(new(0x3000, NativeAnalysisEdit.Data, null, "Packet[4]"))
        .WithOperand(new(0x1010, 1, "struct", "Packet+0x4")).WithOperand(new(0x1020, 0, "dec", null))
        .WithEnumMember(new("Mode", "Fast", 1));

    [Fact]
    public void A_rename_renames_the_type_in_every_kept_edit_by_whole_word()
    {
        var layer = Seeded().WithTypeEdit(new("Packet", "Msg"));
        Assert.Equal("struct Msg { int length; };\nstruct PacketSize { Msg *p; };", Assert.Single(layer.Declarations));
        Assert.Equal("Msg *", layer.Types[0x2000]);
        Assert.Equal("PacketSize", layer.Types[0x2100]);
        Assert.Equal("Msg *", layer.Locals[0x1000][0].Type);
        Assert.Equal("Msg[2]", layer.StackVars[0x1000][0].Type);
        Assert.Equal("Msg[4]", layer.Analysis[0].Type);
        Assert.Equal("Msg+0x4", layer.Operands[(0x1010, 1)].Detail);
        Assert.Equal([new NativeTypeEdit("Packet", "Msg")], layer.TypeEdits);
        Assert.NotEqual(Seeded().Stamp, layer.Stamp);

        // a chain follows the type; an enum's members follow its rename
        var chained = layer.WithTypeEdit(new("Msg", "Frame")).WithTypeEdit(new("Mode", "Speed"));
        Assert.Equal([new NativeTypeEdit("Packet", "Frame"), new("Msg", "Frame"), new("Mode", "Speed")], chained.TypeEdits);
        Assert.Equal(("Speed", "Fast"), Assert.Single(chained.EnumMembers).Key);
        Assert.Contains("struct Frame {", chained.Declarations[0]);
    }

    [Fact]
    public void A_deletion_drops_the_types_enum_members_and_a_later_declaration_drops_the_edit()
    {
        var layer = Seeded().WithTypeEdit(new("Mode", null));
        Assert.Empty(layer.EnumMembers);
        Assert.Equal(Seeded().Types, layer.Types);
        // an edit of the same name replaces the earlier one
        Assert.Equal([new NativeTypeEdit("Mode", "Speed")], layer.WithTypeEdit(new("Mode", "Speed")).TypeEdits);

        var redeclared = layer.WithTypeEdit(new("Packet", "Msg")).WithDeclarations("enum Mode { A = 1 };", ["Mode"]);
        Assert.Equal([new NativeTypeEdit("Packet", "Msg")], redeclared.TypeEdits);
        Assert.Equal(2, redeclared.Declarations.Count);
        // the same block again still drops the edit
        Assert.DoesNotContain(redeclared.WithTypeEdit(new("Mode", null)).WithDeclarations("enum Mode { A = 1 };", ["Mode"]).TypeEdits, e => e.Name == "Mode");
    }

    [Fact]
    public void Type_edits_round_trip_the_sidecar_in_order_reach_the_engine_and_the_exports()
    {
        var store = new AnnotationStore(_dir.File("ann"));
        var ann = new NativeAnnotations(store, _dir.File("image.dll"), "cd34", 0x180000000);
        ann.ChangeUserTypes(_ => Seeded().WithTypeEdit(new("Packet", "Msg")).WithTypeEdit(new("Mode", null)));
        var again = new NativeAnnotations(store, _dir.File("image.dll"), "cd34", 0x180000000).UserTypes;
        Assert.Equal([new NativeTypeEdit("Packet", "Msg"), new("Mode", null)], again.TypeEdits);
        Assert.Equal(ann.UserTypes.Stamp, again.Stamp);
        var sidecar = JsonDocument.Parse(File.ReadAllText(Path.Combine(store.Root, "cd34.json"))).RootElement;
        Assert.Equal(4, sidecar.GetProperty("formatVersion").GetInt32());
        Assert.False(sidecar.GetProperty("typeEdits")[1].TryGetProperty("newName", out _));

        var args = WorkerRows.UserTypeArgs(again.ToBatch(), null, null, false);
        Assert.Equal("[[\"Packet\",\"Msg\"],[\"Mode\",null]]", args["type_edits"]!.ToJsonString());
        Assert.False(WorkerRows.UserTypeArgs(NativeUserTypeBatch.Empty, null, null, false).ContainsKey("type_edits"));
        Assert.Equal("[]", WorkerRows.UserTypeArgs(NativeUserTypeBatch.Empty with { TypeEdits = [] }, null, null, false)["type_edits"]!.ToJsonString());

        var ida = AnnotationExport.Render(ann, AnnotationExport.Format.Ida);
        Assert.True(ida.IndexOf("ndm_type_edit(\"Packet\", \"Msg\")", StringComparison.Ordinal) > ida.IndexOf("ndm_declare(", StringComparison.Ordinal));
        Assert.Contains("ndm_type_edit(\"Mode\", None)", ida);
        // AnnotationStoreTests compiles the helpers; ndm_type_edit is one of them
        Assert.Contains("def ndm_type_edit(name, new_name):", ida);
        var json = JsonDocument.Parse(AnnotationExport.Render(ann, AnnotationExport.Format.Json)).RootElement;
        Assert.Equal("Msg", json.GetProperty("typeEdits")[0].GetProperty("newName").GetString());
    }

    [Theory]
    [InlineData(null, "Packet=", "two different type names")]
    [InlineData(null, "Packet=Packet", "two different type names")]
    [InlineData(null, "Packet", "two different type names")]
    [InlineData("bad name", null, "not a type name")]
    [InlineData("A", "B=C", "not both")]
    public void Delete_and_rename_arguments_are_checked(string? delete, string? rename, string message) =>
        Assert.Contains(message, Assert.Throws<ToolError>(() => NativeTypeTools.TypeEditRequest(delete, rename)).Message);

    private async Task<(NativeTypeTools Tools, ScriptedProvider Engine, NativeCodeService Code, LoadedNative Native)> Rig()
    {
        var options = new ServerOptions { BackgroundIndexing = false };
        var workspace = new AssemblyWorkspace(options);
        var code = new NativeCodeService(workspace, options, null, new AnnotationStore(_dir.File("annotations")));
        var engine = new ScriptedProvider();
        var engines = new NativeEngineService([engine], _dir.File("cache"), code, workspace, options);
        _owned.Add(engines);
        _owned.Add(workspace);
        var native = workspace.LoadAny(McpProtocolTests.NativeSample(_dir)).Native!;
        await code.Index(native, null, default);
        return (new NativeTypeTools(workspace, engines, new NativeUserTypePush(code), code), engine, code, native);
    }

    [Fact]
    public async Task Rename_and_delete_go_to_the_engine_as_the_whole_kept_list_and_are_recorded()
    {
        var (tools, engine, code, native) = await Rig();
        await tools.DeclareNativeTypes(native.Id, "struct Packet { int length; };\nenum Mode { Slow = 1 };");
        code.Annotations(native).ChangeUserTypes(l => l.WithType(0x1000, "Packet *").WithEnumMember(new("Mode", "Fast", 2)));

        // the edit goes alone, followed by the stamp of the new layer
        IReadOnlyList<NativeTypeEdit>? Sent() => engine.Batches[^2].TypeEdits;
        Assert.Contains("Renamed type Packet to Msg", await tools.DeclareNativeTypes(native.Id, rename: "Packet=Msg"));
        Assert.Equal([new NativeTypeEdit("Packet", "Msg")], Sent());
        Assert.Contains("Msg", engine.Types.Keys);
        var layer = code.Annotations(native).UserTypes;
        Assert.Equal("Msg *", layer.Types[0x1000]);
        Assert.StartsWith("struct Msg {", layer.Declarations[0]);

        Assert.Contains("Deleted type Mode", await tools.DeclareNativeTypes(native.Id, delete: "Mode"));
        Assert.Equal([new NativeTypeEdit("Packet", "Msg"), new("Mode", null)], Sent());
        Assert.Empty(code.Annotations(native).UserTypes.EnumMembers);

        Assert.Equal(ErrorCode.NotFound, (await Assert.ThrowsAsync<ToolError>(() => tools.DeclareNativeTypes(native.Id, delete: "Mode"))).Code);
        await tools.DeclareNativeTypes(native.Id, "struct Other { int a; };");
        Assert.Contains("exists", (await Assert.ThrowsAsync<ToolError>(() => tools.DeclareNativeTypes(native.Id, rename: "Msg=Other"))).Message);
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => tools.DeclareNativeTypes(native.Id, "struct X { int a; };", delete: "Msg"))).Code);

        // declaring Mode again drops its deletion, and the engine's kept list follows
        await tools.DeclareNativeTypes(native.Id, "enum Mode { Again = 1 };");
        Assert.Equal([new NativeTypeEdit("Packet", "Msg")], code.Annotations(native).UserTypes.TypeEdits);
        Assert.Equal([new NativeTypeEdit("Packet", "Msg")], engine.Batches[^1].TypeEdits);
        Assert.Null(engine.Batches[^3].TypeEdits);
        // an engine refusal records nothing
        engine.Refuse = "Other";
        await Assert.ThrowsAsync<ToolError>(() => tools.DeclareNativeTypes(native.Id, delete: "Other"));
        Assert.DoesNotContain(code.Annotations(native).UserTypes.TypeEdits, e => e.Name == "Other");
    }

    [Fact]
    public void Fields_parse_names_offsets_types_and_removals()
    {
        Assert.Equal([new NativeFieldEdit("Packet", "len", null, "int"), new("Packet", "data", 8, "char[16]"), new("Packet", null, 0x20, "std::size_t"),
                new("Packet", "old", null, null), new("Packet", null, 4, null)],
            NativeTypeTools.FieldEdits("Packet", "len: int; data@0x8: char[16]\n@0x20: std::size_t; old:; @4:"));
        Assert.Equal("@0x20", new NativeFieldEdit("Packet", null, 0x20, null).Key);
        foreach (var (type, fields) in new[] { ("", "a: int"), ("Packet", "a int"), ("Packet", "bad name: int"), ("Packet", ": int"), ("Packet", "a@zz: int") })
            Assert.Equal(ErrorCode.InvalidArgument, Assert.Throws<ToolError>(() => NativeTypeTools.FieldEdits(type, fields)).Code);
    }

    [Fact]
    public void Field_edits_replace_by_member_follow_renames_drop_with_deletions_and_round_trip()
    {
        var layer = Seeded().WithField(new("Packet", "len", null, "int")).WithField(new("Packet", null, 8, "PacketSize"))
            .WithField(new("PacketSize", "p", null, "Packet *")).WithField(new("Packet", "len", 4, "short"));
        // the same member again replaces the earlier edit and moves after the others
        Assert.Equal(["@0x8", "p", "len"], layer.Fields.Select(f => f.Key));
        Assert.Equal(4, layer.Fields[^1].Offset);

        var renamed = layer.WithTypeEdit(new("Packet", "Msg"));
        Assert.Equal(["Msg", "PacketSize", "Msg"], renamed.Fields.Select(f => f.Type));
        Assert.Equal("Msg *", renamed.Fields[1].FieldType);
        Assert.Equal([new NativeFieldEdit("PacketSize", "p", null, "Packet *")], layer.WithTypeEdit(new("Packet", null)).Fields);

        var store = new AnnotationStore(_dir.File("ann"));
        var ann = new NativeAnnotations(store, _dir.File("image.dll"), "ef56", 0x180000000);
        ann.ChangeUserTypes(_ => layer.WithField(new("PacketSize", "gone", null, null)));
        var again = new NativeAnnotations(store, _dir.File("image.dll"), "ef56", 0x180000000).UserTypes;
        Assert.Equal(ann.UserTypes.Fields, again.Fields);
        Assert.Equal(ann.UserTypes.Stamp, again.Stamp);
        Assert.Equal("[[\"Packet\",null,8,\"PacketSize\"],[\"PacketSize\",\"p\",null,\"Packet *\"],[\"Packet\",\"len\",4,\"short\"],[\"PacketSize\",\"gone\",null,null]]",
            WorkerRows.UserTypeArgs(again.ToBatch(), null, null, false)["fields"]!.ToJsonString());
        var ida = AnnotationExport.Render(ann, AnnotationExport.Format.Ida);
        Assert.Contains("ndm_field(\"Packet\", None, 8, \"PacketSize\")", ida);
        Assert.Contains("ndm_field(\"PacketSize\", \"gone\", None, None)", ida);
        Assert.True(ida.IndexOf("ndm_field(", StringComparison.Ordinal) < ida.IndexOf("ndm_type(", StringComparison.Ordinal));
        Assert.Equal("len", JsonDocument.Parse(AnnotationExport.Render(ann, AnnotationExport.Format.Json)).RootElement.GetProperty("fields")[2].GetProperty("name").GetString());
    }

    [Fact]
    public async Task Fields_go_to_the_engine_and_only_the_applied_ones_are_recorded()
    {
        var (tools, engine, code, native) = await Rig();
        await tools.DeclareNativeTypes(native.Id, "struct Packet { int length; };\nenum Mode { Slow = 1 };");
        var text = await tools.DeclareNativeTypes(native.Id, typeName: "Packet", fields: "length: short; tag@0x8: char[4]");
        Assert.Contains("Packet.tag: char[4]", text);
        Assert.Equal([new NativeFieldEdit("Packet", "length", null, "short"), new("Packet", "tag", 8, "char[4]")], engine.Batches[^2].Fields);
        Assert.Equal(engine.Batches[^2].Fields, code.Annotations(native).UserTypes.Fields);
        Assert.Contains("no struct or union named Mode", (await Assert.ThrowsAsync<ToolError>(() => tools.DeclareNativeTypes(native.Id, typeName: "Mode", fields: "a: int"))).Message);
        Assert.Equal(2, code.Annotations(native).UserTypes.Fields.Count);
        Assert.Equal(ErrorCode.InvalidArgument,
            (await Assert.ThrowsAsync<ToolError>(() => tools.DeclareNativeTypes(native.Id, typeName: "Packet", members: "A=1", fields: "a: int"))).Code);
    }

    [Fact]
    public async Task Only_a_Ghidra_session_refreshes_the_ghidra_name_layer()
    {
        var (_, engine, code, native) = await Rig();
        Assert.Null(GhidraNames.Refresh(native, await engine.OpenAsync(""), code));
        Assert.Null(GhidraNames.LastRefresh(native));
    }

    /// <summary>An engine that keeps named types and applies declarations and type edits as the workers do.</summary>
    internal sealed class ScriptedProvider : INativeDecompilerProvider
    {
        public Dictionary<string, string> Types { get; } = new(StringComparer.Ordinal);
        public List<NativeUserTypeBatch> Batches { get; } = [];
        public Dictionary<string, string> Stamps { get; } = [];
        /// <summary>A type the engine will not rename or delete.</summary>
        public string? Refuse { get; set; }
        public string Id => IdaProvider.ProviderId;
        public string DisplayName => "scripted engine";
        public ProviderAvailability CheckAvailability() => ProviderAvailability.Ok(Id, new Dictionary<string, string>());
        public Task<ProviderAvailability> ProbeAsync(CancellationToken cancellationToken = default) => Task.FromResult(CheckAvailability());

        public Task<INativeDecompilerSession> OpenAsync(string imagePath, string? sha256 = null, NativeOpenOptions? options = null, CancellationToken cancellationToken = default) =>
            Task.FromResult<INativeDecompilerSession>(new ScriptedSession(this));

        public void Dispose() { }

        public UserTypeResult Apply(NativeUserTypeBatch batch, string? stampKey, string? stamp)
        {
            Batches.Add(batch);
            var declared = new List<string>();
            foreach (var d in batch.Declarations)
                foreach (Match m in Regex.Matches(d, @"\b(struct|union|enum)\s+([A-Za-z_]\w*)\s*\{"))
                {
                    Types[m.Groups[2].Value] = m.Groups[1].Value;
                    declared.Add(m.Groups[2].Value);
                }
            var items = new List<NativeUserTypeOutcome>();
            foreach (var e in batch.TypeEdits ?? [])
            {
                bool ok = e.Name != Refuse;
                if (ok && Types.Remove(e.Name, out var kind) && e.NewName != null) Types.TryAdd(e.NewName, kind);
                items.Add(new("type_edit", 0, e.Name, ok, ok ? null : "refused", null, null, ok ? "done" : null));
            }
            foreach (var e in batch.EnumMembers) items.Add(new("enum", 0, $"{e.Enum}::{e.Member}", true, null, null, null, $"{e.Enum}::{e.Member} = 0x{e.Value:X}"));
            foreach (var f in batch.Fields)
            {
                bool ok = Types.GetValueOrDefault(f.Type) is "struct" or "union";
                items.Add(new("field", 0, $"{f.Type}.{f.Key}", ok, ok ? null : $"no struct or union named {f.Type}", null, f.Offset, ok ? $"{f.Type}.{f.Key}: {f.FieldType}" : null));
            }
            foreach (var t in batch.Types) items.Add(new("type", t.Rva, t.Declaration, true, null, null, null, t.Declaration));
            if (stampKey != null) Stamps[stampKey] = stamp ?? "";
            return new UserTypeResult(0, [], declared, items, TimeSpan.Zero);
        }
    }

    private sealed class ScriptedSession(ScriptedProvider provider) : INativeDecompilerSession
    {
        public string ProviderId => provider.Id;
        public string ImagePath => "";
        public string Sha256 => "";
        public NativeArch Arch => NativeArch.X64;
        public ulong ImageBase => 0;
        public bool ReusedDatabase => true;
        public TimeSpan OpenTime => TimeSpan.Zero;
        public bool DecompilerAvailable => true;
        public bool IsOpen => true;

        public Task<UserTypeResult> ApplyUserTypesAsync(NativeUserTypeBatch batch, string? stampKey = null, string? stamp = null, bool save = false,
            CancellationToken cancellationToken = default) => Task.FromResult(provider.Apply(batch, stampKey, stamp));

        public Task<NativeTypeDetail> GetTypeAsync(string name, CancellationToken cancellationToken = default) =>
            provider.Types.TryGetValue(name, out var kind) ? Task.FromResult(new NativeTypeDetail(name, kind, 4, $"{kind} {name};", []))
                : throw new ToolError(ErrorCode.NotFound, $"no type named {name}");

        public Task<string?> GetStampAsync(string key, CancellationToken cancellationToken = default) => Task.FromResult(provider.Stamps.GetValueOrDefault(key));
        public Task<DecompiledFunction> DecompileAsync(uint rva, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<IReadOnlyList<NativeFunctionInfo>> ListFunctionsAsync(CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<NativeFunctionInfo>>([]);
        public Task<FunctionDisassembly> DisassembleAsync(uint rva, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<PatchSyncResult> SyncPatchesAsync(IReadOnlyList<NativeByteRange> wanted, CancellationToken cancellationToken = default) =>
            Task.FromResult(new PatchSyncResult(wanted.Count, 0, 0, 0, 0, 0, [], TimeSpan.Zero));
        public Task<IReadOnlyList<NativeXref>> GetXrefsToAsync(uint rva, CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<NativeXref>>([]);
        public Task<IReadOnlyList<NativeXref>> GetXrefsFromAsync(uint rva, bool wholeFunction = false, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<NativeXref>>([]);
        public Task<string> SetNameAsync(uint rva, string name, CancellationToken cancellationToken = default) => Task.FromResult(name);
        public Task<string> SetCommentAsync(uint rva, string text, bool repeatable = false, CancellationToken cancellationToken = default) => Task.FromResult(text);
        public Task<NameBatchResult> ApplyNamesAsync(IReadOnlyList<NativeNameItem> items, string? stampKey = null, string? stamp = null, bool save = false,
            CancellationToken cancellationToken = default) => Task.FromResult(new NameBatchResult(items.Count, 0, 0, 0, TimeSpan.Zero, []));
        public Task SaveAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task CloseAsync(bool save = true, CancellationToken cancellationToken = default) => Task.CompletedTask;
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
        public void Dispose() { }
    }
}
