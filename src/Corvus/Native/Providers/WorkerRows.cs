using System.Text.Json;
using System.Text.Json.Nodes;

namespace Corvus.Native.Providers;

/// <summary>Request arguments and result rows shared by the engine workers (the IDA and Ghidra workers answer in the same shapes).</summary>
internal static class WorkerRows
{
    public static JsonObject Args(params (string Key, JsonNode? Value)[] values)
    {
        var o = new JsonObject();
        foreach (var (k, v) in values) o[k] = v;
        return o;
    }

    /// <summary>[start, end, name, flags, refs?] rows.</summary>
    public static List<NativeFunctionInfo> Functions(JsonElement r)
    {
        var list = new List<NativeFunctionInfo>(r.GetArrayLength());
        foreach (var f in r.EnumerateArray())
            list.Add(new NativeFunctionInfo(f[0].GetUInt32(), f[1].GetUInt32(), f[2].GetString() ?? "", (NativeFunctionFlags)f[3].GetInt32(),
                f.GetArrayLength() > 4 ? f[4].GetInt32() : null));
        return list;
    }

    /// <summary>Every function, continuing from "next" while the worker answers {rows, partial, next} at its deadline.</summary>
    public static async Task<List<NativeFunctionInfo>> FunctionsPaged(Func<uint?, Task<JsonElement>> request)
    {
        var all = new List<NativeFunctionInfo>();
        uint? start = null;
        while (true)
        {
            var r = await request(start).ConfigureAwait(false);
            if (r.ValueKind == JsonValueKind.Array)
            {
                all.AddRange(Functions(r));
                return all;
            }
            var rows = Functions(r.GetProperty("rows"));
            var next = r.GetProperty("next").GetUInt32();
            if (rows.Count == 0 || (start is { } s && next <= s))
                throw new Core.ToolError(Core.ErrorCode.Timeout, "The engine listed no functions within the request time limit.", "Raise the engine request time limit.");
            all.AddRange(rows);
            start = next;
        }
    }

    /// <summary>The partial marker and cursor of a result cut short ("partial", "next"), or nulls.</summary>
    public static (string? Partial, uint? Next) Partial(JsonElement r) =>
        (r.TryGetProperty("partial", out var p) && p.ValueKind == JsonValueKind.String ? p.GetString() : null,
         r.TryGetProperty("next", out var n) && n.ValueKind == JsonValueKind.Number ? n.GetUInt32() : null);

    public static DecompiledFunction Decompiled(JsonElement r)
    {
        var lines = r.GetProperty("lines").EnumerateArray().Select(l => new PseudocodeLineAddress(l[0].GetInt32(), l[1].GetUInt32())).ToList();
        return new DecompiledFunction(r.GetProperty("start").GetUInt32(), r.GetProperty("name").GetString() ?? "", r.GetProperty("text").GetString() ?? "", lines);
    }

    /// <summary>"items" of {rva, status ok|error|skipped}: ok carries a decompile result, error its code and message.</summary>
    public static List<DecompileOutcome> DecompiledMany(JsonElement r)
    {
        var list = new List<DecompileOutcome>();
        foreach (var i in r.GetProperty("items").EnumerateArray())
        {
            uint rva = i.GetProperty("rva").GetUInt32();
            list.Add(i.GetProperty("status").GetString() switch
            {
                "ok" => new DecompileOutcome(rva, DecompileStatus.Ok, Decompiled(i), null, null),
                "skipped" => new DecompileOutcome(rva, DecompileStatus.Skipped, null, null, null),
                _ => new DecompileOutcome(rva, DecompileStatus.Error, null, i.TryGetProperty("code", out var c) ? c.GetString() ?? "failed" : "failed",
                    i.TryGetProperty("message", out var m) ? m.GetString() : null),
            });
        }
        return list;
    }

    public static JsonObject SliceArgs(EngineSliceRequest r) => Args(("function", r.Function), ("seed", r.Seed), ("rva", r.Rva),
        ("direction", r.Forward ? "forward" : "backward"), ("register", r.Register), ("index", r.Index), ("max_nodes", r.MaxNodes), ("seconds", r.Seconds));

    /// <summary>"nodes" of {kind, rva, text, why, value?, target?, site?, index?, callee?, derived?}, "edges" of [from, to, kind], truncated, note, variable.</summary>
    public static EngineSlice Slice(JsonElement r)
    {
        static string? Str(JsonElement e, string name) => e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
        static uint? U32(JsonElement e, string name) => e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetUInt32(out var u) ? u : null;
        var nodes = new List<EngineSliceNode>();
        foreach (var n in r.GetProperty("nodes").EnumerateArray())
            nodes.Add(new EngineSliceNode(Str(n, "kind") ?? "unknown", U32(n, "rva") ?? 0, Str(n, "text") ?? "", Str(n, "why") ?? "")
            {
                Value = n.TryGetProperty("value", out var v) && v.ValueKind == JsonValueKind.Number
                    ? v.TryGetUInt64(out var u) ? u : v.TryGetInt64(out var s) ? unchecked((ulong)s) : null : null,
                Target = U32(n, "target"),
                Site = U32(n, "site"),
                Index = n.TryGetProperty("index", out var i) && i.ValueKind == JsonValueKind.Number ? i.GetInt32() : -1,
                Callee = Str(n, "callee"),
                Derived = n.TryGetProperty("derived", out var d) && d.ValueKind == JsonValueKind.True,
            });
        var edges = r.GetProperty("edges").EnumerateArray().Select(e => (e[0].GetInt32(), e[1].GetInt32(), e[2].GetString() ?? "copy")).ToList();
        return new EngineSlice(nodes, edges, r.TryGetProperty("truncated", out var t) && t.ValueKind == JsonValueKind.True, Str(r, "note"), Str(r, "variable"));
    }

    /// <summary>[rva, hex bytes, text, comment or null] rows under "insns".</summary>
    public static List<DisassembledInstruction> Instructions(JsonElement r) =>
        r.GetProperty("insns").EnumerateArray()
            .Select(i => new DisassembledInstruction(i[0].GetUInt32(), Convert.FromHexString(i[1].GetString() ?? ""), i[2].GetString() ?? "",
                i[3].ValueKind == JsonValueKind.String ? i[3].GetString() : null))
            .ToList();

    public static FunctionDisassembly Disassembly(JsonElement r) =>
        new(r.GetProperty("start").GetUInt32(), r.GetProperty("end").GetUInt32(), r.GetProperty("name").GetString() ?? "",
            Instructions(r), r.GetProperty("truncated").GetBoolean());

    public static FunctionDisassembly Range(uint rva, JsonElement r)
    {
        var insns = Instructions(r);
        return new FunctionDisassembly(rva, insns.Count > 0 ? insns[^1].Rva + (uint)insns[^1].Bytes.Length : rva, "", insns, r.GetProperty("truncated").GetBoolean());
    }

    /// <summary>[start, end, instructions, kind, successors, switch, optional switch details] rows under "blocks", plus "tail_calls".</summary>
    public static NativeBlockGraph Blocks(JsonElement r)
    {
        var blocks = r.GetProperty("blocks").EnumerateArray()
            .Select(b => new NativeBlockInfo(b[0].GetUInt32(), b[1].GetUInt32(), b[2].GetInt32(), b[3].GetString() ?? "normal",
                b[4].EnumerateArray().Select(s => s.GetUInt32()).ToList(), b[5].GetBoolean())
            {
                SwitchInfo = b.GetArrayLength() > 6 && b[6].ValueKind == JsonValueKind.Object ? Switch(b[6]) : null,
            })
            .ToList();
        return new NativeBlockGraph(r.GetProperty("start").GetUInt32(), r.GetProperty("name").GetString() ?? "", blocks,
            r.GetProperty("tail_calls").EnumerateArray().Select(t => t.GetUInt32()).ToList());
    }

    private static NativeSwitchInfo Switch(JsonElement s)
    {
        uint? Rva(string name) => s.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number ? v.GetUInt32() : null;
        int? Int(string name) => s.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number ? v.GetInt32() : null;
        var cases = s.TryGetProperty("cases", out var c) && c.ValueKind == JsonValueKind.Array
            ? c.EnumerateArray().Select(x => (x[0].GetUInt32(), (IReadOnlyList<long>)x[1].EnumerateArray().Select(v => v.GetInt64()).ToList())).ToList()
            : [];
        return new NativeSwitchInfo(Rva("jump"), cases, Rva("default"), Rva("table"), Int("entry_size") ?? 0, Int("entries") ?? 0, Rva("index_table"), Int("index_entries"),
            s.TryGetProperty("bias", out var b) && b.ValueKind == JsonValueKind.Number ? b.GetInt64() : 0);
    }

    /// <summary>[from, to, kind, from function or null] rows.</summary>
    public static List<NativeXref> Xrefs(JsonElement r) =>
        r.EnumerateArray().Select(x => new NativeXref(x[0].GetUInt32(), x[1].GetUInt32(), XrefKind(x[2].GetString()),
            x[3].ValueKind == JsonValueKind.Number ? x[3].GetUInt32() : null)).ToList();

    private static NativeXrefKind XrefKind(string? kind) => kind switch
    {
        "call" => NativeXrefKind.Call,
        "jump" => NativeXrefKind.Jump,
        "code" => NativeXrefKind.Code,
        "read" => NativeXrefKind.Read,
        "write" => NativeXrefKind.Write,
        "offset" => NativeXrefKind.Offset,
        "text" => NativeXrefKind.Text,
        "info" => NativeXrefKind.Info,
        _ => NativeXrefKind.Data,
    };

    public static JsonArray NameItems(IReadOnlyList<NativeNameItem> items)
    {
        var rows = new JsonArray();
        foreach (var i in items)
            rows.Add(i.CommentKind == null ? new JsonArray(i.Rva, i.Name, i.Comment, i.MakeFunction ? 1 : 0) : new JsonArray(i.Rva, i.Name, i.Comment, i.MakeFunction ? 1 : 0, i.CommentKind));
        return rows;
    }

    public static NameBatchResult NameBatch(JsonElement r) =>
        new(r.GetProperty("named").GetInt32(), r.GetProperty("name_failures").GetInt32(), r.GetProperty("commented").GetInt32(),
            r.GetProperty("functions_created").GetInt32(), TimeSpan.FromSeconds(r.GetProperty("seconds").GetDouble()),
            r.GetProperty("failures").EnumerateArray().Select(f => f.GetString() ?? "").ToList());

    public static NativeTypeGuess TypeGuess(JsonElement r) =>
        new(Text(r.GetProperty("type")), Text(r.GetProperty("method")), r.GetProperty("confidence").GetString() ?? "none");

    /// <summary>[[rva, text]] rows of pseudo_comments.</summary>
    public static JsonObject PseudoCommentArgs(IReadOnlyList<(uint Rva, string Text)> items) =>
        Args(("items", new JsonArray(items.Select(i => (JsonNode)new JsonArray(i.Rva, i.Text)).ToArray())));

    /// <summary>Items [rva, applied, anchor rva or null, error or null].</summary>
    public static IReadOnlyList<PseudoCommentOutcome> PseudoComments(JsonElement r) =>
        r.GetProperty("items").EnumerateArray().Select(i => new PseudoCommentOutcome(i[0].GetUInt32(), i[1].GetBoolean(),
            i[2].ValueKind == JsonValueKind.Number ? i[2].GetUInt32() : null, Text(i[3]))).ToList();

    public static string? Stamp(JsonElement r) =>
        r.GetProperty("stamp").ValueKind == JsonValueKind.String ? r.GetProperty("stamp").GetString() : null;

    public static string? Text(JsonElement e) => e.ValueKind == JsonValueKind.String ? e.GetString() : null;

    /// <summary>[[rva, hex bytes]] rows of a patch sync.</summary>
    public static JsonArray ByteRanges(IReadOnlyList<NativeByteRange> wanted)
    {
        var rows = new JsonArray();
        foreach (var w in wanted) rows.Add(new JsonArray(w.Rva, Convert.ToHexString(w.Bytes)));
        return rows;
    }

    public static PatchSyncResult PatchSync(JsonElement r)
    {
        var problems = r.GetProperty("missing").EnumerateArray().Concat(r.GetProperty("mismatches").EnumerateArray()).Select(e => e.GetUInt32()).ToList();
        return new PatchSyncResult(r.GetProperty("patched").GetInt32(), r.GetProperty("reverted").GetInt32(), r.GetProperty("ranges").GetInt32(),
            r.GetProperty("functions").GetInt32(), r.GetProperty("missing_count").GetInt32(), r.GetProperty("mismatch_count").GetInt32(), problems,
            TimeSpan.FromSeconds(r.GetProperty("seconds").GetDouble()));
    }

    /// <summary>apply_types arguments: decls, prototypes [[rva, declaration]], classes {ptr, classes, methods}, stamp and save.</summary>
    public static JsonObject TypeBatchArgs(NativeTypeBatch batch, string? stampKey, string? stamp, bool save)
    {
        var prototypes = new JsonArray();
        foreach (var p in batch.Prototypes) prototypes.Add(new JsonArray(p.Rva, p.Declaration));
        JsonObject? classes = null;
        if (batch.Classes.Count > 0 || batch.Methods.Count > 0)
        {
            var list = new JsonArray();
            foreach (var c in batch.Classes)
            {
                var vftables = new JsonArray();
                foreach (var v in c.Vftables) vftables.Add(new JsonArray(v.Offset, v.Rva, new JsonArray(v.Slots.Select(s => (JsonNode)s).ToArray())));
                var bases = new JsonArray();
                foreach (var b in c.Bases) bases.Add(new JsonArray(b.Name, b.Offset));
                list.Add(new JsonObject { ["name"] = c.Name, ["vftables"] = vftables, ["bases"] = bases });
            }
            var methods = new JsonArray();
            foreach (var m in batch.Methods) methods.Add(new JsonArray(m.Rva, m.Class));
            classes = new JsonObject { ["ptr"] = batch.PointerSize, ["classes"] = list, ["methods"] = methods };
        }
        return Args(("decls", batch.Declarations), ("prototypes", prototypes), ("classes", classes), ("stamp_key", stampKey), ("stamp", stamp), ("save", save));
    }

    public static TypeBatchResult TypeBatch(JsonElement r) =>
        new(r.GetProperty("decl_errors").GetInt32(), r.GetProperty("typed").GetInt32(), r.GetProperty("type_failures").GetInt32(),
            r.GetProperty("structs").GetInt32(), r.GetProperty("vftables_typed").GetInt32(), r.GetProperty("methods_typed").GetInt32(),
            TimeSpan.FromSeconds(r.GetProperty("seconds").GetDouble()), r.GetProperty("failures").EnumerateArray().Select(f => f.GetString() ?? "").ToList(),
            r.TryGetProperty("method_skips", out var skips) ? skips.EnumerateObject().ToDictionary(p => p.Name, p => p.Value.GetInt32()) : new Dictionary<string, int>())
        {
            DeclarationMessages = r.TryGetProperty("decl_messages", out var m) ? [.. m.EnumerateArray().Select(x => x.GetString() ?? "")] : [],
        };

    /// <summary>[site, kind, target or type name, member offset] rows, plus decompiled / failed / skipped counts.</summary>
    public static NativeCallTargets CallTargets(JsonElement r)
    {
        var targets = new List<NativeCallTarget>();
        foreach (var row in r.GetProperty("rows").EnumerateArray())
        {
            uint site = row[0].GetUInt32();
            var kind = row[1].GetString() ?? "other";
            targets.Add(kind switch
            {
                "xref" or "direct" => new NativeCallTarget(site, kind, row[2].GetUInt32(), null, null),
                "vftable" => new NativeCallTarget(site, kind, null, row[2].GetString(), row[3].GetInt32()),
                _ => new NativeCallTarget(site, "other", null, row.GetArrayLength() > 2 ? row[2].GetString() : null, null),
            });
        }
        var failed = r.GetProperty("failed").EnumerateArray().Select(f => (f[0].GetUInt32(), f[1].GetString() ?? "")).ToList();
        var (partial, next) = Partial(r);
        return new NativeCallTargets(targets, r.GetProperty("decompiled").GetInt32(), failed, r.GetProperty("skipped").GetInt32(), r.GetProperty("decompiler").GetBoolean())
            { Partial = partial, Next = next };
    }

    /// <summary>apply_user_types arguments: decls, types, stack and locals always; enums, fields, analysis, stack_deletes, operands and type_edits when present.</summary>
    public static JsonObject UserTypeArgs(NativeUserTypeBatch batch, string? stampKey, string? stamp, bool save)
    {
        var types = new JsonArray();
        foreach (var t in batch.Types) types.Add(new JsonArray(t.Rva, t.Declaration));
        var stack = new JsonArray();
        var deletes = new JsonArray();
        var stackClears = new JsonArray();
        foreach (var s in batch.StackVars)
            if (s.Clear) stackClears.Add(s.FromReturn is { } c ? new JsonArray(s.Function, s.Offset, c) : new JsonArray(s.Function, s.Offset));
            else if (s.Delete) deletes.Add(s.FromReturn is { } d ? new JsonArray(s.Function, s.Offset, d) : new JsonArray(s.Function, s.Offset));
            else stack.Add(s.FromReturn is { } r ? new JsonArray(s.Function, s.Offset, s.Name, s.Type, r) : new JsonArray(s.Function, s.Offset, s.Name, s.Type));
        var locals = new JsonArray();
        var localClears = new JsonArray();
        foreach (var l in batch.Locals)
            if (l.Clear) localClears.Add(new JsonArray(l.Function, l.Local, l.Stack, l.Name));
            else if (l.Storage == null) locals.Add(new JsonArray(l.Function, l.Local, l.Stack, l.Name, l.Type));
            else locals.Add(new JsonArray(l.Function, l.Local, l.Stack, l.Name, l.Type, l.Storage));
        var args = Args(("decls", new JsonArray(batch.Declarations.Select(d => (JsonNode)d).ToArray())), ("types", types), ("stack", stack),
            ("locals", locals), ("stamp_key", stampKey), ("stamp", stamp), ("save", save));
        if (batch.EnumMembers.Count > 0)
            args["enums"] = new JsonArray(batch.EnumMembers.Select(e => (JsonNode)new JsonArray(e.Enum, e.Member, e.Value)).ToArray());
        if (batch.TypeEdits != null)
            args["type_edits"] = new JsonArray(batch.TypeEdits.Select(e => (JsonNode)new JsonArray(e.Name, e.NewName)).ToArray());
        if (batch.Fields.Count > 0)
            args["fields"] = new JsonArray(batch.Fields.Select(f => (JsonNode)(f.Op != null ? new JsonArray(f.Type, f.Name, f.Offset, f.FieldType, f.Op)
                : new JsonArray(f.Type, f.Name, f.Offset, f.FieldType))).ToArray());
        if (deletes.Count > 0) args["stack_deletes"] = deletes;
        if (localClears.Count > 0) args["local_clears"] = localClears;
        if (stackClears.Count > 0) args["stack_clears"] = stackClears;
        if (batch.Analysis.Count > 0)
            args["analysis"] = new JsonArray(batch.Analysis.Select(a => (JsonNode)new JsonArray(a.Rva, a.Kind, a.End, a.Type)).ToArray());
        if (batch.Operands.Count > 0)
            args["operands"] = new JsonArray(batch.Operands.Select(o => (JsonNode)new JsonArray(o.Rva, o.Operand, o.Display, o.Detail)).ToArray());
        return args;
    }

    /// <summary>Items [kind, rva, target, applied, error, resolved, stack, text] with the declaration outcome.</summary>
    public static UserTypeResult UserTypes(JsonElement r)
    {
        var items = r.GetProperty("items").EnumerateArray().Select(i => new NativeUserTypeOutcome(i[0].GetString() ?? "", i[1].GetUInt32(), i[2].GetString() ?? "",
            i[3].GetBoolean(), Text(i[4]), Text(i[5]), i[6].ValueKind == JsonValueKind.Number ? i[6].GetInt32() : null, Text(i[7]))).ToList();
        return new UserTypeResult(r.GetProperty("decl_errors").GetInt32(), r.GetProperty("decl_messages").EnumerateArray().Select(m => m.GetString() ?? "").ToList(),
            r.GetProperty("declared").EnumerateArray().Select(m => m.GetString() ?? "").ToList(), items, TimeSpan.FromSeconds(r.GetProperty("seconds").GetDouble()));
    }

    /// <summary>[name, kind, size, members] rows and the total.</summary>
    public static NativeTypeList TypeList(JsonElement r) =>
        new(r.GetProperty("total").GetInt32(), r.GetProperty("rows").EnumerateArray()
            .Select(x => new NativeTypeEntry(x[0].GetString() ?? "", x[1].GetString() ?? "", x[2].GetInt64(), x[3].GetInt32())).ToList());

    public static NativeTypeDetail TypeDetail(JsonElement r, string name) =>
        new(r.GetProperty("name").GetString() ?? name, r.GetProperty("kind").GetString() ?? "", r.GetProperty("size").GetInt64(),
            r.GetProperty("decl").GetString() ?? "", r.GetProperty("members").EnumerateArray()
                .Select(x => new NativeTypeMember(x[0].GetInt64(), x[1].GetString() ?? "", x[2].GetString() ?? "", x[3].GetInt64())).ToList());

    /// <summary>Frame members [offset, name, type, size, kind] and locals [name, type, location, stack, argument, user name, user type].</summary>
    public static NativeFrame Frame(JsonElement r)
    {
        var members = r.GetProperty("members").EnumerateArray()
            .Select(x => new NativeFrameMember(x[0].GetInt32(), x[1].GetString() ?? "", x[2].GetString() ?? "", x[3].GetInt32(), x[4].GetString() ?? "local")).ToList();
        var locals = r.GetProperty("locals").EnumerateArray()
            .Select(x => new NativeLocal(x[0].GetString() ?? "", x[1].GetString() ?? "", x[2].GetString() ?? "", x[3].ValueKind == JsonValueKind.Number ? x[3].GetInt32() : null,
                x[4].GetBoolean(), x[5].GetBoolean(), x[6].GetBoolean())).ToList();
        return new NativeFrame(r.GetProperty("start").GetUInt32(), r.GetProperty("name").GetString() ?? "", r.GetProperty("frame_size").GetInt32(),
            r.GetProperty("saved_regs").GetInt32(), r.GetProperty("retaddr").GetInt32(), members, locals, Text(r.GetProperty("decompile_error")));
    }

    public static PdbLoadResult PdbLoad(JsonElement r) =>
        new(r.GetProperty("loaded").GetBoolean(), r.GetProperty("from_analysis").GetBoolean(), r.GetProperty("plugin").GetBoolean(),
            r.GetProperty("types_before").GetInt32(), r.GetProperty("types_after").GetInt32(), TimeSpan.FromSeconds(r.GetProperty("seconds").GetDouble()));

    /// <summary>image_info reply; blocks are [name, start VA, size, permissions, initialized], changed may be null.</summary>
    public static EngineImageInfo ImageInfo(JsonElement r)
    {
        static string? S(JsonElement e, string name) => e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
        static int I(JsonElement e, string name) => e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number ? v.GetInt32() : 0;
        var blocks = r.TryGetProperty("blocks", out var b) && b.ValueKind == JsonValueKind.Array
            ? b.EnumerateArray().Select(x => new EngineMemoryBlock(x[0].GetString() ?? "", x[1].GetUInt64(), x[2].GetUInt64(), x[3].GetString() ?? "", x[4].GetBoolean())).ToList()
            : [];
        var entries = r.TryGetProperty("entry_points", out var ep) && ep.ValueKind == JsonValueKind.Array ? ep.EnumerateArray().Select(x => x.GetUInt32()).ToList() : [];
        bool? changed = r.TryGetProperty("changed", out var c) && c.ValueKind is JsonValueKind.True or JsonValueKind.False ? c.GetBoolean() : null;
        return new EngineImageInfo(S(r, "version") ?? "", S(r, "processor") ?? "", S(r, "language") ?? "", S(r, "compiler"), S(r, "format") ?? "", I(r, "pointer_size"),
            S(r, "endian") ?? "", I(r, "functions"), I(r, "external_functions"), entries, S(r, "md5"), S(r, "sha256"), blocks, changed, S(r, "analysis"));
    }

    /// <summary>defined_data: total and rows [rva, size, type, label or null, value or null, is string].</summary>
    public static EngineDataList DataList(JsonElement r) =>
        new(r.GetProperty("total").GetInt32(), r.GetProperty("rows").EnumerateArray()
            .Select(x => new EngineDataItem(x[0].GetUInt32(), x[1].GetInt64(), x[2].GetString() ?? "", Text(x[3]), Text(x[4]), x[5].GetBoolean())).ToList());

    /// <summary>function_info reply; ranges are [start, end], params [name, type, storage].</summary>
    public static EngineFunctionRecord FunctionRecord(JsonElement r)
    {
        static string? S(JsonElement e, string name) => e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
        static bool B(JsonElement e, string name) => e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.True;
        static int? I(JsonElement e, string name) => e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number ? v.GetInt32() : null;
        uint? thunk = r.TryGetProperty("thunk_target", out var t) && t.ValueKind == JsonValueKind.Number ? t.GetUInt32() : null;
        var ranges = r.GetProperty("ranges").EnumerateArray().Select(x => (x[0].GetUInt32(), x[1].GetUInt32())).ToList();
        var parameters = r.GetProperty("params").EnumerateArray().Select(x => new EngineParameter(x[0].GetString() ?? "", x[1].GetString() ?? "", x[2].GetString() ?? "")).ToList();
        return new EngineFunctionRecord(r.GetProperty("start").GetUInt32(), S(r, "name") ?? "", S(r, "namespace"), S(r, "prototype"), S(r, "convention"),
            S(r, "signature_source"), ranges, thunk, S(r, "thunk_name"), B(r, "external"), B(r, "noreturn"), B(r, "library"), I(r, "stack_purge"), parameters,
            S(r, "return_type"), S(r, "return_storage"), B(r, "varargs"));
    }

    /// <summary>field_xrefs: type, member, offset, size, member_type, rows [rva, kind, function or null], candidates, scanned, failed, skipped, decompiler.</summary>
    public static NativeFieldXrefs FieldXrefs(JsonElement r)
    {
        var rows = r.GetProperty("rows").EnumerateArray()
            .Select(x => new NativeFieldAccess(x[0].GetUInt32(), x[1].GetString() ?? "", x[2].ValueKind == JsonValueKind.Number ? x[2].GetUInt32() : null)).ToList();
        return new NativeFieldXrefs(r.GetProperty("type").GetString() ?? "", r.GetProperty("member").GetString() ?? "", r.GetProperty("offset").GetInt32(),
            r.GetProperty("size").GetInt32(), r.GetProperty("member_type").GetString() ?? "", rows, r.GetProperty("candidates").GetInt32(),
            r.GetProperty("scanned").GetInt32(), r.GetProperty("failed").GetInt32(), r.GetProperty("skipped").GetInt32(), r.GetProperty("decompiler").GetBoolean());
    }

    /// <summary>namespaces: rows [name, kind, functions, vftable rva or null].</summary>
    public static List<EngineNamespace> Namespaces(JsonElement r) =>
        r.GetProperty("rows").EnumerateArray().Select(x => new EngineNamespace(x[0].GetString() ?? "", x[1].GetString() ?? "", x[2].GetInt32(),
            x[3].ValueKind == JsonValueKind.Number ? x[3].GetUInt32() : null)).ToList();

    /// <summary>defined_strings: rows [rva, size, type, text].</summary>
    public static List<EngineString> Strings(JsonElement r) =>
        r.GetProperty("rows").EnumerateArray().Select(x => new EngineString(x[0].GetUInt32(), x[1].GetInt64(), x[2].GetString() ?? "", x[3].GetString() ?? "")).ToList();
}
