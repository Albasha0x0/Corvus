using System.Text.Json;
using System.Text.Json.Nodes;

namespace NetDecompilerMcp.Native.Providers;

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

    public static DecompiledFunction Decompiled(JsonElement r)
    {
        var lines = r.GetProperty("lines").EnumerateArray().Select(l => new PseudocodeLineAddress(l[0].GetInt32(), l[1].GetUInt32())).ToList();
        return new DecompiledFunction(r.GetProperty("start").GetUInt32(), r.GetProperty("name").GetString() ?? "", r.GetProperty("text").GetString() ?? "", lines);
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
            rows.Add(new JsonArray(i.Rva, i.Name, i.Comment, i.MakeFunction ? 1 : 0));
        return rows;
    }

    public static NameBatchResult NameBatch(JsonElement r) =>
        new(r.GetProperty("named").GetInt32(), r.GetProperty("name_failures").GetInt32(), r.GetProperty("commented").GetInt32(),
            r.GetProperty("functions_created").GetInt32(), TimeSpan.FromSeconds(r.GetProperty("seconds").GetDouble()),
            r.GetProperty("failures").EnumerateArray().Select(f => f.GetString() ?? "").ToList());

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
            r.TryGetProperty("method_skips", out var skips) ? skips.EnumerateObject().ToDictionary(p => p.Name, p => p.Value.GetInt32()) : new Dictionary<string, int>());

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
        return new NativeCallTargets(targets, r.GetProperty("decompiled").GetInt32(), failed, r.GetProperty("skipped").GetInt32(), r.GetProperty("decompiler").GetBoolean());
    }

    /// <summary>apply_user_types arguments: decls, types [[rva, declaration]], stack [[function, offset, name, type]], locals [[function, local, stack, name, type]].</summary>
    public static JsonObject UserTypeArgs(NativeUserTypeBatch batch, string? stampKey, string? stamp, bool save)
    {
        var types = new JsonArray();
        foreach (var t in batch.Types) types.Add(new JsonArray(t.Rva, t.Declaration));
        var stack = new JsonArray();
        foreach (var s in batch.StackVars) stack.Add(new JsonArray(s.Function, s.Offset, s.Name, s.Type));
        var locals = new JsonArray();
        foreach (var l in batch.Locals) locals.Add(new JsonArray(l.Function, l.Local, l.Stack, l.Name, l.Type));
        return Args(("decls", new JsonArray(batch.Declarations.Select(d => (JsonNode)d).ToArray())), ("types", types), ("stack", stack),
            ("locals", locals), ("stamp_key", stampKey), ("stamp", stamp), ("save", save));
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
}
