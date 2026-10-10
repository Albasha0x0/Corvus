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

    /// <summary>[start, end, instructions, kind, successors, switch] rows under "blocks", plus "tail_calls".</summary>
    public static NativeBlockGraph Blocks(JsonElement r)
    {
        var blocks = r.GetProperty("blocks").EnumerateArray()
            .Select(b => new NativeBlockInfo(b[0].GetUInt32(), b[1].GetUInt32(), b[2].GetInt32(), b[3].GetString() ?? "normal",
                b[4].EnumerateArray().Select(s => s.GetUInt32()).ToList(), b[5].GetBoolean()))
            .ToList();
        return new NativeBlockGraph(r.GetProperty("start").GetUInt32(), r.GetProperty("name").GetString() ?? "", blocks,
            r.GetProperty("tail_calls").EnumerateArray().Select(t => t.GetUInt32()).ToList());
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
}
