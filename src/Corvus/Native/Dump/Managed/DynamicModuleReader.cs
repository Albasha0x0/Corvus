using Microsoft.Diagnostics.Runtime;

namespace Corvus.Native.Dump.Managed;

/// <summary>
/// One method's IL body and its source ("runtime" or "method_builder"); <see cref="Unknown"/>
/// names why the code could not be read, null when it was.
/// </summary>
public sealed record DynamicMethodBody(
    uint Token, string Type, string Name, ulong IlAddress, int CodeSize, uint LocalSignatureToken, uint Flags, byte[]? Code, string? Unknown,
    string? Source = null, byte[]? LocalSignature = null);

/// <summary>A dynamic module's metadata and method bodies; <see cref="MetadataUnknown"/> is the reason the metadata is unreadable, else null.</summary>
public sealed record DynamicModuleRead(byte[]? Metadata, string? MetadataUnknown, IReadOnlyList<DynamicMethodBody> Methods);

/// <summary>Reads the metadata and IL method bodies the runtime keeps for a dynamic module.</summary>
public static class DynamicModuleReader
{
    // Largest metadata image read; the runtime reports its length as 32 bits.
    private const uint MaxMetadata = 256u << 20;

    // Largest single method body read.
    private const int MaxBody = 64 << 20;

    private const string BuilderType = "System.Reflection.Emit.RuntimeMethodBuilder";

    private sealed record Builder(uint Token, string Name, byte[]? Code, byte[]? Locals);

    /// <summary>The module's metadata bytes and per-method bodies; unreadable parts carry a reason, never an empty success.</summary>
    public static DynamicModuleRead Read(ClrModule module, ClrRuntime runtime) =>
        Read(module, runtime, (address, buffer) => runtime.DataTarget.DataReader.Read(address, buffer));

    /// <summary>As <see cref="Read(ClrModule, ClrRuntime)"/>, reading memory through <paramref name="read"/> (address, buffer, bytes read).</summary>
    public static DynamicModuleRead Read(ClrModule module, ClrRuntime runtime, Func<ulong, byte[], int> read)
    {
        var (metadata, reason) = Metadata(module, read);
        var methods = new List<DynamicMethodBody>();
        IReadOnlyList<Builder>? builders = null;
        string? builderReason = null;
        bool scanned = false;
        try
        {
            foreach (var (mt, _) in module.EnumerateTypeDefToMethodTableMap())
            {
                var type = runtime.GetTypeByMethodTable(mt);
                if (type == null) continue;
                foreach (var method in type.Methods)
                {
                    var body = Body(type, method, read);
                    if (body.Code == null)
                    {
                        // Reflection emit keeps IL in managed builders, not in
                        // the IL table.
                        if (!scanned) { (builders, builderReason) = MethodBuilders(runtime); scanned = true; }
                        body = FromBuilder(body, builders, builderReason);
                    }
                    methods.Add(body);
                }
            }
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or ArgumentException)
        {
            methods.Add(new DynamicMethodBody(0, "", "", 0, 0, 0, 0, null, "type_enumeration_failed: " + ex.Message));
        }
        return new DynamicModuleRead(metadata, reason, methods);
    }

    private static (byte[]?, string?) Metadata(ClrModule module, Func<ulong, byte[], int> read)
    {
        if (module.MetadataAddress == 0 || module.MetadataLength == 0)
            return (null, "metadata_unknown: the runtime keeps no flat metadata image for a dynamic module (reflection emit holds it in an in-process emitter)");
        if (module.MetadataLength > MaxMetadata)
            return (null, $"metadata_too_large: {module.MetadataLength} bytes exceeds the {MaxMetadata}-byte limit");
        var bytes = new byte[module.MetadataLength];
        int got = read(module.MetadataAddress, bytes);
        return got == bytes.Length ? (bytes, null)
            : (null, $"metadata_not_captured: {got} of {bytes.Length} bytes at 0x{module.MetadataAddress:x} are in the dump");
    }

    private static DynamicMethodBody Body(ClrType type, ClrMethod method, Func<ulong, byte[], int> read)
    {
        string owner = type.Name ?? "?", name = method.Name ?? "?";
        uint token = (uint)method.MetadataToken;
        ILInfo? info;
        try { info = method.GetILInfo(); }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or ArgumentException)
        {
            return new DynamicMethodBody(token, owner, name, 0, 0, 0, 0, null, "il_unknown: " + ex.Message);
        }
        if (info == null || info.Address == 0)
            return new DynamicMethodBody(token, owner, name, 0, 0, 0, 0, null, "il_unknown: the runtime reports no IL for the method");
        if (info.Length <= 0 || info.Length > MaxBody)
            return Fail($"il_length_unknown: the runtime reports a code size of {info.Length}");
        var code = new byte[info.Length];
        int got = read(info.Address, code);
        return got == code.Length
            ? new DynamicMethodBody(token, owner, name, info.Address, info.Length, info.LocalVarSignatureToken, info.Flags, code, null, "runtime")
            : Fail($"il_not_captured: {got} of {code.Length} bytes at 0x{info.Address:x} are in the dump");

        DynamicMethodBody Fail(string why) =>
            new(token, owner, name, info.Address, Math.Max(info.Length, 0), info.LocalVarSignatureToken, info.Flags, null, why);
    }

    private static (IReadOnlyList<Builder>?, string?) MethodBuilders(ClrRuntime runtime)
    {
        var heap = runtime.Heap;
        if (!heap.CanWalkHeap) return (null, "heap_not_walkable: the runtime reports the heap in an inconsistent state");
        var found = new List<Builder>();
        try
        {
            foreach (var obj in heap.EnumerateObjects())
            {
                if (obj.Type?.Name != BuilderType) continue;
                var code = Bytes(obj.ReadObjectField("m_ubBody"), null);
                if (code == null && obj.ReadObjectField("m_ilGenerator") is { IsNull: false } generator)
                    code = Bytes(generator.ReadObjectField("m_ILStream"), generator.ReadField<int>("m_length"));
                found.Add(new Builder((uint)obj.ReadField<int>("m_token"), obj.ReadStringField("m_strName") ?? "", code,
                    Bytes(obj.ReadObjectField("m_localSignature"), null)));
            }
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or ArgumentException)
        {
            return (null, "heap_unreadable: " + ex.Message);
        }
        return (found, null);
    }

    private static byte[]? Bytes(ClrObject array, int? length)
    {
        if (array.IsNull || !array.IsArray) return null;
        var items = array.AsArray();
        int count = Math.Min(items.Length, length ?? items.Length);
        return count <= 0 || count > MaxBody ? null : items.ReadValues<byte>(0, count);
    }

    private static DynamicMethodBody FromBuilder(DynamicMethodBody body, IReadOnlyList<Builder>? builders, string? reason)
    {
        if (builders == null) return body with { Unknown = body.Unknown + "; " + reason };
        var match = builders.FirstOrDefault(b => b.Token == body.Token && b.Name == body.Name && b.Code != null);
        return match?.Code is not { } code
            ? body with { Unknown = body.Unknown + "; builder_unknown: no method builder in the heap holds IL for this token and name" }
            : body with { CodeSize = code.Length, Code = code, Unknown = null, Source = "method_builder", LocalSignature = match.Locals };
    }
}
