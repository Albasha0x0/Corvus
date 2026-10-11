using System.Buffers.Binary;
using NetDecompilerMcp.Native.ReadyToRun;

namespace NetDecompilerMcp.Native.NativeAot;

/// <summary>A method body named by NativeAOT metadata. Origin: "stacktrace" (stack-trace map) or "invoke" (reflection invoke map).</summary>
public sealed record NativeAotMethod(uint Rva, NativeAotMethodName Name, string Origin, bool Hidden = false);

/// <summary>A MethodTable named by the reflection type map.</summary>
public sealed record NativeAotTypeName(uint MethodTableRva, string Name);

/// <summary>
/// The name-bearing tables of a NativeAOT module: the stack-trace method map (blob 27; .NET 7 token pairs, .NET 8+
/// command stream, StackTraceMetadata.cs), the reflection TypeMap (blob 1) and InvokeMap (blob 6, ReflectionInvokeMapNode.cs),
/// both resolving MethodTables and entry points through the CommonFixupsTable (blob 8, ExternalReferencesTableNode.cs).
/// </summary>
public sealed class NativeAotNameMaps
{
    private const int MaxEntries = 4_000_000;
    private const uint InvokeHasMetadataHandle = 0x4, InvokeHasEntrypoint = 0x20;

    private NativeAotNameMaps() { }

    /// <summary>Every named body; folded bodies give several entries at one RVA.</summary>
    public IReadOnlyList<NativeAotMethod> Methods { get; private set; } = [];
    /// <summary>One name per code RVA: stack-trace names before invoke-map names, then ordinal by name.</summary>
    public IReadOnlyDictionary<uint, NativeAotMethod> MethodAt { get; private set; } = new Dictionary<uint, NativeAotMethod>();
    /// <summary>MethodTable RVA → type name, from the TypeMap.</summary>
    public IReadOnlyDictionary<uint, string> TypeNames { get; private set; } = new Dictionary<uint, string>();
    /// <summary>Targets of the CommonFixupsTable (MethodTables, entry points), by index; 0 where unreadable.</summary>
    public IReadOnlyList<uint> CommonFixups { get; private set; } = [];
    public IReadOnlyList<NativeAotStage> Stages { get; private set; } = [];

    public static NativeAotNameMaps Read(NativeAotImage aot, CancellationToken ct = default)
    {
        var maps = new NativeAotNameMaps();
        var stages = new List<NativeAotStage>();
        var methods = new List<NativeAotMethod>();
        var md = aot.Metadata;
        maps.CommonFixups = ReadFixups(aot);

        stages.Add(Guard("stack-trace map", () => StackTrace(aot, md, methods, ct)));
        var types = new Dictionary<uint, string>();
        stages.Add(Guard("type map", () => TypeMap(aot, md, maps.CommonFixups, types, ct)));
        maps.TypeNames = types;
        stages.Add(Guard("invoke map", () => InvokeMap(aot, md, maps.CommonFixups, types, methods, ct)));

        maps.Methods = methods;
        maps.MethodAt = methods
            .GroupBy(m => m.Rva)
            .ToDictionary(g => g.Key, g => g.OrderBy(m => m.Origin == "stacktrace" ? 0 : 1).ThenBy(m => m.Name.Full, StringComparer.Ordinal).First());
        maps.Stages = stages;
        return maps;
    }

    private static NativeAotStage Guard(string name, Func<NativeAotStage> stage)
    {
        try { return stage(); }
        catch (Exception ex) when (ex is NativeAotFormatException or R2RFormatException)
        {
            return new NativeAotStage(name, NativeAotStage.Partial, ex.Message);
        }
    }

    private static List<uint> ReadFixups(NativeAotImage aot)
    {
        var fixups = new List<uint>();
        var blob = aot.Header.Blob(BlobId.CommonFixupsTable);
        if (aot.ReadSection(blob) is not { } bytes) return fixups;
        bool relative = aot.Image.Is64Bit; // relative pointers on 64-bit targets, absolute addresses on 32-bit ones
        for (int i = 0; i + 4 <= bytes.Length; i += 4)
        {
            int value = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(i));
            long target = relative ? blob!.StartRva + (long)i + value : (long)(uint)value - (long)aot.Image.ImageBase;
            fixups.Add(target > 0 && target < aot.Image.SizeOfImage ? (uint)target : 0);
        }
        return fixups;
    }

    private static NativeAotStage StackTrace(NativeAotImage aot, NativeAotMetadata? md, List<NativeAotMethod> methods, CancellationToken ct)
    {
        const string name = "stack-trace map";
        var blob = aot.Header.Blob(BlobId.StackTraceMethodRvaToTokenMapping);
        if (blob == null || blob.Length <= 4) return new(name, NativeAotStage.Absent, "empty: built with StackTraceSupport=false");
        if (md == null) return new(name, NativeAotStage.Unsupported, "no readable metadata to resolve the names");
        var view = aot.Hydrated.View;
        int before = methods.Count, hidden = 0;
        if (aot.Format.StackTrace == StackTraceFormat.Pairs)
        {
            for (uint at = blob.StartRva; at + 8 <= blob.EndRva; at += 8)
            {
                if ((at & 0xFFFF) == 0) ct.ThrowIfCancellationRequested();
                methods.Add(new NativeAotMethod(Relative(view, at), md.FormatMethod(md.FromToken(view.U32(at + 4))), "stacktrace"));
            }
            return new(name, NativeAotStage.Complete, $"{methods.Count - before} methods named (.NET 7 token pairs)");
        }

        uint declared = view.U32(blob.StartRva);
        if (declared > MaxEntries) throw new NativeAotFormatException($"stack-trace map declares {declared} entries");
        string owner = "?", method = "?";
        string? signature = null, instantiation = null;
        bool? hasThis = null;
        uint p = blob.StartRva + 4;
        int read = 0, unnamed = 0;
        while (p < blob.EndRva && read < declared)
        {
            if ((read & 0x3FFF) == 0) ct.ThrowIfCancellationRequested();
            byte command = view.U8(p++);
            if ((command & 0x01) != 0)
            {
                owner = md.FormatType(md.FromToken(view.U32(p)));
                p += 4;
            }
            if ((command & 0x02) != 0)
            {
                p = NativeFormat.DecodeUnsigned(view, p, out uint nameOffset);
                method = md.String(nameOffset) ?? "?";
            }
            if ((command & 0x04) != 0)
            {
                p = NativeFormat.DecodeUnsigned(view, p, out uint sig);
                signature = md.FormatSignature(sig);
                hasThis = md.HasThis(sig);
                instantiation = null;
            }
            if ((command & 0x08) != 0)
            {
                p = NativeFormat.DecodeUnsigned(view, p, out uint sig);
                p = NativeFormat.DecodeUnsigned(view, p, out uint args);
                signature = md.FormatSignature(sig);
                hasThis = md.HasThis(sig);
                instantiation = $"<{string.Join(", ", md.StringArray(args))}>";
            }
            bool isHidden = (command & 0x10) != 0;
            if (isHidden) hidden++;
            uint code = Relative(view, p);
            p += 4;
            read++;
            // Hidden startup wrappers may precede the first owner and name: nothing to name them with.
            if (method == "?") { unnamed++; continue; }
            methods.Add(new NativeAotMethod(code, new NativeAotMethodName(owner, method, signature, instantiation) { HasThis = hasThis }, "stacktrace", isHidden));
        }
        string detail = $"{read - unnamed} methods named ({hidden} hidden from stack traces" + (unnamed > 0 ? $", {unnamed} without a name" : "") + ")";
        return read == declared
            ? new(name, NativeAotStage.Complete, detail)
            : new(name, NativeAotStage.Partial, $"{detail}; {read} of {declared} declared entries read");
    }

    /// <summary>The target of the relptr32 at <paramref name="at"/>.</summary>
    private static uint Relative(ImageView view, uint at)
    {
        long target = at + (long)(int)view.U32(at);
        return target is > 0 and <= uint.MaxValue ? (uint)target : throw new NativeAotFormatException($"relative pointer at RVA 0x{at:X} leaves the image");
    }

    private static NativeAotStage TypeMap(NativeAotImage aot, NativeAotMetadata? md, IReadOnlyList<uint> fixups, Dictionary<uint, string> types, CancellationToken ct)
    {
        const string name = "type map";
        var blob = aot.Header.Blob(BlobId.TypeMap);
        if (blob == null) return new(name, NativeAotStage.Absent, "no TypeMap blob");
        if (md == null) return new(name, NativeAotStage.Unsupported, "no readable metadata to resolve the names");
        var view = aot.Hydrated.View;
        int unresolved = 0;
        foreach (uint entry in NativeFormat.HashtableEntries(view, blob.StartRva, blob.EndRva, MaxEntries))
        {
            ct.ThrowIfCancellationRequested();
            uint at = NativeFormat.DecodeUnsigned(view, entry, out uint index);
            NativeFormat.DecodeUnsigned(view, at, out uint token);
            uint mt = index < fixups.Count ? fixups[(int)index] : 0;
            if (mt == 0) { unresolved++; continue; }
            types[mt] = md.FormatType(md.FromToken(token));
        }
        return new(name, unresolved == 0 ? NativeAotStage.Complete : NativeAotStage.Partial,
            $"{types.Count} MethodTables named" + (unresolved > 0 ? $", {unresolved} entries with unresolved fixups" : ""));
    }

    private static NativeAotStage InvokeMap(NativeAotImage aot, NativeAotMetadata? md, IReadOnlyList<uint> fixups, Dictionary<uint, string> types,
        List<NativeAotMethod> methods, CancellationToken ct)
    {
        const string name = "invoke map";
        var blob = aot.Header.Blob(BlobId.InvokeMap);
        if (blob == null) return new(name, NativeAotStage.Absent, "no InvokeMap blob");
        if (md == null) return new(name, NativeAotStage.Unsupported, "no readable metadata to resolve the names");
        var view = aot.Hydrated.View;
        int entries = 0, named = 0, withoutHandle = 0;
        foreach (uint entry in NativeFormat.HashtableEntries(view, blob.StartRva, blob.EndRva, MaxEntries))
        {
            ct.ThrowIfCancellationRequested();
            entries++;
            uint at = NativeFormat.DecodeUnsigned(view, entry, out uint flags);
            at = NativeFormat.DecodeUnsigned(view, at, out uint handle);
            at = NativeFormat.DecodeUnsigned(view, at, out uint owningType);
            if ((flags & InvokeHasEntrypoint) == 0) continue;
            NativeFormat.DecodeUnsigned(view, at, out uint entryIndex);
            uint code = entryIndex < fixups.Count ? fixups[(int)entryIndex] : 0;
            if (code == 0) continue;
            // Before .NET 10 an entry without HasMetadataHandle holds a native-layout name-and-signature instead.
            if (!aot.Format.InvokeMapAlwaysHasMethodHandle && (flags & InvokeHasMetadataHandle) == 0) { withoutHandle++; continue; }
            var methodName = md.FormatMethod(new MdHandle(MdRecord.Method, handle));
            if (methodName.Owner == "?" && owningType < fixups.Count && types.TryGetValue(fixups[(int)owningType], out var owner))
                methodName = methodName with { Owner = owner };
            methods.Add(new NativeAotMethod(code, methodName, "invoke"));
            named++;
        }
        return new(name, NativeAotStage.Complete,
            $"{named} methods with entry points named of {entries} entries" + (withoutHandle > 0 ? $"; {withoutHandle} without a metadata handle" : ""));
    }
}
