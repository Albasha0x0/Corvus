using System.Globalization;
using Microsoft.Diagnostics.Runtime;

namespace NetDecompilerMcp.Native.Dump.Managed;

/// <summary>One type's share of the heap.</summary>
public sealed record HeapTypeStat(string Type, long Count, ulong TotalSize, ClrType? ClrType);

/// <summary>One heap object; strings carry their (clipped) value.</summary>
public sealed record HeapObject(ulong Address, string Type, ulong Size, string? Value);

/// <summary>A field (or array element) of an object, flattened: nested fields of expanded references and structs carry a dotted path.</summary>
public sealed record ObjectField(string Path, int Depth, string? Type, int? Offset, string? Value, ulong? Address);

/// <summary>An object's contents: its fields, string value or array elements, bounded.</summary>
public sealed record ObjectView(ulong Address, ClrType Type, ulong Size, string? Value, int? Length, IReadOnlyList<ObjectField> Fields, bool Truncated);

/// <summary>Bounded reads of a CLR heap: statistics by type, matching objects, and one object's fields.</summary>
public static class ClrHeapView
{
    public const int MaxStringChars = 200;

    /// <summary>
    /// Walks up to <paramref name="maxObjects"/> objects, keeping those whose type matches <paramref name="type"/>
    /// (null: all) and whose size is at least <paramref name="minSize"/>. Returns per-type statistics, the matching
    /// objects in heap order from <paramref name="objectsFrom"/> (up to <paramref name="objectsTake"/>), the matched
    /// count, the walked count and whether the walk stopped early.
    /// </summary>
    public static (List<HeapTypeStat> Stats, List<HeapObject> Objects, long Matched, long Walked, bool Stopped) Walk(
        ClrHeap heap, string? type, ulong minSize, long maxObjects, int objectsFrom, int objectsTake, CancellationToken ct)
    {
        var stats = new Dictionary<ClrType, (long Count, ulong Size)>();
        var objects = new List<HeapObject>();
        long walked = 0, matched = 0;
        bool stopped = false;
        var matches = new Dictionary<ClrType, bool>();
        foreach (var o in heap.EnumerateObjects())
        {
            if (walked >= maxObjects) { stopped = true; break; }
            if ((++walked & 0xFFF) == 0) ct.ThrowIfCancellationRequested();
            var t = o.Type;
            if (t == null || !o.IsValid) continue;
            if (!matches.TryGetValue(t, out var ok)) matches[t] = ok = type == null || Matches(t.Name ?? "", type);
            if (!ok) continue;
            ulong size = o.Size;
            if (size < minSize) continue;
            var s = stats.GetValueOrDefault(t);
            stats[t] = (s.Count + 1, s.Size + size);
            if (matched >= objectsFrom && objects.Count < objectsTake)
                objects.Add(new HeapObject(o.Address, t.Name ?? "?", size, t.IsString ? Clip(o.AsString(MaxStringChars + 1)) : null));
            matched++;
        }
        var list = stats.Select(kv => new HeapTypeStat(kv.Key.Name ?? "?", kv.Value.Count, kv.Value.Size, kv.Key))
            .OrderByDescending(s => s.TotalSize).ThenBy(s => s.Type, StringComparer.Ordinal).ToList();
        return (list, objects, matched, walked, stopped);
    }

    /// <summary>
    /// The object at <paramref name="address"/>: fields (references expanded <paramref name="depth"/> levels, structs
    /// inline), a string's value, or an array's first <paramref name="maxArrayItems"/> elements. Null when no valid object is there.
    /// </summary>
    public static ObjectView? Object(ClrHeap heap, ulong address, int depth, int maxFields, int maxArrayItems)
    {
        var o = heap.GetObject(address);
        if (!o.IsValid || o.Type is not { } type) return null;
        var fields = new List<ObjectField>();
        bool truncated = false;
        string? value = null;
        int? length = null;
        if (type.IsString) value = Clip(o.AsString(MaxStringChars + 1));
        else if (type.IsArray)
        {
            var array = o.AsArray();
            length = array.Length;
            truncated = Elements(array, type, maxArrayItems, fields, maxFields);
        }
        else if (Boxed(o, type) is { } boxed) value = boxed;
        else truncated = Fields(type, o.Address, false, "", 1, depth, fields, maxFields);
        return new ObjectView(o.Address, type, o.Size, value, length, fields, truncated);
    }

    private static bool Fields(ClrType type, ulong at, bool interior, string prefix, int level, int depth, List<ObjectField> output, int maxFields)
    {
        foreach (var f in type.Fields)
        {
            if (output.Count >= maxFields) return true;
            string path = prefix + (f.Name ?? $"<field@{f.Offset}>");
            string? fieldType = f.Type?.Name;
            if (f.IsObjectReference)
            {
                var child = f.ReadObject(at, interior);
                if (child.IsNull) { output.Add(new(path, level, fieldType, f.Offset, "null", null)); continue; }
                var ct = child.Type;
                string? shown = ct is { IsString: true } ? Quote(child.AsString(MaxStringChars + 1)) : Boxed(child, ct) ?? (ct?.IsArray == true ? $"{ct.Name} (length {child.AsArray().Length})" : null);
                output.Add(new(path, level, ct?.Name ?? fieldType, f.Offset, shown, child.Address));
                if (level < depth && ct != null && !ct.IsString && !ct.IsArray && Boxed(child, ct) == null
                    && Fields(ct, child.Address, false, path + ".", level + 1, depth, output, maxFields)) return true;
            }
            else if (f.ElementType == ClrElementType.Struct && f.Type != null)
            {
                ulong inner = f.GetAddress(at, interior);
                output.Add(new(path, level, fieldType, f.Offset, null, inner));
                if (level <= depth && Fields(f.Type, inner, true, path + ".", level + 1, depth, output, maxFields)) return true;
            }
            else output.Add(new(path, level, fieldType ?? f.ElementType.ToString(), f.Offset, Primitive(f, at, interior), null));
        }
        return false;
    }

    private static bool Elements(ClrArray array, ClrType type, int maxItems, List<ObjectField> output, int maxFields)
    {
        int n = Math.Min(array.Length, maxItems);
        var element = type.ComponentType;
        for (int i = 0; i < n; i++)
        {
            if (output.Count >= maxFields) return true;
            string path = $"[{i}]";
            if (element == null || element.IsObjectReference)
            {
                var item = array.GetObjectValue(i);
                if (item.IsNull) { output.Add(new(path, 1, element?.Name, null, "null", null)); continue; }
                var it = item.Type;
                output.Add(new(path, 1, it?.Name, null, it is { IsString: true } ? Quote(item.AsString(MaxStringChars + 1)) : Boxed(item, it), item.Address));
            }
            else if (element.IsPrimitive) output.Add(new(path, 1, element.Name, null, ArrayPrimitive(array, element.ElementType, i), null));
            else output.Add(new(path, 1, element.Name, null, null, array.GetStructValue(i).Address));
        }
        return array.Length > n;
    }

    /// <summary>A boxed primitive's value (an int in an object field, say); null for anything else.</summary>
    private static string? Boxed(ClrObject o, ClrType? type)
    {
        if (type is not { IsPrimitive: true } || type.IsString) return null;
        var reader = type.Heap.Runtime.DataTarget.DataReader;
        ulong at = o.Address + (ulong)reader.PointerSize;
        return Read(reader, at, type.ElementType);
    }

    private static string? Primitive(ClrInstanceField f, ulong at, bool interior)
    {
        var reader = f.ContainingType.Heap.Runtime.DataTarget.DataReader;
        return Read(reader, f.GetAddress(at, interior), f.ElementType);
    }

    private static string? ArrayPrimitive(ClrArray array, ClrElementType element, int i) => element switch
    {
        ClrElementType.Boolean => array.GetValue<bool>(i) ? "true" : "false",
        ClrElementType.Char => Quote(array.GetValue<char>(i).ToString()),
        ClrElementType.Int8 => array.GetValue<sbyte>(i).ToString(CultureInfo.InvariantCulture),
        ClrElementType.UInt8 => array.GetValue<byte>(i).ToString(CultureInfo.InvariantCulture),
        ClrElementType.Int16 => array.GetValue<short>(i).ToString(CultureInfo.InvariantCulture),
        ClrElementType.UInt16 => array.GetValue<ushort>(i).ToString(CultureInfo.InvariantCulture),
        ClrElementType.Int32 => array.GetValue<int>(i).ToString(CultureInfo.InvariantCulture),
        ClrElementType.UInt32 => array.GetValue<uint>(i).ToString(CultureInfo.InvariantCulture),
        ClrElementType.Int64 => array.GetValue<long>(i).ToString(CultureInfo.InvariantCulture),
        ClrElementType.UInt64 => array.GetValue<ulong>(i).ToString(CultureInfo.InvariantCulture),
        ClrElementType.Float => array.GetValue<float>(i).ToString("R", CultureInfo.InvariantCulture),
        ClrElementType.Double => array.GetValue<double>(i).ToString("R", CultureInfo.InvariantCulture),
        ClrElementType.NativeInt or ClrElementType.Pointer or ClrElementType.FunctionPointer => $"0x{array.GetValue<nint>(i):X}",
        ClrElementType.NativeUInt => $"0x{array.GetValue<nuint>(i):X}",
        _ => null,
    };

    private static string? Read(IDataReader reader, ulong at, ClrElementType element)
    {
        Span<byte> b = stackalloc byte[8];
        int size = element switch
        {
            ClrElementType.Boolean or ClrElementType.Int8 or ClrElementType.UInt8 => 1,
            ClrElementType.Char or ClrElementType.Int16 or ClrElementType.UInt16 => 2,
            ClrElementType.Int32 or ClrElementType.UInt32 or ClrElementType.Float => 4,
            ClrElementType.Int64 or ClrElementType.UInt64 or ClrElementType.Double => 8,
            ClrElementType.NativeInt or ClrElementType.NativeUInt or ClrElementType.Pointer or ClrElementType.FunctionPointer => reader.PointerSize,
            _ => 0,
        };
        if (size == 0) return null;
        if (reader.Read(at, b[..size]) != size) return "(not captured)";
        ulong raw = System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(b);
        return element switch
        {
            ClrElementType.Boolean => raw != 0 ? "true" : "false",
            ClrElementType.Char => Quote(((char)raw).ToString()),
            ClrElementType.Int8 => ((sbyte)raw).ToString(CultureInfo.InvariantCulture),
            ClrElementType.Int16 => ((short)raw).ToString(CultureInfo.InvariantCulture),
            ClrElementType.Int32 => ((int)raw).ToString(CultureInfo.InvariantCulture),
            ClrElementType.Int64 => ((long)raw).ToString(CultureInfo.InvariantCulture),
            ClrElementType.Float => BitConverter.Int32BitsToSingle((int)raw).ToString("R", CultureInfo.InvariantCulture),
            ClrElementType.Double => BitConverter.Int64BitsToDouble((long)raw).ToString("R", CultureInfo.InvariantCulture),
            ClrElementType.NativeInt or ClrElementType.NativeUInt or ClrElementType.Pointer or ClrElementType.FunctionPointer => $"0x{raw:X}",
            _ => raw.ToString(CultureInfo.InvariantCulture),
        };
    }

    private static string? Clip(string? s) => s == null ? null : s.Length > MaxStringChars ? s[..MaxStringChars] + "..." : s;

    private static string? Quote(string? s) => s == null ? null : "\"" + Clip(s) + "\"";

    /// <summary>Case-insensitive match of a full type name: '*' and '?' wildcards, else the exact name.</summary>
    public static bool Matches(string name, string pattern)
    {
        int n = 0, p = 0, star = -1, mark = 0;
        while (n < name.Length)
        {
            if (p < pattern.Length && (pattern[p] == '?' || char.ToUpperInvariant(pattern[p]) == char.ToUpperInvariant(name[n]))) { n++; p++; }
            else if (p < pattern.Length && pattern[p] == '*') { star = p++; mark = n; }
            else if (star >= 0) { p = star + 1; n = ++mark; }
            else return false;
        }
        while (p < pattern.Length && pattern[p] == '*') p++;
        return p == pattern.Length;
    }
}
