using System.Text;

namespace Corvus.Tests;

/// <summary>
/// Builds a version 29 global-metadata.dat with one image and assembly per entry and one type, Program, in the first
/// image, with the fields <see cref="Field"/> adds; each attribute a field names becomes a type of the first image with a
/// .ctor, and the field's attribute data names that constructor. Every other section is empty. The layout is the one
/// Unity 2021.3 writes and LibCpp2IL reads as v29.
/// </summary>
internal sealed class Il2CppMetadataWriter
{
    private const uint Magic = 0xFAB11BAF;
    private const int Version = 29;

    // Sections of the v29 header, in file order; each is an (offset, size) pair.
    private static readonly string[] Sections =
    [
        "stringLiteral", "stringLiteralData", "string", "events", "properties", "methods", "parameterDefaultValues", "fieldDefaultValues",
        "fieldAndParameterDefaultValueData", "fieldMarshaledSizes", "parameters", "fields", "genericParameters", "genericParameterConstraints",
        "genericContainers", "nestedTypes", "interfaces", "vtableMethods", "interfaceOffsets", "typeDefinitions", "images", "assemblies",
        "fieldRefs", "referencedAssemblies", "attributeData", "attributeDataRange", "unresolvedVirtualCallParameterTypes",
        "unresolvedVirtualCallParameterRanges", "windowsRuntimeTypeNames", "windowsRuntimeStrings", "exportedTypeDefinitions",
    ];

    private readonly List<(string Name, Version Version, byte[]? Token)> _assemblies = [];
    private readonly List<(string Name, string[] Attributes)> _fields = [];

    /// <summary>Adds a field to Program carrying custom attributes of the named types (full names).</summary>
    public Il2CppMetadataWriter Field(string name, params string[] attributes)
    {
        _fields.Add((name, attributes));
        return this;
    }

    /// <summary>Adds an assembly (and its image); <paramref name="token"/> is the 8-byte public key token or null.</summary>
    public Il2CppMetadataWriter Assembly(string name, string version, byte[]? token = null)
    {
        _assemblies.Add((name, new Version(version), token));
        return this;
    }

    public byte[] Build()
    {
        var strings = new MemoryStream();
        int String(string s)
        {
            int at = (int)strings.Length;
            strings.Write(Encoding.UTF8.GetBytes(s));
            strings.WriteByte(0);
            return at;
        }
        String("");
        var attributeTypes = _fields.SelectMany(f => f.Attributes).Distinct().ToList();
        var images = new MemoryStream();
        var assemblies = new MemoryStream();
        var iw = new BinaryWriter(images);
        var aw = new BinaryWriter(assemblies);
        for (int i = 0; i < _assemblies.Count; i++)
        {
            var (name, version, token) = _assemblies[i];
            // Image: name, assembly, first type, type count, exported types (start, count), entry point, token, attributes (start, count).
            int ranges = i == 0 ? _fields.Count(f => f.Attributes.Length > 0) : 0;
            foreach (var v in new[] { String(name + ".dll"), i, 0, i == 0 ? 1 + attributeTypes.Count : 0, -1, 0, -1, 1, 0, ranges }) iw.Write(v);
            // Assembly: image, token, referenced assemblies (start, count), then its name record.
            foreach (var v in new[] { i, 0x20000001, -1, 0 }) aw.Write(v);
            // Name: name, culture, public key, hash algorithm, hash length, flags, major, minor, build, revision, key token.
            foreach (var v in new[] { String(name), String(""), String(""), 0x8004, 0, 0, version.Major, version.Minor, Math.Max(0, version.Build), Math.Max(0, version.Revision) })
                aw.Write(v);
            aw.Write(token is { Length: 8 } ? BitConverter.ToUInt64(token) : 0UL);
        }
        var types = new MemoryStream();
        var tw = new BinaryWriter(types);
        void Type(string ns, string typeName, int firstField, int firstMethod, ushort methods, ushort fields, int token)
        {
            // Type: name, namespace, byval, declaring, parent, element, generic container, flags, first field, method, event,
            // property, nested type, interfaces, vtable, interface offsets; then eight counts and the bitfield and token.
            foreach (var v in new[] { String(typeName), String(ns), 0, -1, -1, -1, -1, 0x100001, firstField, firstMethod, -1, -1, -1, -1, -1, -1 }) tw.Write(v);
            foreach (var c in new ushort[] { methods, 0, fields, 0, 0, 0, 0, 0 }) tw.Write(c);
            tw.Write(0);
            tw.Write(token);
        }
        Type("", "Program", _fields.Count > 0 ? 0 : -1, -1, 0, (ushort)_fields.Count, 0x02000002);
        var methods = new MemoryStream();
        var mw = new BinaryWriter(methods);
        for (int a = 0; a < attributeTypes.Count; a++)
        {
            int dot = attributeTypes[a].LastIndexOf('.');
            Type(dot < 0 ? "" : attributeTypes[a][..dot], attributeTypes[a][(dot + 1)..], -1, a, 1, 0, 0x02000003 + a);
            // Method: name, declaring type, return type, parameter start, generic container, token; flags, iflags, slot, parameter count.
            foreach (var v in new[] { String(".ctor"), 1 + a, 0, -1, -1, 0x06000001 + a }) mw.Write(v);
            foreach (var v in new ushort[] { 0x1886, 0, 0xFFFF, 0 }) mw.Write(v);
        }
        var fieldDefs = new MemoryStream();
        var fw = new BinaryWriter(fieldDefs);
        var data = new MemoryStream();
        var dataRanges = new MemoryStream();
        var rw = new BinaryWriter(dataRanges);
        for (int f = 0; f < _fields.Count; f++)
        {
            // Field: name, type, token.
            foreach (var v in new[] { String(_fields[f].Name), 0, 0x04000001 + f }) fw.Write(v);
            if (_fields[f].Attributes.Length == 0) continue;
            // Attribute data: a compressed constructor count, then the constructor method indexes.
            rw.Write(0x04000001 + f);
            rw.Write((int)data.Length);
            data.WriteByte((byte)_fields[f].Attributes.Length);
            foreach (var a in _fields[f].Attributes) data.Write(BitConverter.GetBytes(attributeTypes.IndexOf(a)));
        }
        if (dataRanges.Length > 0)
        {
            rw.Write(0);
            rw.Write((int)data.Length);
        }

        var blobs = new Dictionary<string, byte[]>
        {
            ["string"] = strings.ToArray(), ["typeDefinitions"] = types.ToArray(), ["images"] = images.ToArray(), ["assemblies"] = assemblies.ToArray(),
            ["methods"] = methods.ToArray(), ["fields"] = fieldDefs.ToArray(), ["attributeData"] = data.ToArray(), ["attributeDataRange"] = dataRanges.ToArray(),
        };
        int header = 8 + Sections.Length * 8;
        var file = new MemoryStream();
        var w = new BinaryWriter(file);
        w.Write(Magic);
        w.Write(Version);
        // LibCpp2IL reads one record of an empty section too, so empty sections point at zeros after the data.
        int empty = header + blobs.Values.Sum(b => b.Length), offset = header;
        foreach (var s in Sections)
        {
            int size = blobs.TryGetValue(s, out var b) ? b.Length : 0;
            w.Write(size > 0 ? offset : empty);
            w.Write(size);
            offset += size;
        }
        foreach (var s in Sections)
            if (blobs.TryGetValue(s, out var b)) w.Write(b);
        w.Write(new byte[128]);
        return file.ToArray();
    }
}
