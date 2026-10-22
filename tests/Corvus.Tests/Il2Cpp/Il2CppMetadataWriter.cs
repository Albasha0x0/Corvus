using System.Text;

namespace Corvus.Tests;

/// <summary>
/// Builds a version 29 global-metadata.dat with one image and assembly per entry and one type in the first image;
/// every other section is empty. The layout is the one Unity 2021.3 writes and LibCpp2IL reads as v29.
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
        var images = new MemoryStream();
        var assemblies = new MemoryStream();
        var iw = new BinaryWriter(images);
        var aw = new BinaryWriter(assemblies);
        for (int i = 0; i < _assemblies.Count; i++)
        {
            var (name, version, token) = _assemblies[i];
            // Image: name, assembly, first type, type count, exported types (start, count), entry point, token, attributes (start, count).
            foreach (var v in new[] { String(name + ".dll"), i, 0, i == 0 ? 1 : 0, -1, 0, -1, 1, 0, 0 }) iw.Write(v);
            // Assembly: image, token, referenced assemblies (start, count), then its name record.
            foreach (var v in new[] { i, 0x20000001, -1, 0 }) aw.Write(v);
            // Name: name, culture, public key, hash algorithm, hash length, flags, major, minor, build, revision, key token.
            foreach (var v in new[] { String(name), String(""), String(""), 0x8004, 0, 0, version.Major, version.Minor, Math.Max(0, version.Build), Math.Max(0, version.Revision) })
                aw.Write(v);
            aw.Write(token is { Length: 8 } ? BitConverter.ToUInt64(token) : 0UL);
        }
        var types = new MemoryStream();
        var tw = new BinaryWriter(types);
        // Type: name, namespace, byval, declaring, parent, element, generic container, flags, first field, method, event,
        // property, nested type, interfaces, vtable, interface offsets; then eight counts and the bitfield and token.
        foreach (var v in new[] { String("Program"), String(""), 0, -1, -1, -1, -1, 0x100001, -1, -1, -1, -1, -1, -1, -1, -1 }) tw.Write(v);
        for (int i = 0; i < 8; i++) tw.Write((ushort)0);
        tw.Write(0);
        tw.Write(0x02000002);

        var blobs = new Dictionary<string, byte[]> { ["string"] = strings.ToArray(), ["typeDefinitions"] = types.ToArray(), ["images"] = images.ToArray(), ["assemblies"] = assemblies.ToArray() };
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
