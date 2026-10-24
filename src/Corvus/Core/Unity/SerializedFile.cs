using System.Buffers.Binary;
using System.Text;

namespace Corvus.Core.Unity;

/// <summary>One node of a type tree, in depth-first order: the type and field name, its depth, size (-1 when variable) and flags.</summary>
public sealed record UnityTypeNode(string Type, string Name, int Level, int ByteSize, bool IsArray, int MetaFlag)
{
    /// <summary>The meta flag of an integer the engine shows as a boolean (kTreatIntegerValueAsBoolean).</summary>
    public const int BooleanFlag = 0x100;

    /// <summary>The data is aligned to 4 bytes after this node (kAlignBytes).</summary>
    public bool Align => (MetaFlag & 0x4000) != 0;
}

/// <summary>A type of a serialized file: the class id, the script type index for a MonoBehaviour, and its type tree when the file keeps one.</summary>
public sealed record UnityType(int ClassId, int ScriptTypeIndex, IReadOnlyList<UnityTypeNode>? Tree);

/// <summary>An object of a serialized file: its path id, data range in the file, and type.</summary>
public sealed record UnityObject(long PathId, long Start, long Size, int ClassId, UnityType? Type);

/// <summary>A file a serialized file refers to by index (file id 1 is the first).</summary>
public sealed record UnityExternal(string Path, Guid Guid);

/// <summary>
/// A Unity serialized file (formats 9 to 22 and later, either byte order): engine version, target platform, types with
/// their type trees when the file keeps them, the object table, script types and externals. Damaged tables end the read
/// with an issue; what was read before is kept.
/// </summary>
public sealed class SerializedFile
{
    public const int ClassMonoBehaviour = 114, ClassMonoScript = 115, ClassGameObject = 1, ClassTextAsset = 49;
    private const int MaxTypes = 100_000, MaxObjects = 10_000_000, MaxNodes = 100_000;

    public string Name { get; }
    public int Format { get; private set; }
    public string? UnityVersion { get; private set; }
    public int Platform { get; private set; }
    public bool BigEndian { get; private set; }
    public bool HasTypeTrees { get; private set; }
    public IReadOnlyList<UnityType> Types => _types;
    public IReadOnlyList<UnityObject> Objects => _objects;
    public IReadOnlyList<UnityExternal> Externals => _externals;
    public IReadOnlyList<string> Issues => _issues;

    private readonly byte[] _d;
    private readonly List<UnityType> _types = [];
    private readonly List<UnityObject> _objects = [];
    private readonly List<UnityExternal> _externals = [];
    private readonly List<string> _issues = [];
    private Dictionary<long, UnityObject>? _byPath;

    private SerializedFile(byte[] data, string name)
    {
        _d = data;
        Name = name;
    }

    /// <summary>
    /// Whether <paramref name="head"/> starts like a serialized file: a plausible format, sizes that fit and a data offset
    /// past the header. Unity files have no magic number, so this is a consistency check.
    /// </summary>
    public static bool IsSerializedFile(ReadOnlySpan<byte> head, long fileLength)
    {
        if (head.Length < 48) return false;
        uint format = BinaryPrimitives.ReadUInt32BigEndian(head[8..]);
        if (format is < 9 or > 50) return false;
        long size, dataOffset;
        if (format >= 22)
        {
            size = BinaryPrimitives.ReadInt64BigEndian(head[24..]);
            dataOffset = BinaryPrimitives.ReadInt64BigEndian(head[32..]);
        }
        else
        {
            size = BinaryPrimitives.ReadUInt32BigEndian(head[4..]);
            dataOffset = BinaryPrimitives.ReadUInt32BigEndian(head[12..]);
        }
        return size == fileLength && dataOffset > 20 && dataOffset <= fileLength && head[format >= 22 ? 16 : 16] is 0 or 1;
    }

    /// <summary>The engine version string of a serialized file's header, or null when the header has none.</summary>
    public static string? VersionOf(ReadOnlySpan<byte> head)
    {
        if (head.Length < 24) return null;
        uint format = BinaryPrimitives.ReadUInt32BigEndian(head[8..]);
        int at = format is >= 9 and < 22 ? 20 : format is >= 22 and < 100 ? 48 : -1;
        if (at < 0 || at >= head.Length) return null;
        int zero = head[at..].IndexOf((byte)0);
        return zero > 0 ? Encoding.ASCII.GetString(head.Slice(at, zero)) : null;
    }

    /// <summary>Reads the header and metadata of <paramref name="data"/>; never throws for damaged input.</summary>
    public static SerializedFile Read(byte[] data, string name)
    {
        var f = new SerializedFile(data, name);
        try
        {
            f.ReadMetadata();
        }
        catch (InvalidDataException e)
        {
            f._issues.Add(e.Message);
        }
        return f;
    }

    /// <summary>
    /// True when the file's head is a serialized file or a UnityFS bundle, its size checked against <paramref name="length"/>
    /// (the whole of a split file) or the file's own; false for any other or unreadable file.
    /// </summary>
    public static bool IsAssetFile(string path, long? length = null)
    {
        try
        {
            if (!File.Exists(path)) return false;
            var head = new byte[64];
            length ??= new FileInfo(path).Length;
            using (var s = File.OpenRead(path)) s.ReadAtLeast(head, head.Length, throwOnEndOfStream: false);
            return UnityFsBundle.IsBundle(head) || IsSerializedFile(head, length.Value);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return false; }
    }

    /// <summary>The object with this path id, or null.</summary>
    public UnityObject? Find(long pathId)
    {
        _byPath ??= _objects.GroupBy(o => o.PathId).ToDictionary(g => g.Key, g => g.First());
        return _byPath.GetValueOrDefault(pathId);
    }

    /// <summary>A reader over one object's data, in the file's byte order; null when its range is outside the file.</summary>
    internal UnityBinary? Data(UnityObject o) =>
        o.Start >= 0 && o.Size >= 0 && o.Start + o.Size <= _d.Length ? new UnityBinary(_d, (int)o.Start, (int)(o.Start + o.Size), BigEndian) : null;

    private void ReadMetadata()
    {
        var r = new UnityBinary(_d, true);
        r.Skip(8);
        Format = r.I32();
        if (Format is < 9 or > 50) throw new InvalidDataException($"format {Format} is not a serialized file format this reader knows (9-50)");
        long dataOffset = r.U32();
        BigEndian = r.U8() != 0;
        r.Skip(3);
        if (Format >= 22)
        {
            r.Skip(4 + 8);
            dataOffset = r.I64();
            r.Skip(8);
        }
        r.BigEndian = BigEndian;
        UnityVersion = r.CString(64);
        Platform = r.I32();
        HasTypeTrees = Format < 13 || r.Bool();
        int typeCount = Count(r.I32(), MaxTypes, "types");
        for (int i = 0; i < typeCount; i++) _types.Add(ReadType(r, reference: false));
        bool bigIds = Format is >= 7 and < 14 && r.I32() != 0;
        int objectCount = Count(r.I32(), MaxObjects, "objects");
        for (int i = 0; i < objectCount; i++)
        {
            long pathId;
            if (bigIds) pathId = r.I64();
            else if (Format < 14) pathId = r.I32();
            else
            {
                r.Align();
                pathId = r.I64();
            }
            long start = (Format >= 22 ? r.I64() : r.U32()) + dataOffset;
            long size = r.U32();
            int typeId = r.I32();
            int classId;
            UnityType? type = null;
            if (Format < 16)
            {
                classId = r.U16();
                type = _types.FirstOrDefault(t => t.ClassId == typeId);
            }
            else
            {
                type = (uint)typeId < (uint)_types.Count ? _types[typeId] : null;
                classId = type?.ClassId ?? -1;
            }
            if (Format < 11) r.Skip(2);
            if (Format is >= 11 and < 17)
            {
                int scriptIndex = r.I16();
                if (type != null && type.ScriptTypeIndex < 0) type = type with { ScriptTypeIndex = scriptIndex };
            }
            if (Format is 15 or 16) r.Skip(1);
            _objects.Add(new UnityObject(pathId, start, size, classId, type));
        }
        if (Format >= 11)
        {
            int scripts = Count(r.I32(), MaxObjects, "script types");
            for (int i = 0; i < scripts; i++)
            {
                r.Skip(4);
                if (Format < 14) r.Skip(4);
                else
                {
                    r.Align();
                    r.Skip(8);
                }
            }
        }
        int externals = Count(r.I32(), MaxTypes, "externals");
        for (int i = 0; i < externals; i++)
        {
            if (Format >= 6) r.CString();
            var guid = Format >= 5 ? new Guid(r.Bytes(16)) : Guid.Empty;
            if (Format >= 5) r.Skip(4);
            _externals.Add(new UnityExternal(r.CString(), guid));
        }
    }

    private static int Count(int n, int max, string what) =>
        n >= 0 && n <= max ? n : throw new InvalidDataException($"{n} {what} is outside 0-{max}");

    private UnityType ReadType(UnityBinary r, bool reference)
    {
        int classId = r.I32();
        if (Format >= 16) r.Skip(1);
        int scriptIndex = Format >= 17 ? r.I16() : -1;
        if (Format >= 13 && (reference && scriptIndex >= 0 || Format < 16 && classId < 0 || Format >= 16 && classId == ClassMonoBehaviour)) r.Skip(16);
        if (Format >= 13) r.Skip(16);
        List<UnityTypeNode>? tree = null;
        if (HasTypeTrees)
        {
            tree = Format >= 12 || Format == 10 ? ReadBlobTree(r) : ReadOldTree(r);
            if (Format >= 21)
            {
                if (reference)
                {
                    r.CString();
                    r.CString();
                    r.CString();
                }
                else r.Skip(4 * Count(r.I32(), MaxNodes, "type dependencies"));
            }
        }
        return new UnityType(classId, scriptIndex, tree);
    }

    private List<UnityTypeNode> ReadBlobTree(UnityBinary r)
    {
        int nodes = Count(r.I32(), MaxNodes, "type tree nodes");
        int stringSize = Count(r.I32(), 1 << 24, "type tree string bytes");
        int nodeSize = Format >= 19 ? 32 : 24;
        var raw = new (int Level, bool Array, uint Type, uint Name, int Size, int Flags)[nodes];
        for (int i = 0; i < nodes; i++)
        {
            r.Skip(2);
            int level = r.U8();
            bool array = (r.U8() & 1) != 0;
            uint type = r.U32(), name = r.U32();
            int size = r.I32();
            r.Skip(4);
            int flags = r.I32();
            if (nodeSize == 32) r.Skip(8);
            raw[i] = (level, array, type, name, size, flags);
        }
        var strings = r.Bytes(stringSize);
        string Text(uint offset)
        {
            if ((offset & 0x80000000) != 0) return CommonString((int)(offset & 0x7FFFFFFF));
            if (offset >= strings.Length) return $"<string {offset}>";
            int zero = Array.IndexOf(strings, (byte)0, (int)offset);
            return Encoding.UTF8.GetString(strings, (int)offset, (zero < 0 ? strings.Length : zero) - (int)offset);
        }
        return [.. raw.Select(n => new UnityTypeNode(Text(n.Type), Text(n.Name), n.Level, n.Size, n.Array, n.Flags))];
    }

    private List<UnityTypeNode> ReadOldTree(UnityBinary r)
    {
        var list = new List<UnityTypeNode>();
        void Node(int level)
        {
            if (list.Count >= MaxNodes || level > 64) throw new InvalidDataException("a type tree deeper or larger than this reader reads");
            var type = r.CString();
            var name = r.CString();
            int size = r.I32();
            if (Format == 2) r.Skip(4);
            if (Format != 3) r.Skip(4);
            bool array = r.I32() != 0;
            r.Skip(4);
            int flags = r.I32();
            list.Add(new UnityTypeNode(type, name, level, size, array, flags));
            int children = Count(r.I32(), MaxNodes, "type tree children");
            for (int i = 0; i < children; i++) Node(level + 1);
        }
        Node(0);
        return list;
    }

    /// <summary>The engine's shared type tree strings, in order; an offset with the high bit set names one by its byte offset.</summary>
    private static readonly string[] Common =
    [
        "AABB", "AnimationClip", "AnimationCurve", "AnimationState", "Array", "Base", "BitField", "bitset", "bool", "char", "ColorRGBA",
        "Component", "data", "deque", "double", "dynamic_array", "FastPropertyName", "first", "float", "Font", "GameObject", "Generic Mono",
        "GradientNEW", "GUID", "GUIStyle", "int", "list", "long long", "map", "Matrix4x4f", "MdFour", "MonoBehaviour", "MonoScript",
        "m_ByteSize", "m_Curve", "m_EditorClassIdentifier", "m_EditorHideFlags", "m_Enabled", "m_ExtensionPtr", "m_GameObject", "m_Index",
        "m_IsArray", "m_IsStatic", "m_MetaFlag", "m_Name", "m_ObjectHideFlags", "m_PrefabInternal", "m_PrefabParentObject", "m_Script",
        "m_StaticEditorFlags", "m_Type", "m_Version", "Object", "pair", "PPtr<Component>", "PPtr<GameObject>", "PPtr<Material>",
        "PPtr<MonoBehaviour>", "PPtr<MonoScript>", "PPtr<Object>", "PPtr<Prefab>", "PPtr<Sprite>", "PPtr<TextAsset>", "PPtr<Texture>",
        "PPtr<Texture2D>", "PPtr<Transform>", "Prefab", "Quaternionf", "Rectf", "RectInt", "RectOffset", "second", "set", "short", "size",
        "SInt16", "SInt32", "SInt64", "SInt8", "staticvector", "string", "TextAsset", "TextMesh", "Texture", "Texture2D", "Transform",
        "TypelessData", "UInt16", "UInt32", "UInt64", "UInt8", "unsigned int", "unsigned long long", "unsigned short", "vector", "Vector2f",
        "Vector3f", "Vector4f", "m_ScriptingClassIdentifier", "Gradient", "Type*", "int2_storage", "int3_storage", "BoundsInt",
        "m_CorrespondingSourceObject", "m_PrefabInstance", "m_PrefabAsset", "FileSize", "Hash128", "RenderingLayerMask",
    ];

    private static readonly Dictionary<int, string> CommonByOffset = BuildCommon();

    private static Dictionary<int, string> BuildCommon()
    {
        var map = new Dictionary<int, string>();
        int offset = 0;
        foreach (var s in Common)
        {
            map[offset] = s;
            offset += Encoding.ASCII.GetByteCount(s) + 1;
        }
        return map;
    }

    /// <summary>The shared string at a byte offset; an offset this reader does not know is named by its number.</summary>
    internal static string CommonString(int offset) => CommonByOffset.GetValueOrDefault(offset) ?? $"<common string {offset}>";

    /// <summary>The byte offset of a shared string, or -1; writers of test files use it.</summary>
    internal static int CommonOffset(string s) => CommonByOffset.FirstOrDefault(p => p.Value == s) is { Value: not null } p ? p.Key : -1;
}
