using System.Globalization;
using System.Text.RegularExpressions;

namespace Corvus.Core.Assets;

/// <summary>A PPtr: file id 0 is the same file, n the n-th external; path id 0 with file id 0 is null.</summary>
public readonly record struct AssetPointer(int FileId, long PathId)
{
    public bool IsNull => FileId == 0 && PathId == 0;
}

/// <summary>The class a MonoScript names: its class, namespace (empty for none) and assembly file name.</summary>
public sealed record AssetScriptClass(string ClassName, string Namespace, string Assembly)
{
    public string FullName => Namespace.Length > 0 ? $"{Namespace}.{ClassName}" : ClassName;
}

/// <summary>The fixed part of MonoBehaviour and MonoScript objects: base fields and the named script class.</summary>
internal static partial class AssetScriptObject
{
    /// <summary>The names of the base fields a MonoBehaviour's type tree starts with, before the script's own fields.</summary>
    public static readonly HashSet<string> BaseFields =
    [
        "m_ObjectHideFlags", "m_CorrespondingSourceObject", "m_PrefabInstance", "m_PrefabAsset", "m_PrefabParentObject", "m_PrefabInternal",
        "m_GameObject", "m_Enabled", "m_EditorHideFlags", "m_Script", "m_Name", "m_EditorClassIdentifier",
    ];

    /// <summary>The type tree of a player build's MonoBehaviour base: GameObject, enabled, script and name.</summary>
    public static List<AssetTypeNode> BaseTree(int format)
    {
        var nodes = new List<AssetTypeNode> { new("MonoBehaviour", "Base", 0, -1, false, 0) };
        Pointer(nodes, "PPtr<GameObject>", "m_GameObject", 1, format);
        nodes.Add(new AssetTypeNode("UInt8", "m_Enabled", 1, 1, false, 0x4000));
        Pointer(nodes, "PPtr<MonoScript>", "m_Script", 1, format);
        String(nodes, "m_Name", 1);
        return nodes;
    }

    /// <summary>Appends a PPtr node: an int file id and a path id, 64-bit from format 14 on.</summary>
    public static void Pointer(List<AssetTypeNode> nodes, string type, string name, int level, int format)
    {
        bool wide = format >= 14;
        nodes.Add(new AssetTypeNode(type, name, level, wide ? 12 : 8, false, 0));
        nodes.Add(new AssetTypeNode("int", "m_FileID", level + 1, 4, false, 0));
        nodes.Add(wide ? new AssetTypeNode("SInt64", "m_PathID", level + 1, 8, false, 0) : new AssetTypeNode("int", "m_PathID", level + 1, 4, false, 0));
    }

    /// <summary>Appends a string node: an aligned array of chars.</summary>
    public static void String(List<AssetTypeNode> nodes, string name, int level)
    {
        nodes.Add(new AssetTypeNode("string", name, level, -1, false, 0));
        nodes.Add(new AssetTypeNode("Array", "Array", level + 1, -1, true, 0x4000));
        nodes.Add(new AssetTypeNode("int", "size", level + 2, 4, false, 0));
        nodes.Add(new AssetTypeNode("char", "data", level + 2, 1, false, 0));
    }

    /// <summary>The pointer a PPtr value shows ("null" is the null pointer), or null when the text is not one.</summary>
    public static AssetPointer? ParsePointer(string? value)
    {
        if (value == "null") return new AssetPointer(0, 0);
        return value != null && PointerText().Match(value) is { Success: true } m
            ? new AssetPointer(int.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture), long.Parse(m.Groups[2].Value, CultureInfo.InvariantCulture))
            : null;
    }

    /// <summary>A string value without its quotes, or null when the text is not a shown string.</summary>
    public static string? ParseString(string? value) =>
        value is ['"', .., '"'] && !value.EndsWith("...", StringComparison.Ordinal) ? value[1..^1].Replace("\\\"", "\"").Replace("\\\\", "\\") : null;

    /// <summary>The class a MonoScript names, by type tree or the version's fixed layout; null when the data does not read.</summary>
    public static AssetScriptClass? ScriptClass(SerializedFile file, AssetObject script)
    {
        if (file.Data(script) is not { } r) return null;
        try
        {
            if (script.Type?.Tree is { Count: > 1 } tree)
            {
                // A damaged tree can name a field twice; the first is kept.
                var fields = AssetTreeReader.Read(tree, r).DistinctBy(f => f.Name).ToDictionary(f => f.Name, f => f.Value);
                return ParseString(fields.GetValueOrDefault("m_ClassName")) is { } cls
                    ? new AssetScriptClass(cls, ParseString(fields.GetValueOrDefault("m_Namespace")) ?? "", ParseString(fields.GetValueOrDefault("m_AssemblyName")) ?? "")
                    : null;
            }
            r.String(true);
            r.Skip(4);
            r.Skip(Major(file.EngineVersion) is >= 5 or 0 ? 16 : 4);
            var className = r.String(true);
            var ns = r.String(true);
            return new AssetScriptClass(className, ns, r.String(true));
        }
        catch (InvalidDataException)
        {
            return null;
        }
    }

    /// <summary>The major engine version of a version string, or 0 when it has none.</summary>
    public static int Major(string? version) =>
        version != null && int.TryParse(version.AsSpan(0, Math.Max(0, version.IndexOf('.'))), NumberStyles.None, CultureInfo.InvariantCulture, out int major) ? major : 0;

    [GeneratedRegex(@"^PPtr<[^>]*>\(file (-?\d+), path (-?\d+)\)$", RegexOptions.CultureInvariant)]
    private static partial Regex PointerText();
}
