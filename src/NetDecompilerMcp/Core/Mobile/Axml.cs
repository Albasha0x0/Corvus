using System.Text;
using NetDecompilerMcp.Native;

namespace NetDecompilerMcp.Core.Mobile;

/// <summary>An attribute of a compiled XML element. <see cref="RawValue"/> is the original string, when the compiler kept one.</summary>
public sealed record AxmlAttribute(string? Namespace, string Name, uint ResourceId, string? RawValue, ResValue Value);

/// <summary>An element of a compiled XML document.</summary>
public sealed class AxmlElement(string? ns, string name, int line)
{
    public string? Namespace { get; } = ns;
    public string Name { get; } = name;
    public int Line { get; } = line;
    public List<AxmlAttribute> Attributes { get; } = [];
    public List<AxmlElement> Children { get; } = [];
    /// <summary>Character data directly inside the element, if any.</summary>
    public string? Text { get; internal set; }

    /// <summary>The attribute named <paramref name="name"/> (in the android namespace when <paramref name="android"/>), or null.</summary>
    public AxmlAttribute? Attribute(string name, bool android = true) =>
        Attributes.FirstOrDefault(a => a.Name == name && (a.Namespace == AxmlDocument.AndroidNamespace) == android);

    public IEnumerable<AxmlElement> Elements(string name) => Children.Where(c => c.Name == name);
}

/// <summary>
/// Android binary XML (AndroidManifest.xml and compiled res/*.xml inside an APK). Never throws: what cannot be read
/// is reported in <see cref="Issues"/> and the tree read so far is kept.
/// </summary>
public sealed class AxmlDocument
{
    public const string AndroidNamespace = "http://schemas.android.com/apk/res/android";

    /// <summary>Most elements read from one document.</summary>
    public const int MaxElements = 1_000_000;
    public const int MaxDepth = 1_000;

    public AxmlElement? Root { get; private set; }
    public ResStringPool Strings { get; private set; } = ResStringPool.Empty;
    /// <summary>Resource ids of attribute names, by string index (the compiler puts attribute names first in the pool).</summary>
    public IReadOnlyList<uint> ResourceIds { get; private set; } = [];
    /// <summary>Namespace declarations in document order: prefix and URI.</summary>
    public IReadOnlyList<(string Prefix, string Uri)> Namespaces => _namespaces;
    public IReadOnlyList<ParseIssue> Issues => _issues;

    private readonly List<(string, string)> _namespaces = [];
    private readonly List<ParseIssue> _issues = [];

    private AxmlDocument() { }

    /// <summary>True when <paramref name="data"/> starts with a binary XML chunk header.</summary>
    public static bool IsAxml(ReadOnlySpan<byte> data) => data.Length >= 8 && ResChunk.U16(data, 0) == ResChunk.Xml && ResChunk.U16(data, 2) == 8;

    public static AxmlDocument Read(ReadOnlySpan<byte> data)
    {
        var doc = new AxmlDocument();
        doc.Parse(data);
        return doc;
    }

    private void Parse(ReadOnlySpan<byte> data)
    {
        const string Area = "axml";
        if (ResChunk.Outer(data, Area, _issues) is not { } top) return;
        if (top.Type != ResChunk.Xml) { _issues.Add(new(Area, $"not binary XML (chunk type 0x{top.Type:x4})", 0)); return; }
        int end = top.Size;
        var stack = new Stack<AxmlElement>();
        int elements = 0;
        for (int at = top.HeaderSize; at < end;)
        {
            if (ResChunk.Header(data, at, end, Area, _issues) is not { } chunk) break;
            var body = at + chunk.HeaderSize;
            switch (chunk.Type)
            {
                case ResChunk.StringPool:
                    Strings = ResStringPool.Read(data, at, chunk.HeaderSize, chunk.Size, Area, _issues);
                    break;
                case ResChunk.XmlResourceMap:
                    var ids = new uint[(chunk.Size - chunk.HeaderSize) / 4];
                    for (int i = 0; i < ids.Length; i++) ids[i] = ResChunk.U32(data, body + i * 4);
                    ResourceIds = ids;
                    break;
                case ResChunk.XmlStartNamespace:
                    if (Strings.Get(ResChunk.U32(data, body + 4)) is { } uri)
                        _namespaces.Add((Strings.Get(ResChunk.U32(data, body)) ?? "", uri));
                    break;
                case ResChunk.XmlEndNamespace:
                    break;
                case ResChunk.XmlStartElement:
                    if (++elements > MaxElements) { _issues.Add(new(Area, $"more than {MaxElements} elements; the rest is not read", at)); return; }
                    if (stack.Count >= MaxDepth) { _issues.Add(new(Area, $"elements nested deeper than {MaxDepth}; the rest is not read", at)); return; }
                    var element = StartElement(data, at, body, at + chunk.Size);
                    if (stack.TryPeek(out var parent)) parent.Children.Add(element);
                    else if (Root == null) Root = element;
                    else _issues.Add(new(Area, $"a second root element <{element.Name}> is ignored", at));
                    stack.Push(element);
                    break;
                case ResChunk.XmlEndElement:
                    var name = Strings.Get(ResChunk.U32(data, body + 4));
                    if (stack.Count == 0) _issues.Add(new(Area, $"end of <{name}> without a start", at));
                    else if (stack.Pop().Name != name) _issues.Add(new(Area, $"end of <{name}> closes another element", at));
                    break;
                case ResChunk.XmlCData:
                    if (stack.TryPeek(out var holder) && Strings.Get(ResChunk.U32(data, body)) is { } text) holder.Text = (holder.Text ?? "") + text;
                    break;
                default:
                    _issues.Add(new(Area, $"unknown chunk 0x{chunk.Type:x4} skipped", at));
                    break;
            }
            at += chunk.Size;
        }
        if (stack.Count > 0) _issues.Add(new(Area, $"{stack.Count} element(s) not closed", end));
        if (Root == null) _issues.Add(new(Area, "no root element", 0));
    }

    private AxmlElement StartElement(ReadOnlySpan<byte> data, int at, int body, int chunkEnd)
    {
        int line = (int)ResChunk.U32(data, at + 8);
        var element = new AxmlElement(Strings.Get(ResChunk.U32(data, body)), Strings.Get(ResChunk.U32(data, body + 4)) ?? "", line);
        int attrStart = ResChunk.U16(data, body + 8), attrSize = ResChunk.U16(data, body + 10), attrCount = ResChunk.U16(data, body + 12);
        if (attrCount > 0 && (attrSize < 20 || body + attrStart + (long)attrSize * attrCount > chunkEnd))
        {
            _issues.Add(new("axml", $"<{element.Name}>: {attrCount} attributes of {attrSize} bytes do not fit the element", at));
            return element;
        }
        for (int i = 0; i < attrCount; i++)
        {
            int a = body + attrStart + i * attrSize;
            uint nameIndex = ResChunk.U32(data, a + 4);
            uint id = nameIndex < (uint)ResourceIds.Count ? ResourceIds[(int)nameIndex] : 0;
            var name = Strings.Get(nameIndex);
            // Obfuscated or stripped manifests leave the name empty; the resource id still identifies the attribute.
            if (string.IsNullOrEmpty(name)) name = id != 0 ? AndroidAttributes.Name(id) ?? $"attr_0x{id:x8}" : $"attr_{nameIndex}";
            var value = ResValue.Read(data, a + 12) ?? default;
            element.Attributes.Add(new(Strings.Get(ResChunk.U32(data, a)), name, id, Strings.Get(ResChunk.U32(data, a + 8)), value));
        }
        return element;
    }

    /// <summary>The value of an attribute as text: its string, else its typed value through <paramref name="resolve"/>.</summary>
    public string Text(AxmlAttribute attribute, Func<uint, string?>? resolve = null) =>
        attribute.RawValue != null && attribute.Value.DataType is ResValue.String or ResValue.Null
            ? attribute.RawValue
            : attribute.Value.Format(Strings, resolve);

    /// <summary>The document as XML text; references are shown through <paramref name="resolve"/> (e.g. an ARSC table).</summary>
    public string ToXml(Func<uint, string?>? resolve = null)
    {
        var sb = new StringBuilder("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
        if (Root != null) Write(sb, Root, 0, resolve, true);
        return sb.ToString();
    }

    private void Write(StringBuilder sb, AxmlElement e, int depth, Func<uint, string?>? resolve, bool root)
    {
        sb.Append(' ', depth * 2).Append('<').Append(Qualified(e.Namespace, e.Name));
        if (root)
            foreach (var (prefix, uri) in _namespaces.Distinct())
                sb.Append(prefix.Length == 0 ? " xmlns" : " xmlns:" + prefix).Append("=\"").Append(Escape(uri)).Append('"');
        foreach (var a in e.Attributes)
            sb.Append(' ').Append(Qualified(a.Namespace, a.Name)).Append("=\"").Append(Escape(Text(a, resolve))).Append('"');
        if (e.Children.Count == 0 && e.Text == null) { sb.Append(" />\n"); return; }
        sb.Append('>');
        if (e.Text != null) sb.Append(Escape(e.Text));
        if (e.Children.Count > 0)
        {
            sb.Append('\n');
            foreach (var c in e.Children) Write(sb, c, depth + 1, resolve, false);
            sb.Append(' ', depth * 2);
        }
        sb.Append("</").Append(Qualified(e.Namespace, e.Name)).Append(">\n");
    }

    private string Qualified(string? ns, string name)
    {
        if (string.IsNullOrEmpty(ns)) return name;
        foreach (var (prefix, uri) in _namespaces)
            if (uri == ns && prefix.Length > 0) return prefix + ":" + name;
        return ns == AndroidNamespace ? "android:" + name : name;
    }

    private static string Escape(string s) =>
        s.Replace("&", "&amp;", StringComparison.Ordinal).Replace("<", "&lt;", StringComparison.Ordinal)
         .Replace(">", "&gt;", StringComparison.Ordinal).Replace("\"", "&quot;", StringComparison.Ordinal);
}

/// <summary>Names of framework attributes by resource id, for manifests whose attribute names were stripped.</summary>
public static class AndroidAttributes
{
    // Ids from the framework's public.xml; these never change between API levels.
    private static readonly Dictionary<uint, string> Names = new()
    {
        [0x01010000] = "theme", [0x01010001] = "label", [0x01010002] = "icon", [0x01010003] = "name",
        [0x01010006] = "permission", [0x01010007] = "readPermission", [0x01010008] = "writePermission", [0x01010009] = "protectionLevel",
        [0x0101000a] = "permissionGroup", [0x0101000c] = "hasCode", [0x0101000e] = "enabled", [0x0101000f] = "debuggable", [0x01010010] = "exported",
        [0x01010011] = "process", [0x01010018] = "authorities", [0x0101001b] = "grantUriPermissions", [0x0101001c] = "priority",
        [0x01010024] = "value", [0x01010025] = "resource",
        [0x01010026] = "mimeType", [0x01010027] = "scheme", [0x01010028] = "host", [0x01010029] = "port",
        [0x0101002a] = "path", [0x0101002b] = "pathPrefix", [0x0101002c] = "pathPattern",
        [0x0101020c] = "minSdkVersion", [0x0101021b] = "versionCode", [0x0101021c] = "versionName",
        [0x01010202] = "targetActivity", [0x01010270] = "targetSdkVersion", [0x01010271] = "maxSdkVersion", [0x01010272] = "testOnly",
        [0x0101027f] = "backupAgent", [0x01010280] = "allowBackup", [0x010104ea] = "extractNativeLibs", [0x010104eb] = "fullBackupContent",
        [0x010104ec] = "usesCleartextTraffic", [0x010104ee] = "autoVerify", [0x01010527] = "networkSecurityConfig", [0x01010572] = "compileSdkVersion",
        [0x0101057a] = "appComponentFactory",
    };

    public static string? Name(uint id) => Names.GetValueOrDefault(id);
}
