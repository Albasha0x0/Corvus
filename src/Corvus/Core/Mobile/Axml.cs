using System.Text;
using Corvus.Native;

namespace Corvus.Core.Mobile;

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

/// <summary>Android binary XML; never throws, problems go to <see cref="Issues"/> and the tree read so far is kept.</summary>
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

    /// <summary>A document built from an already decoded tree (an app bundle's protobuf XML).</summary>
    internal static AxmlDocument FromTree(AxmlElement? root, IEnumerable<(string Prefix, string Uri)> namespaces, IEnumerable<ParseIssue> issues)
    {
        var doc = new AxmlDocument { Root = root };
        doc._namespaces.AddRange(namespaces.Distinct());
        doc._issues.AddRange(issues);
        return doc;
    }

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

    /// <summary>An attribute value as text: string, framework enum or flag name, else resolved through <paramref name="resolve"/>.</summary>
    public string Text(AxmlAttribute attribute, Func<uint, string?>? resolve = null) =>
        attribute.RawValue != null && attribute.Value.DataType is ResValue.String or ResValue.Null
            ? attribute.RawValue
            : attribute.Namespace == AndroidNamespace && attribute.Value.DataType is ResValue.IntDec or ResValue.IntHex
                && AndroidAttributes.Symbolic(attribute.Name, attribute.Value.Data) is { } symbolic
                ? symbolic
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

    // The compiled manifest keeps enum and flag values as numbers, but aapt2 accepts only their names.
    private static readonly Dictionary<string, (bool Flags, (uint Value, string Name)[] Values)> Symbols = new()
    {
        ["installLocation"] = (false, [(0, "auto"), (1, "internalOnly"), (2, "preferExternal")]),
        ["launchMode"] = (false, [(0, "standard"), (1, "singleTop"), (2, "singleTask"), (3, "singleInstance"), (4, "singleInstancePerTask")]),
        ["screenOrientation"] = (false, [(uint.MaxValue, "unspecified"), (0, "landscape"), (1, "portrait"), (2, "user"), (3, "behind"), (4, "sensor"),
            (5, "nosensor"), (6, "sensorLandscape"), (7, "sensorPortrait"), (8, "reverseLandscape"), (9, "reversePortrait"), (10, "fullSensor"),
            (11, "userLandscape"), (12, "userPortrait"), (13, "fullUser"), (14, "locked")]),
        ["documentLaunchMode"] = (false, [(0, "none"), (1, "intoExisting"), (2, "always"), (3, "never")]),
        ["persistableMode"] = (false, [(0, "persistRootOnly"), (1, "persistNever"), (2, "persistAcrossReboots")]),
        ["lockTaskMode"] = (false, [(0, "normal"), (1, "never"), (2, "always"), (3, "if_whitelisted")]),
        ["uiOptions"] = (false, [(0, "none"), (1, "splitActionBarWhenNarrow")]),
        ["rotationAnimation"] = (false, [(0, "rotate"), (1, "crossfade"), (2, "jumpcut"), (3, "seamless")]),
        ["colorMode"] = (false, [(0, "default"), (1, "wideColorGamut"), (2, "hdr")]),
        ["gwpAsanMode"] = (false, [(uint.MaxValue, "default"), (0, "never"), (1, "always")]),
        ["memtagMode"] = (false, [(uint.MaxValue, "default"), (0, "off"), (1, "async"), (2, "sync")]),
        ["configChanges"] = (true, [(0x1, "mcc"), (0x2, "mnc"), (0x4, "locale"), (0x8, "touchscreen"), (0x10, "keyboard"), (0x20, "keyboardHidden"),
            (0x40, "navigation"), (0x80, "orientation"), (0x100, "screenLayout"), (0x200, "uiMode"), (0x400, "screenSize"), (0x800, "smallestScreenSize"),
            (0x1000, "density"), (0x2000, "layoutDirection"), (0x4000, "colorMode"), (0x8000, "grammaticalGender"), (0x8000000, "resourcesUnused"),
            (0x10000000, "fontWeightAdjustment"), (0x40000000, "fontScale"), (0x80000000, "assetsPaths")]),
        ["recreateOnConfigChanges"] = (true, [(0x1, "mcc"), (0x2, "mnc")]),
        ["foregroundServiceType"] = (true, [(0x1, "dataSync"), (0x2, "mediaPlayback"), (0x4, "phoneCall"), (0x8, "location"), (0x10, "connectedDevice"),
            (0x20, "mediaProjection"), (0x40, "camera"), (0x80, "microphone"), (0x100, "health"), (0x200, "remoteMessaging"), (0x400, "systemExempted"),
            (0x800, "shortService"), (0x2000, "mediaProcessing"), (0x40000000, "specialUse")]),
        ["usesPermissionFlags"] = (true, [(0x10000, "neverForLocation")]),
        ["permissionFlags"] = (true, [(0x1, "costsMoney"), (0x2, "removed"), (0x4, "hardRestricted"), (0x8, "softRestricted"), (0x10, "immutablyRestricted"),
            (0x20, "installerExemptIgnored")]),
        ["permissionGroupFlags"] = (true, [(0x1, "personalInfo")]),
        ["intentMatchingFlags"] = (true, [(0x1, "none"), (0x2, "enforceIntentFilter"), (0x4, "allowNullAction")]),
        ["reqTouchScreen"] = (false, [(0, "undefined"), (1, "notouch"), (2, "stylus"), (3, "finger")]),
        ["reqKeyboardType"] = (false, [(0, "undefined"), (1, "nokeys"), (2, "qwerty"), (3, "twelvekey")]),
        ["reqNavigation"] = (false, [(0, "undefined"), (1, "nonav"), (2, "dpad"), (3, "trackball"), (4, "wheel")]),
        ["appCategory"] = (false, [(0, "game"), (1, "audio"), (2, "video"), (3, "image"), (4, "social"), (5, "news"), (6, "maps"), (7, "productivity"),
            (8, "accessibility")]),
        ["autoRevokePermissions"] = (false, [(0, "allowed"), (1, "discouraged"), (2, "disallowed")]),
        ["rollbackDataPolicy"] = (false, [(0, "restore"), (1, "wipe"), (2, "retain")]),
        ["requireContentUriPermissionFromCaller"] = (false, [(0, "none"), (1, "read"), (2, "write"), (3, "readOrWrite"), (4, "readAndWrite")]),
        ["pageSizeCompat"] = (false, [(32, "enabled"), (64, "disabled")]),
        ["screenSize"] = (false, [(200, "small"), (300, "normal"), (400, "large"), (500, "xlarge")]),
        ["screenDensity"] = (false, [(120, "ldpi"), (160, "mdpi"), (240, "hdpi"), (320, "xhdpi"), (480, "xxhdpi"), (640, "xxxhdpi")]),
    };

    /// <summary>The source name of an enum or flag attribute value (installLocation 1 is "internalOnly"), or null when it has none.</summary>
    public static string? Symbolic(string attribute, uint value)
    {
        if (attribute == "protectionLevel")
            return (value & 0xF) <= 4 && AllBitsNamed(value) ? AndroidManifestSummary.ProtectionLevel(value) : null;
        if (attribute == "windowSoftInputMode")
        {
            uint state = value & 0xF, adjust = value >> 4;
            if (state > 5 || adjust > 3) return null;
            string[] states = ["stateUnspecified", "stateUnchanged", "stateHidden", "stateAlwaysHidden", "stateVisible", "stateAlwaysVisible"];
            string[] adjusts = ["adjustUnspecified", "adjustResize", "adjustPan", "adjustNothing"];
            return adjust == 0 ? states[state] : state == 0 ? adjusts[adjust] : $"{states[state]}|{adjusts[adjust]}";
        }
        if (!Symbols.TryGetValue(attribute, out var symbols)) return null;
        if (!symbols.Flags) return symbols.Values.FirstOrDefault(v => v.Value == value).Name;
        var set = symbols.Values.Where(v => (value & v.Value) == v.Value).ToList();
        return set.Count == 0 || set.Aggregate(0u, (m, v) => m | v.Value) != value ? null : string.Join("|", set.Select(v => v.Name));
    }

    // ProtectionLevel names only the bits it knows; an unknown bit keeps the number.
    private static bool AllBitsNamed(uint value)
    {
        for (int bit = 4; bit < 32; bit++)
            if ((value & (1u << bit)) != 0 && AndroidManifestSummary.ProtectionLevel(1u << bit).Split('|').Length < 2) return false;
        return true;
    }
}
