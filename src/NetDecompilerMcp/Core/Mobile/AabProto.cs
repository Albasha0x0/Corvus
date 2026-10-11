using System.Text;
using NetDecompilerMcp.Native;

namespace NetDecompilerMcp.Core.Mobile;

/// <summary>A bounded protobuf reader: fields of one message, nested messages as sub-readers. Malformed data ends the message.</summary>
internal sealed class ProtoMessage(byte[] data, int start, int end)
{
    public static ProtoMessage Of(byte[] data) => new(data, 0, data.Length);

    public readonly record struct Field(int Number, int WireType, ulong Varint, int Start, int Length);

    public bool Truncated { get; private set; }

    public IEnumerable<Field> Fields()
    {
        int at = start;
        while (at < end)
        {
            if (!TryVarint(ref at, out var key)) { Truncated = true; yield break; }
            int number = (int)(key >> 3), wire = (int)(key & 7);
            switch (wire)
            {
                case 0:
                    if (!TryVarint(ref at, out var v)) { Truncated = true; yield break; }
                    yield return new(number, 0, v, 0, 0);
                    break;
                case 1:
                    if (at + 8 > end) { Truncated = true; yield break; }
                    yield return new(number, 1, BitConverter.ToUInt64(data, at), at, 8);
                    at += 8;
                    break;
                case 2:
                    if (!TryVarint(ref at, out var length) || length > (ulong)(end - at)) { Truncated = true; yield break; }
                    yield return new(number, 2, 0, at, (int)length);
                    at += (int)length;
                    break;
                case 5:
                    if (at + 4 > end) { Truncated = true; yield break; }
                    yield return new(number, 5, BitConverter.ToUInt32(data, at), at, 4);
                    at += 4;
                    break;
                default:
                    Truncated = true;
                    yield break;
            }
        }
    }

    private bool TryVarint(ref int at, out ulong value)
    {
        value = 0;
        for (int shift = 0; shift < 64 && at < end; shift += 7)
        {
            byte b = data[at++];
            value |= (ulong)(b & 0x7F) << shift;
            if ((b & 0x80) == 0) return true;
        }
        return false;
    }

    public ProtoMessage Message(Field f) => new(data, f.Start, f.Start + f.Length);
    public string String(Field f) => Encoding.UTF8.GetString(data, f.Start, f.Length);
}

/// <summary>
/// Android App Bundle protobuf formats (aapt2 Resources.proto / Configuration.proto): the manifest and compiled XML files
/// (XmlNode), converted to the binary-XML tree the manifest reader uses, and the resource table (resources.pb).
/// </summary>
public static class AabProto
{
    private const int MaxDepth = 1_000, MaxElements = 1_000_000;

    /// <summary>An XmlNode message as a document; problems are its issues.</summary>
    public static AxmlDocument ReadXml(byte[] bytes)
    {
        var issues = new List<ParseIssue>();
        var namespaces = new List<(string, string)>();
        int count = 0;
        AxmlElement? Node(ProtoMessage m, int depth)
        {
            foreach (var f in m.Fields())
                if (f.Number == 1 && f.WireType == 2) return Element(m.Message(f), depth);
            return null;
        }
        AxmlElement? Element(ProtoMessage m, int depth)
        {
            if (depth > MaxDepth || ++count > MaxElements) { issues.Add(new("aab xml", "elements nested too deep or too many; the rest is not read")); return null; }
            string? ns = null, name = null;
            var attributes = new List<AxmlAttribute>();
            var children = new List<AxmlElement>();
            string? text = null;
            foreach (var f in m.Fields())
                switch (f.Number)
                {
                    case 1 when f.WireType == 2:
                        string prefix = "", uri = "";
                        foreach (var g in m.Message(f).Fields())
                            if (g.Number == 1) prefix = m.String(g); else if (g.Number == 2) uri = m.String(g);
                        namespaces.Add((prefix, uri));
                        break;
                    case 2 when f.WireType == 2: ns = m.String(f); break;
                    case 3 when f.WireType == 2: name = m.String(f); break;
                    case 4 when f.WireType == 2: attributes.Add(Attribute(m.Message(f))); break;
                    case 5 when f.WireType == 2:
                        var child = m.Message(f);
                        foreach (var g in child.Fields())
                        {
                            if (g.Number == 1 && g.WireType == 2 && Element(child.Message(g), depth + 1) is { } e) children.Add(e);
                            else if (g.Number == 2 && g.WireType == 2) text = (text ?? "") + child.String(g);
                        }
                        break;
                }
            if (m.Truncated) issues.Add(new("aab xml", $"<{name}> is truncated"));
            var element = new AxmlElement(string.IsNullOrEmpty(ns) ? null : ns, name ?? "", 0) { Text = string.IsNullOrWhiteSpace(text) ? null : text };
            element.Attributes.AddRange(attributes);
            element.Children.AddRange(children);
            return element;
        }
        var root = Node(ProtoMessage.Of(bytes), 0);
        if (root == null) issues.Add(new("aab xml", "no root element", 0));
        return AxmlDocument.FromTree(root, namespaces, issues);
    }

    public static AxmlDocument ReadManifest(byte[] bytes) => ReadXml(bytes);

    private static AxmlAttribute Attribute(ProtoMessage m)
    {
        string? ns = null, name = null, value = null;
        uint id = 0;
        ResValue? compiled = null;
        string? compiledText = null;
        foreach (var f in m.Fields())
            switch (f.Number)
            {
                case 1 when f.WireType == 2: ns = m.String(f); break;
                case 2 when f.WireType == 2: name = m.String(f); break;
                case 3 when f.WireType == 2: value = m.String(f); break;
                case 5 when f.WireType == 0: id = (uint)f.Varint; break;
                case 6 when f.WireType == 2: (compiled, compiledText) = Item(m.Message(f)); break;
            }
        if (string.IsNullOrEmpty(name)) name = id != 0 ? AndroidAttributes.Name(id) ?? $"attr_0x{id:x8}" : "attr";
        var v = compiled ?? new ResValue(ResValue.String, uint.MaxValue);
        return new AxmlAttribute(string.IsNullOrEmpty(ns) ? null : ns, name, id, v.DataType is ResValue.String or ResValue.Null ? compiledText ?? value : value, v);
    }

    /// <summary>An Item as a typed value; strings and file paths come back as text.</summary>
    private static (ResValue? Value, string? Text) Item(ProtoMessage m)
    {
        foreach (var f in m.Fields())
        {
            if (f.WireType != 2) continue;
            var inner = m.Message(f);
            switch (f.Number)
            {
                case 1: // Reference
                    uint id = 0;
                    bool attribute = false;
                    string? refName = null;
                    foreach (var g in inner.Fields())
                        if (g.Number == 1) attribute = g.Varint == 1;
                        else if (g.Number == 2) id = (uint)g.Varint;
                        else if (g.Number == 3 && g.WireType == 2) refName = inner.String(g);
                    return (new ResValue(attribute ? ResValue.Attribute : ResValue.Reference, id), refName);
                case 2 or 3 or 4: // String, RawString, StyledString
                case 5: // FileReference
                    foreach (var g in inner.Fields())
                        if (g.Number == 1 && g.WireType == 2) return (new ResValue(ResValue.String, uint.MaxValue), inner.String(g));
                    return (new ResValue(ResValue.String, uint.MaxValue), "");
                case 6: return (new ResValue(ResValue.IntBoolean, 1), null); // Id
                case 7: return (Primitive(inner), null);
            }
        }
        return (null, null);
    }

    private static ResValue Primitive(ProtoMessage m)
    {
        foreach (var f in m.Fields())
            return f.Number switch
            {
                1 => new(ResValue.Null, 0), 2 => new(ResValue.Null, 1),
                3 => new(ResValue.Float, (uint)f.Varint),
                13 => new(ResValue.Dimension, (uint)f.Varint), 14 => new(ResValue.Fraction, (uint)f.Varint),
                6 => new(ResValue.IntDec, (uint)f.Varint), 7 => new(ResValue.IntHex, (uint)f.Varint), 8 => new(ResValue.IntBoolean, f.Varint != 0 ? 1u : 0),
                9 => new(ResValue.ColorArgb8, (uint)f.Varint), 10 => new(ResValue.ColorRgb8, (uint)f.Varint),
                11 => new(ResValue.ColorArgb4, (uint)f.Varint), 12 => new(ResValue.ColorRgb4, (uint)f.Varint),
                _ => new(ResValue.Null, 0),
            };
        return new(ResValue.Null, 0);
    }

    /// <summary>resources.pb.</summary>
    public static IResourceTable ReadResources(byte[] bytes) => new ProtoResources(bytes);

    private sealed class ProtoResources : IResourceTable
    {
        private sealed record Entry(uint Id, string Type, string Name, string Config, ProtoMessage Value);

        private readonly List<Entry> _entries = [];
        private readonly Dictionary<uint, (string Type, string Name, string Package)> _names = [];
        private readonly List<ParseIssue> _issues = [];
        public IReadOnlyList<ParseIssue> Issues => _issues;

        public ProtoResources(byte[] bytes)
        {
            var table = ProtoMessage.Of(bytes);
            foreach (var p in table.Fields().Where(f => f.Number == 2 && f.WireType == 2))
            {
                var package = table.Message(p);
                uint pid = 0x7F;
                string pname = "";
                var types = new List<ProtoMessage.Field>();
                foreach (var f in package.Fields())
                    if (f.Number == 1 && f.WireType == 2) pid = Id(package.Message(f));
                    else if (f.Number == 2 && f.WireType == 2) pname = package.String(f);
                    else if (f.Number == 3 && f.WireType == 2) types.Add(f);
                foreach (var t in types)
                {
                    var type = package.Message(t);
                    uint tid = 0;
                    string tname = "";
                    var entries = new List<ProtoMessage.Field>();
                    foreach (var f in type.Fields())
                        if (f.Number == 1 && f.WireType == 2) tid = Id(type.Message(f));
                        else if (f.Number == 2 && f.WireType == 2) tname = type.String(f);
                        else if (f.Number == 3 && f.WireType == 2) entries.Add(f);
                    foreach (var e in entries)
                    {
                        var entry = type.Message(e);
                        uint eid = 0;
                        string ename = "";
                        var values = new List<ProtoMessage.Field>();
                        foreach (var f in entry.Fields())
                            if (f.Number == 1 && f.WireType == 2) eid = Id(entry.Message(f));
                            else if (f.Number == 2 && f.WireType == 2) ename = entry.String(f);
                            else if (f.Number == 6 && f.WireType == 2) values.Add(f);
                        uint id = pid << 24 | tid << 16 | eid;
                        _names.TryAdd(id, (tname, ename, pname));
                        foreach (var v in values)
                        {
                            var cv = entry.Message(v);
                            string config = "";
                            ProtoMessage? value = null;
                            foreach (var f in cv.Fields())
                                if (f.Number == 1 && f.WireType == 2) config = Qualifiers(cv.Message(f));
                                else if (f.Number == 2 && f.WireType == 2) value = cv.Message(f);
                            if (value != null) _entries.Add(new(id, tname, ename, config, value));
                        }
                    }
                }
                if (package.Truncated) _issues.Add(new("resources.pb", $"package {pname} is truncated"));
            }
            if (table.Truncated) _issues.Add(new("resources.pb", "the table is truncated"));
        }

        private static uint Id(ProtoMessage m)
        {
            foreach (var f in m.Fields()) if (f.Number == 1 && f.WireType == 0) return (uint)f.Varint;
            return 0;
        }

        public string? Name(uint id) => _names.TryGetValue(id, out var n) ? id >> 24 == 0x7F || n.Package.Length == 0 ? $"@{n.Type}/{n.Name}" : $"@{n.Package}:{n.Type}/{n.Name}" : null;

        public uint? Find(string type, string name) => _names.Where(p => p.Value.Type == type && p.Value.Name == name).Select(p => (uint?)p.Key).FirstOrDefault();

        public string? DefaultText(uint id)
        {
            for (int depth = 0; depth < 8; depth++)
            {
                var pick = _entries.FirstOrDefault(e => e.Id == id && e.Config.Length == 0) ?? _entries.FirstOrDefault(e => e.Id == id);
                if (pick == null) return null;
                var (kind, text, target) = Render(pick.Value);
                if (kind == "reference" && target != 0) { id = target; continue; }
                return kind == "bag" ? null : text;
            }
            return null;
        }

        public IEnumerable<ResourceRow> Rows => _entries.Select(e =>
        {
            var (kind, text, _) = Render(e.Value);
            return new ResourceRow(e.Id, e.Type, e.Name, e.Config, kind, text, false);
        });

        /// <summary>A Value as (value type, text, referenced id).</summary>
        private (string Kind, string Text, uint Target) Render(ProtoMessage value)
        {
            foreach (var f in value.Fields())
            {
                if (f.WireType != 2) continue;
                if (f.Number == 4) return RenderItem(value.Message(f));
                if (f.Number == 5) return ("bag", Compound(value.Message(f)), 0);
            }
            return ("null", "@null", 0);
        }

        private (string Kind, string Text, uint Target) RenderItem(ProtoMessage item)
        {
            foreach (var f in item.Fields())
            {
                if (f.WireType != 2) continue;
                if (f.Number == 5)
                    foreach (var g in item.Message(f).Fields()) if (g.Number == 1 && g.WireType == 2) return ("file", item.Message(f).String(g), 0);
            }
            var (v, text) = Item(item);
            if (v is not { } value) return ("null", "@null", 0);
            if (value.IsReference) return ("reference", Name(value.Data) ?? (text != null ? "@" + text : $"@0x{value.Data:x8}"), value.Data);
            if (value.DataType == ResValue.String) return ("string", text ?? "", 0);
            return (value.TypeName, value.Format(ResStringPool.Empty, Name), 0);
        }

        private string Compound(ProtoMessage compound)
        {
            foreach (var f in compound.Fields())
            {
                if (f.WireType != 2) continue;
                var m = compound.Message(f);
                var parts = new List<string>();
                switch (f.Number)
                {
                    case 2: // Style
                        foreach (var g in m.Fields())
                            if (g.Number == 1 && g.WireType == 2) parts.Add("parent=" + RenderItemReference(m.Message(g)));
                            else if (g.Number == 3 && g.WireType == 2) parts.Add(StyleEntry(m.Message(g)));
                        return string.Join("; ", parts);
                    case 4: // Array
                        int i = 0;
                        foreach (var g in m.Fields().Where(g => g.Number == 1 && g.WireType == 2))
                            parts.Add($"[{i++}]={ElementItem(m.Message(g), 3)}");
                        return string.Join("; ", parts);
                    case 5: // Plural
                        foreach (var g in m.Fields().Where(g => g.Number == 1 && g.WireType == 2))
                        {
                            var entry = m.Message(g);
                            var arity = entry.Fields().FirstOrDefault(x => x.Number == 3).Varint switch { 0 => "zero", 1 => "one", 2 => "two", 3 => "few", 4 => "many", _ => "other" };
                            parts.Add($"{arity}={ElementItem(entry, 4)}");
                        }
                        return string.Join("; ", parts);
                    case 1: return "attr";
                    case 3: return "styleable";
                    case 6: return "macro";
                }
            }
            return "";
        }

        private string ElementItem(ProtoMessage holder, int field)
        {
            foreach (var g in holder.Fields()) if (g.Number == field && g.WireType == 2) return RenderItem(holder.Message(g)).Text;
            return "";
        }

        private string RenderItemReference(ProtoMessage reference)
        {
            uint id = 0;
            string? name = null;
            foreach (var g in reference.Fields())
                if (g.Number == 2) id = (uint)g.Varint;
                else if (g.Number == 3 && g.WireType == 2) name = reference.String(g);
            return Name(id) ?? (name != null ? "@" + name : $"@0x{id:x8}");
        }

        private string StyleEntry(ProtoMessage entry)
        {
            string key = "", item = "";
            foreach (var g in entry.Fields())
                if (g.Number == 3 && g.WireType == 2) key = RenderItemReference(entry.Message(g)).TrimStart('@');
                else if (g.Number == 4 && g.WireType == 2) item = RenderItem(entry.Message(g)).Text;
            return $"{key}={item}";
        }
    }

    /// <summary>A Configuration message as aapt's qualifier string ("pt-rBR", "night-xxhdpi-v31"); "" for the default.</summary>
    internal static string Qualifiers(ProtoMessage c)
    {
        var v = new Dictionary<int, ulong>();
        string locale = "", product = "";
        foreach (var f in c.Fields())
            if (f.Number == 3 && f.WireType == 2) locale = c.String(f);
            else if (f.Number == 25 && f.WireType == 2) product = c.String(f);
            else if (f.WireType == 0) v[f.Number] = f.Varint;
        ulong Get(int n) => v.GetValueOrDefault(n);
        var q = new List<string>();
        void Add(int field, params string[] names) { var x = Get(field); if (x > 0 && x <= (ulong)names.Length && names[x - 1].Length > 0) q.Add(names[x - 1]); }
        if (Get(1) != 0) q.Add($"mcc{Get(1)}");
        if (Get(2) != 0) q.Add($"mnc{Get(2)}");
        if (locale.Length > 0) q.Add(Locale(locale));
        Add(4, "ldltr", "ldrtl");
        if (Get(9) != 0) q.Add($"sw{Get(9)}dp");
        if (Get(7) != 0) q.Add($"w{Get(7)}dp");
        if (Get(8) != 0) q.Add($"h{Get(8)}dp");
        Add(10, "small", "normal", "large", "xlarge");
        Add(11, "long", "notlong");
        Add(12, "round", "notround");
        Add(13, "widecg", "nowidecg");
        Add(14, "highdr", "lowdr");
        Add(15, "port", "land", "square");
        Add(16, "", "desk", "car", "television", "appliance", "watch", "vrheadset");
        Add(17, "night", "notnight");
        if (Get(18) != 0)
            q.Add(Get(18) switch
            {
                120 => "ldpi", 160 => "mdpi", 213 => "tvdpi", 240 => "hdpi", 320 => "xhdpi", 480 => "xxhdpi", 640 => "xxxhdpi", 0xFFFE => "anydpi", 0xFFFF => "nodpi",
                var d => $"{d}dpi",
            });
        Add(19, "notouch", "stylus", "finger");
        Add(20, "keysexposed", "keyshidden", "keyssoft");
        Add(21, "nokeys", "qwerty", "12key");
        Add(22, "navexposed", "navhidden");
        Add(23, "nonav", "dpad", "trackball", "wheel");
        if (Get(5) != 0 && Get(6) != 0) q.Add($"{Math.Max(Get(5), Get(6))}x{Math.Min(Get(5), Get(6))}");
        if (Get(24) != 0) q.Add($"v{Get(24)}");
        if (product.Length > 0) q.Add(product);
        return string.Join('-', q);
    }

    /// <summary>A BCP-47 locale ("pt-BR", "sr-Latn-RS") as aapt writes it in qualifiers ("pt-rBR", "b+sr+Latn+RS").</summary>
    private static string Locale(string bcp47)
    {
        var parts = bcp47.Replace('_', '-').Split('-', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 1 && parts[0].Length == 2) return parts[0].ToLowerInvariant();
        if (parts.Length == 2 && parts[0].Length == 2 && parts[1].Length == 2) return $"{parts[0].ToLowerInvariant()}-r{parts[1].ToUpperInvariant()}";
        return "b+" + string.Join('+', parts);
    }
}
