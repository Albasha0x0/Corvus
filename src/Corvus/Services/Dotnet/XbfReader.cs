using System.Buffers.Binary;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;

namespace Corvus.Services;

/// <summary>
/// Decodes XBF, the binary XAML that UWP and WinUI compilers write, back to XAML; version 2 in full including deferred
/// streams, version 1 and unknown versions as partial with their metadata tables.
/// </summary>
public static partial class XbfReader
{
    private const string PresentationUri = "http://schemas.microsoft.com/winfx/2006/xaml/presentation";
    private const string XamlUri = "http://schemas.microsoft.com/winfx/2006/xaml";
    // The low bit of a resource key's stored hash marks a key that is a type (an implicit style's TargetType).
    private const ulong KeyTypeFlag = 1;

    /// <summary>One element the code-behind connects to: its type and x:Name (null when it has none).</summary>
    public sealed record Element(string Type, string? Name);

    /// <summary>
    /// The decoded XAML (null when no node stream was read), version, x:Class, connected elements and notes; Partial when anything was left out.
    /// </summary>
    public sealed record Result(string? Xaml, int Major, int Minor, string? ClassName, IReadOnlyDictionary<int, Element> Connections,
        IReadOnlyList<string> Notes, bool Partial);

    /// <summary>True when <paramref name="head"/> starts with the XBF signature.</summary>
    public static bool IsXbf(ReadOnlySpan<byte> head) => head.Length >= 4 && head[..4].SequenceEqual("XBF\0"u8);

    /// <summary>
    /// Decodes an XBF file, writing <paramref name="handlers"/> as attributes and <paramref name="className"/> as x:Class when
    /// the file names none; damage gives a partial result. Throws InvalidDataException without the XBF signature.
    /// </summary>
    public static Result Read(byte[] data, IReadOnlyDictionary<int, IReadOnlyList<(string Event, string Method)>>? handlers = null, string? className = null)
    {
        if (!IsXbf(data)) throw new InvalidDataException("not an XBF file: the signature XBF\\0 is missing");
        if (data.Length < 0x14) return new Result(null, 0, 0, null, new Dictionary<int, Element>(), ["the header is cut short"], true);
        int major = (int)BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(12)), minor = (int)BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(16));
        var file = new XbfFile(data, major, minor);
        if (major != 2)
        {
            var reason = major == 1
                ? "XBF 1 (Windows 8.1): the node stream is not decoded; only the metadata tables are read"
                : $"XBF {major}.{minor} is a version this reader does not know; only the metadata tables are read";
            var notes = new List<string> { reason };
            try
            {
                file.ReadMetadata();
                notes.Add($"metadata: {file.Strings.Count} strings, {file.TypeTable.Count} types, {file.PropertyTable.Count} properties, {file.XmlNamespaces.Count} XML namespaces");
                notes.Add("types: " + string.Join(", ", file.TypeTable.Select(t => file.Strings.ElementAtOrDefault((int)t.Name) ?? "?").Take(100)));
            }
            catch (Exception e) when (e is InvalidDataException or ArgumentOutOfRangeException or IndexOutOfRangeException)
            {
                notes.Add($"the metadata tables could not be read: {e.Message}");
            }
            return new Result(null, major, minor, null, new Dictionary<int, Element>(), notes, true);
        }
        try { file.ReadMetadata(); }
        catch (InvalidDataException e)
        {
            return new Result(null, major, minor, null, new Dictionary<int, Element>(), [$"the metadata tables could not be read: {e.Message}"], true);
        }
        var writer = new TreeBuilder(file);
        writer.Run();
        var root = writer.Root;
        string? xaml = null;
        if (root != null)
        {
            if (root.Attributes.FirstOrDefault(a => a.Name == "x:Class").Value is { } named) className = named;
            else if (className != null) root.Attributes.Insert(0, ("x:Class", className));
            xaml = writer.Render(root, handlers);
        }
        else
        {
            className = null;
            writer.Notes.Add("the node stream produced no root element");
        }
        var connections = writer.Connections.ToDictionary(c => c.Key, c => new Element(c.Value.Type, c.Value.Name));
        return new Result(xaml, major, minor, className, connections, writer.Notes, writer.Notes.Count > 0);
    }

    /// <summary>The metadata tables and node streams of one file.</summary>
    private sealed class XbfFile(byte[] data, int major, int minor)
    {
        public readonly byte[] Data = data;
        public readonly int Major = major, Minor = minor;
        public List<string> Strings = [];
        public List<(uint Kind, uint Name)> Assemblies = [];
        public List<(uint Assembly, uint Name)> TypeNamespaces = [];
        public List<(uint Flags, uint Namespace, uint Name)> TypeTable = [];
        public List<(uint Flags, uint Type, uint Name)> PropertyTable = [];
        public List<uint> XmlNamespaces = [];
        public List<(int Start, int End)> Streams = [];

        public void ReadMetadata()
        {
            // Offsets in the header count from the end of the signature and the two section sizes.
            const int Base = 12;
            uint metadataSize = U32(4);
            int at = (int)(Base + (long)U64(0x14));
            int count = I32(ref at);
            bool terminated = Major == 2 && Minor >= 1;
            for (int i = 0; i < count; i++)
            {
                int length = I32(ref at);
                Check(at, length * 2L);
                Strings.Add(Encoding.Unicode.GetString(Data, at, length * 2));
                at += length * 2 + (terminated ? 2 : 0);
            }
            at = (int)(Base + (long)U64(0x1C));
            Assemblies = Table(ref at, () => (U32At(ref at), U32At(ref at)));
            at = (int)(Base + (long)U64(0x24));
            TypeNamespaces = Table(ref at, () => (U32At(ref at), U32At(ref at)));
            at = (int)(Base + (long)U64(0x2C));
            TypeTable = Table(ref at, () => (U32At(ref at), U32At(ref at), U32At(ref at)));
            at = (int)(Base + (long)U64(0x34));
            PropertyTable = Table(ref at, () => (U32At(ref at), U32At(ref at), U32At(ref at)));
            at = (int)(Base + (long)U64(0x3C));
            XmlNamespaces = Table(ref at, () => U32At(ref at));
            if (Major != 2) return;
            at = (int)(Base + metadataSize);
            int streams = I32(ref at);
            var offsets = new List<(uint Node, uint Line)>();
            for (int i = 0; i < streams; i++) offsets.Add((U32At(ref at), U32At(ref at)));
            for (int i = 0; i < streams; i++)
            {
                long start = at + (long)offsets[i].Node, end = at + (long)offsets[i].Line;
                if (start > Data.Length || end > Data.Length || end < start) throw new InvalidDataException($"node stream {i} lies outside the file");
                Streams.Add(((int)start, (int)end));
            }
        }

        private List<T> Table<T>(ref int at, Func<T> item)
        {
            int count = I32(ref at);
            if (count < 0 || count > Data.Length) throw new InvalidDataException("a metadata table count is out of range");
            var list = new List<T>(count);
            for (int i = 0; i < count; i++) list.Add(item());
            return list;
        }

        private void Check(long at, long length)
        {
            if (at < 0 || length < 0 || at + length > Data.Length) throw new InvalidDataException("the metadata is cut short");
        }

        private uint U32(int at) { Check(at, 4); return BinaryPrimitives.ReadUInt32LittleEndian(Data.AsSpan(at)); }
        private ulong U64(int at) { Check(at, 8); return BinaryPrimitives.ReadUInt64LittleEndian(Data.AsSpan(at)); }
        private uint U32At(ref int at) { var v = U32(at); at += 4; return v; }
        private int I32(ref int at) => (int)U32At(ref at);
    }

    /// <summary>An element of the rebuilt tree: attributes in order, then property elements and content.</summary>
    private sealed class Node(string type)
    {
        public string Type = type;
        public readonly List<(string Name, string Value)> Attributes = [];
        public readonly List<object> Children = [];
        public int? ConnectionId;
        public string? Condition;
        public bool IsProperty;
        public string? Text;

        public void Set(string name, string value)
        {
            int i = Attributes.FindIndex(a => a.Name == name);
            if (i >= 0) Attributes[i] = (name, value);
            else Attributes.Add((name, value));
        }
    }

    /// <summary>A markup extension value written as an attribute: {StaticResource key}.</summary>
    private sealed record Markup(string Text);

    private sealed class Frame
    {
        public Node? Instance;
        public string? Property;
        public bool ContentProperty;
        public readonly List<object> Items = [];
        public object? Value;
    }

    private readonly record struct Prop(string Owner, string Name, bool Attached, string? Prefix, bool Implicit);

    /// <summary>Replays the object writer's nodes into a tree.</summary>
    private sealed class TreeBuilder(XbfFile file)
    {
        public readonly List<string> Notes = [];
        public readonly Dictionary<int, (string Type, string? Name)> Connections = [];
        public Node? Root;
        private readonly Dictionary<string, string> _prefixes = new(StringComparer.Ordinal);
        private readonly Dictionary<string, string> _uris = new(StringComparer.Ordinal);
        private readonly List<string> _conditions = [];
        private readonly List<(string Prefix, string Uri)> _added = [];
        private readonly Dictionary<Node, int> _connectionNodes = [];
        private int _depth;
        private bool _replaced;

        public void Run()
        {
            if (file.Streams.Count == 0) { Notes.Add("the file has no node stream"); return; }
            var bottom = new Frame();
            var frames = new List<Frame> { bottom };
            Execute(0, file.Streams[0].Start, frames, stopWhen: null);
            Unwind(frames);
            Root = bottom.Value as Node ?? bottom.Items.OfType<Node>().FirstOrDefault() ?? bottom.Instance;
            foreach (var (node, id) in _connectionNodes)
                Connections[id] = (node.Type, node.Attributes.FirstOrDefault(a => a.Name is "x:Name" or "Name").Value);
        }

        /// <summary>
        /// Runs stream <paramref name="stream"/> from <paramref name="at"/> on <paramref name="frames"/> until its end
        /// or until <paramref name="stopWhen"/> holds after a node.
        /// </summary>
        private void Execute(int stream, int at, List<Frame> frames, Func<bool>? stopWhen)
        {
            if (++_depth > 64) { Notes.Add("node streams nest deeper than 64; the inner ones are not read"); _depth--; return; }
            try
            {
                var r = new NodeReader(file, stream, at);
                while (!r.AtEnd)
                {
                    int nodeAt = r.Offset;
                    byte type = r.Byte();
                    if (!Step(type, r, frames))
                    {
                        Notes.Add($"node stream {stream}: node type {type} at offset {nodeAt} is not a known XBF 2 node; the rest of the stream is not read");
                        return;
                    }
                    if (type == 37 || frames.Count == 0 || stopWhen?.Invoke() == true) return;
                }
            }
            catch (Exception e) when (e is InvalidDataException or ArgumentOutOfRangeException or IndexOutOfRangeException)
            {
                Notes.Add($"node stream {stream}: {e.Message}; the rest of the stream is not read");
            }
            finally { _depth--; }
        }

        private Frame Top(List<Frame> frames) => frames[^1];

        /// <summary>Closes the scopes a stream left open (it ended early), so what was read joins the tree.</summary>
        private void Unwind(List<Frame> frames)
        {
            while (frames.Count > 1)
            {
                if (Top(frames).Property != null || Top(frames).Instance == null) PopScope(frames);
                else EndInit(frames);
            }
        }

        private Node Current(List<Frame> frames)
        {
            for (int i = frames.Count - 1; i >= 0; i--)
                if (frames[i].Instance is { } n) return n;
            return frames[^1].Instance = new Node("Unknown");
        }

        private bool Step(byte type, NodeReader r, List<Frame> frames)
        {
            switch (type)
            {
                case 1: frames.Add(new Frame()); break;
                case 2: PopScope(frames); break;
                case 3: AddNamespace(r); break;
                case 4: Top(frames).Value = Constant(r); break;
                case 7: SetValue(frames, Property(r.Node())); break;
                case 8: case 9: AddToCollection(frames, null); break;
                case 10: AddToCollection(frames, Constant(r)); break;
                case 11: Current(frames).Set("x:Class", r.UniqueString()); break;
                case 12:
                {
                    var node = Current(frames);
                    if (int.TryParse(Constant(r), NumberStyles.Integer, CultureInfo.InvariantCulture, out var id))
                    {
                        node.ConnectionId = id;
                        _connectionNodes[node] = id;
                    }
                    break;
                }
                case 13: Current(frames).Set("x:Name", Constant(r)); break;
                case 14: Current(frames).Set("x:Uid", Constant(r)); break;
                case 15: CustomRuntimeData(r, frames); break;
                case 17: DeferredProperty(r, frames); break;
                case 18: frames.Add(new Frame()); AddNamespace(r); break;
                case 19:
                {
                    var p = Property(r.Node());
                    frames.Add(new Frame { Property = PropertyElement(p, Current(frames)), ContentProperty = IsContent(p) });
                    break;
                }
                case 20: frames.Add(new Frame()); Create(frames, TypeName(r.Node()), null); break;
                case 21: case 22: frames.Add(new Frame()); Create(frames, TypeName(r.Node()), Constant(r)); break;
                case 23: Create(frames, TypeName(r.Node()), null); break;
                case 24: case 25: Create(frames, TypeName(r.Node()), Constant(r)); break;
                case 26: case 27: { var p = Property(r.Node()); Attribute(frames, p, Constant(r)); break; }
                case 28: { var p = Property(r.Node()); Attribute(frames, p, PropertyValue(Property(r.Node()))); break; }
                case 29: { var p = Property(r.Node()); Attribute(frames, p, TypeName(r.Node())); break; }
                case 30: { var p = Property(r.Node()); Attribute(frames, p, $"{{StaticResource {Escape(Constant(r))}}}"); break; }
                case 31: { var p = Property(r.Node()); Attribute(frames, p, $"{{TemplateBinding {Property(r.Node()).Name}}}"); break; }
                case 32: SetValue(frames, Property(r.Node())); break;
                case 33: case 40: EndInit(frames); break;
                case 34: Top(frames).Value = new Markup($"{{StaticResource {Escape(Constant(r))}}}"); break;
                case 35: Top(frames).Value = new Markup($"{{ThemeResource {Escape(Constant(r))}}}"); break;
                case 36: { var p = Property(r.Node()); Attribute(frames, p, $"{{ThemeResource {Escape(Constant(r))}}}"); break; }
                case 37: break;
                case 38: { var predicate = TypeName(r.Node()); _conditions.Add($"{predicate}({r.SharedString(this)})"); break; }
                case 39: if (_conditions.Count > 0) _conditions.RemoveAt(_conditions.Count - 1); break;
                case 139: break;
                default: return false;
            }
            return true;
        }

        private void AddNamespace(NodeReader r)
        {
            var uri = Str(file.XmlNamespaces[r.Node().Id]);
            var prefix = r.UniqueString();
            if (_prefixes.ContainsKey(uri)) return;
            if (prefix.Length > 0) prefix = XmlConvert.EncodeLocalName(prefix);
            // Names resolve against one set of declarations on the root, so a prefix bound again to another
            // namespace in an inner scope gets a prefix of its own.
            while (_uris.ContainsKey(prefix)) prefix = prefix.Length == 0 ? "p" : prefix + "_";
            _prefixes[uri] = prefix;
            _uris[prefix] = uri;
        }

        private void Create(List<Frame> frames, string type, string? text)
        {
            var frame = Top(frames);
            var node = new Node(type) { Text = text };
            if (_conditions.Count > 0) node.Condition = string.Join(" and ", _conditions);
            frame.Instance = node;
        }

        private void EndInit(List<Frame> frames)
        {
            var done = Top(frames).Instance;
            frames.RemoveAt(frames.Count - 1);
            if (frames.Count > 0 && done != null) Top(frames).Value = done;
        }

        private void PopScope(List<Frame> frames)
        {
            var frame = Top(frames);
            frames.RemoveAt(frames.Count - 1);
            if (frames.Count == 0) return;
            if (frame.Property != null)
            {
                var owner = Current(frames);
                if (frame.ContentProperty) owner.Children.AddRange(frame.Items);
                else if (frame.Items.Count > 0)
                {
                    var element = new Node(frame.Property) { IsProperty = true };
                    element.Children.AddRange(frame.Items);
                    owner.Children.Add(element);
                }
            }
            else if ((frame.Instance ?? frame.Value) is { } value) Top(frames).Value = value;
        }

        private void AddToCollection(List<Frame> frames, string? key)
        {
            var frame = Top(frames);
            var value = frame.Value;
            frame.Value = null;
            if (value == null) return;
            if (key != null && value is Node keyed) keyed.Attributes.Insert(0, ("x:Key", key));
            if (frame.Property != null || frame.Instance == null) frame.Items.Add(value);
            else frame.Instance.Children.Add(value is string s ? s : value);
        }

        private void SetValue(List<Frame> frames, Prop p)
        {
            var frame = Top(frames);
            var value = frame.Value;
            frame.Value = null;
            var owner = Current(frames);
            switch (value)
            {
                case null: return;
                case string s: Attribute(owner, p, s); break;
                case Markup m: Attribute(owner, p, m.Text); break;
                case Node n when p.Implicit: owner.Children.Add(n); break;
                case Node n when MarkupText(n) is { } text: Attribute(owner, p, text); break;
                case Node n when IsContent(p): owner.Children.Add(n); break;
                case Node n:
                {
                    var element = new Node(PropertyElement(p, owner)) { IsProperty = true };
                    element.Children.Add(n);
                    owner.Children.Add(element);
                    break;
                }
            }
        }

        private void Attribute(List<Frame> frames, Prop p, string value) => Attribute(Current(frames), p, value);

        private static void Attribute(Node owner, Prop p, string value)
        {
            // The text content of x:String and other initialization text is the value itself, not an attribute.
            if (p.Implicit) { owner.Text = value; return; }
            owner.Set(AttributeName(p), value);
        }

        private static string AttributeName(Prop p) => p.Prefix != null ? $"{p.Prefix}:{p.Name}" : p.Attached ? $"{p.Owner}.{p.Name}" : p.Name;

        // A property element names the element's own type unless the property is attached, as the source XAML does.
        private static string PropertyElement(Prop p, Node owner) =>
            p.Prefix != null ? $"{p.Prefix}:{p.Name}" : p.Attached || owner.Type.Length == 0 ? $"{p.Owner}.{p.Name}" : $"{owner.Type}.{p.Name}";

        private static string PropertyValue(Prop p) => p.Attached ? $"{p.Owner}.{p.Name}" : p.Name;

        /// <summary>The attribute form of a markup extension with only simple attributes; null for any other element.</summary>
        private static string? MarkupText(Node n)
        {
            var name = n.Type switch
            {
                "Binding" or "TemplateBinding" or "RelativeSource" or "StaticResource" or "ThemeResource" or "CustomResource" => n.Type,
                "NullExtension" => "x:Null",
                _ => null,
            };
            if (name == null || n.Children.Count > 0 || n.Text != null) return null;
            if (n.Attributes.Count == 0) return $"{{{name}}}";
            if (n.Type is "StaticResource" or "ThemeResource" or "CustomResource" && n.Attributes is [("ResourceKey", var key)]) return $"{{{name} {Escape(key)}}}";
            if (n.Type == "RelativeSource" && n.Attributes is [("Mode", var mode)]) return $"{{RelativeSource {mode}}}";
            if (n.Type == "TemplateBinding" && n.Attributes is [("Property", var property)]) return $"{{TemplateBinding {property}}}";
            return $"{{{name} {string.Join(", ", n.Attributes.Select(a => $"{a.Name}={Escape(a.Value)}"))}}}";
        }

        private static string Escape(string value) =>
            value.Length > 0 && !value.StartsWith('{') && value.IndexOfAny([',', '=', '{', '}', '\'', ' ']) < 0 ? value
            : value.StartsWith('{') && value.EndsWith('}') ? value
            : "'" + value.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("'", "\\'", StringComparison.Ordinal) + "'";

        private static readonly HashSet<string> ContentProperties =
        [
            "Panel.Children", "ItemsControl.Items", "ContentControl.Content", "Border.Child", "UserControl.Content", "Window.Content",
            "TextBlock.Inlines", "Span.Inlines", "Paragraph.Inlines", "RichTextBlock.Blocks", "ContentPresenter.Content", "Viewbox.Child",
            "Popup.Child", "ResourceDictionary.MergedDictionaries_", "VisualStateGroup.States", "Storyboard.Children", "VisualState.Storyboard",
            "Style.Setters", "ItemsPresenter.Header_", "Flyout.Content", "MenuFlyout.Items", "Canvas.Children_", "Path.Data_", "PathGeometry.Figures",
            "PathFigure.Segments", "GeometryGroup.Children", "TransformGroup.Children", "GradientBrush.GradientStops", "ColorKeyFrameCollection_",
            "DoubleAnimationUsingKeyFrames.KeyFrames", "ColorAnimationUsingKeyFrames.KeyFrames", "ObjectAnimationUsingKeyFrames.KeyFrames",
            "PointAnimationUsingKeyFrames.KeyFrames", "VisualTransition.Storyboard", "Hyperlink.Inlines", "Bold.Inlines", "Italic.Inlines", "Underline.Inlines",
            "InlineUIContainer.Child", "ScrollViewer.Content", "Frame.Content", "AppBar.Content", "CommandBar.PrimaryCommands", "SwipeItems.Items_",
            "MenuBar.Items", "MenuBarItem.Items", "MenuFlyoutSubItem.Items", "NavigationView.MenuItems_", "TreeView.RootNodes_", "Grid.Children_",
        ];

        private static bool IsContent(Prop p) => p.Implicit || ContentProperties.Contains($"{p.Owner}.{p.Name}");

        private string Str(uint index) => index < file.Strings.Count ? file.Strings[(int)index] : throw new InvalidDataException($"string {index} is not in the string table");

        private string Prefixed(string uri, string name)
        {
            if (!_prefixes.TryGetValue(uri, out var prefix))
            {
                prefix = uri == XamlUri ? "x" : $"ns{_added.Count}";
                while (_uris.ContainsKey(prefix)) prefix += "_";
                _prefixes[uri] = prefix;
                _uris[prefix] = uri;
                _added.Add((prefix, uri));
            }
            return prefix.Length == 0 ? name : $"{prefix}:{name}";
        }

        private static readonly HashSet<string> XamlPrimitives = ["String", "Double", "Int32", "Boolean", "Object", "Int64", "Single", "Char16", "TimeSpan", "Uri", "Byte"];

        private string TypeName(NodeReader.Persisted n)
        {
            if (n.Trusted)
            {
                var name = XbfIndexes.Type(n.Id) ?? $"KnownType{n.Id}";
                return XamlPrimitives.Contains(name) ? Prefixed(XamlUri, name) : Prefixed(PresentationUri, name);
            }
            if (n.Id >= file.TypeTable.Count) throw new InvalidDataException($"type {n.Id} is not in the type table");
            var (flags, ns, typeName) = file.TypeTable[n.Id];
            var local = Str(typeName);
            if ((flags & 1) != 0) return Prefixed(XamlUri, local);
            if ((flags & 2) != 0) return Prefixed(Str(file.XmlNamespaces[(int)ns]), local);
            var clr = Str(file.TypeNamespaces[(int)ns].Name);
            // A system XAML namespace (Windows.UI.Xaml.Controls, Microsoft.UI.Xaml.Controls) is the presentation namespace.
            if (clr.StartsWith("Windows.UI.Xaml", StringComparison.Ordinal) || clr.StartsWith("Microsoft.UI.Xaml", StringComparison.Ordinal))
                return Prefixed(PresentationUri, local);
            return Prefixed("using:" + clr, local);
        }

        private Prop Property(NodeReader.Persisted n)
        {
            if (n.Trusted)
            {
                var entry = XbfIndexes.Property(n.Id) ?? $"Unknown.Property{n.Id}";
                bool attached = entry.EndsWith('*');
                if (attached) entry = entry[..^1];
                int dot = entry.IndexOf('.');
                return new Prop(Prefixed(PresentationUri, entry[..dot]), entry[(dot + 1)..], attached, null, false);
            }
            if (n.Id >= file.PropertyTable.Count) throw new InvalidDataException($"property {n.Id} is not in the property table");
            var (flags, type, name) = file.PropertyTable[n.Id];
            var local = Str(name);
            if ((flags & 4) != 0) return new Prop("", local, false, null, true);
            if ((flags & 2) != 0) return new Prop("", local, false, "x", false);
            if ((flags & 1) != 0) return new Prop("", local, false, "xml", false);
            var owner = TypeName(new NodeReader.Persisted((ushort)type, false));
            return new Prop(owner, local, false, null, false);
        }

        private string Constant(NodeReader r) => r.Constant(this);

        public string Enum(ushort type, uint value) =>
            XbfIndexes.EnumMember(type, value) ?? value.ToString(CultureInfo.InvariantCulture);

        public string SharedString(ushort index) => Str(index);

        private void DeferredProperty(NodeReader r, List<Frame> frames)
        {
            var p = Property(r.Node());
            int stream = (int)r.UInt();
            uint statics = r.UInt(), themes = r.UInt();
            for (uint i = 0; i < statics + themes; i++) r.Node();
            var owner = Current(frames);
            var content = ReadStream(stream);
            // A template's content is written as the template's own content.
            if (p.Name == "Template" || IsContent(p)) owner.Children.AddRange(content);
            else
            {
                var element = new Node(PropertyElement(p, owner)) { IsProperty = true };
                element.Children.AddRange(content);
                owner.Children.Add(element);
            }
        }

        /// <summary>The values stream <paramref name="stream"/> produces when read from its start.</summary>
        private List<object> ReadStream(int stream)
        {
            if (stream >= file.Streams.Count) { Notes.Add($"node stream {stream} is not in the stream table"); return []; }
            var bottom = new Frame();
            var frames = new List<Frame> { bottom };
            Execute(stream, file.Streams[stream].Start, frames, stopWhen: null);
            Unwind(frames);
            var items = new List<object>(bottom.Items);
            if ((bottom.Value ?? bottom.Instance) is { } value) items.Add(value);
            return items;
        }

        /// <summary>The one value the nodes at <paramref name="offset"/> of stream <paramref name="stream"/> produce; null when none.</summary>
        private object? ReadValueAt(int stream, uint offset)
        {
            if (stream >= file.Streams.Count) return null;
            var bottom = new Frame();
            var frames = new List<Frame> { bottom };
            int at = file.Streams[stream].Start + (int)offset;
            if (at >= file.Streams[stream].End) { Notes.Add($"node stream {stream}: offset {offset} lies outside the stream"); return null; }
            Execute(stream, at, frames, stopWhen: () => frames.Count == 1 && (bottom.Value != null || bottom.Items.Count > 0));
            return bottom.Value ?? bottom.Items.FirstOrDefault();
        }

        /// <summary>The items a collection read from <paramref name="offset"/> of stream <paramref name="stream"/> holds.</summary>
        private List<object> ReadCollectionAt(int stream, uint offset)
        {
            if (stream >= file.Streams.Count) return [];
            // The collection's nodes start with getting the collection from the owner, so they run on a stand-in owner.
            var holder = new Node("");
            var frames = new List<Frame> { new() { Instance = holder } };
            Execute(stream, file.Streams[stream].Start + (int)offset, frames, stopWhen: () => frames.Count < 1);
            return [.. holder.Children.SelectMany(c => c is Node { IsProperty: true } p ? p.Children : [c])];
        }

        /// <summary>Applies the one node at <paramref name="offset"/> of stream <paramref name="stream"/> to <paramref name="instance"/>.</summary>
        private void ApplyNodeAt(int stream, uint offset, Node instance)
        {
            if (stream >= file.Streams.Count) return;
            var frames = new List<Frame> { new() { Instance = instance } };
            Execute(stream, file.Streams[stream].Start + (int)offset, frames, stopWhen: () => true);
        }

        private void CustomRuntimeData(NodeReader r, List<Frame> frames)
        {
            int stream = (int)r.UInt();
            uint statics = r.UInt(), themes = r.UInt();
            for (uint i = 0; i < statics + themes; i++) r.Node();
            var owner = Current(frames);
            // Content read for a property being set (Resources, VisualStateGroups) goes to that property's element.
            var top = Top(frames);
            Action<object> sink = top.Property != null && top.Instance == null ? top.Items.Add : owner.Children.Add;
            uint kind = r.UInt();
            switch (kind)
            {
                case 420: case 1: case 3: case 4: case 5: VisualStates(r, kind, stream, sink); break;
                case 371: case 7: case 10: case 12: Resources(r, kind, stream, sink); break;
                case 2: case 8: case 11: Setters(r, kind, stream, owner); break;
                case 745: case 6: case 9: Deferred(r, kind, stream, owner, frames); break;
                default: throw new InvalidDataException($"deferred content of kind {kind} is not known");
            }
            if (kind is 10 or 12 or 11)
            {
                uint objects = r.UInt();
                for (uint i = 0; i < objects; i++)
                {
                    r.UInt();
                    uint predicates = r.UInt();
                    for (uint k = 0; k < predicates; k++) { r.Node(); r.Node(); }
                }
            }
        }

        private void VisualStates(NodeReader r, uint kind, int stream, Action<object> sink)
        {
            Skip(r, () => r.UInt());
            uint states = r.UInt();
            for (uint i = 0; i < states; i++)
            {
                r.Node();
                r.UInt();
                r.Constant(this);
                if (kind == 420) continue;
                Skip(r, () => r.UInt());
                Skip(r, () => Skip(r, () => r.UInt()));
                if (kind == 1) continue;
                Skip(r, () => r.UInt());
                Skip(r, () => r.UInt());
                if (kind is 3 or 4) continue;
                Skip(r, () => r.UInt());
            }
            Skip(r, () => { r.Node(); r.Constant(this); r.UInt(); });
            Skip(r, () => { r.Node(); r.Node(); r.UInt(); });
            r.Constant(this);
            Skip(r, () => { r.UInt(); r.UInt(); r.UInt(); });
            Skip(r, () => r.UInt());
            uint whole = r.UInt();
            if (kind is 4 or 5) Skip(r, () => r.Node());
            ReadCollectionAt(stream, whole).ForEach(sink);
        }

        private void Resources(NodeReader r, uint kind, int stream, Action<object> sink)
        {
            var entries = new List<(string? Key, uint Offset)>();
            void Map(bool implicitKey) => Skip(r, () => { var key = r.SharedString(this); entries.Add((implicitKey ? null : key, r.UInt())); });
            void Conditional(bool implicitKey) => Skip(r, () =>
            {
                var key = r.SharedString(this);
                Skip(r, () => entries.Add((implicitKey ? null : key, r.UInt())));
            });
            switch (kind)
            {
                case 371: Map(false); Skip(r, () => r.Node()); Map(true); Skip(r, () => r.Node()); Skip(r, () => r.Node()); break;
                case 7: Map(false); Skip(r, () => r.Node()); Map(true); Skip(r, () => r.Node()); break;
                case 10: Map(false); Skip(r, () => r.Node()); Map(true); Conditional(false); Conditional(true); break;
                case 12:
                    Skip(r, () =>
                    {
                        var key = r.SharedString(this);
                        bool isType = (r.FixedUInt64() & KeyTypeFlag) != 0;
                        entries.Add((isType ? null : key, r.UInt()));
                    });
                    Skip(r, () => r.Node());
                    Skip(r, () =>
                    {
                        var key = r.SharedString(this);
                        bool isType = (r.FixedUInt64() & KeyTypeFlag) != 0;
                        Skip(r, () => entries.Add((isType ? null : key, r.UInt())));
                    });
                    break;
            }
            foreach (var (key, offset) in entries.OrderBy(e => e.Offset))
            {
                if (ReadValueAt(stream, offset) is not { } value) continue;
                if (key != null && value is Node n && !n.Attributes.Any(a => a.Name == "x:Key")) n.Attributes.Insert(0, ("x:Key", key));
                sink(value);
            }
        }

        private void Setters(NodeReader r, uint kind, int stream, Node owner)
        {
            uint count = r.UInt();
            for (uint i = 0; i < count; i++)
            {
                uint flags = r.UInt();
                bool self = (flags & 0x40) != 0, container = (flags & 0x20) != 0, resolved = (flags & 0x10) != 0, obj = (flags & 0x08) != 0,
                    text = (flags & 0x04) != 0, statics = (flags & 0x02) != 0, themes = (flags & 0x01) != 0;
                string? property = null;
                if (kind != 11 || !self)
                {
                    if (resolved) property = PropertyValue(Property(r.Node()));
                    else
                    {
                        var name = r.SharedString(this);
                        var ownerType = TypeName(r.Node());
                        property = name.Contains('.') ? name : $"{ownerType}.{name}";
                    }
                }
                Node setter;
                if (text || container)
                {
                    setter = new Node(Prefixed(PresentationUri, "Setter"));
                    setter.Set("Property", property ?? "?");
                    setter.Set("Value", text ? r.SharedString(this) : r.Constant(this));
                }
                else if (statics || themes)
                {
                    // The value's node sets Setter.Value from the resource, so it is applied to the setter itself.
                    setter = new Node(Prefixed(PresentationUri, "Setter"));
                    setter.Set("Property", property ?? "?");
                    ApplyNodeAt(stream, r.UInt(), setter);
                }
                else if (obj || self)
                {
                    uint offset = r.UInt();
                    var value = ReadValueAt(stream, offset);
                    if (self && value is Node selfNode) { owner.Children.Add(selfNode); continue; }
                    setter = new Node(Prefixed(PresentationUri, "Setter"));
                    setter.Set("Property", property ?? "?");
                    switch (value)
                    {
                        case Markup m: setter.Set("Value", m.Text); break;
                        case string s: setter.Set("Value", s); break;
                        case Node n when MarkupText(n) is { } t: setter.Set("Value", t); break;
                        case Node n:
                        {
                            var element = new Node(Prefixed(PresentationUri, "Setter.Value")) { IsProperty = true };
                            element.Children.Add(n);
                            setter.Children.Add(element);
                            break;
                        }
                        default: Notes.Add($"a setter of {property} has a value that could not be read"); break;
                    }
                }
                else
                {
                    setter = new Node(Prefixed(PresentationUri, "Setter"));
                    setter.Set("Property", property ?? "?");
                }
                owner.Children.Add(setter);
            }
        }

        private void Deferred(NodeReader r, uint kind, int stream, Node owner, List<Frame> frames)
        {
            r.SharedString(this);
            string? realize = null;
            if (kind != 745)
            {
                Skip(r, () => { r.Node(); r.Constant(this); });
                if (kind == 9) realize = r.Constant(this);
            }
            var content = ReadStream(stream);
            if (content.FirstOrDefault() is Node element)
            {
                // The placeholder stands in for the element until x:Load realizes it.
                if (realize != null) element.Set("x:Load", realize);
                var frame = frames.LastOrDefault(f => f.Instance == owner);
                if (frame != null) frame.Instance = element;
                if (_connectionNodes.Remove(owner, out var id)) { element.ConnectionId ??= id; _connectionNodes[element] = element.ConnectionId.Value; }
            }
            else owner.Children.AddRange(content);
        }

        private static void Skip(NodeReader r, Action item)
        {
            uint count = r.UInt();
            for (uint i = 0; i < count; i++) item();
        }

        /// <summary>Writes the tree as XAML, with each connected element's event handlers as attributes.</summary>
        public string Render(Node root, IReadOnlyDictionary<int, IReadOnlyList<(string Event, string Method)>>? handlers)
        {
            var scope = new Dictionary<string, string>(StringComparer.Ordinal) { ["xml"] = XNamespace.Xml.NamespaceName };
            foreach (var (uri, prefix) in _prefixes) scope.TryAdd(prefix, Text(uri));
            var element = ToXml(root, scope, handlers);
            foreach (var (uri, prefix) in _prefixes.OrderBy(p => p.Value.Length > 0).ThenBy(p => p.Value, StringComparer.Ordinal))
                element.Add(new XAttribute(prefix.Length == 0 ? "xmlns" : XNamespace.Xmlns + prefix, Text(uri)));
            // Declarations go first, as the source XAML writes them.
            var attributes = element.Attributes().OrderBy(a => a.IsNamespaceDeclaration ? 0 : 1).ToList();
            element.ReplaceAttributes(attributes);
            if (_replaced) Notes.Add("characters XML does not allow are written as U+FFFD");
            return element.ToString();
        }

        /// <summary><paramref name="s"/> with each character XML does not allow replaced by U+FFFD.</summary>
        private string Text(string s)
        {
            int bad = 0;
            for (int i = 0; i < s.Length; i++)
            {
                if (char.IsHighSurrogate(s[i]) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1])) { i++; continue; }
                if (!XmlConvert.IsXmlChar(s[i])) bad++;
            }
            if (bad == 0) return s;
            _replaced = true;
            var sb = new StringBuilder(s.Length);
            for (int i = 0; i < s.Length; i++)
            {
                if (char.IsHighSurrogate(s[i]) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1])) { sb.Append(s, i++, 2); continue; }
                sb.Append(XmlConvert.IsXmlChar(s[i]) ? s[i] : '\uFFFD');
            }
            return sb.ToString();
        }

        private XElement ToXml(Node node, Dictionary<string, string> scope, IReadOnlyDictionary<int, IReadOnlyList<(string Event, string Method)>>? handlers)
        {
            var element = new XElement(Name(node.Type, scope, element: true));
            foreach (var (name, value) in node.Attributes)
            {
                var xname = Name(name, scope, element: false);
                if (element.Attribute(xname) == null) element.Add(new XAttribute(xname, Text(value)));
            }
            if (node.ConnectionId is { } id && handlers?.TryGetValue(id, out var events) == true)
                foreach (var (evt, method) in events)
                    if (element.Attribute(evt) == null) element.Add(new XAttribute(evt, Text(method)));
            foreach (var child in node.Children)
            {
                switch (child)
                {
                    case Node n:
                        if (n.Condition != null) element.Add(new XComment($" when {Text(n.Condition).Replace("--", "- -", StringComparison.Ordinal)} "));
                        element.Add(ToXml(n, scope, handlers));
                        break;
                    case Markup m: element.Add(Text(m.Text)); break;
                    default: element.Add(Text(child.ToString() ?? "")); break;
                }
            }
            if (node.Text != null) element.Add(Text(node.Text));
            return element;
        }

        private static XName Name(string qualified, Dictionary<string, string> scope, bool element)
        {
            int colon = qualified.IndexOf(':');
            var prefix = colon > 0 ? qualified[..colon] : "";
            // A generic type's arity suffix (List`1) is no XML name; XAML names the type without it.
            var local = XmlConvert.EncodeLocalName(GenericArity().Replace(colon > 0 ? qualified[(colon + 1)..] : qualified, ""));
            if (prefix.Length == 0) return element && scope.TryGetValue("", out var defaultUri) ? XName.Get(local, defaultUri) : XName.Get(local);
            return scope.TryGetValue(prefix, out var uri) ? XName.Get(local, uri) : XName.Get(local);
        }
    }

    [GeneratedRegex(@"`\d+")]
    private static partial Regex GenericArity();

    /// <summary>Reads the nodes and constants of one node stream.</summary>
    private sealed class NodeReader(XbfFile file, int stream, int at)
    {
        private readonly byte[] _data = file.Data;
        private readonly int _start = file.Streams[stream].Start, _end = file.Streams[stream].End;
        private int _at = at;

        /// <summary>A node's type or property id; Trusted means an id in the platform's known table, not the file's own.</summary>
        public readonly record struct Persisted(ushort Id, bool Trusted);

        public bool AtEnd => _at >= _end;
        public int Offset => _at - _start;

        private void Need(int count)
        {
            if (_at + count > _end) throw new InvalidDataException($"a node at offset {Offset} runs past the end of its stream");
        }

        public byte Byte() { Need(1); return _data[_at++]; }
        public ushort U16() { Need(2); var v = BinaryPrimitives.ReadUInt16LittleEndian(_data.AsSpan(_at)); _at += 2; return v; }
        public uint U32() { Need(4); var v = BinaryPrimitives.ReadUInt32LittleEndian(_data.AsSpan(_at)); _at += 4; return v; }
        public float F32() { Need(4); var v = BinaryPrimitives.ReadSingleLittleEndian(_data.AsSpan(_at)); _at += 4; return v; }
        public ulong FixedUInt64() { Need(8); var v = BinaryPrimitives.ReadUInt64LittleEndian(_data.AsSpan(_at)); _at += 8; return v; }

        public Persisted Node()
        {
            var raw = U16();
            return new Persisted((ushort)(raw & 0x7FFF), (raw & 0x8000) != 0);
        }

        public uint UInt()
        {
            uint value = 0;
            for (int shift = 0; shift < 35; shift += 7)
            {
                byte b = Byte();
                value |= (uint)(b & 0x7F) << shift;
                if ((b & 0x80) == 0) return value;
            }
            throw new InvalidDataException($"a 7-bit encoded integer at offset {Offset} is longer than 5 bytes");
        }

        public string UniqueString()
        {
            uint count = U32();
            if (count > int.MaxValue / 2) throw new InvalidDataException($"a string at offset {Offset} is longer than its stream");
            Need((int)count * 2);
            var s = Encoding.Unicode.GetString(_data, _at, (int)count * 2);
            _at += (int)count * 2;
            return s;
        }

        public string SharedString(TreeBuilder owner) => owner.SharedString(Node().Id);

        public string Constant(TreeBuilder owner)
        {
            byte kind = Byte();
            switch (kind)
            {
                case 1: return "False";
                case 2: return "True";
                case 3: return Float(F32());
                case 4: return ((int)U32()).ToString(CultureInfo.InvariantCulture);
                case 5: return owner.SharedString(Node().Id);
                case 6:
                {
                    float left = F32(), top = F32(), right = F32(), bottom = F32();
                    return left == right && top == bottom ? left == top ? Float(left) : $"{Float(left)},{Float(top)}" : $"{Float(left)},{Float(top)},{Float(right)},{Float(bottom)}";
                }
                case 7:
                {
                    uint unit = U32();
                    float value = F32();
                    return unit switch { 0 => "Auto", 2 => value == 1 ? "*" : $"{Float(value)}*", _ => Float(value) };
                }
                case 8: return $"#{U32():X8}";
                case 9: return UniqueString();
                case 10: return "{x:Null}";
                case 11:
                {
                    var type = U16();
                    return owner.Enum(type, U32());
                }
                default: throw new InvalidDataException($"constant kind {kind} at offset {Offset - 1} is not known");
            }
        }

        private static string Float(float f) => f.ToString("R", CultureInfo.InvariantCulture);
    }
}
