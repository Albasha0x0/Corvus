using System.Buffers.Binary;
using System.Text;
using Corvus.Services;

namespace Corvus.Tests;

/// <summary>Builds XBF 2.1 files in the XAML compiler's layout.</summary>
internal sealed class XbfWriter
{
    public const string Presentation = "http://schemas.microsoft.com/winfx/2006/xaml/presentation";
    public const string Xaml = "http://schemas.microsoft.com/winfx/2006/xaml";

    private readonly List<string> _strings = [];
    private readonly List<(uint Kind, uint Name)> _assemblies = [];
    private readonly List<(uint Assembly, uint Name)> _typeNamespaces = [];
    private readonly List<(uint Flags, uint Namespace, uint Name)> _types = [];
    private readonly List<(uint Flags, uint Type, uint Name)> _properties = [];
    private readonly List<uint> _xmlNamespaces = [];
    public readonly List<Nodes> Streams = [];

    public int Major { get; init; } = 2;
    public int Minor { get; init; } = 1;

    public XbfWriter() => Streams.Add(new Nodes(this));

    public Nodes Main => Streams[0];

    /// <summary>A new node stream for deferred content, and its index.</summary>
    public (Nodes Nodes, uint Index) Stream()
    {
        Streams.Add(new Nodes(this));
        return (Streams[^1], (uint)Streams.Count - 1);
    }

    public ushort String(string s)
    {
        int i = _strings.IndexOf(s);
        if (i < 0) { _strings.Add(s); i = _strings.Count - 1; }
        return (ushort)i;
    }

    public ushort XmlNamespace(string uri)
    {
        var s = String(uri);
        int i = _xmlNamespaces.IndexOf(s);
        if (i < 0) { _xmlNamespaces.Add(s); i = _xmlNamespaces.Count - 1; }
        return (ushort)i;
    }

    /// <summary>A system XAML type by its stable index, found by name in the reader's table.</summary>
    public static ushort Known(string type)
    {
        for (int i = 1; i < 2000; i++)
            if (XbfIndexes.Type(i) == type) return (ushort)(i | 0x8000);
        throw new ArgumentException($"no stable type {type}");
    }

    /// <summary>A system XAML property by its stable index ("Owner.Name").</summary>
    public static ushort KnownProperty(string property)
    {
        for (int i = 1; i < 4000; i++)
            if (XbfIndexes.Property(i)?.TrimEnd('*') == property) return (ushort)(i | 0x8000);
        throw new ArgumentException($"no stable property {property}");
    }

    /// <summary>An app type in the type table: CLR namespace, name and assembly.</summary>
    public ushort Type(string clrNamespace, string name, string assembly)
    {
        _assemblies.Add((2, String(assembly)));
        _typeNamespaces.Add(((uint)_assemblies.Count - 1, String(clrNamespace)));
        _types.Add((0, (uint)_typeNamespaces.Count - 1, String(name)));
        return (ushort)(_types.Count - 1);
    }

    /// <summary>A property of an app type in the property table.</summary>
    public ushort Property(ushort type, string name, uint flags = 0)
    {
        _properties.Add((flags, type, String(name)));
        return (ushort)(_properties.Count - 1);
    }

    public byte[] Build()
    {
        var meta = new List<byte>();
        void U32(List<byte> to, uint v) { Span<byte> b = stackalloc byte[4]; BinaryPrimitives.WriteUInt32LittleEndian(b, v); to.AddRange(b.ToArray()); }
        void U64(List<byte> to, ulong v) { Span<byte> b = stackalloc byte[8]; BinaryPrimitives.WriteUInt64LittleEndian(b, v); to.AddRange(b.ToArray()); }
        // The metadata section counts from offset 12: version, six table offsets, the 64-byte hash, then the tables.
        var tables = new List<byte>();
        long[] offsets = new long[6];
        const int TablesAt = 8 + 48 + 64;
        offsets[0] = TablesAt;
        U32(tables, (uint)_strings.Count);
        foreach (var s in _strings)
        {
            U32(tables, (uint)s.Length);
            tables.AddRange(Encoding.Unicode.GetBytes(s));
            if (Major == 2 && Minor >= 1) tables.AddRange([0, 0]);
        }
        offsets[1] = TablesAt + tables.Count;
        U32(tables, (uint)_assemblies.Count);
        foreach (var (k, n) in _assemblies) { U32(tables, k); U32(tables, n); }
        offsets[2] = TablesAt + tables.Count;
        U32(tables, (uint)_typeNamespaces.Count);
        foreach (var (a, n) in _typeNamespaces) { U32(tables, a); U32(tables, n); }
        offsets[3] = TablesAt + tables.Count;
        U32(tables, (uint)_types.Count);
        foreach (var (f, ns, n) in _types) { U32(tables, f); U32(tables, ns); U32(tables, n); }
        offsets[4] = TablesAt + tables.Count;
        U32(tables, (uint)_properties.Count);
        foreach (var (f, t, n) in _properties) { U32(tables, f); U32(tables, t); U32(tables, n); }
        offsets[5] = TablesAt + tables.Count;
        U32(tables, (uint)_xmlNamespaces.Count);
        foreach (var x in _xmlNamespaces) U32(tables, x);
        U32(meta, (uint)Major);
        U32(meta, (uint)Minor);
        foreach (var o in offsets) U64(meta, (ulong)o);
        meta.AddRange(Encoding.ASCII.GetBytes(new string('0', 64)));
        meta.AddRange(tables);

        var nodes = new List<byte>();
        U32(nodes, (uint)Streams.Count);
        var body = new List<byte>();
        foreach (var s in Streams)
        {
            U32(nodes, (uint)body.Count);
            body.AddRange(s.Bytes);
            // No line information: the line stream of each node stream is empty.
            U32(nodes, (uint)body.Count);
        }
        nodes.AddRange(body);

        var file = new List<byte>(Encoding.ASCII.GetBytes("XBF\0"));
        U32(file, (uint)meta.Count);
        U32(file, (uint)nodes.Count);
        file.AddRange(meta);
        file.AddRange(nodes);
        return [.. file];
    }

    /// <summary>One node stream: object writer nodes and their constants.</summary>
    internal sealed class Nodes(XbfWriter owner)
    {
        public readonly List<byte> Bytes = [];

        public int Offset => Bytes.Count;

        public Nodes Op(byte op) { Bytes.Add(op); return this; }
        public Nodes U16(ushort v) { Bytes.Add((byte)v); Bytes.Add((byte)(v >> 8)); return this; }
        public Nodes U32(uint v) { Span<byte> b = stackalloc byte[4]; BinaryPrimitives.WriteUInt32LittleEndian(b, v); Bytes.AddRange(b.ToArray()); return this; }
        public Nodes U64Fixed(ulong v) { Span<byte> b = stackalloc byte[8]; BinaryPrimitives.WriteUInt64LittleEndian(b, v); Bytes.AddRange(b.ToArray()); return this; }
        public Nodes F32(float v) { Span<byte> b = stackalloc byte[4]; BinaryPrimitives.WriteSingleLittleEndian(b, v); Bytes.AddRange(b.ToArray()); return this; }
        public Nodes UInt(uint v)
        {
            do { byte b = (byte)(v & 0x7F); v >>= 7; Bytes.Add(v != 0 ? (byte)(b | 0x80) : b); } while (v != 0);
            return this;
        }
        public Nodes Unique(string s) { U32((uint)s.Length); Bytes.AddRange(Encoding.Unicode.GetBytes(s)); return this; }
        public Nodes Shared(string s) => U16(owner.String(s));

        public Nodes Str(string s) => Op(5).Shared(s);
        public Nodes Float(float f) => Op(3).F32(f);
        public Nodes Int(int i) => Op(4).U32((uint)i);
        public Nodes Bool(bool b) => Op(b ? (byte)2 : (byte)1);
        public Nodes Thickness(float l, float t, float r, float b) => Op(6).F32(l).F32(t).F32(r).F32(b);
        public Nodes GridLength(uint unit, float value) => Op(7).U32(unit).F32(value);
        public Nodes Color(uint argb) => Op(8).U32(argb);
        public Nodes Enum(string type, uint value) => Op(11).U16((ushort)(Known(type) & 0x7FFF)).U32(value);

        public Nodes PushScopeAddNamespace(string uri, string prefix) => Op(18).U16(owner.XmlNamespace(uri)).Unique(prefix);
        public Nodes AddNamespace(string uri, string prefix) => Op(3).U16(owner.XmlNamespace(uri)).Unique(prefix);
        public Nodes CreateType(ushort type) => Op(23).U16(type);
        public Nodes PushScopeCreateType(ushort type) => Op(20).U16(type);
        public Nodes PushScopeCreateTypeWithConstant(ushort type) => Op(21).U16(type);
        public Nodes CheckPeerType(string className) => Op(11).Unique(className);
        public Nodes ConnectionId(int id) => Op(12).Int(id);
        public Nodes Name(string name) => Op(13).Str(name);
        public Nodes Uid(string uid) => Op(14).Str(uid);
        public Nodes GetValue(ushort property) => Op(19).U16(property);
        public Nodes SetValueConstant(ushort property) => Op(26).U16(property);
        public Nodes SetValueType(ushort property, ushort type) => Op(29).U16(property).U16(type);
        public Nodes SetValueProperty(ushort property, ushort value) => Op(28).U16(property).U16(value);
        public Nodes StaticResource(ushort property, string key) => Op(30).U16(property).Str(key);
        public Nodes ThemeResource(ushort property, string key) => Op(36).U16(property).Str(key);
        public Nodes TemplateBinding(ushort property, ushort source) => Op(31).U16(property).U16(source);
        public Nodes SetValue(ushort property) => Op(7).U16(property);
        public Nodes EndInitPopScope() => Op(33);
        public Nodes PopScope() => Op(2);
        public Nodes AddToCollection() => Op(8);
        public Nodes AddToDictionaryWithKey(string key) => Op(10).Str(key);
        public Nodes BeginConditional(ushort predicate, string arguments) => Op(38).U16(predicate).Shared(arguments);
        public Nodes EndConditional() => Op(39);
        public Nodes DeferredProperty(ushort property, uint stream) => Op(17).U16(property).UInt(stream).UInt(0).UInt(0);

        /// <summary>SetCustomRuntimeData: the deferred stream, no pre-resolved resources, then the data's kind.</summary>
        public Nodes CustomData(uint stream, uint kind) => Op(15).UInt(stream).UInt(0).UInt(0).UInt(kind);
    }
}
