using System.Text;

namespace Corvus.Tests;

/// <summary>Builds a TPI stream record by record; each method returns the new record's type index.</summary>
internal sealed class TpiBuilder
{
    private readonly List<byte[]> _records = [];

    public uint Next => 0x1000 + (uint)_records.Count;

    public uint Add(ushort kind, Action<List<byte>> body)
    {
        _records.Add(PdbBuilder.Record(kind, body));
        return Next - 1;
    }

    /// <summary>Reserves an index, filled later by <see cref="Set"/> (records that refer to later ones).</summary>
    public uint Reserve() => Add(0x1201, b => U32(b, 0));

    public void Set(uint index, ushort kind, Action<List<byte>> body) => _records[(int)(index - 0x1000)] = PdbBuilder.Record(kind, body);

    public static void U16(List<byte> b, int v) => b.AddRange(BitConverter.GetBytes((ushort)v));
    public static void U32(List<byte> b, uint v) => b.AddRange(BitConverter.GetBytes(v));
    public static void Name(List<byte> b, string s) { b.AddRange(Encoding.UTF8.GetBytes(s)); b.Add(0); }

    /// <summary>A field list entry padded to 4 bytes with LF_PAD.</summary>
    private static byte[] Field(Action<List<byte>> body)
    {
        var b = new List<byte>();
        body(b);
        while (b.Count % 4 != 0) b.Add((byte)(0xF0 | (4 - b.Count % 4)));
        return [.. b];
    }

    public static byte[] Member(uint type, int offset, string name) => Field(b => { U16(b, 0x150D); U16(b, 3); U32(b, type); U16(b, offset); Name(b, name); });
    public static byte[] Base(uint type, int offset) => Field(b => { U16(b, 0x1400); U16(b, 3); U32(b, type); U16(b, offset); });
    public static byte[] VfuncTab(uint shape) => Field(b => { U16(b, 0x1409); U16(b, 0); U32(b, shape); });
    public static byte[] Static(uint type, string name) => Field(b => { U16(b, 0x150E); U16(b, 3); U32(b, type); Name(b, name); });
    public static byte[] Enumerate(int value, string name) => Field(b => { U16(b, 0x1502); U16(b, 3); U16(b, value); Name(b, name); });

    public uint FieldList(params byte[][] fields) => Add(0x1203, b => { foreach (var f in fields) b.AddRange(f); });
    public uint Pointer(uint to, int size = 8) => Add(0x1002, b => { U32(b, to); U32(b, 0x0C | ((uint)size << 13)); });
    public uint Const(uint of) => Add(0x1001, b => { U32(b, of); U16(b, 1); });
    public uint Array(uint element, int bytes) => Add(0x1503, b => { U32(b, element); U32(b, 0x23); U16(b, bytes); Name(b, ""); });
    public uint Bitfield(uint type, int length, int position) => Add(0x1205, b => { U32(b, type); b.Add((byte)length); b.Add((byte)position); });
    public uint ArgList(params uint[] types) => Add(0x1201, b => { U32(b, (uint)types.Length); foreach (var t in types) U32(b, t); });
    public uint Procedure(uint ret, uint args, int count) => Add(0x1008, b => { U32(b, ret); b.Add(0); b.Add(0); U16(b, count); U32(b, args); });

    public uint MemberFunction(uint ret, uint cls, uint thisType, uint args, int count) =>
        Add(0x1009, b => { U32(b, ret); U32(b, cls); U32(b, thisType); b.Add(0x0B); b.Add(0); U16(b, count); U32(b, args); U32(b, 0); });

    /// <summary>LF_STRUCTURE (or LF_CLASS); property 0x80 marks a forward reference, 0x200 a unique name.</summary>
    public uint Struct(string name, uint fields, int size, bool forward = false, string? unique = null, bool cls = false) =>
        Add(cls ? (ushort)0x1504 : (ushort)0x1505, b =>
        {
            U16(b, 0); U16(b, (forward ? 0x80 : 0) | (unique != null ? 0x200 : 0)); U32(b, fields); U32(b, 0); U32(b, 0); U16(b, size); Name(b, name);
            if (unique != null) Name(b, unique);
        });

    public uint Union(string name, uint fields, int size) => Add(0x1506, b => { U16(b, 0); U16(b, 0); U32(b, fields); U16(b, size); Name(b, name); });
    public uint Enum(string name, uint underlying, uint fields) => Add(0x1507, b => { U16(b, 0); U16(b, 0); U32(b, underlying); U32(b, fields); Name(b, name); });

    public byte[] Build()
    {
        var tpi = new List<byte>();
        U32(tpi, 20040203); U32(tpi, 56); U32(tpi, 0x1000); U32(tpi, Next); U32(tpi, (uint)_records.Sum(r => r.Length));
        tpi.AddRange(new byte[56 - tpi.Count]);
        foreach (var r in _records) tpi.AddRange(r);
        return [.. tpi];
    }
}

/// <summary>
/// A PDB with types: enum Color (flags-like, declared out of value order), struct Vec, Header (bit fields), union Value,
/// Sensor (nested structs, an array, a self pointer), Team (an array of Sensor), Dup twice (different unique names and
/// sizes), a forward-only Opaque, class Base with a vftable pointer and Derived from it, procedure and member function types,
/// the S_UDT typedef PSensor, and the global g_Team (a Team at rva 0x3010) beside <see cref="PdbBuilder.Sample"/>'s symbols.
/// </summary>
internal static class PdbTypeFixture
{
    public const uint TeamRva = 0x3010;

    /// <param name="globalTwice">g_Team listed twice, as a global in the globals stream and again in its module's stream.</param>
    public static byte[] Pdb(bool globalTwice = false)
    {
        var t = new TpiBuilder();
        uint args = t.Reserve();                                       // 0x1000 (Sensor*, int)
        uint proc = t.Reserve();                                       // 0x1001: the type of Sample's procedures
        uint color = t.Enum("Color", 0x74, t.FieldList(TpiBuilder.Enumerate(4, "Blue"), TpiBuilder.Enumerate(1, "Red"), TpiBuilder.Enumerate(2, "Green")));
        uint vec = t.Struct("Vec", t.FieldList(TpiBuilder.Member(0x40, 0, "x"), TpiBuilder.Member(0x40, 4, "y"), TpiBuilder.Member(0x40, 8, "z")), 12);
        uint urgent = t.Bitfield(0x75, 1, 0), retries = t.Bitfield(0x75, 3, 1);
        uint header = t.Struct("Header", t.FieldList(TpiBuilder.Member(0x21, 0, "magic"), TpiBuilder.Member(0x20, 2, "version"), TpiBuilder.Member(color, 4, "kind"),
            TpiBuilder.Member(urgent, 8, "urgent"), TpiBuilder.Member(retries, 8, "retries")), 12);
        uint value = t.Union("Value", t.FieldList(TpiBuilder.Member(0x74, 0, "i"), TpiBuilder.Member(0x40, 0, "f"), TpiBuilder.Member(vec, 0, "v")), 12);
        uint sensorForward = t.Struct("Sensor", 0, 0, forward: true);
        uint sensorPtr = t.Pointer(sensorForward);
        uint levels = t.Array(0x74, 16);
        uint sensor = t.Struct("Sensor", t.FieldList(TpiBuilder.Member(header, 0, "header"), TpiBuilder.Member(vec, 0xC, "pos"), TpiBuilder.Member(value, 0x18, "val"),
            TpiBuilder.Member(levels, 0x24, "levels"), TpiBuilder.Member(sensorPtr, 0x38, "next")), 0x40);
        uint sensors = t.Array(sensor, 0x100);
        uint team = t.Struct("Team", t.FieldList(TpiBuilder.Member(0x74, 0, "count"), TpiBuilder.Member(sensors, 8, "sensors"), TpiBuilder.Static(0x74, "instances")), 0x108);
        uint dup1 = t.Struct("Dup", t.FieldList(TpiBuilder.Member(0x74, 0, "a")), 4, unique: ".?AUDup@?A0x1@@");
        uint dup2 = t.Struct("Dup", t.FieldList(TpiBuilder.Member(0x13, 0, "b")), 8, unique: ".?AUDup@?A0x2@@");
        uint opaque = t.Struct("Opaque", 0, 0, forward: true);
        uint baseForward = t.Struct("Base", 0, 0, forward: true, cls: true);
        uint baseClass = t.Struct("Base", t.FieldList(TpiBuilder.VfuncTab(0), TpiBuilder.Member(0x74, 8, "a")), 16, cls: true);
        uint derived = t.Struct("Derived", t.FieldList(TpiBuilder.Base(baseClass, 0), TpiBuilder.Member(0x74, 16, "b")), 24, cls: true);
        uint basePtr = t.Pointer(baseForward);
        t.MemberFunction(0x74, baseForward, basePtr, t.ArgList(0x74), 1);
        t.Set(args, 0x1201, b => { TpiBuilder.U32(b, 2); TpiBuilder.U32(b, sensorPtr); TpiBuilder.U32(b, 0x74); });
        t.Set(proc, 0x1008, b => { TpiBuilder.U32(b, 0x74); b.Add(0); b.Add(0); TpiBuilder.U16(b, 2); TpiBuilder.U32(b, args); });

        var pdb = PdbBuilder.Sample();
        foreach (var (type, name) in new[] { (sensorPtr, "PSensor"), (team, "Team"), (derived, "Derived"), (dup1, "Dup"), (dup2, "Dup"), (opaque, "Opaque"), (color, "Color") })
            pdb.GlobalRecords.Add(PdbBuilder.Record(0x1108, b => { TpiBuilder.U32(b, type); TpiBuilder.Name(b, name); }));
        for (int i = 0; i < (globalTwice ? 2 : 1); i++)
            pdb.GlobalRecords.Add(PdbBuilder.Record(0x110D, b => { TpiBuilder.U32(b, team); TpiBuilder.U32(b, TeamRva - 0x3000); TpiBuilder.U16(b, 2); TpiBuilder.Name(b, "g_Team"); }));
        var msf = pdb.Msf();
        msf.Streams[2] = t.Build();
        return msf.Build();
    }

    /// <summary>The fixture PDB and a tiny image it matches, as typed.dll and typed.pdb in <paramref name="dir"/>.</summary>
    public static string Image(TempDir dir, bool globalTwice = false)
    {
        var path = dir.File("typed.dll");
        if (!File.Exists(path))
        {
            File.WriteAllBytes(dir.File("typed.pdb"), Pdb(globalTwice));
            File.WriteAllBytes(path, PdbTests.TinyImage(PdbBuilder.Sample().Guid, 3, "typed.pdb"));
        }
        return path;
    }
}
