using System.Buffers.Binary;
using System.Text;

namespace Corvus.Core.Flash;

/// <summary>An ActionScript 3 bytecode block (ABC) per the AVM2 Overview; names read "namespace:local", a private namespace "private".</summary>
internal sealed class AbcFile
{
    /// <summary>A trait: its name, kind (slot, method, getter, setter, class, function, const) and, for a method, its method index.</summary>
    public sealed record Trait(string Name, string Kind, int Method);

    /// <summary>A class: name, base class (null for none), interfaces, flags (sealed, final, interface), constructor and static initializer methods, instance and static traits.</summary>
    public sealed record Class(string Name, string? Super, IReadOnlyList<string> Interfaces, bool IsInterface, bool IsFinal, bool IsSealed,
        int Constructor, int StaticInitializer, IReadOnlyList<Trait> Traits, IReadOnlyList<Trait> StaticTraits);

    /// <summary>A method body: the method it implements, stack and scope sizes, local count, where its code starts in the block, and its length.</summary>
    public sealed record Body(int Method, int MaxStack, int Locals, int CodeAt, int CodeLength, int Exceptions);

    public required int Minor { get; init; }
    public required int Major { get; init; }
    public required int[] Integers { get; init; }
    public required uint[] Unsigned { get; init; }
    public required double[] Doubles { get; init; }
    public required string[] Strings { get; init; }
    public required int Namespaces { get; init; }
    public required int NamespaceSets { get; init; }
    public required string[] Multinames { get; init; }
    /// <summary>Each method's name (empty when the block names none).</summary>
    public required string[] Methods { get; init; }
    public required int Metadata { get; init; }
    public required List<Class> Classes { get; init; }
    public required int Scripts { get; init; }
    public required List<Body> Bodies { get; init; }

    private const int MaxCount = 1 << 22;

    /// <summary>Reads a block; throws <see cref="InvalidDataException"/> when a count or index runs past the bytes.</summary>
    public static AbcFile Read(ReadOnlySpan<byte> abc)
    {
        var r = new Reader(abc);
        int minor = r.U16(), major = r.U16();
        var ints = new int[Math.Max(1, r.Count())];
        for (int i = 1; i < ints.Length; i++) ints[i] = r.S32();
        var uints = new uint[Math.Max(1, r.Count())];
        for (int i = 1; i < uints.Length; i++) uints[i] = (uint)r.U32();
        var doubles = new double[Math.Max(1, r.Count())];
        for (int i = 1; i < doubles.Length; i++) doubles[i] = r.Double();
        var strings = new string[Math.Max(1, r.Count())];
        strings[0] = "";
        for (int i = 1; i < strings.Length; i++) strings[i] = r.Utf8(r.Count());
        var nsKind = new byte[Math.Max(1, r.Count())];
        var nsName = new string[nsKind.Length];
        nsName[0] = "*";
        for (int i = 1; i < nsKind.Length; i++)
        {
            nsKind[i] = r.U8();
            int s = r.Index(strings.Length);
            // A private namespace (0x05) prints as "private" whatever its name.
            nsName[i] = nsKind[i] == 0x05 ? "private" : strings[s];
        }
        var sets = new int[Math.Max(1, r.Count())][];
        int nsSets = sets.Length;
        sets[0] = [];
        for (int i = 1; i < nsSets; i++)
        {
            sets[i] = new int[r.Count()];
            for (int k = 0; k < sets[i].Length; k++) sets[i][k] = r.Index(nsKind.Length);
        }
        var multinames = new string[Math.Max(1, r.Count())];
        multinames[0] = "*";
        var typeParams = new List<(int At, int Base, int[] Params)>();
        for (int i = 1; i < multinames.Length; i++)
        {
            byte kind = r.U8();
            switch (kind)
            {
                case 0x07 or 0x0D:
                    int ns = r.Index(nsKind.Length), name = r.Index(strings.Length);
                    multinames[i] = nsName[ns] + ":" + strings[name];
                    break;
                case 0x0F or 0x10:
                    multinames[i] = strings[r.Index(strings.Length)];
                    break;
                case 0x11 or 0x12:
                    multinames[i] = "*";
                    break;
                case 0x09 or 0x0E:
                    string local = strings[r.Index(strings.Length)];
                    // A set of one namespace names the type as a QName would.
                    multinames[i] = sets[r.Index(nsSets)] is [int only] ? nsName[only] + ":" + local : local;
                    break;
                case 0x1B or 0x1C:
                    r.Index(nsSets);
                    multinames[i] = "*";
                    break;
                case 0x1D:
                    int baseName = r.Count();
                    var ps = new int[r.Count()];
                    for (int k = 0; k < ps.Length; k++) ps[k] = r.Count();
                    typeParams.Add((i, baseName, ps));
                    multinames[i] = "";
                    break;
                default:
                    throw new InvalidDataException($"multiname {i}: unknown kind 0x{kind:X2}");
            }
        }
        // A type name (Vector.<T>) refers to multinames by index, earlier or later ones.
        foreach (var (at, baseName, ps) in typeParams)
            multinames[at] = (baseName < multinames.Length ? multinames[baseName] : "?") + ".<" + string.Join(",", ps.Select(p => p < multinames.Length ? multinames[p] : "?")) + ">";
        var methods = new string[r.Count()];
        for (int i = 0; i < methods.Length; i++)
        {
            int parameters = r.Count();
            r.Index(multinames.Length);
            for (int k = 0; k < parameters; k++) r.Index(multinames.Length);
            methods[i] = strings[r.Index(strings.Length)];
            byte flags = r.U8();
            if ((flags & 0x08) != 0)
            {
                int options = r.Count();
                for (int k = 0; k < options; k++) { r.Count(); r.U8(); }
            }
            if ((flags & 0x80) != 0)
                for (int k = 0; k < parameters; k++) r.Index(strings.Length);
        }
        int metadata = r.Count();
        for (int i = 0; i < metadata; i++)
        {
            r.Index(strings.Length);
            int items = r.Count();
            for (int k = 0; k < 2 * items; k++) r.Index(strings.Length);
        }
        int classCount = r.Count();
        var instances = new (string Name, string? Super, string[] Interfaces, byte Flags, int Init, List<Trait> Traits)[classCount];
        for (int i = 0; i < classCount; i++)
        {
            string name = multinames[r.Index(multinames.Length)];
            int super = r.Index(multinames.Length);
            byte flags = r.U8();
            if ((flags & 0x08) != 0) r.Index(nsKind.Length);
            var interfaces = new string[r.Count()];
            for (int k = 0; k < interfaces.Length; k++) interfaces[k] = multinames[r.Index(multinames.Length)];
            int init = r.Index(methods.Length);
            instances[i] = (name, super == 0 ? null : multinames[super], interfaces, flags, init, Traits(ref r, multinames, methods.Length, metadata));
        }
        var classes = new List<Class>(classCount);
        for (int i = 0; i < classCount; i++)
        {
            int cinit = r.Index(methods.Length);
            var statics = Traits(ref r, multinames, methods.Length, metadata);
            var x = instances[i];
            classes.Add(new Class(x.Name, x.Super, x.Interfaces, (x.Flags & 0x04) != 0, (x.Flags & 0x02) != 0, (x.Flags & 0x01) != 0, x.Init, cinit, x.Traits, statics));
        }
        int scripts = r.Count();
        for (int i = 0; i < scripts; i++)
        {
            r.Index(methods.Length);
            Traits(ref r, multinames, methods.Length, metadata);
        }
        var bodies = new List<Body>(Math.Min(r.Remaining, 1 << 16));
        int bodyCount = r.Count();
        for (int i = 0; i < bodyCount; i++)
        {
            int method = r.Index(methods.Length);
            int maxStack = r.Count(), locals = r.Count();
            r.Count();
            r.Count();
            int length = r.Count();
            int at = r.Skip(length);
            int exceptions = r.Count();
            for (int k = 0; k < exceptions; k++) { r.Count(); r.Count(); r.Count(); r.Index(multinames.Length); r.Index(multinames.Length); }
            Traits(ref r, multinames, methods.Length, metadata);
            bodies.Add(new Body(method, maxStack, locals, at, length, exceptions));
        }
        return new AbcFile
        {
            Minor = minor, Major = major, Integers = ints, Unsigned = uints, Doubles = doubles, Strings = strings, Namespaces = nsKind.Length,
            NamespaceSets = nsSets, Multinames = multinames, Methods = methods, Metadata = metadata, Classes = classes, Scripts = scripts, Bodies = bodies,
        };
    }

    private static List<Trait> Traits(ref Reader r, string[] multinames, int methods, int metadata)
    {
        int count = r.Count();
        var traits = new List<Trait>(Math.Min(count, 4096));
        for (int i = 0; i < count; i++)
        {
            string name = multinames[r.Index(multinames.Length)];
            byte kind = r.U8();
            int method = -1;
            string label;
            switch (kind & 0x0F)
            {
                case 0 or 6:
                    label = (kind & 0x0F) == 0 ? "slot" : "const";
                    r.Count();
                    r.Index(multinames.Length);
                    if (r.Count() != 0) r.U8();
                    break;
                case 1 or 2 or 3:
                    label = (kind & 0x0F) switch { 1 => "method", 2 => "getter", _ => "setter" };
                    r.Count();
                    method = r.Index(methods);
                    break;
                case 4:
                    label = "class";
                    r.Count();
                    r.Count();
                    break;
                case 5:
                    label = "function";
                    r.Count();
                    method = r.Index(methods);
                    break;
                default:
                    throw new InvalidDataException($"trait {name}: unknown kind 0x{kind:X2}");
            }
            if ((kind & 0x40) != 0)
            {
                int n = r.Count();
                for (int k = 0; k < n; k++) r.Index(metadata);
            }
            traits.Add(new Trait(name, label, method));
        }
        return traits;
    }

    /// <summary>The variable-length integers of ABC (u30, s32, u32), little-endian groups of 7 bits.</summary>
    private ref struct Reader(ReadOnlySpan<byte> b)
    {
        private readonly ReadOnlySpan<byte> _b = b;
        private int _p;

        public readonly int Remaining => _b.Length - _p;

        public byte U8() => _p < _b.Length ? _b[_p++] : throw new InvalidDataException($"the block ends at 0x{_p:X}");

        public int U16()
        {
            if (_p + 2 > _b.Length) throw new InvalidDataException("the block ends in its header");
            int v = BinaryPrimitives.ReadUInt16LittleEndian(_b[_p..]);
            _p += 2;
            return v;
        }

        public long U32()
        {
            long v = 0;
            for (int shift = 0; shift < 35; shift += 7)
            {
                byte x = U8();
                v |= (long)(x & 0x7F) << shift;
                if ((x & 0x80) == 0) break;
            }
            return v & 0xFFFFFFFF;
        }

        public int S32()
        {
            long v = 0;
            int shift = 0;
            byte x;
            do
            {
                x = U8();
                v |= (long)(x & 0x7F) << shift;
                shift += 7;
            }
            while ((x & 0x80) != 0 && shift < 35);
            // Sign-extend from the last bit read.
            if (shift < 32 && (x & 0x40) != 0) v |= -1L << shift;
            return (int)v;
        }

        /// <summary>A count, bounded by the bytes left so a damaged block cannot ask for more entries than it holds.</summary>
        public int Count()
        {
            long v = U32();
            if (v > MaxCount || v > (long)Remaining * 8 + 8) throw new InvalidDataException($"a count of {v:N0} at 0x{_p:X} runs past the block");
            return (int)v;
        }

        /// <summary>An index below <paramref name="limit"/>.</summary>
        public int Index(int limit)
        {
            long v = U32();
            return v < limit ? (int)v : throw new InvalidDataException($"index {v:N0} at 0x{_p:X} is past its table of {limit:N0}");
        }

        public double Double()
        {
            if (_p + 8 > _b.Length) throw new InvalidDataException($"the block ends at 0x{_p:X}");
            double v = BinaryPrimitives.ReadDoubleLittleEndian(_b[_p..]);
            _p += 8;
            return v;
        }

        public string Utf8(int length)
        {
            if (_p + length > _b.Length) throw new InvalidDataException($"a string at 0x{_p:X} runs past the block");
            var s = Encoding.UTF8.GetString(_b.Slice(_p, length));
            _p += length;
            return s;
        }

        public int Skip(int length)
        {
            if (_p + length > _b.Length) throw new InvalidDataException($"code at 0x{_p:X} runs past the block");
            int at = _p;
            _p += length;
            return at;
        }
    }
}
