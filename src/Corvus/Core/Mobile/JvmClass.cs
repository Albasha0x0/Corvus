using System.Buffers.Binary;
using System.Text;

namespace Corvus.Core.Mobile;

/// <summary>One constant pool entry: <see cref="A"/> and <see cref="B"/> are the indexes or the kind it holds, by tag.</summary>
public readonly record struct JvmConstant(byte Tag, int A, int B, long Bits, string? Text);

/// <summary>An attribute: its name and the range of its bytes in <see cref="JvmClass.Data"/>.</summary>
public readonly record struct JvmAttribute(string Name, int Offset, int Length);

/// <summary>A field or method.</summary>
public sealed record JvmMember(int Access, string Name, string Descriptor, IReadOnlyList<JvmAttribute> Attributes)
{
    public JvmAttribute? Find(string name) => Attributes.Any(a => a.Name == name) ? Attributes.First(a => a.Name == name) : null;
}

/// <summary>
/// A JVM class file (JVMS chapter 4): the constant pool, access flags, names, members and attributes, read without a JVM.
/// Attribute bodies stay as byte ranges, decoded by the reader that needs them.
/// </summary>
public sealed class JvmClass
{
    public const int Utf8 = 1, Integer = 3, Float = 4, Long = 5, Double = 6, Class = 7, String = 8, FieldRef = 9, MethodRef = 10,
        InterfaceMethodRef = 11, NameAndType = 12, MethodHandle = 15, MethodType = 16, Dynamic = 17, InvokeDynamic = 18, Module = 19, Package = 20;

    public const int AccPublic = 0x0001, AccPrivate = 0x0002, AccProtected = 0x0004, AccStatic = 0x0008, AccFinal = 0x0010, AccInterface = 0x0200,
        AccAbstract = 0x0400, AccModule = 0x8000;

    public required byte[] Data { get; init; }
    public required int Minor { get; init; }
    public required int Major { get; init; }
    public required JvmConstant[] Pool { get; init; }
    public required int Access { get; init; }
    public required int ThisIndex { get; init; }
    public required int SuperIndex { get; init; }
    public required int[] InterfaceIndexes { get; init; }
    public required IReadOnlyList<JvmMember> Fields { get; init; }
    public required IReadOnlyList<JvmMember> Methods { get; init; }
    public required IReadOnlyList<JvmAttribute> Attributes { get; init; }

    /// <summary>The internal name (a/b/C).</summary>
    public string Name => ClassName(ThisIndex);
    public string? SuperName => SuperIndex == 0 ? null : ClassName(SuperIndex);
    public IEnumerable<string> Interfaces => InterfaceIndexes.Select(ClassName);

    public JvmAttribute? Find(string name) => Attributes.Any(a => a.Name == name) ? Attributes.First(a => a.Name == name) : null;

    public JvmConstant Entry(int index) =>
        index > 0 && index < Pool.Length && Pool[index].Tag != 0 ? Pool[index] : throw new InvalidDataException($"constant pool index {index} is not an entry");

    public string Utf(int index) => Entry(index) is { Tag: Utf8, Text: { } t } ? t : throw new InvalidDataException($"constant #{index} is not Utf8");

    public string ClassName(int index) => Entry(index) is { Tag: Class } c ? Utf(c.A) : throw new InvalidDataException($"constant #{index} is not a Class");

    public int U2(int offset) => BinaryPrimitives.ReadUInt16BigEndian(Data.AsSpan(offset));
    public int S4(int offset) => BinaryPrimitives.ReadInt32BigEndian(Data.AsSpan(offset));

    /// <summary>The source file named by the SourceFile attribute.</summary>
    public string? SourceFile => Find("SourceFile") is { } a && a.Length >= 2 ? Utf(U2(a.Offset)) : null;

    public static bool IsClassFile(ReadOnlySpan<byte> head) => head.Length >= 10 && BinaryPrimitives.ReadUInt32BigEndian(head) == 0xCAFEBABE
        && BinaryPrimitives.ReadUInt16BigEndian(head[6..]) is >= 45 and < 100;

    public static JvmClass Read(byte[] data)
    {
        var r = new Reader(data);
        if ((uint)r.U4() != 0xCAFEBABE) throw new InvalidDataException("not a class file (no 0xCAFEBABE)");
        int minor = r.U2(), major = r.U2();
        int count = r.U2();
        var pool = new JvmConstant[count];
        for (int i = 1; i < count; i++)
        {
            byte tag = r.U1();
            switch (tag)
            {
                case Utf8:
                    int length = r.U2();
                    pool[i] = new JvmConstant(tag, 0, 0, 0, ModifiedUtf8(r.Bytes(length)));
                    break;
                case Integer or Float: pool[i] = new JvmConstant(tag, 0, 0, (uint)r.U4(), null); break;
                case Long or Double:
                    long hi = (uint)r.U4(), lo = (uint)r.U4();
                    pool[i] = new JvmConstant(tag, 0, 0, (hi << 32) | lo, null);
                    i++; // takes two slots
                    break;
                case Class or String or MethodType or Module or Package: pool[i] = new JvmConstant(tag, r.U2(), 0, 0, null); break;
                case MethodHandle: pool[i] = new JvmConstant(tag, r.U1(), r.U2(), 0, null); break;
                case FieldRef or MethodRef or InterfaceMethodRef or NameAndType or Dynamic or InvokeDynamic:
                    pool[i] = new JvmConstant(tag, r.U2(), r.U2(), 0, null);
                    break;
                default: throw new InvalidDataException($"constant #{i} has unknown tag {tag}");
            }
        }
        int access = r.U2(), self = r.U2(), super = r.U2();
        var interfaces = new int[r.U2()];
        for (int i = 0; i < interfaces.Length; i++) interfaces[i] = r.U2();
        var fields = Members(r, pool);
        var methods = Members(r, pool);
        var attributes = Attrs(r, pool);
        return new JvmClass
        {
            Data = data, Minor = minor, Major = major, Pool = pool, Access = access, ThisIndex = self, SuperIndex = super,
            InterfaceIndexes = interfaces, Fields = fields, Methods = methods, Attributes = attributes,
        };
    }

    private static List<JvmMember> Members(Reader r, JvmConstant[] pool)
    {
        var list = new List<JvmMember>(r.Peek2());
        for (int i = 0, n = r.U2(); i < n; i++)
        {
            int access = r.U2(), name = r.U2(), descriptor = r.U2();
            list.Add(new JvmMember(access, Text(pool, name), Text(pool, descriptor), Attrs(r, pool)));
        }
        return list;
    }

    private static List<JvmAttribute> Attrs(Reader r, JvmConstant[] pool)
    {
        var list = new List<JvmAttribute>();
        for (int i = 0, n = r.U2(); i < n; i++)
        {
            var name = Text(pool, r.U2());
            int length = r.U4();
            if (length < 0) throw new InvalidDataException($"attribute {name} is longer than 2 GB");
            list.Add(new JvmAttribute(name, r.Position, length));
            r.Skip(length);
        }
        return list;
    }

    private static string Text(JvmConstant[] pool, int index) =>
        index > 0 && index < pool.Length && pool[index] is { Tag: Utf8, Text: { } t } ? t : throw new InvalidDataException($"constant #{index} is not Utf8");

    /// <summary>JVM modified UTF-8: U+0000 as two bytes, supplementary characters as two three-byte surrogates.</summary>
    public static string ModifiedUtf8(ReadOnlySpan<byte> bytes)
    {
        if (!bytes.ContainsAnyExceptInRange((byte)1, (byte)0x7F)) return Encoding.ASCII.GetString(bytes);
        var sb = new StringBuilder(bytes.Length);
        for (int i = 0; i < bytes.Length;)
        {
            int b = bytes[i];
            if (b < 0x80) { sb.Append((char)b); i++; }
            else if ((b & 0xE0) == 0xC0 && i + 1 < bytes.Length) { sb.Append((char)(((b & 0x1F) << 6) | (bytes[i + 1] & 0x3F))); i += 2; }
            else if ((b & 0xF0) == 0xE0 && i + 2 < bytes.Length) { sb.Append((char)(((b & 0x0F) << 12) | ((bytes[i + 1] & 0x3F) << 6) | (bytes[i + 2] & 0x3F))); i += 3; }
            else throw new InvalidDataException($"malformed modified UTF-8 at byte {i}");
        }
        return sb.ToString();
    }

    private sealed class Reader(byte[] data)
    {
        public int Position { get; private set; }

        private ReadOnlySpan<byte> Take(int n)
        {
            if (n < 0 || Position + n > data.Length) throw new InvalidDataException($"class file ends at {data.Length}, read of {n} bytes at {Position}");
            var span = data.AsSpan(Position, n);
            Position += n;
            return span;
        }

        public byte U1() => Take(1)[0];
        public int U2() => BinaryPrimitives.ReadUInt16BigEndian(Take(2));
        public int Peek2() => Position + 2 <= data.Length ? BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(Position)) : 0;
        public int U4() => BinaryPrimitives.ReadInt32BigEndian(Take(4));
        public ReadOnlySpan<byte> Bytes(int n) => Take(n);
        public void Skip(int n) => Take(n);
    }
}
