using Corvus.Native.NativeAot;
using W = Corvus.Tests.NativeAotMetadataWriter;

namespace Corvus.Tests;

public class NativeAotMetadataTests
{
    /// <summary>Handles of the sample model written by <see cref="Model"/>.</summary>
    internal sealed record Sample(byte[] Blob, NativeAotFormat Format, MdHandle Dog, MdHandle Inner, MdHandle Speak, MdHandle Int32,
        MdHandle BoxOfInt, MdHandle DogArray, MdHandle GetRef, MdHandle GetInst, MdHandle Qualified, MdHandle Signature, MdHandle Pointer)
    {
        public W Writer { get; init; } = null!;
        public MdHandle Box { get; init; }
        public MdHandle Object { get; init; }
        public MdHandle String { get; init; }
        /// <summary>With statics: the name string of Dog::.cctor.</summary>
        public MdHandle CctorName { get; init; }
    }

    /// <summary>
    /// Scope "app": namespace Sample.Zoo with Dog (method Speak(int, Sample.Zoo.Dog[])), Box`1 and Box`1+Inner;
    /// reference System.Int32; specs Box&lt;int&gt;, Dog[], int*; MemberReference Box&lt;int&gt;::Get(); instantiation Get&lt;int&gt;.
    /// </summary>
    internal static Sample Model(ushort major, bool statics = false)
    {
        var w = new W(major);
        bool net11 = w.Format.Metadata == MetadataDialect.Net11;
        // Parents are written after their children: forward references, typed or as handles (.NET 11 TypeDefinition).
        var zoo = (T: new W.Fwd(), H: new W.Fwd { Record = MdRecord.NamespaceDefinition });
        var boxParent = (T: new W.Fwd(), H: new W.Fwd { Record = MdRecord.TypeDefinition });
        var sampleParent = new W.Fwd { Record = MdRecord.NamespaceDefinition };
        var rootParent = new W.Fwd { Record = MdRecord.NamespaceDefinition };
        var scopeParent = new W.Fwd { Record = MdRecord.ScopeDefinition };

        MdHandle Type(string name, bool nested, uint[] nestedTypes, uint[] methods, uint[]? fields = null) => net11
            ? w.Record(MdRecord.TypeDefinition, 0u, default(MdHandle), nested ? boxParent.H : zoo.H, w.String(name), 0u, 0u,
                nestedTypes, methods, fields, null, null, null, null, null)
            : w.Record(MdRecord.TypeDefinition, 0u, default(MdHandle), nested ? 0u : zoo.T, w.String(name), 0u, 0u, nested ? boxParent.T : 0u,
                nestedTypes, methods, fields, null, null, null, null, null);

        var corlib = w.Record(MdRecord.ScopeReference, 0u, w.String("System.Runtime"), 8u, 0u, 0u, 0u, null, 0u);
        var system = w.Record(MdRecord.NamespaceReference, corlib, w.String("System"));
        var int32 = w.Record(MdRecord.TypeReference, system, w.String("Int32"));
        var objectRef = w.Record(MdRecord.TypeReference, system, w.String("Object"));
        var stringRef = w.Record(MdRecord.TypeReference, system, w.String("String"));
        var pointer = w.Record(MdRecord.TypeSpecification, w.Record(MdRecord.PointerSignature, int32));

        var inner = Type("Inner", true, [], []);
        var box = Type("Box`1", false, [inner.Offset], []);
        boxParent.T.Value = boxParent.H.Value = box.Offset;
        var dogRef = new W.Fwd { Record = MdRecord.TypeDefinition };
        var dogArray = w.Record(MdRecord.TypeSpecification, w.Record(MdRecord.SZArraySignature, dogRef));
        var speakSig = w.Record(MdRecord.MethodSignature, 0x20u, 0, pointer, new[] { int32, dogArray }, null);
        var speak = w.Record(MdRecord.Method, 0x86u, 0u, w.String("Speak"), speakSig, null, null, null);
        // Statics: static string Name; const int Max (no storage); static int Count.
        uint[]? fields = null;
        var cctorName = statics ? w.String(".cctor") : default;
        if (statics)
        {
            MdHandle Field(int flags, string name, MdHandle type) =>
                w.Record(MdRecord.Field, (uint)flags, w.String(name), w.Record(MdRecord.FieldSignature, type), default(MdHandle), 0u, null);
            fields = [Field(0x16, "Name", stringRef).Offset, Field(0x56, "Max", int32).Offset, Field(0x16, "Count", int32).Offset, Field(0x06, "legs", int32).Offset];
        }
        var dog = Type("Dog", false, [], [speak.Offset], fields);
        dogRef.Value = dog.Offset;

        var boxOfInt = w.Record(MdRecord.TypeSpecification, w.Record(MdRecord.TypeInstantiationSignature, box, new[] { int32 }));
        var getRef = w.Record(MdRecord.MemberReference, boxOfInt, w.String("Get"), w.Record(MdRecord.MethodSignature, 0x20u, 0, int32, null, null));
        var getInst = w.Record(MdRecord.MethodInstantiation, getRef, new[] { int32 });
        var qualified = w.Record(MdRecord.QualifiedMethod, speak.Offset, dog.Offset);

        var zooNs = w.Record(MdRecord.NamespaceDefinition, sampleParent, w.String("Zoo"), new[] { dog.Offset, box.Offset }, null, null);
        zoo.T.Value = zoo.H.Value = zooNs.Offset;
        var sample = w.Record(MdRecord.NamespaceDefinition, rootParent, w.String("Sample"), null, null, new[] { zooNs.Offset });
        sampleParent.Value = sample.Offset;
        var root = w.Record(MdRecord.NamespaceDefinition, scopeParent, 0u, null, null, new[] { sample.Offset });
        rootParent.Value = root.Offset;
        var scope = w.Record(MdRecord.ScopeDefinition, 0u, w.String("app"), 0u, 1u, 0u, 0u, 0u, null, 0u, root.Offset, 0u, 0u, null, 0u, null, null);
        scopeParent.Value = scope.Offset;
        w.AddScope(scope);
        return new Sample(w.ToArray(), w.Format, dog, inner, speak, int32, boxOfInt, dogArray, getRef, getInst, qualified, speakSig, pointer)
        {
            Writer = w,
            Box = box,
            Object = objectRef,
            String = stringRef,
            CctorName = cctorName,
        };
    }

    public static readonly TheoryData<ushort> Majors = new() { 8, 9, 10, 16, 31 };

    [Theory]
    [MemberData(nameof(Majors))]
    public void TypeNames_InEachDialect(ushort major)
    {
        var m = Model(major);
        var md = new NativeAotMetadata(m.Blob, m.Format);
        Assert.Single(md.ScopeDefinitions);
        Assert.Equal("Sample.Zoo.Dog", md.FormatType(m.Dog));
        Assert.Equal("Sample.Zoo.Box`1+Inner", md.FormatType(m.Inner));
        Assert.Equal("System.Int32", md.FormatType(m.Int32));
        Assert.Equal("Sample.Zoo.Box<int>", md.FormatType(m.BoxOfInt));
        Assert.Equal("Sample.Zoo.Dog[]", md.FormatType(m.DogArray));
        Assert.Equal("int*", md.FormatType(m.Pointer));
        Assert.Equal("(int, Sample.Zoo.Dog[])", md.FormatSignature(m.Signature.Offset));
    }

    [Theory]
    [MemberData(nameof(Majors))]
    public void MethodNames_InEachDialect(ushort major)
    {
        var m = Model(major);
        var md = new NativeAotMetadata(m.Blob, m.Format);
        Assert.Equal("Sample.Zoo.Dog::Speak(int, Sample.Zoo.Dog[])", md.FormatMethod(m.Speak).Full);
        Assert.Equal("Sample.Zoo.Dog::Speak(int, Sample.Zoo.Dog[])", md.FormatMethod(m.Qualified).Full);
        Assert.Equal("Sample.Zoo.Box<int>::Get()", md.FormatMethod(m.GetRef).Full);
        Assert.Equal("Sample.Zoo.Box<int>::Get<int>()", md.FormatMethod(m.GetInst).Full);
        Assert.Equal(3, md.TypeDefinitions().Count);
    }

    [Theory]
    [MemberData(nameof(Majors))]
    public void Tokens_UseTheDialectShift(ushort major)
    {
        var m = Model(major);
        var md = new NativeAotMetadata(m.Blob, m.Format);
        uint token = m.Writer.Token(m.Dog);
        Assert.Equal(m.Dog, md.FromToken(token));
        Assert.Equal(major >= 16 ? 25 : 24, m.Format.TokenShift);
    }

    [Fact]
    public void HandleTypeNumbering_DiffersBetweenDialects()
    {
        // ConstantBoxedEnumValue (.NET 7/8) sorts before ConstantByteArray; ConstantEnumValue (.NET 9+) after ConstantEnumArray.
        Assert.Equal(5u, NativeAotSchema.RawType(MetadataDialect.Net7, MdRecord.ConstantEnumValue));
        Assert.Equal(0xCu, NativeAotSchema.RawType(MetadataDialect.Net9, MdRecord.ConstantEnumValue));
        Assert.Equal(0x6u, NativeAotSchema.RawType(MetadataDialect.Net7, MdRecord.ConstantByteArray));
        Assert.Equal(0x5u, NativeAotSchema.RawType(MetadataDialect.Net10, MdRecord.ConstantByteArray));
        Assert.Equal(0x3Au, NativeAotSchema.RawType(MetadataDialect.Net7, MdRecord.TypeDefinition));
        Assert.Equal(0x3Au, NativeAotSchema.RawType(MetadataDialect.Net10, MdRecord.TypeDefinition));
        Assert.Equal(0x1Au, NativeAotSchema.RawType(MetadataDialect.Net10, MdRecord.ConstantStringValue));
    }

    [Fact]
    public void Malformed_ThrowsFormatException()
    {
        var m = Model(16);
        Assert.Throws<NativeAotFormatException>(() => new NativeAotMetadata([1, 2, 3, 4, 5], m.Format));
        var md = new NativeAotMetadata(m.Blob[..(int)(m.Dog.Offset + 2)], m.Format);
        Assert.Throws<NativeAotFormatException>(() => md.FormatType(m.Dog));
        Assert.Throws<NativeAotFormatException>(() => md.FromToken(0x7Fu << 25));
    }
}
