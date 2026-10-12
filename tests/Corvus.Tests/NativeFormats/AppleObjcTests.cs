using Corvus.Native.MachO;

namespace Corvus.Tests.NativeFormats;

public sealed class AppleObjcTests
{
    /// <summary>
    /// An arm64 dylib with Objective-C metadata: Animal : NSObject (classic instance methods, a relative class method
    /// list through a selector reference, an ivar, a property, a protocol), Dog : Animal (Swift data bits), a category on
    /// NSString (a bind), protocol Pet with an optional method, selector and class references.
    /// </summary>
    internal static (byte[] Bytes, AppleMetadataBuilder Layout) Sample(ushort format = 6)
    {
        var w = new MachOWriter { Text = Enumerable.Repeat(new byte[] { 0xC0, 0x03, 0x5F, 0xD6 }, 0x40).SelectMany(b => b).ToArray() };
        var b = new AppleMetadataBuilder(w);
        b.Define("imp:speak", 0x1010);
        b.Define("imp:name", 0x1020);
        b.Define("imp:create", 0x1030);
        b.Define("imp:bark", 0x1040);
        b.Define("imp:fancy", 0x1050);

        var classlist = b.Section("__DATA_CONST", "__objc_classlist", 0x5000);
        var catlist = b.Section("__DATA_CONST", "__objc_catlist", 0x5100);
        var protolist = b.Section("__DATA_CONST", "__objc_protolist", 0x5200);
        var selrefs = b.Section("__DATA_CONST", "__objc_selrefs", 0x5300, 0x10000005);
        var classrefs = b.Section("__DATA_CONST", "__objc_classrefs", 0x5400);
        var cst = b.Section("__DATA_CONST", "__objc_const", 0x5800);
        var data = b.Section("__DATA", "__objc_data", 0xA100);
        var ivarVars = b.Section("__DATA", "__objc_ivar", 0xA800);

        void ClassT(string label, string? isaLabel, string? isaBind, string? superLabel, string? superBind, string ro, int dataBits = 0)
        {
            b.Label(data, label);
            if (isaLabel != null) b.Ptr(data, isaLabel); else b.Bind(data, isaBind!);
            if (superLabel != null) b.Ptr(data, superLabel); else b.Bind(data, superBind!);
            b.Bind(data, "__objc_empty_cache");
            b.Ptr(data, null);
            b.Ptr(data, ro, dataBits);
        }
        void Ro(string label, uint flags, uint start, uint size, string name, string? methods, string? protos, string? ivars, string? props)
        {
            b.Label(cst, label);
            cst.W.U32(flags); cst.W.U32(start); cst.W.U32(size); cst.W.U32(0);
            b.Ptr(cst, null);
            b.Ptr(cst, b.Str(name));
            b.Ptr(cst, methods);
            b.Ptr(cst, protos);
            b.Ptr(cst, ivars);
            b.Ptr(cst, null);
            b.Ptr(cst, props);
        }
        void ClassicMethods(string label, params (string Sel, string Types, string? Imp)[] methods)
        {
            b.Label(cst, label);
            cst.W.U32(24); cst.W.U32((uint)methods.Length);
            foreach (var (sel, types, imp) in methods)
            {
                b.Ptr(cst, b.Str(sel));
                b.Ptr(cst, b.Str(types));
                b.Ptr(cst, imp);
            }
        }
        void SmallMethods(string label, params (string SelRef, string Types, string Imp)[] methods)
        {
            b.Label(cst, label, 4);
            cst.W.U32(12 | 0x80000000); cst.W.U32((uint)methods.Length);
            foreach (var (selRef, types, imp) in methods)
            {
                b.Rel(cst, selRef);
                b.Rel(cst, b.Str(types));
                b.Rel(cst, imp);
            }
        }
        void SelRef(string sel)
        {
            b.Label(selrefs, "selref:" + sel);
            b.Ptr(selrefs, b.Str(sel));
        }

        SelRef("create");
        SelRef("bark");
        SelRef("speak");
        ClassT("Animal", "Animal.meta", null, null, "_OBJC_CLASS_$_NSObject", "Animal.ro");
        ClassT("Animal.meta", null, "_OBJC_METACLASS_$_NSObject", null, "_OBJC_METACLASS_$_NSObject", "Animal.metaro");
        ClassT("Dog", "Dog.meta", null, "Animal", null, "Dog.ro", dataBits: 2);
        ClassT("Dog.meta", null, "_OBJC_METACLASS_$_NSObject", "Animal.meta", null, "Dog.metaro");
        Ro("Animal.ro", 0, 8, 12, "Animal", "Animal.methods", "Animal.protos", "Animal.ivars", "Animal.props");
        Ro("Animal.metaro", 1, 40, 40, "Animal", "Animal.cmethods", null, null, null);
        Ro("Dog.ro", 0, 12, 12, "Dog", "Dog.methods", null, null, null);
        Ro("Dog.metaro", 1, 40, 40, "Dog", null, null, null, null);
        ClassicMethods("Animal.methods", ("speak", "v16@0:8", "imp:speak"), ("name", "@16@0:8", "imp:name"));
        SmallMethods("Animal.cmethods", ("selref:create", "@16@0:8", "imp:create"));
        SmallMethods("Dog.methods", ("selref:bark", "v16@0:8", "imp:bark"));
        b.Label(cst, "Animal.ivars");
        cst.W.U32(32); cst.W.U32(1);
        b.Ptr(cst, "ivar:_age"); b.Ptr(cst, b.Str("_age")); b.Ptr(cst, b.Str("i")); cst.W.U32(2); cst.W.U32(4);
        b.Label(ivarVars, "ivar:_age", 4);
        ivarVars.W.U32(8);
        b.Label(cst, "Animal.props");
        cst.W.U32(16); cst.W.U32(1);
        b.Ptr(cst, b.Str("name")); b.Ptr(cst, b.Str("T@\"NSString\",R,N"));
        b.Label(cst, "Animal.protos");
        cst.W.U64(1);
        b.Ptr(cst, "Pet");

        // category Fancy on NSString (another image's class)
        b.Label(cst, "cat.Fancy");
        b.Ptr(cst, b.Str("Fancy"));
        b.Bind(cst, "_OBJC_CLASS_$_NSString");
        b.Ptr(cst, "cat.Fancy.methods");
        for (int i = 0; i < 4; i++) b.Ptr(cst, null);
        ClassicMethods("cat.Fancy.methods", ("fancyString", "@16@0:8", "imp:fancy"));

        // protocol Pet: required -play, optional -rest
        b.Label(data, "Pet");
        b.Ptr(data, null);
        b.Ptr(data, b.Str("Pet"));
        b.Ptr(data, null);
        b.Ptr(data, "Pet.required");
        b.Ptr(data, null);
        b.Ptr(data, "Pet.optional");
        b.Ptr(data, null);
        b.Ptr(data, null);
        data.W.U32(96); data.W.U32(0);
        ClassicMethods("Pet.required", ("play", "v16@0:8", null));
        ClassicMethods("Pet.optional", ("rest", "v16@0:8", null));

        b.Ptr(classlist, "Animal");
        b.Ptr(classlist, "Dog");
        b.Ptr(catlist, "cat.Fancy");
        b.Ptr(protolist, "Pet");
        b.Ptr(classrefs, "Dog");
        b.Bind(classrefs, "_OBJC_CLASS_$_NSString");
        b.Build(format);
        return (w.Build(), b);
    }

    [Theory]
    [InlineData((ushort)6)]
    [InlineData((ushort)12)]
    public void ReadsClassesCategoriesProtocolsThroughFixups(ushort format)
    {
        var (bytes, layout) = Sample(format);
        var image = MachOFile.FromBytes(bytes);
        Assert.Empty(image.Issues);
        var objc = AppleObjcMetadata.Read(image);
        Assert.Empty(objc.Issues);

        Assert.Equal(["Animal", "Dog"], objc.Classes.Select(c => c.Name));
        var animal = objc.Classes[0];
        Assert.Equal(layout["Animal"], animal.Va);
        Assert.Equal(layout["Animal.meta"], animal.MetaclassVa);
        Assert.Equal("NSObject", animal.Superclass);
        Assert.True(animal.SuperclassExternal);
        Assert.False(animal.IsSwift);
        Assert.Equal(12u, animal.InstanceSize);
        Assert.Equal(["-speak@0x1010", "-name@0x1020", "+create@0x1030"], animal.Methods.Select(m => $"{(m.IsClassMethod ? '+' : '-')}{m.Selector}@0x{m.Imp:X}"));
        Assert.Equal("v16@0:8", animal.Methods[0].Types);
        var ivar = Assert.Single(animal.Ivars);
        Assert.Equal(("_age", "i", 8u, 4u, 4u), (ivar.Name, ivar.Type, ivar.Offset!.Value, ivar.Size, ivar.Alignment));
        Assert.Equal(layout["ivar:_age"], ivar.OffsetVa);
        Assert.Equal("T@\"NSString\",R,N", Assert.Single(animal.Properties).Attributes);
        Assert.Equal(["Pet"], animal.Protocols);

        var dog = objc.Classes[1];
        Assert.Equal("Animal", dog.Superclass);
        Assert.False(dog.SuperclassExternal);
        Assert.Equal(animal.Va, dog.SuperclassVa);
        Assert.True(dog.IsSwift);
        Assert.Equal(layout["Dog.ro"], dog.RoVa);
        Assert.Equal("bark", Assert.Single(dog.Methods).Selector);
        Assert.Equal(0x1040UL, dog.Methods[0].Imp);

        var category = Assert.Single(objc.Categories);
        Assert.Equal(("Fancy", "NSString", true), (category.Name, category.ClassName, category.ClassExternal));
        Assert.Equal(0x1050UL, Assert.Single(category.Methods).Imp);

        var pet = Assert.Single(objc.Protocols);
        Assert.Equal(["play", "rest"], pet.Methods.Select(m => m.Selector));
        Assert.Equal([false, true], pet.Methods.Select(m => m.Optional));

        Assert.Equal(["create", "bark", "speak"], objc.References.Where(r => r.Kind == "selector").Select(r => r.Name));
        Assert.Equal(["Dog/False", "NSString/True"], objc.References.Where(r => r.Kind == "class").Select(r => $"{r.Name}/{r.External}"));
    }

    [Fact]
    public void ImageWithoutObjcSections_IsEmpty()
    {
        var objc = AppleObjcMetadata.Read(MachOFile.FromBytes(new MachOWriter().Build()));
        Assert.True(objc.IsEmpty);
    }

    [Theory]
    [InlineData("i", "int")]
    [InlineData("@\"NSString\"", "NSString *")]
    [InlineData("@\"<NSCopying>\"", "id<NSCopying>")]
    [InlineData("^{CGPoint=dd}", "struct CGPoint *")]
    [InlineData("[4c]", "char[4]")]
    [InlineData("r*", "char *")]
    [InlineData("b3", "unsigned int : 3")]
    [InlineData("@?", "id /* block */")]
    [InlineData("{?=ii}", "struct anonymous")]
    [InlineData("^", "^")]
    public void TypeEncodings(string encoding, string c) => Assert.Equal(c, ObjcTypeEncoding.ToC(encoding));
}
