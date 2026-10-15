using Corvus.Native.MachO;

namespace Corvus.Tests.NativeFormats;

public sealed class AppleSwiftTests
{
    /// <summary>
    /// Module Zoo: struct Animal { var age: Int; let keeper: Keeper } (a field typed by a direct symbolic reference),
    /// class Keeper : Base.Parent (superclass through an indirect symbolic reference to a bind) with one vtable method
    /// whose method descriptor is exported, protocol Feeder, and conformances Keeper : Feeder and Animal : Swift.Hashable
    /// (protocol of another image, through a bind).
    /// </summary>
    internal static (byte[] Bytes, AppleMetadataBuilder Layout) Sample()
    {
        var w = new MachOWriter { Text = Enumerable.Repeat(new byte[] { 0xC0, 0x03, 0x5F, 0xD6 }, 0x40).SelectMany(b => b).ToArray() };
        var b = new AppleMetadataBuilder(w);
        b.Define("code:Animal.Ma", 0x1060);
        b.Define("code:Keeper.Ma", 0x1070);
        b.Define("code:Keeper.feed", 0x1080);
        var cst = b.Section("__TEXT", "__const", 0x2400);
        var fieldmd = b.Section("__TEXT", "__swift5_fieldmd", 0x2700);
        var types = b.Section("__TEXT", "__swift5_types", 0x2900);
        var protos = b.Section("__TEXT", "__swift5_protos", 0x2940);
        var proto = b.Section("__TEXT", "__swift5_proto", 0x2980);
        var got = b.Section("__DATA_CONST", "__got", 0x5000);
        var wt = b.Section("__DATA_CONST", "__const", 0x5100);

        b.Label(got, "got.Parent");
        b.Bind(got, "_$s4Base6ParentCMn");
        b.Label(got, "got.Hashable");
        b.Bind(got, "_$sSHMp");

        b.Label(cst, "Zoo", 4);
        cst.W.U32(0); cst.W.U32(0); b.Rel(cst, b.Str("Zoo"));

        b.Label(cst, "Animal", 4);
        cst.W.U32(0x51); b.Rel(cst, "Zoo"); b.Rel(cst, b.Str("Animal")); b.Rel(cst, "code:Animal.Ma"); b.Rel(cst, "fd.Animal");
        cst.W.U32(2); cst.W.U32(2);

        b.Label(cst, "Keeper", 4);
        cst.W.U32(0x80000050); b.Rel(cst, "Zoo"); b.Rel(cst, b.Str("Keeper")); b.Rel(cst, "code:Keeper.Ma"); b.Rel(cst, "fd.Keeper");
        b.Rel(cst, b.Mangled("tn.Parent", AppleMetadataBuilder.SymbolicRef(2, "got.Parent")));
        cst.W.U32(2); cst.W.U32(11); cst.W.U32(1); cst.W.U32(1); cst.W.U32(10);
        cst.W.U32(11); cst.W.U32(1);
        b.Label(cst, "Keeper.feed.md", 4);
        cst.W.U32(0x10); b.Rel(cst, "code:Keeper.feed");

        b.Label(cst, "Feeder", 4);
        cst.W.U32(0x43); b.Rel(cst, "Zoo"); b.Rel(cst, b.Str("Feeder")); cst.W.U32(0); cst.W.U32(0); cst.W.U32(0); cst.W.U32(0);

        b.Label(fieldmd, "fd.Animal", 4);
        b.Rel(fieldmd, b.Mangled("tn.Animal", AppleMetadataBuilder.SymbolicRef(1, "Animal"))); fieldmd.W.U32(0); fieldmd.W.U16(0); fieldmd.W.U16(12); fieldmd.W.U32(2);
        fieldmd.W.U32(2); b.Rel(fieldmd, b.Mangled("tn.Int", "Si")); b.Rel(fieldmd, b.Str("age"));
        fieldmd.W.U32(0); b.Rel(fieldmd, b.Mangled("tn.Keeper", AppleMetadataBuilder.SymbolicRef(1, "Keeper"))); b.Rel(fieldmd, b.Str("keeper"));
        b.Label(fieldmd, "fd.Keeper", 4);
        b.Rel(fieldmd, "tn.Keeper"); fieldmd.W.U32(0); fieldmd.W.U16(1); fieldmd.W.U16(12); fieldmd.W.U32(1);
        fieldmd.W.U32(2); b.Rel(fieldmd, b.Mangled("tn.String", "SS")); b.Rel(fieldmd, b.Str("name"));

        b.Rel(types, "Animal");
        b.Rel(types, "Keeper");
        b.Rel(protos, "Feeder");
        b.Label(wt, "wt.Keeper.Feeder");
        b.Ptr(wt, "conf.Keeper.Feeder");
        b.Label(wt, "wt.Animal.Hashable");
        b.Ptr(wt, "conf.Animal.Hashable");
        b.Label(cst, "conf.Keeper.Feeder", 4);
        b.Rel(cst, "Feeder"); b.Rel(cst, "Keeper"); b.Rel(cst, "wt.Keeper.Feeder"); cst.W.U32(0);
        b.Label(cst, "conf.Animal.Hashable", 4);
        b.Rel(cst, "got.Hashable", 1); b.Rel(cst, "Animal"); b.Rel(cst, "wt.Animal.Hashable"); cst.W.U32(0);
        b.Rel(proto, "conf.Keeper.Feeder");
        b.Rel(proto, "conf.Animal.Hashable");
        b.Build();
        w.Exports.Add(new MachOWriter.Export("_$s3Zoo6KeeperC4feedyyFTq", b["Keeper.feed.md"]));
        return (w.Build(), b);
    }

    [Fact]
    public void ReadsTypesFieldsVtablesAndConformances()
    {
        var (bytes, layout) = Sample();
        var image = MachOFile.FromBytes(bytes);
        Assert.Empty(image.Issues);
        var swift = AppleSwiftMetadata.Read(image);
        Assert.Empty(swift.Issues);

        Assert.Equal(["struct Zoo.Animal", "class Zoo.Keeper"], swift.Types.Select(t => $"{t.Kind} {t.Name}"));
        var animal = swift.Types[0];
        Assert.Equal(("Zoo", "3Zoo6AnimalV", 0x1060UL), (animal.Module, animal.Symbol, animal.AccessorVa));
        Assert.Equal(["var age: Swift.Int", "let keeper: Zoo.Keeper"], animal.Fields.Select(f => $"{(f.IsVar ? "var" : "let")} {f.Name}: {f.Type}"));
        var keeper = swift.Types[1];
        Assert.Equal("Base.Parent", keeper.Superclass);
        var method = Assert.Single(keeper.Methods);
        Assert.Equal(("method", true, 0x1080UL, (ulong)layout["Keeper.feed.md"]), (method.Kind, method.IsInstance, method.Impl, method.DescriptorVa));
        Assert.Equal("Zoo.Feeder", Assert.Single(swift.Protocols).Name);
        Assert.Equal(["Zoo.Keeper : Zoo.Feeder/False", "Zoo.Animal : Swift.Hashable/True"], swift.Conformances.Select(c => $"{c.Type} : {c.Protocol}/{c.ProtocolExternal}"));
        Assert.Equal(layout["wt.Animal.Hashable"], swift.Conformances[1].WitnessTableVa);
    }

    [Fact]
    public void Header_ListsSwiftTypesAsComments()
    {
        var header = ObjcHeader.Render(null, AppleSwiftMetadata.Read(MachOFile.FromBytes(Sample().Bytes)), "Zoo");
        Assert.Contains("// struct Zoo.Animal : Swift.Hashable {\n//     var age: Swift.Int\n//     let keeper: Zoo.Keeper\n// }\n", header);
        Assert.Contains("// class Zoo.Keeper : Base.Parent, Zoo.Feeder {\n", header);
        Assert.Contains("// protocol Zoo.Feeder\n", header);
    }

    [Fact]
    public void NameLayer_UsesMangledSymbols()
    {
        var (bytes, layout) = Sample();
        var image = MachOFile.FromBytes(bytes);
        var names = AppleSwiftNames.Build(image, AppleSwiftMetadata.Read(image));
        Assert.Equal("_$s3Zoo6AnimalVMn", names.Names[layout["Animal"]]);
        Assert.Equal("_$s3Zoo6AnimalVMa", names.Names[0x1060]);
        Assert.Equal("_$s3Zoo6KeeperC4feedyyF", names.Names[0x1080]);
        Assert.Equal("_$s3Zoo6FeederPMp", names.Names[layout["Feeder"]]);
        Assert.Equal("_$s3Zoo6AnimalVs8HashableP3ZooMc", names.Names[layout["conf.Animal.Hashable"]]);
        Assert.Equal("_$s3Zoo6AnimalVs8HashableP3ZooWP", names.Names[layout["wt.Animal.Hashable"]]);
        Assert.StartsWith("Swift struct Zoo.Animal; fields: age: Swift.Int, keeper: Zoo.Keeper", names.Comments[layout["Animal"]]);
        Assert.Contains(0x1080u, names.FunctionStarts);
        Assert.Equal(1, names.Methods);
    }
}
