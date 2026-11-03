using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using Corvus.Native.Dump.Managed;
using Corvus.Native.Dump.Rebuild;

namespace Corvus.Tests;

/// <summary>A dynamic module's metadata and bodies written as an assembly.</summary>
public sealed class DynamicModuleImageTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    // ldc.i4 20212, ret.
    private static readonly byte[] ConstantBody = [0x20, 0xF4, 0x4E, 0x00, 0x00, 0x2A];

    // Metadata of a type Emitted with two static int methods, Value (token
    // 0x06000001) and Missing (0x06000002).
    private static byte[] EmittedMetadata()
    {
        var md = new MetadataBuilder();
        md.AddModule(0, md.GetOrAddString("Emitted.dll"), md.GetOrAddGuid(Guid.NewGuid()), default, default);
        md.AddAssembly(md.GetOrAddString("Emitted"), new Version(1, 0, 0, 0), default, default, 0, AssemblyHashAlgorithm.None);
        md.AddTypeDefinition(0, default, md.GetOrAddString("<Module>"), default, MetadataTokens.FieldDefinitionHandle(1), MetadataTokens.MethodDefinitionHandle(1));
        var signature = new BlobBuilder();
        new BlobEncoder(signature).MethodSignature().Parameters(0, r => r.Type().Int32(), _ => { });
        var blob = md.GetOrAddBlob(signature);
        var methodAttributes = MethodAttributes.Public | MethodAttributes.Static;
        var methods = MetadataTokens.MethodDefinitionHandle(1);
        md.AddTypeDefinition(TypeAttributes.Public | TypeAttributes.Sealed | TypeAttributes.Abstract | TypeAttributes.BeforeFieldInit,
            md.GetOrAddString("Emitted"), md.GetOrAddString("E"), default, MetadataTokens.FieldDefinitionHandle(1), methods);
        md.AddMethodDefinition(methodAttributes, MethodImplAttributes.IL, md.GetOrAddString("Value"), blob, 0, MetadataTokens.ParameterHandle(1));
        md.AddMethodDefinition(methodAttributes, MethodImplAttributes.IL, md.GetOrAddString("Missing"), blob, 0, MetadataTokens.ParameterHandle(1));
        var root = new BlobBuilder();
        new MetadataRootBuilder(md).Serialize(root, 0, 0);
        return root.ToArray();
    }

    private static DynamicMethodBody Body(uint token, string name, byte[]? code) =>
        new(token, "Emitted.E", name, 0, code?.Length ?? 0, 0, 0, code, code == null ? "il_unknown: no IL" : null);

    [Fact]
    public void A_saved_dynamic_module_loads_and_decompiles_to_its_methods()
    {
        var built = DynamicModuleImage.Build(new DynamicModuleRead(EmittedMetadata(), null, [Body(0x06000001, "Value", ConstantBody), Body(0x06000002, "Missing", ConstantBody)]));
        Assert.NotNull(built.Bytes);
        Assert.Empty(built.Bodiless);
        string path = _dir.File("Emitted.dll");
        File.WriteAllBytes(path, built.Bytes);
        using var env = new Env(path);
        Assert.Contains("return 20212;", env.Decompile("Emitted.E::Value"));
    }

    [Fact]
    public void A_method_without_a_body_is_written_as_throw_and_named()
    {
        var built = DynamicModuleImage.Build(new DynamicModuleRead(EmittedMetadata(), null, [Body(0x06000001, "Value", ConstantBody), Body(0x06000002, "Missing", null)]));
        Assert.Equal(["E::Missing"], built.Bodiless);
        Assert.Equal(1, built.Methods);
        string path = _dir.File("Emitted.dll");
        File.WriteAllBytes(path, built.Bytes!);
        using var env = new Env(path);
        Assert.Contains("throw null;", env.Decompile("Emitted.E::Missing"));
        Assert.Contains("return 20212;", env.Decompile("Emitted.E::Value"));
    }

    [Fact]
    public void A_module_without_metadata_yields_its_reason_and_no_bytes()
    {
        var built = DynamicModuleImage.Build(new DynamicModuleRead(null, "metadata_unknown: held in an emitter", []));
        Assert.Null(built.Bytes);
        Assert.StartsWith("metadata_unknown", built.Failure);
    }
}
