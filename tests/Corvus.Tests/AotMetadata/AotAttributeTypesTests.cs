using AssetRipper.Primitives;
using Corvus.Services;
using LibCpp2IL.Metadata;

namespace Corvus.Tests;

/// <summary>Custom attribute types read from the attribute data of a v29 global-metadata.dat the tests write.</summary>
public sealed class AotAttributeTypesTests
{
    [Fact]
    public void Field_attribute_types_are_read_from_the_attribute_data()
    {
        var bytes = new AotMetadataWriter().Assembly("Assembly-CSharp", "0.0.0.0")
            .Field("spawn", "UnityEngine.SerializeField").Field("hidden").Field("both", "UnityEngine.SerializeField", "UnityEngine.HideInInspector").Build();
        lock (AotMetadataReader.Gate)
        {
            var meta = Il2CppMetadata.ReadFrom(bytes, UnityVersion.Parse("2021.3.0f1"));
            var types = AotAttributeTypes.Read(meta, meta.imageDefinitions[0], _ => null);
            string Names(uint token) => string.Join(",", types[token].Select(t => $"{meta.GetStringFromIndex(meta.typeDefs[t].NamespaceIndex)}.{meta.GetStringFromIndex(meta.typeDefs[t].NameIndex)}"));
            Assert.Equal("UnityEngine.SerializeField", Names(0x04000001));
            Assert.False(types.ContainsKey(0x04000002));
            Assert.Equal("UnityEngine.SerializeField,UnityEngine.HideInInspector", Names(0x04000003));
        }
    }

    [Fact]
    public void Attribute_data_reads_every_compressed_count_form_and_refuses_a_truncated_blob()
    {
        Assert.Equal([7], AotAttributeTypes.Constructors([0x01, 7, 0, 0, 0]));
        Assert.Equal([1, 2], AotAttributeTypes.Constructors([0x80, 0x02, 1, 0, 0, 0, 2, 0, 0, 0]));
        Assert.Equal([3], AotAttributeTypes.Constructors([0xC0, 0, 0, 1, 3, 0, 0, 0]));
        Assert.Equal([4], AotAttributeTypes.Constructors([0xF0, 0, 0, 0, 1, 4, 0, 0, 0]));
        Assert.Empty(AotAttributeTypes.Constructors([0x00]));
        foreach (byte[] damaged in new byte[][] { [], [0x02, 7, 0, 0, 0], [0x80], [0xF8, 0], [0xFF] })
            Assert.Throws<InvalidDataException>(() => AotAttributeTypes.Constructors(damaged));
    }
}
