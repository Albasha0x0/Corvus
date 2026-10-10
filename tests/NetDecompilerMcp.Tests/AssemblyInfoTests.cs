using System.Buffers.Binary;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using NetDecompilerMcp.Services;

namespace NetDecompilerMcp.Tests;

/// <summary>get_assembly_info facts: build identity, metadata inventory and structural problems.</summary>
public class AssemblyInfoTests
{
    [Fact]
    public void Provenance_FileSha256AndMvid_InTextAndStructured()
    {
        using var env = new Env();
        var sha = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(Env.FixturePath)));
        AssemblyReport.Summary summary = null!;
        var text = env.Workspace.Read(() => env.Report.Build(env.Fixture, out summary));
        Assert.Contains($"SHA-256: {sha}\n", text.ReplaceLineEndings("\n"));
        Assert.Contains($"MVID {env.Fixture.Module.Mvid}", text);
        Assert.Equal(sha, summary.Sha256);
        Assert.Equal(env.Fixture.Module.Mvid.ToString(), summary.Mvid);

        env.Edit(() => env.Edits.StubMethod(env.One("Fixture.Model.Account::Score"), "5"));
        Assert.Contains($"SHA-256: {sha} (file as loaded; unsaved edits not included)", env.Workspace.Read(() => env.Report.Build(env.Fixture)));
    }

    /// <summary>Row counts and heap sizes agree with System.Reflection.Metadata reading the same file.</summary>
    [Fact]
    public void TableRowsAndHeapSizes_MatchAnIndependentReader()
    {
        using var env = new Env();
        AssemblyReport.Summary summary = null!;
        var text = env.Workspace.Read(() => env.Report.Build(env.Fixture, out summary));
        using var pe = new PEReader(File.OpenRead(Env.FixturePath));
        var md = pe.GetMetadataReader();
        foreach (var table in Enum.GetValues<TableIndex>().Distinct())
        {
            int rows = md.GetTableRowCount(table);
            var name = table == TableIndex.MethodDef ? "Method" : table.ToString();
            var listed = summary.Tables.SingleOrDefault(t => string.Equals(t.Table, name, StringComparison.OrdinalIgnoreCase));
            Assert.Equal(rows, (int)(listed?.Rows ?? 0));
        }
        Assert.All(summary.Tables, t => Assert.True(t.Rows > 0));
        var streams = StreamSizes(pe.GetMetadata().GetContent().AsSpan());
        foreach (var heap in summary.Heaps)
            Assert.Equal(streams[heap.Heap], heap.Bytes);
        Assert.Equal(2, summary.Heaps.Single(h => h.Heap == "#Strings").IndexBytes);
        Assert.Null(summary.Heaps.Single(h => h.Heap == "#US").IndexBytes);
        Assert.Contains($"Metadata tables (rows): Module 1, TypeRef {md.GetTableRowCount(TableIndex.TypeRef)}, TypeDef {md.GetTableRowCount(TableIndex.TypeDef)}", text);
        Assert.Contains($"Metadata heaps: #Strings {streams["#Strings"]} bytes (2-byte indexes), #US ", text);
    }

    /// <summary>Stream sizes from the metadata root's stream headers (ECMA-335 II.24.2.1-2).</summary>
    private static Dictionary<string, uint> StreamSizes(ReadOnlySpan<byte> md)
    {
        int at = 16 + BinaryPrimitives.ReadInt32LittleEndian(md[12..]);
        int count = BinaryPrimitives.ReadUInt16LittleEndian(md[(at + 2)..]);
        at += 4;
        var result = new Dictionary<string, uint>();
        for (int i = 0; i < count; i++)
        {
            uint size = BinaryPrimitives.ReadUInt32LittleEndian(md[(at + 4)..]);
            int length = md[(at + 8)..].IndexOf((byte)0);
            result[System.Text.Encoding.ASCII.GetString(md.Slice(at + 8, length))] = size;
            at += 8 + ((length + 4) & ~3);
        }
        return result;
    }
}
