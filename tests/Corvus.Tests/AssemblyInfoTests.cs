using System.Buffers.Binary;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using Corvus.Core;
using Corvus.Services;

namespace Corvus.Tests;

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

    /// <summary>No false positives on the fixture and on large runtime assemblies.</summary>
    [Fact]
    public void RowSweep_CleanAssemblies_HaveNoIssues()
    {
        var runtime = Path.GetDirectoryName(typeof(object).Assembly.Location)!;
        foreach (var path in new[] { Env.FixturePath, typeof(object).Assembly.Location, Path.Combine(runtime, "System.Linq.dll"),
                     Path.Combine(runtime, "System.Text.Json.dll"), Path.Combine(runtime, "System.Private.Xml.dll") })
        {
            var bytes = File.ReadAllBytes(path);
            using var module = dnlib.DotNet.ModuleDefMD.Load(bytes);
            var sweep = MetadataSurvey.Rows(module, bytes);
            Assert.True(sweep.Count == 0, $"{Path.GetFileName(path)}: {string.Join("; ", sweep.Issues.Take(5))}");
        }
    }

    /// <summary>Rows broken the way obfuscators break them: each is reported with its column, reason and file offset; get_assembly_info lists them.</summary>
    [Fact]
    public void RowSweep_BadIndexes_ReportedWithReasonAndOffset()
    {
        var image = File.ReadAllBytes(Env.FixturePath);
        var (typeDef, typeDefSize) = MetadataPatcher.Row(image, TableIndex.TypeDef, 2);
        var (memberRef, memberRefSize) = MetadataPatcher.Row(image, TableIndex.MemberRef, 1);
        var (attribute, attributeSize) = MetadataPatcher.Row(image, TableIndex.CustomAttribute, 1);
        var (method, methodSize) = MetadataPatcher.Row(image, TableIndex.MethodDef, 1);
        Assert.Equal((14, 6, 6, 14), (typeDefSize, memberRefSize, attributeSize, methodSize)); // 2-byte heap and table indexes
        int listRow = Enumerable.Range(4, MetadataPatcher.RowCount(image, TableIndex.TypeDef) - 3)
            .First(r => BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan(MetadataPatcher.Row(image, TableIndex.TypeDef, r - 1).Offset + 12)) > 1);
        int list = MetadataPatcher.Row(image, TableIndex.TypeDef, listRow).Offset;

        BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(typeDef + 8), 3 | 1 << 2);   // Extends: TypeDefOrRef tag 3
        BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(memberRef), 999 << 3 | 1);   // Class: TypeRef row 999
        BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(attribute + 2), 0);         // Type: null
        BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(method + 8), 0xFFF0);       // Name: past #Strings
        BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(list + 12), 1);             // MethodList: below the previous row's

        using var module = dnlib.DotNet.ModuleDefMD.Load(image);
        var sweep = MetadataSurvey.Rows(module, image);
        void Has(string code, string location, string detail, int offset) =>
            Assert.True(sweep.Issues.Any(i => i.Code == code && i.Location.EndsWith(location, StringComparison.Ordinal)
                && i.Detail.StartsWith(detail, StringComparison.Ordinal) && i.FileOffset == $"0x{offset:X}"), string.Join('\n', sweep.Issues));
        Has("bad_coded_index", "TypeDef row 2 (token 0x02000002), column Extends", "TypeDefOrRef tag 3 is not defined", typeDef);
        Has("bad_coded_index", "MemberRef row 1 (token 0x0A000001), column Class", "MemberRefParent names TypeRef row 999, past the table", memberRef);
        Has("bad_coded_index", "CustomAttribute row 1 (token 0x0C000001), column Type", "null CustomAttributeType reference where one is required", attribute);
        Has("bad_heap_index", "Method row 1 (token 0x06000001), column Name", "#Strings offset 0xFFF0 is past the heap", method);
        Has("bad_list_index", $"TypeDef row {listRow} (token 0x{0x02000000 | listRow:X8}), column MethodList", "list start 1 is below the previous row's", list);
        Assert.Equal(sweep.Issues.Count, sweep.Count);

        using var dir = new TempDir();
        var path = dir.File("Broken.dll");
        File.WriteAllBytes(path, image);
        using var env = new Env(path);
        AssemblyReport.Summary summary = null!;
        var text = env.Workspace.Read(() => env.Report.Build(env.Fixture, out summary));
        Assert.Contains($"bad_coded_index at #~ TypeDef row 2 (token 0x02000002), column Extends, file offset 0x{typeDef:X}: TypeDefOrRef tag 3 is not defined", text);
        Assert.True(summary.MetadataIssueCount >= 5);
        Assert.Contains(summary.MetadataIssues, i => i.Code == "bad_list_index");
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
