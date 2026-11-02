using System.Buffers.Binary;
using System.Text;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>get_pe_info: every count of issues has its items, and view=code leaves out the summary fields.</summary>
public sealed class PeInfoIssueTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    // Two sections named .reloc and one writable executable section, in the section table of a built image.
    private string Fixture()
    {
        var bytes = NativePeTests.KitchenSink(is64: true);
        int pe = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(0x3C));
        int table = pe + 24 + BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(pe + 20));
        int count = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(pe + 6));
        Assert.True(count >= 2);
        foreach (int s in new[] { count - 1, count - 2 })
        {
            Array.Clear(bytes, table + 40 * s, 8);
            Encoding.ASCII.GetBytes(".reloc").CopyTo(bytes, table + 40 * s);
        }
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(table + 36), 0xE0000020);
        var path = _dir.File("sections.dll");
        File.WriteAllBytes(path, bytes);
        return path;
    }

    private (NativeTools Tools, string Path) Open()
    {
        var options = new ServerOptions { BackgroundIndexing = false };
        var workspace = new AssemblyWorkspace(options);
        var code = new NativeCodeService(workspace, options, null, new Native.Annotations.AnnotationStore(_dir.File("annotations")));
        return (new NativeTools(workspace, new OutputPager(options), code), Fixture());
    }

    [Fact]
    public async Task Section_notes_name_the_duplicate_and_the_writable_executable_section()
    {
        var (tools, path) = Open();
        var collector = ToolOutput.Collect();
        var text = await tools.GetPeInfo(path);
        var record = Assert.IsType<PeSummary>(collector.Value);
        Assert.Contains("Section notes (2):", text);
        Assert.Contains(record.SectionNotes!, n => n.StartsWith("duplicate section name .reloc (2 sections"));
        Assert.Contains(record.SectionNotes!, n => n.Contains("writable and executable"));
    }

    [Fact]
    public async Task Every_counted_issue_is_listed_in_the_record_and_the_text()
    {
        var (tools, path) = Open();
        var collector = ToolOutput.Collect();
        var text = await tools.GetPeInfo(path);
        var record = Assert.IsType<PeSummary>(collector.Value);
        Assert.Equal(record.Issues, record.IssueList?.Count ?? 0);
        foreach (var row in record.IssueList ?? []) Assert.Contains(row, text);
    }

    [Fact]
    public async Task The_code_view_leaves_out_the_summary_fields()
    {
        var (tools, path) = Open();
        var collector = ToolOutput.Collect();
        await tools.GetPeInfo(path, view: "code");
        var record = Assert.IsType<PeSummary>(collector.Value);
        Assert.Null(record.Sections);
        Assert.Null(record.MitigationsOn);
        Assert.Null(record.SectionNotes);
        Assert.NotNull(record.Code);
    }
}
