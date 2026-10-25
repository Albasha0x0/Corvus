using Corvus.Core;
using Corvus.Mcp;
using Corvus.Native;
using Corvus.Native.Annotations;
using Corvus.Native.Code;
using Corvus.Services;
using Corvus.Services.Analysis;

namespace Corvus.Tests.NativeFormats;

/// <summary>Code names read from a Dart AOT program snapshot's objects, on snapshots <see cref="DartProgramWriter"/> builds.</summary>
public sealed class DartProgramTests
{
    private const int TopLevel = (1 << 20) + 3;

    private sealed record Sample(byte[] Bytes, DartProgramWriter Writer, Dictionary<string, int> Functions, int Ledger, int AllocationStub, int VmStub);

    private static Sample Program(string? features = null, bool split = false)
    {
        var w = new DartProgramWriter { Features = features ?? DartProgramWriter.DefaultFeatures, Split = split };
        // Dart 3.12's kGrowableObjectArrayCid: a predefined class, listed first in a split image.
        int? list = split ? w.Class("_GrowableList@0150898", 92) : null;
        int ledger = w.Class("Ledger", 200), library = w.Class("::", TopLevel), account = w.Class("_Account@71234", 201), mixin = w.Class("_Base&Object&Totals", 202);
        var f = new Dictionary<string, int>
        {
            ["balanceOf"] = w.Function("balanceOf", ledger),
            ["total"] = w.Function("get:total", ledger, kind: 3),
            ["limit="] = w.Function("set:limit", ledger, kind: 4),
            ["new"] = w.Function("Ledger.named", ledger, kind: 5),
            ["main"] = w.Function("main", library, discarded: true),
            ["deposit"] = w.Function("_deposit@71234", account),
            ["sum"] = w.Function("sum", mixin),
        };
        f["closure"] = w.Function("<anonymous closure>", ledger, kind: 1, closureParent: f["balanceOf"]);
        if (list is { } l) f["add"] = w.Function("add", l);
        int allocation = w.CodeCount;
        w.Stub(ledger);
        int vm = w.CodeCount;
        w.Stub(null);
        return new Sample(w.Build(), w, f, ledger, allocation, vm);
    }

    private static DartProgram Read(byte[] bytes) => DartNames.Read(NativeImageLoader.FromBytes(bytes, "libapp.so"))!.Value.Program;

    [Fact]
    public void Code_is_named_as_the_VM_prints_its_functions()
    {
        var s = Program();
        var program = Read(s.Bytes);
        Assert.Null(program.Unsupported);
        var at = program.Code.ToDictionary(c => ElfWriter.TextRva + c.Offset, c => c.Name);
        string Name(string key) => at[s.Writer.AddressOf(s.Functions[key])];
        Assert.Equal("Ledger.balanceOf", Name("balanceOf"));
        Assert.Equal("Ledger.total", Name("total"));
        Assert.Equal("Ledger.limit=", Name("limit="));
        Assert.Equal("new Ledger.named", Name("new"));
        Assert.Equal("main", Name("main"));
        Assert.Equal("_Account._deposit", Name("deposit"));
        Assert.Equal("Totals.sum", Name("sum"));
        Assert.Equal("Ledger.balanceOf.<anonymous closure>", Name("closure"));
        Assert.Equal("new Ledger", at[s.Writer.StubAddress(s.AllocationStub)]);
        Assert.False(at.ContainsKey(s.Writer.StubAddress(s.VmStub)));
        Assert.Equal((8, 1), (program.Functions, program.Unnamed));
    }

    [Fact]
    public async Task The_dart_layer_names_functions_when_the_index_is_built()
    {
        using var dir = new TempDir();
        var s = Program();
        var path = dir.File("libapp.so");
        File.WriteAllBytes(path, s.Bytes);
        using var ws = new AssemblyWorkspace();
        var native = ws.LoadAny(path).Native!;
        var code = new NativeCodeService(ws, new ServerOptions { BackgroundIndexing = false }, annotations: new AnnotationStore(dir.File("ann")));
        var index = await code.Index(native, null, default);
        uint balance = s.Writer.AddressOf(s.Functions["balanceOf"]);
        Assert.Equal(("Ledger.balanceOf", NativeNameSource.Dart), index.Sourced.NameAt(balance));
        Assert.NotNull(index.FunctionByStart(s.Writer.AddressOf(s.Functions["closure"])));
        Assert.StartsWith("Dart AOT snapshot (8 functions, 9 code objects named)", NativeNameLayers.Of(native).Get(NativeNameSource.Dart)!.Origin);
    }

    [Fact]
    public void A_compressed_pointer_snapshot_names_its_code_from_strings_in_the_stream()
    {
        var s = Program("product no-dwarf_stack_traces x64 android compressed-pointers");
        var program = Read(s.Bytes);
        Assert.Null(program.Unsupported);
        var at = program.Code.ToDictionary(c => ElfWriter.TextRva + c.Offset, c => c.Name);
        Assert.Equal("Ledger.balanceOf", at[s.Writer.AddressOf(s.Functions["balanceOf"])]);
        Assert.Equal("Ledger.balanceOf.<anonymous closure>", at[s.Writer.AddressOf(s.Functions["closure"])]);
        Assert.Equal((8, 1), (program.Functions, program.Unnamed));
    }

    [Theory]
    [InlineData(DartProgramWriter.DefaultFeatures)]
    [InlineData("product no-dwarf_stack_traces x64 android compressed-pointers")]
    public void A_Dart_3_12_image_names_its_code_from_its_VM_and_isolate_snapshots(string features)
    {
        var s = Program(features, split: true);
        var program = Read(s.Bytes);
        Assert.Null(program.Unsupported);
        Assert.Equal("3.12", program.Layout);
        var at = program.Code.ToDictionary(c => ElfWriter.TextRva + c.Offset, c => c.Name);
        // Strings from both snapshots: the VM snapshot holds the first half.
        Assert.Equal("Ledger.balanceOf", at[s.Writer.AddressOf(s.Functions["balanceOf"])]);
        Assert.Equal("Totals.sum", at[s.Writer.AddressOf(s.Functions["sum"])]);
        Assert.Equal("Ledger.balanceOf.<anonymous closure>", at[s.Writer.AddressOf(s.Functions["closure"])]);
        Assert.Equal("List.add", at[s.Writer.AddressOf(s.Functions["add"])]);
        Assert.Equal("new Ledger", at[s.Writer.StubAddress(s.AllocationStub)]);
        Assert.Equal((9, 1), (program.Functions, program.Unnamed));
    }

    [Fact]
    public void The_flutter_view_counts_the_names_of_a_Dart_3_12_image()
    {
        var bytes = Program(split: true).Bytes;
        var facts = (FlutterFileView.Facts)new FlutterFileView().Inspect(new FileInput("libapp.so", bytes, Blob.Identify(bytes)), default)!.Detail;
        Assert.Equal((9, 10, null), (facts.CodeNames!.Functions, facts.CodeNames.Named, facts.CodeNames.Unsupported));
    }

    [Theory]
    [InlineData("release x64 linux no-compressed-pointers", "non-product")]
    [InlineData("product ia32 linux", "ia32")]
    public void A_snapshot_of_another_layout_is_reported_unread(string features, string reason)
    {
        var program = Read(Program(features).Bytes);
        Assert.Contains(reason, program.Unsupported);
        Assert.Empty(program.Code);
    }

    [Fact]
    public void An_isolate_snapshot_without_its_VM_snapshot_is_reported_unread()
    {
        var bytes = Program(split: true).Bytes;
        var snapshot = DartScan.Snapshots(bytes)[1] with { Symbol = "kDartIsolateSnapshotData" };
        Assert.Contains("without its VM snapshot", DartProgramReader.Read(bytes, snapshot).Unsupported);
    }

    [Fact]
    public void A_truncated_object_stream_is_reported_unread()
    {
        var bytes = Program().Bytes;
        var snapshot = DartScan.Snapshots(bytes).Single() with { Symbol = "kDartSnapshotData" };
        var cut = bytes[..(int)(snapshot.Offset + 52 + DartProgramWriter.DefaultFeatures.Length + 12)];
        Assert.Contains("does not parse", DartProgramReader.Read(cut, snapshot).Unsupported);
    }

    [Fact]
    public void Kinds_follow_the_program_snapshot_numbering_in_an_image_that_names_one()
    {
        var snapshot = DartScan.Snapshots(Program().Bytes).Single();
        Assert.Equal("full-aot", snapshot.Kind);
    }

    [Theory]
    [InlineData("get:current", "current")]
    [InlineData("set:limit", "limit=")]
    [InlineData("_endIndex@10040228", "_endIndex")]
    [InlineData("get:_state@4048458", "_state")]
    [InlineData("ArgumentError.", "ArgumentError")]
    [InlineData("ArgumentError.value", "ArgumentError.value")]
    [InlineData("_CompactIterator@3099033.", "_CompactIterator")]
    [InlineData("<anonymous closure>", "<anonymous closure>")]
    public void Private_keys_and_accessor_prefixes_are_dropped_as_ScrubName_does(string name, string shown) =>
        Assert.Equal(shown, DartProgramReader.Scrub(name));

    [Theory]
    [InlineData("Totals|get#sum", "Totals.sum")]
    [InlineData("Totals|add", "Totals.add")]
    public void Extension_members_print_their_extension(string name, string shown) =>
        Assert.Equal(shown, DartProgramReader.Scrub(name, extension: true));

    [Fact]
    [FuzzEntry(typeof(DartProgramReader))]
    public void Fuzzed_program_snapshot_never_throws()
    {
        var failures = FormatFuzz.Run([Program().Bytes, Program(split: true).Bytes], 1500, 13, b =>
        {
            var snapshots = DartScan.Snapshots(b);
            foreach (var snapshot in snapshots) DartProgramReader.Read(b, snapshot with { Symbol = "kDartSnapshotData" });
            if (snapshots.Count >= 2)
                DartProgramReader.Read(b, snapshots[0] with { Symbol = "kDartVmSnapshotData" }, snapshots[1] with { Symbol = "kDartIsolateSnapshotData" });
        });
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(5)));
    }
}
