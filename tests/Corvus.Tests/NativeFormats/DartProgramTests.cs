using Corvus.Core;
using Corvus.Mcp;
using Corvus.Native;
using Corvus.Native.Annotations;
using Corvus.Native.Code;
using Corvus.Services;

namespace Corvus.Tests.NativeFormats;

/// <summary>Code names read from a Dart AOT program snapshot's objects, on snapshots <see cref="DartProgramWriter"/> builds.</summary>
public sealed class DartProgramTests
{
    private const int TopLevel = (1 << 20) + 3;

    private sealed record Sample(byte[] Bytes, DartProgramWriter Writer, Dictionary<string, int> Functions, int Ledger, int AllocationStub, int VmStub);

    private static Sample Program(string? features = null)
    {
        var w = new DartProgramWriter { Features = features ?? DartProgramWriter.DefaultFeatures };
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

    [Theory]
    [InlineData("product x64 linux compressed-pointers", "compressed pointers")]
    [InlineData("release x64 linux no-compressed-pointers", "non-product")]
    [InlineData("product ia32 linux", "ia32")]
    public void A_snapshot_of_another_layout_is_reported_unread(string features, string reason)
    {
        var program = Read(Program(features).Bytes);
        Assert.Contains(reason, program.Unsupported);
        Assert.Empty(program.Code);
    }

    [Fact]
    public void A_snapshot_beside_a_VM_snapshot_is_reported_unread()
    {
        var bytes = Program().Bytes;
        var snapshot = DartScan.Snapshots(bytes).Single() with { Symbol = "kDartIsolateSnapshotData" };
        Assert.Contains("Dart before 3.13", DartProgramReader.Read(bytes, snapshot).Unsupported);
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
        var failures = FormatFuzz.Run([Program().Bytes], 1500, 13, b =>
        {
            foreach (var snapshot in DartScan.Snapshots(b)) DartProgramReader.Read(b, snapshot with { Symbol = "kDartSnapshotData" });
        });
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(5)));
    }
}
