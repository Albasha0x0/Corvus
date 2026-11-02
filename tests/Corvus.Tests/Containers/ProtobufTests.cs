using System.Text;
using Corvus.Core;
using Corvus.Core.Protobuf;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>Protobuf wire writer for descriptor fixtures.</summary>
internal sealed class ProtoWriter
{
    private readonly MemoryStream _s = new();

    public byte[] ToArray() => _s.ToArray();

    private void Varint(ulong v)
    {
        do { byte b = (byte)(v & 0x7F); v >>= 7; _s.WriteByte((byte)(b | (v != 0 ? 0x80 : 0))); } while (v != 0);
    }

    public ProtoWriter Int(int field, long value) { Varint((ulong)field << 3); Varint((ulong)value); return this; }
    public ProtoWriter Bytes(int field, byte[] value) { Varint((ulong)field << 3 | 2); Varint((ulong)value.Length); _s.Write(value); return this; }
    public ProtoWriter Str(int field, string value) => Bytes(field, Encoding.UTF8.GetBytes(value));
    public ProtoWriter Msg(int field, Action<ProtoWriter> body) { var inner = new ProtoWriter(); body(inner); return Bytes(field, inner.ToArray()); }

    /// <summary>FieldDescriptorProto: name, number, label, type, type name, oneof index, proto3 optional.</summary>
    public ProtoWriter Field(int field, string name, int number, int type, int label = 1, string? typeName = null, int? oneof = null, bool proto3Optional = false) =>
        Msg(field, f =>
        {
            f.Str(1, name).Int(3, number).Int(4, label).Int(5, type);
            if (typeName != null) f.Str(6, typeName);
            if (oneof != null) f.Int(9, oneof.Value);
            if (proto3Optional) f.Int(17, 1);
        });

    /// <summary>demo.proto: a proto3 message with scalars, a map, a oneof, an optional, an enum and a message reference, and a service.</summary>
    public static byte[] Demo() => new ProtoWriter()
        .Str(1, "demo.proto").Str(2, "demo.v1").Str(3, "google/protobuf/timestamp.proto")
        .Msg(4, m => m.Str(1, "User")
            .Field(2, "id", 1, 3).Field(2, "name", 2, 9).Field(2, "tags", 3, 9, label: 3)
            .Field(2, "scores", 4, 11, label: 3, typeName: ".demo.v1.User.ScoresEntry")
            .Field(2, "email", 5, 9, oneof: 0).Field(2, "phone", 6, 9, oneof: 0)
            .Field(2, "active", 7, 8, oneof: 1, proto3Optional: true)
            .Field(2, "role", 8, 14, typeName: ".demo.v1.User.Role")
            .Field(2, "created", 9, 11, typeName: ".google.protobuf.Timestamp")
            .Msg(3, e => e.Str(1, "ScoresEntry").Field(2, "key", 1, 9).Field(2, "value", 2, 5).Msg(7, o => o.Int(7, 1)))
            .Msg(4, e => e.Str(1, "Role").Msg(2, v => v.Str(1, "ROLE_UNSPECIFIED").Int(2, 0)).Msg(2, v => v.Str(1, "ADMIN").Int(2, 1)))
            .Msg(8, o => o.Str(1, "contact")).Msg(8, o => o.Str(1, "_active"))
            .Msg(9, r => r.Int(1, 10).Int(2, 13)).Str(10, "legacy"))
        .Msg(6, s => s.Str(1, "Users")
            .Msg(2, m => m.Str(1, "GetUser").Str(2, ".demo.v1.User").Str(3, ".demo.v1.User"))
            .Msg(2, m => m.Str(1, "Watch").Str(2, ".demo.v1.User").Str(3, ".demo.v1.User").Int(6, 1)))
        .Msg(8, o => o.Str(1, "com.example.demo"))
        .Str(12, "proto3").ToArray();
}

/// <summary>FileDescriptorProto reading, .proto text, the raw scan and view=protobuf.</summary>
public sealed class ProtobufTests
{
    private const string DemoText = """
        // demo.proto (rebuilt from an embedded FileDescriptorProto)
        syntax = "proto3";

        package demo.v1;

        import "google/protobuf/timestamp.proto";

        option java_package = "com.example.demo";

        message User {
          int64 id = 1;
          string name = 2;
          repeated string tags = 3;
          map<string, int32> scores = 4;
          oneof contact {
            string email = 5;
            string phone = 6;
          }
          optional bool active = 7;
          .demo.v1.User.Role role = 8;
          .google.protobuf.Timestamp created = 9;
          enum Role {
            ROLE_UNSPECIFIED = 0;
            ADMIN = 1;
          }
          reserved 10 to 12;
          reserved "legacy";
        }

        service Users {
          rpc GetUser(.demo.v1.User) returns (.demo.v1.User);
          rpc Watch(.demo.v1.User) returns (stream .demo.v1.User);
        }

        """;

    [Fact]
    public void Descriptor_is_written_as_proto_source_with_maps_oneofs_and_streams()
    {
        var file = ProtoFile.Read(ProtoWriter.Demo());
        Assert.NotNull(file);
        Assert.Equal(DemoText.ReplaceLineEndings("\n"), ProtoText.Write(file));
    }

    [Fact]
    public void Raw_scan_finds_a_descriptor_between_other_bytes_and_stops_at_its_end()
    {
        var demo = ProtoWriter.Demo();
        byte[] blob = [.. "junk .proto \n\x05x.pro"u8, .. demo, 0, 0, 0x0A, 0x41, .. new byte[64]];
        var found = Assert.Single(ProtoScan.Raw(blob));
        Assert.Equal(19, found.Offset);
        Assert.Equal(demo.Length, found.File.Length);
        Assert.Equal("demo.proto", found.File.Name);
    }

    [Fact]
    public void Protobuf_view_rebuilds_descriptors_of_a_native_image()
    {
        var writer = NativeFormats.FormatWriterTests.SampleMachO();
        writer.ExtraSections = [("__TEXT", "__const", 0x2000, ProtoWriter.Demo(), 0)];
        var bytes = writer.Build();
        var view = new ProtobufFileView().Inspect(new FileInput("demo", bytes, Blob.Identify(bytes)) { Options = new FileViewOptions("protobuf") }, default);
        var facts = Assert.IsType<ProtobufFileView.Facts>(view?.Detail);
        var d = Assert.Single(facts.Files);
        Assert.Equal(("demo.proto", "raw bytes", 1), (d.Name, d.Encoding, d.Services));
        Assert.Equal(DemoText.ReplaceLineEndings("\n"), d.Proto);
        Assert.Contains("gRPC services demo.v1.Users", view!.Highlights[0], StringComparison.Ordinal);
    }

    private static byte[] Second() => new ProtoWriter().Str(1, "b.proto").Str(2, "b")
        .Msg(4, m => m.Str(1, "A").Field(2, "x", 1, 5)).Msg(4, m => m.Str(1, "B").Field(2, "y", 1, 5))
        .Msg(4, m => m.Str(1, "C").Field(2, "z", 1, 5)).Str(12, "proto3").ToArray();

    private static async Task<(Corvus.Tools.FileSummaryRecord Overview, Func<string, Task<(Corvus.Tools.FileSummaryRecord Record, string Text)>> View)> PagedSummary(TempDir dir)
    {
        var writer = NativeFormats.FormatWriterTests.SampleMachO();
        writer.ExtraSections = [("__TEXT", "__const", 0x2000, ProtoWriter.Demo(), 0), ("__TEXT", "__cstring", 0x3000, Second(), 0)];
        var path = dir.File("paged.bin");
        File.WriteAllBytes(path, writer.Build());
        var workspace = new AssemblyWorkspace();
        var tools = new Corvus.Tools.InspectionTools(new InspectionService(workspace), workspace);
        var collector = Corvus.Mcp.ToolOutput.Collect();
        await tools.SummarizeFile(path: path);
        var overview = Assert.IsType<Corvus.Tools.FileSummaryRecord>(collector.Value);
        return (overview, async view =>
        {
            var c = Corvus.Mcp.ToolOutput.Collect();
            var text = await tools.SummarizeFile(path: path, view: view, limit: view == "protobuf" ? 1 : null);
            return (Assert.IsType<Corvus.Tools.FileSummaryRecord>(c.Value), text);
        });
    }

    [Fact]
    public async Task Every_summary_view_repeats_the_file_facts()
    {
        using var dir = new TempDir();
        var (overview, view) = await PagedSummary(dir);
        Assert.NotEqual(0, overview.Entropy);
        foreach (var name in overview.Views!.Where(v => v != "overview"))
        {
            var (record, _) = await view(name);
            Assert.Equal((overview.Entropy, overview.Md5, overview.Sha1), (record.Entropy, record.Md5, record.Sha1));
        }
    }

    [Fact]
    public async Task A_paging_value_is_not_a_note()
    {
        using var dir = new TempDir();
        var (_, view) = await PagedSummary(dir);
        var (record, text) = await view("protobuf");
        Assert.All(record.Notes!, n => Assert.Contains(' ', n));
        Assert.DoesNotMatch(@"(?m)^\s*next: ", text);
        Assert.DoesNotMatch(@"(?m)^Note: [0-9]+?$", text);
    }

    [Fact]
    public void The_protobuf_highlight_names_each_descriptor_with_its_message_count()
    {
        var writer = NativeFormats.FormatWriterTests.SampleMachO();
        writer.ExtraSections = [("__TEXT", "__const", 0x2000, ProtoWriter.Demo(), 0), ("__TEXT", "__cstring", 0x3000, Second(), 0)];
        var bytes = writer.Build();
        var view = new ProtobufFileView().Inspect(new FileInput("demo", bytes, Blob.Identify(bytes)), default);
        var facts = Assert.IsType<ProtobufFileView.Facts>(view?.Detail);
        Assert.Equal(2, facts.Total);
        var line = view!.Highlights[0];
        Assert.Contains("2 embedded protobuf descriptor(s), 4 message(s): ", line, StringComparison.Ordinal);
        Assert.Contains("demo.proto (1)", line, StringComparison.Ordinal);
        Assert.Contains("b.proto (3)", line, StringComparison.Ordinal);
    }

    [Fact]
    public void The_overview_of_an_archive_names_descriptors_of_its_native_library()
    {
        var writer = NativeFormats.FormatWriterTests.SampleMachO();
        writer.ExtraSections = [("__TEXT", "__const", 0x2000, ProtoWriter.Demo(), 0)];
        var path = Path.Combine(Path.GetTempPath(), $"pb-{Guid.NewGuid():N}.zip");
        try
        {
            using (var zip = System.IO.Compression.ZipFile.Open(path, System.IO.Compression.ZipArchiveMode.Create))
            {
                using var w = zip.CreateEntry("lib/arm64-v8a/libdemo.so").Open();
                w.Write(writer.Build());
            }
            var bytes = File.ReadAllBytes(path);
            var view = new ProtobufFileView().Inspect(new FileInput(path, bytes, "zip"), default);
            Assert.Contains("1 embedded protobuf descriptor(s), 1 message(s): demo.proto (1)", view?.Highlights[0], StringComparison.Ordinal);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void An_asked_protobuf_view_of_an_image_without_descriptors_says_none_was_found()
    {
        var facts = AskedFacts(NativeFormats.FormatWriterTests.SampleMachO().Build());
        Assert.Equal(0, facts.Total);
        Assert.Equal([ProtobufFileView.NoDescriptorNote], facts.Notes);
    }

    [Fact]
    public void An_asked_protobuf_view_of_a_name_only_descriptor_says_it_was_rejected()
    {
        var writer = NativeFormats.FormatWriterTests.SampleMachO();
        writer.ExtraSections = [("__TEXT", "__const", 0x2000, new ProtoWriter().Str(1, "demo.proto").ToArray(), 0)];
        var facts = AskedFacts(writer.Build());
        Assert.Equal(0, facts.Total);
        Assert.Contains(facts.Notes, n => n.Contains("descriptor candidate(s) rejected", StringComparison.Ordinal));
        Assert.Equal(ProtobufFileView.NoReadableNote, facts.Notes[^1]);
        Assert.DoesNotContain(ProtobufFileView.NoDescriptorNote, facts.Notes);
    }

    [Fact]
    public void An_unasked_protobuf_view_of_an_image_without_descriptors_is_absent()
    {
        var bytes = NativeFormats.FormatWriterTests.SampleMachO().Build();
        Assert.Null(new ProtobufFileView().Inspect(new FileInput("plain", bytes, Blob.Identify(bytes)), default));
    }

    [Fact]
    public void The_empty_protobuf_note_names_a_registered_view()
    {
        Assert.Equal("overview", new FileViewOptions().View);
        Assert.Contains("view=overview", ProtobufFileView.NoDescriptorNote, StringComparison.Ordinal);
        Assert.Contains("view=overview", ProtobufFileView.NoReadableNote, StringComparison.Ordinal);
    }

    private static ProtobufFileView.Facts AskedFacts(byte[] bytes)
    {
        var input = new FileInput("plain", bytes, Blob.Identify(bytes)) { Options = new FileViewOptions("protobuf") };
        return Assert.IsType<ProtobufFileView.Facts>(new ProtobufFileView().Inspect(input, default)?.Detail);
    }

    // A structural fuzz edit renumbered a map entry's value field to 127.
    [Fact]
    public void A_map_entry_without_fields_1_and_2_prints_as_a_repeated_message()
    {
        var text = ProtoText.Write(ProtoFile.Read(new ProtoWriter().Str(1, "m.proto").Str(2, "m")
            .Msg(4, m => m.Str(1, "M")
                .Field(2, "scores", 1, 11, label: 3, typeName: ".m.M.ScoresEntry")
                .Msg(3, e => e.Str(1, "ScoresEntry").Field(2, "key", 1, 9).Field(2, "value", 127, 5).Msg(7, o => o.Int(7, 1))))
            .Str(12, "proto3").ToArray())!);
        Assert.Contains("repeated .m.M.ScoresEntry scores = 1;", text);
        Assert.Contains("message ScoresEntry", text);
    }

    [Fact]
    [FuzzEntry(typeof(ProtoFile))]
    public void Fuzzed_descriptors_never_throw()
    {
        var failures = FormatFuzz.Run(ProtoWriter.Demo(), b =>
        {
            if (ProtoFile.Read(b) is { } f) ProtoText.Write(f);
            ProtoScan.Raw(b);
        }, 3000);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(5)));
    }

    // Pb/igame.pbe layout: a marked container whose payload is a descriptor padded to whole blocks.
    private static byte[] Package(byte[] pbe, string script, byte[]? transformedScript = null)
    {
        var ms = new MemoryStream();
        using (var zip = new System.IO.Compression.ZipArchive(ms, System.IO.Compression.ZipArchiveMode.Create, true))
        {
            void Add(string name, byte[] data)
            {
                using var w = zip.CreateEntry(name, System.IO.Compression.CompressionLevel.NoCompression).Open();
                w.Write(data);
            }
            Add("Pb/igame.pbe", pbe);
            Add("Scripts/ids.lua", System.Text.Encoding.UTF8.GetBytes(script));
            if (transformedScript != null) Add("Scripts/main.luae", transformedScript);
        }
        return ms.ToArray();
    }

    private static byte[] MarkedBlocks(byte[] payload)
    {
        int padded = (payload.Length + 7) / 8 * 8;
        var bytes = new byte[8 + padded];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(bytes, 0xFFFFFFFF);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(4), (uint)padded);
        payload.CopyTo(bytes, 8);
        return bytes;
    }

    private const string IdScript = "Msg = {\n  User = 1001,\n  [1002] = \"demo.v1.Users\",\n  Other = 7 -- unrelated\n}\n";

    private static ProtobufFileView.Facts PackageFacts(byte[] zip)
    {
        var path = Path.Combine(Path.GetTempPath(), $"pb-{Guid.NewGuid():N}.zip");
        try
        {
            File.WriteAllBytes(path, zip);
            var input = new FileInput(path, zip, "zip") { Options = new FileViewOptions("protobuf") };
            return Assert.IsType<ProtobufFileView.Facts>(new ProtobufFileView().Inspect(input, default)?.Detail);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void A_script_message_id_joins_the_descriptor_message_with_its_fields()
    {
        var facts = PackageFacts(Package(MarkedBlocks(ProtoWriter.Demo()), IdScript));
        Assert.Equal(1, facts.Total);
        var user = Assert.Single(facts.Ids!, i => i.Id == 1001);
        Assert.Equal(("joined", "demo.v1.User", 9), (user.State, user.Message, user.FieldCount));
        Assert.Contains("id = 1", user.Fields);
        Assert.Equal("Pb/igame.pbe", Assert.Single(facts.Files).Source);
    }

    [Fact]
    public void A_named_script_id_without_a_message_is_unmatched_and_bare_assignments_are_only_counted()
    {
        var facts = PackageFacts(Package(MarkedBlocks(ProtoWriter.Demo()), IdScript));
        Assert.Equal("unmatched", Assert.Single(facts.Ids!, i => i.Id == 1002).State);
        Assert.Equal(2, facts.Ids!.Count);
        Assert.Contains(facts.Notes, n => n.Contains("1 bare name = number assignment(s)"));
    }

    [Fact]
    public void An_untransformed_pbe_without_a_descriptor_leaves_the_ids_unknown_and_names_the_next_call()
    {
        var facts = PackageFacts(Package(MarkedBlocks(new byte[64]), IdScript));
        Assert.All(facts.Ids!, i => Assert.Equal("unknown", i.State));
        Assert.Contains(facts.Notes, n => n.Contains("scanned 1 of 2 package entries") && n.Contains("Pb/igame.pbe (no readable descriptor)") && n.Contains("unpack_container"));
    }

    [Fact]
    public void A_transformed_luae_entry_is_counted_as_unreadable_because_its_ids_are_not_read()
    {
        var facts = PackageFacts(Package(MarkedBlocks(ProtoWriter.Demo()), IdScript, MarkedBlocks(new byte[32])));
        Assert.Contains(facts.Notes, n => n.Contains("Scripts/main.luae (transformed payload)"));
    }

    [Fact]
    public void A_simple_name_shared_by_two_messages_is_ambiguous()
    {
        var two = new ProtoWriter().Str(1, "a.proto").Str(2, "a").Msg(4, m => m.Str(1, "User").Field(2, "id", 1, 3))
            .Msg(4, m => m.Str(1, "Box").Msg(3, n => n.Str(1, "User").Field(2, "x", 1, 3))).Str(12, "proto3").ToArray();
        var facts = PackageFacts(Package(MarkedBlocks(two), "User = 5\n"));
        Assert.Equal("ambiguous", Assert.Single(facts.Ids!).State);
    }

    [Fact]
    public void Message_ids_beyond_the_limit_are_counted_and_name_the_raise()
    {
        var script = string.Concat(Enumerable.Range(1, 30).Select(i => $"[{i}] = \"M{i}\"\n"));
        var facts = PackageFacts(Package(MarkedBlocks(ProtoWriter.Demo()), script));
        Assert.Equal(20, facts.Ids!.Count);
        Assert.Contains(facts.Notes, n => n.Contains("30 message ids; the first 20 are listed; limit=80 lists more"));
    }

    [Fact]
    public void A_marked_container_with_an_oversized_length_is_counted_as_corrupt_not_fatal()
    {
        var bad = MarkedBlocks(new byte[16]);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(bad.AsSpan(4), 0x7FFFFFF0);
        var facts = PackageFacts(Package(bad, IdScript));
        Assert.All(facts.Ids!, i => Assert.Equal("unknown", i.State));
    }

    [Fact]
    [FuzzEntry(typeof(PackageMessages))]
    public void Fuzzed_packages_never_throw_past_a_tool_error()
    {
        var path = Path.Combine(Path.GetTempPath(), $"pb-fuzz-{Guid.NewGuid():N}.zip");
        try
        {
            var failures = FormatFuzz.Run(Package(MarkedBlocks(ProtoWriter.Demo()), IdScript), b =>
            {
                File.WriteAllBytes(path, b);
                try { new ProtobufFileView().Inspect(new FileInput(path, b, "zip") { Options = new FileViewOptions("protobuf") }, default); }
                catch (ToolError) { }
            }, 300);
            Assert.True(failures.Count == 0, string.Join("\n", failures.Take(5)));
        }
        finally { File.Delete(path); }
    }
}
