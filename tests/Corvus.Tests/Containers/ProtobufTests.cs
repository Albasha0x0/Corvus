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
}
