using System.ComponentModel;
using Corvus.Core;
using Corvus.Core.Mobile;
using Corvus.Core.Protobuf;
using Corvus.Native;
using Corvus.Services.Analysis.Endpoints;

namespace Corvus.Services.Analysis;

/// <summary>
/// view=protobuf: FileDescriptorProto blobs embedded in a native image (C++, Go), DEX code (Java descriptorData) or a .NET
/// assembly (C# base64 descriptorData), each rebuilt as .proto text that protoc compiles back to the same descriptor. An
/// APK, IPA or jar is read when view=protobuf is asked for; on its own the overview reads single files only.
/// </summary>
internal sealed class ProtobufFileView : IFileSummaryView
{
    private const int DefaultLimit = 20, MaxLimit = 200;

    public sealed record Descriptor(string Name, string? Package, string Syntax, string Source,
        [property: Description("raw bytes, Latin-1 string constants (Java) or base64 string (C#).")] string Encoding,
        long Offset, [property: Description("The method that builds it, for string constants.")] string? Site,
        int Messages, int Enums, int Services, IReadOnlyList<string> Dependencies,
        [property: Description("The .proto source rebuilt from the descriptor.")] string Proto);

    public sealed record Facts(int Total, long Offset, long? Next, IReadOnlyList<Descriptor> Files, IReadOnlyList<string> Notes);

    public string Name => "protobuf";

    public FileView? Inspect(FileInput file, CancellationToken ct)
    {
        bool asked = file.Options.Wants(Name);
        List<ContainerItem> items;
        if (file.Kind == "zip")
        {
            if (!asked) return null;
            items = ApiSurface.CodeItems(file.Path, [], AnalysisLimits.Default, ct);
        }
        else
        {
            var head = file.Head;
            bool native = NativeImageLoader.Detect(head) != NativeFileKind.Unknown;
            bool dex = DexFile.IsDex(head);
            if (!native && !dex) return null;
            var bytes = file.Bytes;
            // C# descriptors reference Google.Protobuf; the others keep ".proto" names in their bytes
            bool dotnet = file.Kind == ".NET assembly";
            if (!asked && bytes.AsSpan().IndexOf(dotnet ? "Google.Protobuf"u8 : ".proto"u8) < 0) return null;
            items = [new ContainerItem(Path.GetFileName(file.Path), dex ? "dex" : Blob.Identify(head), "file", bytes)];
        }
        var surface = ApiSurface.Read(items, ct, endpoints: false);
        var all = surface.Descriptors;
        if (all.Count == 0) return asked ? new FileView(new Facts(0, 0, null, [], [.. surface.Notes, "no FileDescriptorProto found"]), []) : null;
        int limit = Math.Clamp(file.Options.Limit ?? DefaultLimit, 1, MaxLimit);
        long offset = Math.Clamp(file.Options.Offset, 0, all.Count);
        var page = all.Skip((int)offset).Take(limit).Select(d => new Descriptor(d.File.Name, d.File.Package, d.File.Syntax, d.Source, d.Encoding, d.Offset, d.Site,
            d.File.Messages.Count, d.File.Enums.Count, d.File.Services.Count, d.File.Dependencies, ProtoText.Write(d.File))).ToList();
        long? next = offset + page.Count < all.Count ? offset + page.Count : null;
        var notes = new List<string>(surface.Notes);
        if (next != null) notes.Add($"{all.Count} descriptors; offset={next} lists the next");
        var services = all.SelectMany(d => d.File.Services.Select(s => (d.File.Package is { } p ? p + "." : "") + s.Name)).Distinct().ToList();
        var highlights = new List<string>
        {
            $"{all.Count} embedded protobuf descriptor(s): {string.Join(", ", all.Take(8).Select(d => d.File.Name))}{(all.Count > 8 ? ", ..." : "")}" +
            (services.Count > 0 ? $"; gRPC services {string.Join(", ", services.Take(6))}{(services.Count > 6 ? ", ..." : "")}" : "") + " (view=protobuf gives the .proto text).",
        };
        return new FileView(new Facts(all.Count, offset, next, page, notes), highlights);
    }
}
