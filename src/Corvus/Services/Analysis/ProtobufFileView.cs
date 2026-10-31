using System.ComponentModel;
using Corvus.Core;
using Corvus.Core.Mobile;
using Corvus.Core.Protobuf;
using Corvus.Native;
using Corvus.Services.Analysis.Endpoints;

namespace Corvus.Services.Analysis;

/// <summary>view=protobuf: embedded FileDescriptorProto blobs rebuilt as .proto text; archives are read only when the view is asked for.</summary>
internal sealed class ProtobufFileView : IFileSummaryView
{
    private const int DefaultLimit = 20, MaxLimit = 200;

    internal const string NoDescriptorNote = "input inspected; no FileDescriptorProto found. Try view=overview.";
    internal const string NoReadableNote = "input inspected; no readable FileDescriptorProto. Try view=overview.";

    public sealed record Descriptor(string Name, string? Package, string Syntax, string Source,
        [property: Description("raw bytes, Latin-1 string constants (Java) or base64 string (C#).")] string Encoding,
        long Offset, [property: Description("The method that builds it, for string constants.")] string? Site,
        int Messages, int Enums, int Services, IReadOnlyList<string> Dependencies,
        [property: Description("The .proto source rebuilt from the descriptor.")] string Proto);

    public sealed record Facts(int Total, long Offset, long? Next, IReadOnlyList<Descriptor> Files, IReadOnlyList<string> Notes);

    public string Name => "protobuf";

    // Bounds the overview read of an archive; view=protobuf lifts it.
    private const long OverviewItemBytes = 32L * 1024 * 1024;

    // True when the archive holds a code entry within the overview bound; counts the larger ones.
    private static bool OverviewCode(string path, out int oversized, CancellationToken ct)
    {
        oversized = 0;
        bool any = false;
        using var zip = System.IO.Compression.ZipFile.OpenRead(path);
        foreach (var e in zip.Entries)
        {
            ct.ThrowIfCancellationRequested();
            var n = e.FullName;
            if (!(n.EndsWith(".dex", StringComparison.Ordinal) || n.EndsWith(".so", StringComparison.Ordinal) || n.EndsWith(".dylib", StringComparison.Ordinal))) continue;
            if (e.Length > OverviewItemBytes) oversized++;
            else any = true;
        }
        return any;
    }

    public FileView? Inspect(FileInput file, CancellationToken ct)
    {
        bool asked = file.Options.Wants(Name);
        List<ContainerItem> items;
        int skipped = 0;
        if (file.Kind == "zip")
        {
            var limits = asked ? AnalysisLimits.Default : AnalysisLimits.Default with { MaxItemBytes = OverviewItemBytes };
            if (!asked && !OverviewCode(file.Path, out skipped, ct)) return null;
            items = ApiSurface.CodeItems(file.Path, [], limits, ct);
        }
        else
        {
            var head = file.Head;
            bool native = NativeImageLoader.Detect(head) != NativeFileKind.Unknown;
            bool dex = DexFile.IsDex(head);
            if (!native && !dex) return null;
            var bytes = native ? file.Image : file.Bytes;
            // C# descriptors reference Google.Protobuf; the others keep ".proto" names in their bytes.
            bool dotnet = file.Kind == ".NET assembly";
            if (!asked && bytes.AsSpan().IndexOf(dotnet ? "Google.Protobuf"u8 : ".proto"u8) < 0) return null;
            items = [new ContainerItem(Path.GetFileName(file.Path), dex ? "dex" : Blob.Identify(head), "file", bytes)];
        }
        var surface = ApiSurface.Read(items, ct, endpoints: false);
        var all = surface.Descriptors;
        if (all.Count == 0)
        {
            if (!asked) return null;
            // Notes present means a candidate was rejected or an item was unreadable.
            string summary = surface.Notes.Count > 0 ? NoReadableNote : NoDescriptorNote;
            string[] empty = [.. surface.Notes, summary];
            return new FileView(new Facts(0, 0, null, [], empty), []);
        }
        int limit = Math.Clamp(file.Options.Limit ?? DefaultLimit, 1, MaxLimit);
        long offset = Math.Clamp(file.Options.Offset, 0, all.Count);
        var page = all.Skip((int)offset).Take(limit).Select(d => new Descriptor(d.File.Name, d.File.Package, d.File.Syntax, d.Source, d.Encoding, d.Offset, d.Site,
            d.File.Messages.Count, d.File.Enums.Count, d.File.Services.Count, d.File.Dependencies, ProtoText.Write(d.File))).ToList();
        long? next = offset + page.Count < all.Count ? offset + page.Count : null;
        var notes = new List<string>(surface.Notes);
        if (next != null) notes.Add($"{all.Count} descriptors; offset={next} lists the next");
        if (skipped > 0) notes.Add($"overview: {skipped} code entr(ies) over {OverviewItemBytes >> 20} MiB not read (unknown); view=protobuf reads them.");
        var services = all.SelectMany(d => d.File.Services.Select(s => (d.File.Package is { } p ? p + "." : "") + s.Name)).Distinct().ToList();
        var highlights = new List<string>
        {
            $"{all.Count} embedded protobuf descriptor(s), {all.Sum(d => d.File.Messages.Count)} message(s): {string.Join(", ", all.Take(8).Select(d => $"{d.File.Name} ({d.File.Messages.Count})"))}{(all.Count > 8 ? ", ..." : "")}" +
            (services.Count > 0 ? $"; gRPC services {string.Join(", ", services.Take(6))}{(services.Count > 6 ? ", ..." : "")}" : "") + " (view=protobuf gives the .proto text).",
        };
        return new FileView(new Facts(all.Count, offset, next, page, notes), highlights);
    }
}
