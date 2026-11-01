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

    public sealed record MessageId(int Id, string Name, string? Message, int? FieldCount, IReadOnlyList<string> Fields, string State, string Source);

    public sealed record Facts(int Total, long Offset, long? Next, IReadOnlyList<Descriptor> Files, IReadOnlyList<string> Notes, IReadOnlyList<MessageId>? Ids = null);

    private const int MaxFieldNames = 64;

    public string Name => "protobuf";

    // Bounds the overview read of an archive; view=protobuf lifts it.
    private const long OverviewItemBytes = 32L * 1024 * 1024;

    // True when the archive holds a code entry within the overview bound; counts the larger ones.
    private static bool OverviewCode(string path, out int oversized, CancellationToken ct)
    {
        oversized = 0;
        bool any = false;
        using var zip = ApiSurface.OpenZip(path);
        foreach (var e in ApiSurface.Entries(zip, path))
        {
            ct.ThrowIfCancellationRequested();
            var n = e.FullName;
            if (!(n.EndsWith(".dex", StringComparison.Ordinal) || n.EndsWith(".so", StringComparison.Ordinal) || n.EndsWith(".dylib", StringComparison.Ordinal))) continue;
            if (e.Length > OverviewItemBytes) oversized++;
            else any = true;
        }
        return any || PackageMessages.Any(path);
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
        var package = file.Kind == "zip"
            ? PackageMessages.Read(file.Path, asked ? AnalysisLimits.Default : AnalysisLimits.Default with { MaxItemBytes = OverviewItemBytes }, ct)
            : new PackageMessages.Package([], [], [], 0, 0);
        var all = surface.Descriptors.Concat(package.Descriptors).ToList();
        if (all.Count == 0 && package.Ids.Count == 0 && package.Unreadable.Count == 0)
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
        int idLimit = Math.Clamp(file.Options.Limit ?? DefaultLimit, 1, MaxLimit);
        var (allIds, listedIds) = Join(package.Ids, all, package.Unreadable.Count > 0 || skipped > 0 || surface.Notes.Count > 0, idLimit, notes);
        if (package.Unreadable.Count > 0)
            notes.Add($"scanned {package.Scanned} of {package.Total} package entries; {package.Unreadable.Count} unreadable (unknown): {string.Join(", ", package.Unreadable.Take(3))}{(package.Unreadable.Count > 3 ? ", ..." : "")}. unpack_container on the package writes its entries.");
        if (next != null) notes.Add($"{all.Count} descriptors; offset={next} lists the next");
        if (skipped > 0) notes.Add($"overview: {skipped} code entr(ies) over {OverviewItemBytes >> 20} MiB not read (unknown); view=protobuf reads them.");
        var services = all.SelectMany(d => d.File.Services.Select(s => (d.File.Package is { } p ? p + "." : "") + s.Name)).Distinct().ToList();
        var highlights = new List<string>();
        if (allIds.Count > 0)
            highlights.Add($"{allIds.Count} script message id(s): {allIds.Count(i => i.State == "joined")} joined to descriptors (view=protobuf lists them).");
        if (all.Count > 0) highlights.Add(
            $"{all.Count} embedded protobuf descriptor(s), {all.Sum(d => d.File.Messages.Count)} message(s): {string.Join(", ", all.Take(8).Select(d => $"{d.File.Name} ({d.File.Messages.Count})"))}{(all.Count > 8 ? ", ..." : "")}" +
            (services.Count > 0 ? $"; gRPC services {string.Join(", ", services.Take(6))}{(services.Count > 6 ? ", ..." : "")}" : "") + " (view=protobuf gives the .proto text).");
        return new FileView(new Facts(all.Count, offset, next, page, notes, listedIds), highlights);
    }

    // Matches a script name to a message by full name, then by a unique simple name.
    private static (List<MessageId> All, IReadOnlyList<MessageId> Listed) Join(IReadOnlyList<PackageMessages.Id> ids, IReadOnlyList<FoundDescriptor> descriptors, bool unknownEntries, int limit, List<string> notes)
    {
        var messages = descriptors.SelectMany(d => PackageMessages.Messages(d.File)).ToList();
        var byFull = messages.ToLookup(m => m.Full, StringComparer.Ordinal);
        var bySimple = messages.ToLookup(m => m.Full[(m.Full.LastIndexOf('.') + 1)..], StringComparer.Ordinal);
        var all = new List<MessageId>();
        int bare = 0;
        foreach (var id in ids.Distinct().OrderBy(i => i.Source, StringComparer.Ordinal).ThenBy(i => i.Number))
        {
            var hits = byFull[id.Name].Take(2).ToList();
            if (hits.Count == 0) hits = bySimple[id.Name].Take(2).ToList();
            if (hits.Count == 1)
            {
                var (full, m) = hits[0];
                all.Add(new MessageId(id.Number, id.Name, full, m.Fields.Count, m.Fields.Take(MaxFieldNames).Select(f => $"{f.Name} = {f.Number}").ToList(), "joined", id.Source));
            }
            else if (id.Bare && hits.Count == 0) bare++;
            else all.Add(new MessageId(id.Number, id.Name, null, null, [], hits.Count > 1 ? "ambiguous" : unknownEntries ? "unknown" : "unmatched", id.Source));
        }
        var ordered = all.OrderBy(i => i.State == "joined" ? 0 : 1).ToList();
        if (bare > 0) notes.Add($"{bare} bare name = number assignment(s) match no message and are not listed.");
        if (ordered.Count > limit)
            notes.Add($"{ordered.Count} message ids; the first {limit} are listed{(limit < MaxLimit ? $"; limit={Math.Min(MaxLimit, limit * 4)} lists more" : $"; the rest are not listed, joined ids sort first")}.");
        return (all, ordered.Take(limit).ToList());
    }
}
