using Corvus.Core;
using Corvus.Core.Mobile;
using Corvus.Core.Protobuf;
using System.IO.Compression;
using Corvus.Native;
using dnlib.DotNet;

namespace Corvus.Services.Analysis.Endpoints;

/// <summary>
/// The API surface of an app's code: endpoints from DEX, .NET and Mach-O code (<see cref="DexEndpoints"/>,
/// <see cref="IlEndpoints"/>, <see cref="MachOEndpoints"/>) and embedded protobuf descriptors (raw in native images), with
/// each descriptor's gRPC methods as POST /package.Service/Method endpoints.
/// </summary>
public sealed record ApiSurface(IReadOnlyList<CodeEndpoint> Endpoints, IReadOnlyList<FoundDescriptor> Descriptors, IReadOnlyList<string> Notes)
{
    /// <summary>
    /// The code files of <paramref name="source"/>: the assemblies the container walk found, and from an APK, AAB, IPA, jar
    /// or zip its DEX files, Mach-O images and native libraries (one ABI of each library); any other file is itself.
    /// </summary>
    public static List<ContainerItem> CodeItems(string source, IReadOnlyList<ContainerItem> walked, AnalysisLimits limits, CancellationToken ct)
    {
        var items = walked.Where(i => i.Kind == ".NET assembly").ToList();
        var head = new byte[8];
        using (var f = File.OpenRead(source)) _ = f.ReadAtLeast(head, head.Length, throwOnEndOfStream: false);
        if (Blob.Identify(head) != "zip")
        {
            if (new FileInfo(source).Length <= limits.MaxItemBytes)
            {
                var bytes = File.ReadAllBytes(source);
                if (!items.Any(i => i.Bytes.AsSpan().SequenceEqual(bytes))) items.Add(new ContainerItem(Path.GetFileName(source), Blob.Identify(bytes), "file", bytes));
            }
            return items;
        }
        using var zip = ZipFile.OpenRead(source);
        var libraries = new HashSet<string>(StringComparer.Ordinal);
        foreach (var e in zip.Entries.OrderBy(e => e.FullName.Contains("/arm64-v8a/", StringComparison.Ordinal) ? 0 : 1).ThenBy(e => e.FullName, StringComparer.Ordinal))
        {
            ct.ThrowIfCancellationRequested();
            var name = e.FullName;
            bool dex = name.EndsWith(".dex", StringComparison.Ordinal);
            bool library = name.EndsWith(".so", StringComparison.Ordinal) || name.EndsWith(".dylib", StringComparison.Ordinal);
            bool app = name.Contains(".app/", StringComparison.Ordinal) && !Path.GetFileName(name).Contains('.', StringComparison.Ordinal);
            if (!(dex || library || app) || e.Length < 64 || e.Length > limits.MaxItemBytes) continue;
            if (library && name.StartsWith("lib/", StringComparison.Ordinal) && !libraries.Add(Path.GetFileName(name))) continue;
            using var s = e.Open();
            if (Blob.ReadBounded(s, limits.MaxItemBytes) is not { } bytes) continue;
            if (DexFile.IsDex(bytes)) items.Add(new ContainerItem(name, "dex", "zip", bytes));
            else if (NativeImageLoader.Detect(bytes) != NativeFileKind.Unknown) items.Add(new ContainerItem(name, Blob.Identify(bytes), "zip", bytes));
        }
        return items;
    }

    /// <summary>Reads every file of a container (or one file): DEX files together, so annotation types resolve across them.</summary>
    public static ApiSurface Read(IEnumerable<ContainerItem> items, CancellationToken ct, bool endpoints = true)
    {
        var rows = new List<CodeEndpoint>();
        var descriptors = new List<FoundDescriptor>();
        var notes = new List<string>();
        var dex = new DexEndpoints();
        foreach (var item in items)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                if (DexFile.IsDex(item.Bytes)) dex.Add(DexFile.Read(item.Bytes, item.Path), item.Path, ct);
                else if (item.Kind == ".NET assembly")
                {
                    using var module = ModuleDefMD.Load(item.Bytes);
                    IlEndpoints.Scan(module, item.Path, rows, descriptors, ct);
                }
                else if (item.Kind is "elf" or "mach-o" or "native PE" or "NativeAOT executable" or "data")
                {
                    foreach (var (offset, file) in ProtoScan.Raw(item.Bytes, ct))
                        descriptors.Add(new FoundDescriptor(file, item.Path, "raw bytes", offset));
                    if (endpoints && item.Kind == "mach-o") MachOEndpoints.Scan(item.Bytes, item.Path, rows, ct);
                }
            }
            catch (Exception ex) when (ex is BadImageFormatException or ToolError or IOException or InvalidOperationException or ArgumentException)
            {
                notes.Add($"{item.Path}: not read ({ex.Message}).");
            }
        }
        dex.Finish(rows, descriptors);
        foreach (var d in descriptors)
            foreach (var s in d.File.Services)
                foreach (var m in s.Methods)
                    rows.Add(new CodeEndpoint("POST", $"/{(d.File.Package is { } p ? p + "." : "")}{s.Name}/{m.Name}", "proto", d.Source,
                        $"{d.File.Name} service {s.Name}", d.Site ?? $"offset 0x{d.Offset:x}"));
        var distinct = rows.DistinctBy(r => (r.Verb, r.Url, r.Client, r.File, r.Member, r.Location)).ToList();
        var unique = descriptors.DistinctBy(d => (d.File.Name, d.Source, d.Offset)).ToList();
        return new ApiSurface(distinct, unique, notes);
    }
}
