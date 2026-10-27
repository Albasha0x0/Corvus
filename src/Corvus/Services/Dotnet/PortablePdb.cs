using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Text.RegularExpressions;
using Corvus.Core;
using ICSharpCode.Decompiler.DebugInfo;
using SequencePoint = ICSharpCode.Decompiler.DebugInfo.SequencePoint;

namespace Corvus.Services;

/// <summary>
/// The Portable PDB of a loaded assembly, embedded or beside the file and used only when its id matches the image;
/// serves sequence points, local names and SourceLink URLs.
/// </summary>
public sealed partial class PortablePdb : IDebugInfoProvider, IDisposable
{
    private static readonly ConditionalWeakTable<LoadedAssembly, Lookup> Cache = new();
    private sealed record Lookup(PortablePdb? Pdb, string Status);

    private readonly MetadataReaderProvider _provider;
    private readonly MetadataReader _reader;
    private readonly List<(string Prefix, string Url)> _sourceLink = [];

    /// <summary>"embedded" or the PDB's path.</summary>
    public string Origin { get; }
    public int SourceLinkDocuments { get; private set; }

    private PortablePdb(MetadataReaderProvider provider, string origin)
    {
        _provider = provider;
        _reader = provider.GetMetadataReader();
        Origin = origin;
        ReadSourceLink();
    }

    public void Dispose() => _provider.Dispose();

    /// <summary>The PDB and a one-line status; null with the reason when none matches or the assembly has edits.</summary>
    public static (PortablePdb? Pdb, string Status) For(LoadedAssembly asm)
    {
        if (asm.IsDirty) return (null, "no source lines: the assembly has unsaved edits, and its PDB describes the file as built");
        var found = Cache.GetValue(asm, Find);
        return (found.Pdb, found.Status);
    }

    private static Lookup Find(LoadedAssembly asm)
    {
        try
        {
            using var pe = new PEReader(new MemoryStream(asm.OriginalBytes, writable: false));
            var entries = pe.ReadDebugDirectory();
            var embedded = entries.FirstOrDefault(e => e.Type == DebugDirectoryEntryType.EmbeddedPortablePdb);
            if (embedded.DataSize > 0)
                return new Lookup(new PortablePdb(pe.ReadEmbeddedPortablePdbDebugDirectoryData(embedded), "embedded"), "Portable PDB: embedded");
            var entry = entries.FirstOrDefault(e => e.Type == DebugDirectoryEntryType.CodeView);
            if (entry.DataSize == 0) return new Lookup(null, "no source lines: the image names no PDB");
            var cv = pe.ReadCodeViewDebugDirectoryData(entry);
            var dir = Path.GetDirectoryName(asm.FilePath) ?? "";
            var candidates = new[] { Path.Combine(dir, Path.GetFileName(cv.Path.Replace('\\', '/'))), Path.ChangeExtension(asm.FilePath, ".pdb") }.Distinct(StringComparer.OrdinalIgnoreCase);
            foreach (var path in candidates.Where(File.Exists))
            {
                var bytes = File.ReadAllBytes(path);
                if (bytes.Length < 4 || bytes[0] != 'B' || bytes[1] != 'S' || bytes[2] != 'J' || bytes[3] != 'B')
                    return new Lookup(null, $"no source lines: {path} is a Windows PDB, not a Portable PDB");
                var provider = MetadataReaderProvider.FromPortablePdbImage(System.Collections.Immutable.ImmutableArray.Create(bytes));
                var id = new BlobContentId(provider.GetMetadataReader().DebugMetadataHeader!.Id);
                if (id.Guid == cv.Guid && id.Stamp == entry.Stamp)
                    return new Lookup(new PortablePdb(provider, path), $"Portable PDB: {path} (id matches the image)");
                provider.Dispose();
                return new Lookup(null, $"no source lines: {path} is from another build (its id differs from the image's)");
            }
            return new Lookup(null, $"no source lines: no {Path.GetFileName(cv.Path.Replace('\\', '/'))} beside the assembly");
        }
        catch (Exception ex) when (ex is BadImageFormatException or IOException or UnauthorizedAccessException or InvalidOperationException or ArgumentException)
        {
            return new Lookup(null, $"no source lines: the PDB is unreadable ({ex.Message})");
        }
    }

    /// <summary>Reads the SourceLink JSON ({"documents": {"/_/*": "https://.../*"}}) from the module's custom debug information.</summary>
    private void ReadSourceLink()
    {
        var sourceLink = new Guid("CC110556-A091-4D38-9FEC-25AB9A351A6A");
        foreach (var h in _reader.GetCustomDebugInformation(EntityHandle.ModuleDefinition))
        {
            var info = _reader.GetCustomDebugInformation(h);
            if (_reader.GetGuid(info.Kind) != sourceLink) continue;
            try
            {
                using var json = JsonDocument.Parse(_reader.GetBlobBytes(info.Value));
                if (!json.RootElement.TryGetProperty("documents", out var docs)) return;
                foreach (var p in docs.EnumerateObject())
                    if (p.Value.GetString() is { } url) _sourceLink.Add((p.Name, url));
            }
            catch (JsonException) { return; }
        }
        // Longest prefix first, as the SourceLink spec matches.
        _sourceLink.Sort((a, b) => b.Prefix.Length.CompareTo(a.Prefix.Length));
        SourceLinkDocuments = _reader.Documents.Count(d => Url(_reader.GetString(_reader.GetDocument(d).Name)) != null);
    }

    /// <summary>The SourceLink URL of a document path, or null.</summary>
    public string? Url(string document)
    {
        foreach (var (prefix, url) in _sourceLink)
        {
            if (prefix.EndsWith('*'))
            {
                var stem = prefix[..^1];
                if (document.StartsWith(stem, StringComparison.Ordinal) && url.EndsWith('*'))
                    return url[..^1] + document[stem.Length..].Replace('\\', '/');
            }
            else if (document == prefix) return url;
        }
        return null;
    }

    public string Description => "Portable PDB " + Origin;
    public string SourceFileName => Origin;

    public IList<SequencePoint> GetSequencePoints(MethodDefinitionHandle method)
    {
        var points = new List<SequencePoint>();
        var info = _reader.GetMethodDebugInformation(method.ToDebugInformationHandle());
        if (info.SequencePointsBlob.IsNil) return points;
        foreach (var sp in info.GetSequencePoints())
        {
            var doc = _reader.GetString(_reader.GetDocument(sp.Document).Name);
            var p = new SequencePoint { Offset = sp.Offset, StartLine = sp.StartLine, StartColumn = sp.StartColumn, EndLine = sp.EndLine, EndColumn = sp.EndColumn, DocumentUrl = Url(doc) ?? doc };
            if (points.Count > 0) points[^1].EndOffset = sp.Offset;
            points.Add(p);
        }
        if (points.Count > 0) points[^1].EndOffset = points[^1].Offset + 1;
        return points;
    }

    public IList<Variable> GetVariables(MethodDefinitionHandle method)
    {
        var variables = new List<Variable>();
        foreach (var scope in _reader.GetLocalScopes(method))
            foreach (var v in _reader.GetLocalScope(scope).GetLocalVariables())
            {
                var local = _reader.GetLocalVariable(v);
                variables.Add(new Variable(local.Index, _reader.GetString(local.Name)));
            }
        return variables;
    }

    public bool TryGetName(MethodDefinitionHandle method, int index, out string name)
    {
        name = GetVariables(method).FirstOrDefault(v => v.Index == index).Name;
        return name != null;
    }

    public bool TryGetExtraTypeInfo(MethodDefinitionHandle method, int index, out PdbExtraTypeInfo extraTypeInfo)
    {
        extraTypeInfo = default;
        return false;
    }

    /// <summary>
    /// The disassembler's sequence point comments made compact: "// line 12:9-12:37", the document (or its SourceLink URL)
    /// added where it changes within a method, "// hidden" for hidden points.
    /// </summary>
    public static string Compact(string il)
    {
        string? last = null;
        var lines = il.Split('\n');
        for (int i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (line.TrimStart().StartsWith(".method", StringComparison.Ordinal)) last = null;
            var m = PointLine().Match(line);
            if (!m.Success) continue;
            var indent = line[..(line.Length - line.TrimStart().Length)];
            if (m.Groups["hidden"].Success) { lines[i] = indent + "// hidden"; continue; }
            var doc = m.Groups["doc"].Value.TrimEnd('\r');
            lines[i] = $"{indent}// line {m.Groups["sl"].Value}:{m.Groups["sc"].Value}-{m.Groups["el"].Value}:{m.Groups["ec"].Value}{(doc != last ? " in " + doc : "")}";
            last = doc;
        }
        return string.Join('\n', lines);
    }

    [GeneratedRegex(@"^\s*// sequence point: (?:!! at \S+ !!)?(?:(?<hidden>hidden)|\(line (?<sl>\d+), col (?<sc>\d+)\) to \(line (?<el>\d+), col (?<ec>\d+)\) in (?<doc>.*))")]
    private static partial Regex PointLine();
}
