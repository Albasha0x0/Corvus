using System.Security.Cryptography;
using System.Text;
using Corvus.Core;
using Corvus.Services.Web.Packages;

namespace Corvus.Services.Analysis;

/// <summary>search_container kind=incident: locked packages and file hashes that an incident list names, queried as a list file or pack:name; a match is listed, not a verdict.</summary>
internal sealed class IncidentSearchKind : IContainerSearchKind
{
    private const int MaxFiles = 20000;
    private const long MaxFileBytes = 256L << 20;
    private static readonly string[] ListExtensions = [".txt", ".list"];

    public IReadOnlyList<string> Kinds => ["incident"];

    public IEnumerable<ContainerMatch> Search(ContainerScope scope, string kind, Func<string, bool> matches, CancellationToken ct) => [];

    public UnpackService.ContainerSearch SearchFile(string path, string query, int offset, int limit, ContainerSearchArgs args, CancellationToken ct)
    {
        var source = Directory.Exists(Path.GetFullPath(path)) ? Path.GetFullPath(path) : InputFiles.RequireRegularFile(path, "file");
        if (string.IsNullOrWhiteSpace(query))
            throw new ToolError(ErrorCode.InvalidArgument, "kind=incident takes an incident list as query.", "pass a list file path or pack:<name>");
        var lists = Lists(query.Trim());
        var notes = new List<string>();
        foreach (var l in lists.Where(l => l.Unreadable > 0)) notes.Add($"{l.Name}: {l.Unreadable} line(s) are neither name@version nor a SHA-256; skipped");
        var rows = new List<ContainerMatch>();
        bool folder = Directory.Exists(source);
        int searched = 0;

        void Packages(string where, Lockfile lockfile)
        {
            foreach (var p in lockfile.Packages.DistinctBy(p => (p.Name, p.Version)))
                foreach (var l in lists.Where(l => l.Lists(p.Name, p.Version, lockfile.Ecosystem == "pypi")))
                    rows.Add(new ContainerMatch(where, $"{p.Name}@{p.Version}", "incident") { Detail = $"listed in {l.Name}, {lockfile.Format}" });
        }

        void Hash(string where, byte[] bytes)
        {
            var sha = Convert.ToHexStringLower(SHA256.HashData(bytes));
            foreach (var l in lists.Where(l => l.Lists(sha)))
                rows.Add(new ContainerMatch(where, sha, "incident") { Detail = $"listed in {l.Name}, sha256, {bytes.Length:N0} bytes" });
        }

        var hashes = lists.Any(l => l.HasHashes);
        if (folder)
        {
            var found = Lockfiles.Find(source, ct, out bool complete);
            foreach (var relative in found)
            {
                ct.ThrowIfCancellationRequested();
                searched++;
                if (Lockfiles.Load(Path.Combine(source, relative)) is { } lockfile) Packages(relative, lockfile);
                else notes.Add($"{relative}: not read");
            }
            if (!complete) notes.Add($"the walk stopped at {Lockfiles.MaxFiles} lockfiles or an unreadable folder; others are unknown");
            if (hashes) searched += HashFolder(source, Hash, notes, ct);
        }
        else
        {
            var name = Path.GetFileName(source);
            if (hashes && new FileInfo(source).Length <= MaxFileBytes) Hash(name, File.ReadAllBytes(source));
            try
            {
                var (scope, scopeNotes) = UnpackService.Scope(source, AnalysisLimits.Default, ct);
                notes.AddRange(scopeNotes);
                foreach (var item in scope.Items)
                {
                    ct.ThrowIfCancellationRequested();
                    searched++;
                    if (hashes && item.Bytes.Length > 0) Hash(item.Path, item.Bytes);
                    if (Lockfiles.Named(Path.GetFileName(item.Path)) && Lockfiles.Read(item.Path, Encoding.UTF8.GetString(item.Bytes)) is { } lockfile)
                        Packages(item.Path, lockfile);
                }
            }
            catch (ToolError e)
            {
                notes.Add($"members unknown: {e.Message}");
            }
            if (Lockfiles.Named(name) && Lockfiles.Load(source) is { } own) Packages(name, own);
        }
        var unique = rows.DistinctBy(r => (r.Path, r.Name, r.Detail)).ToList();
        notes.Insert(0, $"{string.Join(", ", lists.Select(l => $"{l.Name} ({l.Count:N0})"))}: {unique.Count} listed; a listing is not a verdict.");
        return UnpackService.Ranked(source, folder ? "folder" : "file", searched, unique, "", offset, limit, notes);
    }

    private static int HashFolder(string root, Action<string, byte[]> hash, List<string> notes, CancellationToken ct)
    {
        int count = 0;
        var pending = new Stack<string>([root]);
        while (pending.Count > 0)
        {
            var dir = pending.Pop();
            try
            {
                // Links are not followed, so a link cycle cannot repeat the walk.
                foreach (var d in Directory.EnumerateDirectories(dir))
                    if (!new DirectoryInfo(d).Attributes.HasFlag(FileAttributes.ReparsePoint)) pending.Push(d);
                foreach (var f in Directory.EnumerateFiles(dir).Order(StringComparer.Ordinal))
                {
                    ct.ThrowIfCancellationRequested();
                    if (count == MaxFiles)
                    {
                        notes.Add($"hashing stopped at {MaxFiles:N0} files; others are unknown");
                        return count;
                    }
                    var relative = Path.GetRelativePath(root, f).Replace('\\', '/');
                    if (new FileInfo(f).Length > MaxFileBytes)
                    {
                        notes.Add($"{relative}: larger than {MaxFileBytes >> 20} MB; not hashed");
                        continue;
                    }
                    hash(relative, File.ReadAllBytes(f));
                    count++;
                }
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                notes.Add($"{Path.GetRelativePath(root, dir).Replace('\\', '/')}: not listed; its files are unknown");
            }
        }
        return count;
    }

    private static List<IncidentList> Lists(string query)
    {
        if (RulePacks.ResolveQuery(query, RulePacks.Root) is { } folder)
        {
            var files = Directory.EnumerateFiles(folder, "*", SearchOption.AllDirectories)
                .Where(f => ListExtensions.Contains(Path.GetExtension(f).ToLowerInvariant()) && !Path.GetFileName(f).Equals("LICENSE", StringComparison.OrdinalIgnoreCase))
                .Order(StringComparer.Ordinal).ToList();
            var pack = query[RulePacks.QueryPrefix.Length..].Trim();
            if (files.Count == 0)
                throw new ToolError(ErrorCode.MalformedInput, $"Rule pack '{pack}' holds no .txt or .list incident list.", "install a pack that ships an incident list");
            return [.. files.Select(f => IncidentList.Parse(Read(f), $"{pack}/{Path.GetRelativePath(folder, f).Replace('\\', '/')}"))];
        }
        var path = InputFiles.RequireRegularFile(query, "incident list");
        return [IncidentList.Parse(Read(path), Path.GetFileName(path))];
    }

    private static byte[] Read(string path)
    {
        if (new FileInfo(path).Length > IncidentList.MaxBytes)
            throw new ToolError(ErrorCode.LimitExceeded, $"{path} is larger than {IncidentList.MaxBytes >> 20} MB.", "split the list");
        return File.ReadAllBytes(path);
    }
}
