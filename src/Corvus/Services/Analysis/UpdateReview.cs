using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Pe;
using Corvus.Services.Analysis.Hunts;

namespace Corvus.Services.Analysis;

/// <summary>A function the new build adds or changes; an address is absent on the side that has none.</summary>
public sealed record ReviewFunction(string? OldAddress, string? NewAddress, string Name, string? Reason, string? Diff);

/// <summary>An imported function only the new build has; Concern names the hold table row it matches, if any.</summary>
public sealed record ReviewImport(string Name, string? Concern);

/// <summary>A host, URL or address only the new build holds.</summary>
public sealed record ReviewHost(string Kind, string Value, string Evidence);

/// <summary>A PE image inside the new build that the old build does not hold.</summary>
public sealed record ReviewEmbedded(string Offset, long Size, string Sha256, string Machine);

/// <summary>The signer of each build and what changed: unsigned, signed, same_signer, new_signer, signature_lost or unknown.</summary>
public sealed record ReviewSigner(string? Old, string? New, string Change, string? Detail = null);

/// <summary>A version resource field with a different value in the new build.</summary>
public sealed record ReviewVersionChange(string Field, string? Old, string? New);

/// <summary>One reason the verdict is hold, from the table in <see cref="UpdateReviewer.HoldReasons"/>.</summary>
public sealed record ReviewHold(string Id, string Reason, string Evidence);

/// <summary>A section of the report and how much of it was read: read, partial or unknown.</summary>
public sealed record ReviewSection(string Name, string Status, string? Detail = null)
{
    /// <summary>The section as one line: name, status and detail.</summary>
    public override string ToString() => $"{Name}: {Status}{(Detail != null ? ", " + Detail : "")}";
}

/// <summary>What a new build of a program adds to an old one, and the verdict on it: pass lists no hold reason, hold lists each one.</summary>
public sealed record UpdateReview(
    string OldImage, string NewImage, string Verdict, IReadOnlyList<ReviewHold> Holds, IReadOnlyList<string> Sections,
    IReadOnlyList<ReviewFunction> Added, int AddedTotal, IReadOnlyList<ReviewFunction> Changed, int ChangedTotal,
    IReadOnlyList<ReviewImport> Imports, IReadOnlyList<ReviewHost> Hosts, IReadOnlyList<ReviewEmbedded> Embedded,
    ReviewSigner Signer, IReadOnlyList<ReviewVersionChange> Version);

/// <summary>What the review reads from two builds.</summary>
public sealed record ReviewSources(
    string OldImage, string NewImage, PeFile? OldPe, PeFile? NewPe,
    IReadOnlyList<ReviewFunction> Added, IReadOnlyList<ReviewFunction> Changed,
    IReadOnlyList<HuntFact> OldFacts, IReadOnlyList<string> OldNotes, IReadOnlyList<HuntFact> NewFacts, IReadOnlyList<string> NewNotes,
    byte[]? OldBytes, byte[]? NewBytes, IReadOnlyList<Hunt> Hunts);

/// <summary>The review of an update: what the new build adds and the hold reasons found in it.</summary>
public static partial class UpdateReviewer
{
    /// <summary>Rows of each function list kept in a report; the totals count all.</summary>
    public const int MaxListed = 200;

    /// <summary>The hold reasons: id and the condition. Pass means none was found, not that the update is safe.</summary>
    public static readonly IReadOnlyList<(string Id, string Reason)> HoldReasons =
    [
        ("new_signer", "The new build is signed by a different signer."),
        ("signature_lost", "The old build was signed and the new build has no signature, or its digest does not match."),
        ("new_network_host", "The new build holds a host, URL or address the old build does not."),
        ("new_process_import", "The new build imports a process-creation or injection-capable function the old build does not."),
        ("new_embedded_executable", "The new build holds a PE image the old build does not."),
        ("unread_section", "A section the verdict needs could not be read, so it is unknown."),
    ];

    // Process creation, then cross-process memory and thread control.
    [GeneratedRegex(@"^(?:CreateProcess(?:AsUser|WithLogon|WithToken|Internal)?[AW]?|ShellExecute(?:Ex)?[AW]?|WinExec|NtCreateUserProcess|NtCreateProcessEx?|ZwCreateUserProcess|RtlCreateUserProcess)$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ProcessCreation();

    [GeneratedRegex(@"^(?:WriteProcessMemory|NtWriteVirtualMemory|ZwWriteVirtualMemory|VirtualAllocEx|CreateRemoteThread(?:Ex)?|NtCreateThreadEx|RtlCreateUserThread|QueueUserAPC2?|NtQueueApcThread(?:Ex)?|(?:Wow64)?SetThreadContext|NtSetContextThread|(?:Nt|Zw)UnmapViewOfSection|SetWindowsHookEx[AW]?)$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex Injection();

    private static readonly HashSet<string> HostKinds = new(StringComparer.Ordinal) { HuntKind.Domain, HuntKind.Url, HuntKind.Ipv4, HuntKind.Ipv6 };

    /// <summary>The functions imported by the new build only, as module!name, in name order; the Concern of each is process creation, injection or null.</summary>
    public static IReadOnlyList<ReviewImport> AddedImports(IEnumerable<NativeImport> oldImports, IEnumerable<NativeImport> newImports)
    {
        static string Spelled(NativeImport i) => $"{i.Module}!{i.Name ?? "#" + i.Ordinal}";
        var before = oldImports.Select(Spelled).ToHashSet(StringComparer.OrdinalIgnoreCase);
        return [.. newImports.Where(i => !before.Contains(Spelled(i))).GroupBy(Spelled, StringComparer.OrdinalIgnoreCase).Select(g => g.First())
            .OrderBy(Spelled, StringComparer.OrdinalIgnoreCase).Select(i => new ReviewImport(Spelled(i), Concern(i.Name)))];
    }

    private static string? Concern(string? name) =>
        name == null ? null : ProcessCreation().IsMatch(name) ? "process creation" : Injection().IsMatch(name) ? "injection" : null;

    /// <summary>The hosts, URLs and addresses of <paramref name="newFacts"/> that <paramref name="oldFacts"/> lacks; case is ignored.</summary>
    public static IReadOnlyList<ReviewHost> AddedHosts(IEnumerable<HuntFact> oldFacts, IEnumerable<HuntFact> newFacts)
    {
        var before = oldFacts.Where(f => HostKinds.Contains(f.Kind)).Select(f => (f.Kind, f.Value.Trim().ToLowerInvariant())).ToHashSet();
        return [.. newFacts.Where(f => HostKinds.Contains(f.Kind) && !before.Contains((f.Kind, f.Value.Trim().ToLowerInvariant())))
            .DistinctBy(f => (f.Kind, f.Value.Trim().ToLowerInvariant())).OrderBy(f => f.Kind, StringComparer.Ordinal).ThenBy(f => f.Value, StringComparer.OrdinalIgnoreCase)
            .Select(f => new ReviewHost(f.Kind, f.Value, f.Evidence))];
    }

    /// <summary>The PE images inside <paramref name="newer"/> past its own header whose SHA-256 no image inside <paramref name="older"/> has.</summary>
    public static IReadOnlyList<ReviewEmbedded> AddedEmbedded(byte[] older, byte[] newer, CancellationToken ct)
    {
        // Scanning from byte 1 skips the outer header and still covers its sections.
        List<(Blob.Carved Image, string Sha)> Images(byte[] bytes) => [.. Blob.CarvePe(bytes.AsSpan(1), ct: ct)
            .Select(c => (c with { Offset = c.Offset + 1 }, Blob.Sha256(bytes.AsSpan(c.Offset + 1, c.Length))))];
        var before = Images(older).Select(i => i.Sha).ToHashSet(StringComparer.Ordinal);
        return [.. Images(newer).Where(i => !before.Contains(i.Sha)).DistinctBy(i => i.Sha)
            .Select(i => new ReviewEmbedded($"0x{i.Image.Offset:X}", i.Image.Length, i.Sha, i.Image.Machine))];
    }

    /// <summary>The signer change between two builds' signatures and its detail; an unreadable signature gives change unknown.</summary>
    public static ReviewSigner Signer(CertificateInfo? older, CertificateInfo? newer)
    {
        static bool Unreadable(CertificateInfo c) => c.Present && c.Problem != null && string.IsNullOrEmpty(c.Signer);
        if (older == null || newer == null) return new ReviewSigner(null, null, "unknown", "a build is not a PE image");
        if (Unreadable(older) || Unreadable(newer))
            return new ReviewSigner(older.Signer, newer.Signer, "unknown", $"signature unreadable: {(Unreadable(older) ? older : newer).Problem}");
        if (!older.Present && !newer.Present) return new ReviewSigner(null, null, "unsigned");
        if (!older.Present) return new ReviewSigner(null, newer.Signer, "signed");
        if (!newer.Present) return new ReviewSigner(older.Signer, null, "signature_lost");
        if (newer.DigestMatches == false) return new ReviewSigner(older.Signer, newer.Signer, "signature_lost", "the digest of the new build does not match its signature");
        if (!string.Equals(older.Signer, newer.Signer, StringComparison.OrdinalIgnoreCase)) return new ReviewSigner(older.Signer, newer.Signer, "new_signer");
        return new ReviewSigner(older.Signer, newer.Signer, "same_signer",
            older.Thumbprint != newer.Thumbprint ? "the certificate differs: its thumbprint changed" : null);
    }

    /// <summary>The version resource fields, file and product version included, whose value differs; a field one build lacks has a null value there.</summary>
    public static IReadOnlyList<ReviewVersionChange> VersionChanges(PeVersionInfo? older, PeVersionInfo? newer)
    {
        var fields = new List<string> { "FileVersion (fixed)", "ProductVersion (fixed)" };
        fields.AddRange(Keys(older).Concat(Keys(newer)).Distinct(StringComparer.OrdinalIgnoreCase));
        string? Value(PeVersionInfo? v, string f) => v == null ? null : f switch
        {
            "FileVersion (fixed)" => v.Fixed?.FileVersionText,
            "ProductVersion (fixed)" => v.Fixed?.ProductVersionText,
            _ => v.Get(f),
        };
        return [.. fields.Select(f => new ReviewVersionChange(f, Value(older, f), Value(newer, f))).Where(c => c.Old != c.New)];
    }

    private static IEnumerable<string> Keys(PeVersionInfo? v) => v?.StringTables.SelectMany(t => t.Strings).Select(s => s.Key) ?? [];

    // The notes that say strings were not scanned or the image did not parse; others only limit the facts read.
    private static bool Unread(string note) =>
        note.StartsWith("The image is streamed", StringComparison.Ordinal) || note.StartsWith("The version resource and imports are unknown", StringComparison.Ordinal)
        || note.StartsWith("The version resource, imports and strings are read for PE images only", StringComparison.Ordinal);

    /// <summary>The review of <paramref name="s"/>: each section, then the hold reasons found or the pass.</summary>
    public static UpdateReview Review(ReviewSources s, CancellationToken ct)
    {
        var sections = new List<ReviewSection>();
        var holds = new List<ReviewHold>();
        void Unknown(string section, string detail)
        {
            sections.Add(new ReviewSection(section, "unknown", detail));
            holds.Add(new ReviewHold("unread_section", HoldReasons[^1].Reason, $"{section}: {detail}"));
        }

        sections.Add(new ReviewSection("functions", "read", $"{s.Added.Count} added or unmatched, {s.Changed.Count} changed"));

        IReadOnlyList<ReviewImport> imports = [];
        var importIssues = new[] { s.OldPe, s.NewPe }.Where(p => p != null).SelectMany(p => p!.Issues).Where(i => i.Area is "imports" or "delay imports").ToList();
        if (s.OldPe == null || s.NewPe == null) Unknown("imports", "a build is not a PE image");
        else if (importIssues.Count > 0) Unknown("imports", importIssues[0].Message);
        else
        {
            imports = AddedImports(s.OldPe.Imports, s.NewPe.Imports);
            sections.Add(new ReviewSection("imports", "read", $"{imports.Count} added"));
            foreach (var i in imports.Where(i => i.Concern != null))
                holds.Add(new ReviewHold("new_process_import", HoldReasons[3].Reason, $"{i.Name} ({i.Concern})"));
        }

        var factNotes = s.OldNotes.Select(n => "old: " + n).Concat(s.NewNotes.Select(n => "new: " + n)).ToList();
        IReadOnlyList<ReviewHost> hosts = [];
        if (factNotes.FirstOrDefault(n => Unread(n[5..])) is { } missed) Unknown("hosts", missed);
        else
        {
            hosts = AddedHosts(s.OldFacts, s.NewFacts);
            bool partial = s.OldNotes.Concat(s.NewNotes).Any(HuntFacts.LimitsFacts);
            sections.Add(new ReviewSection("hosts", partial ? "partial" : "read", $"{hosts.Count} added" + (partial ? "; some strings were not read, so more may exist" : "")));
            foreach (var h in hosts) holds.Add(new ReviewHold("new_network_host", HoldReasons[2].Reason, $"{h.Kind} {h.Value}"));
        }

        IReadOnlyList<ReviewEmbedded> embedded = [];
        if (s.OldBytes == null || s.NewBytes == null) Unknown("embedded files", "a build is too large to read whole");
        else
        {
            embedded = AddedEmbedded(s.OldBytes, s.NewBytes, ct);
            sections.Add(new ReviewSection("embedded files", "read", $"{embedded.Count} added"));
            foreach (var e in embedded) holds.Add(new ReviewHold("new_embedded_executable", HoldReasons[4].Reason, $"{e.Machine} image at {e.Offset}, {e.Size} bytes, sha256 {e.Sha256}"));
        }

        var signer = Signer(s.OldPe?.Certificate, s.NewPe?.Certificate);
        if (signer.Change == "unknown") Unknown("signer", signer.Detail ?? "unknown");
        else
        {
            sections.Add(new ReviewSection("signer", "read", signer.Change));
            if (signer.Change == "new_signer") holds.Add(new ReviewHold("new_signer", HoldReasons[0].Reason, $"{signer.Old} -> {signer.New}"));
            if (signer.Change == "signature_lost") holds.Add(new ReviewHold("signature_lost", HoldReasons[1].Reason, signer.Detail ?? $"{signer.Old} -> unsigned"));
        }

        var version = VersionChanges(s.OldPe?.VersionInfo, s.NewPe?.VersionInfo);
        if (s.OldPe == null || s.NewPe == null) sections.Add(new ReviewSection("version resource", "unknown", "a build is not a PE image"));
        else if (new[] { s.OldPe, s.NewPe }.SelectMany(p => p.Issues).Any(i => i.Area == "resources"))
            sections.Add(new ReviewSection("version resource", "partial", "the resource directory has parse issues"));
        else sections.Add(new ReviewSection("version resource", "read", $"{version.Count} field(s) changed"));

        sections.Add(new ReviewSection("hunts", "read", $"{s.Hunts.Count} quer{(s.Hunts.Count == 1 ? "y" : "ies")}"));
        return new UpdateReview(s.OldImage, s.NewImage, holds.Count == 0 ? "pass" : "hold", holds, [.. sections.Select(x => x.ToString())],
            [.. s.Added.Take(MaxListed)], s.Added.Count, [.. s.Changed.Take(MaxListed)], s.Changed.Count, imports, hosts, embedded, signer, version);
    }

    /// <summary>The verdict line: pass names no listed reason found and is not a statement of safety; hold counts its reasons.</summary>
    public static string VerdictText(UpdateReview r) => r.Verdict == "pass"
        ? "Verdict: pass. No hold reason in the table was found; this does not show the update is safe."
        : $"Verdict: hold. {r.Holds.Count} reason(s):\n" + string.Join('\n', r.Holds.Select(h => $"  {h.Id}: {h.Evidence}"));

    /// <summary>The review as Markdown: verdict first, then a section per fact, the hunting queries and the notes.</summary>
    public static string Markdown(UpdateReview r, IReadOnlyList<Hunt> hunts, IReadOnlyList<string> notes)
    {
        var sb = new StringBuilder();
        sb.Append($"# Update review: {r.OldImage} -> {r.NewImage}\n\n## Verdict\n\n{VerdictText(r)}\n\n## Sections read\n\n");
        foreach (var s in r.Sections) sb.Append($"- {s}\n");
        if (r.AddedTotal > MaxListed || r.ChangedTotal > MaxListed) sb.Append($"- Each function list holds the first {MaxListed} rows; view=changed and view=unmatched list all.\n");
        sb.Append("\n## Hold reasons\n\n| Id | Reason |\n|---|---|\n");
        foreach (var (id, reason) in HoldReasons) sb.Append($"| {id} | {reason} |\n");
        void Functions(string title, IReadOnlyList<ReviewFunction> rows, int total)
        {
            sb.Append($"\n## {title} ({total})\n\n");
            foreach (var f in rows) sb.Append($"- {f.OldAddress ?? "-"} -> {f.NewAddress ?? "-"} {f.Name}{(f.Reason != null ? $" ({f.Reason})" : "")}{(f.Diff != null ? $"; {f.Diff}" : "")}\n");
            if (total > rows.Count) sb.Append($"- {total - rows.Count} more\n");
        }
        Functions("Added or unmatched functions", r.Added, r.AddedTotal);
        Functions("Changed functions", r.Changed, r.ChangedTotal);
        sb.Append($"\n## New imports ({r.Imports.Count})\n\n");
        foreach (var i in r.Imports) sb.Append($"- {i.Name}{(i.Concern != null ? $" ({i.Concern})" : "")}\n");
        sb.Append($"\n## New hosts and addresses ({r.Hosts.Count})\n\n");
        foreach (var h in r.Hosts) sb.Append($"- {h.Kind} {h.Value} ({h.Evidence})\n");
        sb.Append($"\n## New embedded files ({r.Embedded.Count})\n\n");
        foreach (var e in r.Embedded) sb.Append($"- {e.Machine} image at {e.Offset}, {e.Size} bytes, sha256 {e.Sha256}\n");
        sb.Append($"\n## Signer\n\n- {r.Signer.Change}: {r.Signer.Old ?? "none"} -> {r.Signer.New ?? "none"}{(r.Signer.Detail != null ? $"; {r.Signer.Detail}" : "")}\n");
        sb.Append($"\n## Version resource ({r.Version.Count} changed)\n\n");
        foreach (var v in r.Version) sb.Append($"- {v.Field}: {v.Old ?? "none"} -> {v.New ?? "none"}\n");
        sb.Append($"\n## Hunting queries ({hunts.Count})\n\n");
        foreach (var h in hunts) sb.Append($"- {h.Id} ({h.Table}) {h.Title}\n");
        if (notes.Count > 0)
        {
            sb.Append("\n## Notes\n\n");
            foreach (var n in notes) sb.Append($"- {n}\n");
        }
        return sb.ToString();
    }

    /// <summary>The review, the ids and titles of the hunting queries and the notes as indented JSON.</summary>
    public static string Json(UpdateReview r, IReadOnlyList<Hunt> hunts, IReadOnlyList<string> notes) =>
        JsonSerializer.Serialize(new { Review = r, Hunts = hunts.Select(h => new { h.Id, h.Title, h.Table }), Notes = notes }, Indented);

    private static readonly JsonSerializerOptions Indented = new() { WriteIndented = true };
}
