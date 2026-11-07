using System.Buffers.Binary;
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

/// <summary>An imported function only the new build has; Concern names why it matters: process creation, injection, unnamed or dynamic resolution.</summary>
public sealed record ReviewImport(string Name, string? Concern);

/// <summary>A host, URL or address only the new build holds.</summary>
public sealed record ReviewHost(string Kind, string Value, string Evidence);

/// <summary>A PE image inside the new build that the old build does not hold; Sha256 is of its bytes as stored.</summary>
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
    public override string ToString() => $"{Name}: {Status}{(Detail != null ? ", " + UpdateReviewer.Line(Detail) : "")}";
}

/// <summary>What a new build of a program adds to an old one, and the verdict on it: pass lists no hold reason, hold lists each one.</summary>
public sealed record UpdateReview(
    string OldImage, string NewImage, string Verdict, IReadOnlyList<ReviewHold> Holds, IReadOnlyList<string> Sections,
    IReadOnlyList<ReviewFunction> Added, int AddedTotal, IReadOnlyList<ReviewFunction> Changed, int ChangedTotal,
    IReadOnlyList<ReviewImport> Imports, IReadOnlyList<ReviewHost> Hosts, IReadOnlyList<ReviewEmbedded> Embedded,
    ReviewSigner Signer, IReadOnlyList<ReviewVersionChange> Version);

/// <summary>What one build gave the review: its image, bytes, hosts and embedded images, and what was not read of each.</summary>
public sealed record BuildReading
{
    internal PeFile? Pe { get; init; }

    /// <summary>The file bytes; null when the file is too large to read whole.</summary>
    internal byte[]? Bytes { get; init; }

    internal IReadOnlyList<ReviewHost> Hosts { get; init; } = [];
    internal int HostsSkipped { get; init; }
    internal IReadOnlyList<string> HostLimits { get; init; } = [];
    internal IReadOnlyList<(ReviewEmbedded Item, string Key)> Images { get; init; } = [];
    internal bool ImagesCapped { get; init; }
    internal int Undecoded { get; init; }
    internal int FunctionLimits { get; init; }
}

/// <summary>What the review reads from two builds.</summary>
public sealed record ReviewSources(
    string OldImage, string NewImage, BuildReading Old, BuildReading New, int Matched,
    IReadOnlyList<ReviewFunction> Added, IReadOnlyList<ReviewFunction> Changed, IReadOnlyList<Hunt> Hunts)
{
    /// <summary>Why the function pairs may be incomplete, such as a stopped fuzzy comparison; the functions section is partial and does not hold.</summary>
    public IReadOnlyList<string> MatchLimits { get; init; } = [];

    /// <summary>Why the facts the hunts came from were read in part; the hunts section is partial and does not hold.</summary>
    public IReadOnlyList<string> HuntLimits { get; init; } = [];
}

/// <summary>The review of an update: what the new build adds and the hold reasons found in it.</summary>
public static partial class UpdateReviewer
{
    /// <summary>Rows of each function list kept in a report; the totals count all.</summary>
    public const int MaxListed = 200;

    /// <summary>Strings kept per encoding in a host scan, and PE images kept per build.</summary>
    public const int MaxScanStrings = 2_000_000, MaxImages = 10_000;

    private const int MaxImageDepth = 4;

    /// <summary>The hold reasons: id and the condition. Pass means none was found, not that the update is safe.</summary>
    public static readonly IReadOnlyList<(string Id, string Reason)> HoldReasons =
    [
        ("new_signer", "The new build is signed by a different subject or issuer."),
        ("signature_lost", "The old build was signed and the new build has no signature; or the new signature does not verify, or its digest is unknown, and the old one did."),
        ("new_network_host", "The new build holds a host, URL or address the old build does not."),
        ("new_process_import", "The new build imports a process-creation or injection-capable function the old build does not."),
        ("new_unnamed_import", "The new build imports a function by ordinal only that the old build does not."),
        ("new_embedded_executable", "The new build holds a PE image the old build does not."),
        ("unread_section", "A section the verdict needs is unknown, or partial in the new build and not in the old."),
    ];

    private static string Reason(string id) => HoldReasons.First(h => h.Id == id).Reason;

    // Process creation, then cross-process memory and thread control, then run-time resolution.
    [GeneratedRegex(@"^(?:CreateProcess(?:AsUser|WithLogon|WithToken|Internal)?[AW]?|ShellExecute(?:Ex)?[AW]?|WinExec|(?:Nt|Zw)CreateUserProcess|(?:Nt|Zw)CreateProcessEx?|RtlCreateUserProcess|_?w?system|_w?popen|_w?spawn(?:l|le|lp|lpe|v|ve|vp|vpe)|_w?exec(?:l|le|lp|lpe|v|ve|vp|vpe))$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ProcessCreation();

    [GeneratedRegex(@"^(?:WriteProcessMemory|(?:Nt|Zw)WriteVirtualMemory|VirtualAllocEx|VirtualProtectEx|CreateRemoteThread(?:Ex)?|(?:Nt|Zw)CreateThread(?:Ex)?|RtlCreateUserThread|QueueUserAPC2?|NtQueueApcThread(?:Ex)?|(?:Wow64)?SetThreadContext|(?:Nt|Zw)SetContextThread|(?:Nt|Zw)UnmapViewOfSection|(?:Nt|Zw)MapViewOfSection|(?:Nt|Zw)ResumeThread|SetWindowsHookEx[AW]?)$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex Injection();

    [GeneratedRegex(@"^(?:GetProcAddress|LoadLibrary(?:Ex)?[AW]?|LdrGetProcedureAddress(?:Ex)?|LdrLoadDll)$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex Resolution();

    private static readonly HashSet<string> HostKinds = new(StringComparer.Ordinal) { HuntKind.Domain, HuntKind.Url, HuntKind.Ipv4, HuntKind.Ipv6 };

    // The loader forwards these libraries to one another, so a function moving between them is not new.
    private static string ModuleGroup(string module)
    {
        var m = module.ToLowerInvariant();
        return m is "kernel32.dll" or "kernelbase.dll" || m.StartsWith("api-ms-win-", StringComparison.Ordinal) || m.StartsWith("ext-ms-win-", StringComparison.Ordinal)
            ? "kernel" : m;
    }

    private static (string Group, string Name) Key(NativeImport i) => (ModuleGroup(i.Module), (i.Name ?? "#" + i.Ordinal).ToLowerInvariant());

    /// <summary>The functions imported by the new build only, as module!name, in name order; kernel32, kernelbase and api-ms-win names are one library. Concern is set for a function that creates a process, injects, is imported by ordinal or resolves at run time.</summary>
    public static IReadOnlyList<ReviewImport> AddedImports(IEnumerable<NativeImport> oldImports, IEnumerable<NativeImport> newImports)
    {
        static string Spelled(NativeImport i) => $"{i.Module}!{i.Name ?? "#" + i.Ordinal}";
        var before = oldImports.Select(Key).ToHashSet();
        return [.. newImports.Where(i => !before.Contains(Key(i))).GroupBy(Key).Select(g => g.First())
            .OrderBy(Spelled, StringComparer.OrdinalIgnoreCase).Select(i => new ReviewImport(Spelled(i), Concern(i.Name)))];
    }

    private static string? Concern(string? name) =>
        name == null ? "unnamed" : ProcessCreation().IsMatch(name) ? "process creation" : Injection().IsMatch(name) ? "injection" : Resolution().IsMatch(name) ? "dynamic resolution" : null;

    private static string? HoldOf(string? concern) => concern switch
    {
        "process creation" or "injection" => "new_process_import",
        "unnamed" => "new_unnamed_import",
        _ => null,
    };

    /// <summary>The hosts, URLs and addresses of <paramref name="newer"/> that <paramref name="older"/> lacks; case is ignored.</summary>
    public static IReadOnlyList<ReviewHost> AddedHosts(IEnumerable<ReviewHost> older, IEnumerable<ReviewHost> newer)
    {
        var before = older.Select(f => (f.Kind, f.Value.Trim().ToLowerInvariant())).ToHashSet();
        return [.. newer.Where(f => !before.Contains((f.Kind, f.Value.Trim().ToLowerInvariant())))
            .OrderBy(f => f.Kind, StringComparer.Ordinal).ThenBy(f => f.Value, StringComparer.OrdinalIgnoreCase)];
    }

    /// <summary>The signer change between two builds' signatures and its detail; an unreadable signature gives change unknown.</summary>
    public static ReviewSigner Signer(CertificateInfo? older, CertificateInfo? newer)
    {
        static bool Unreadable(CertificateInfo c) => c.Present && c.Problem != null && string.IsNullOrEmpty(c.Signer);
        // A signature that does not verify, or whose digest could not be checked.
        static string? Defect(CertificateInfo c) => !c.Present ? null
            : c.SignatureValid == false ? "the signature does not verify"
            : c.DigestMatches == false ? "the digest does not match the file"
            : c.DigestMatches == null ? "the digest could not be checked"
            : null;
        if (older == null || newer == null) return new ReviewSigner(null, null, "unknown", "a build is not a PE image");
        if (Unreadable(older) || Unreadable(newer))
            return new ReviewSigner(older.Signer, newer.Signer, "unknown", $"signature unreadable: {(Unreadable(older) ? older : newer).Problem}");
        if (!older.Present && !newer.Present) return new ReviewSigner(null, null, "unsigned");
        if (older.Present && !newer.Present) return new ReviewSigner(older.Signer, null, "signature_lost");
        var (before, after) = (Defect(older), Defect(newer));
        if (after != null && after != before) return new ReviewSigner(older.Signer, newer.Signer, "signature_lost", after);
        var shared = after != null ? $"{after} in both builds" : null;
        if (!older.Present) return new ReviewSigner(null, newer.Signer, "signed", shared);
        bool Same(string? a, string? b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);
        if (!Same(older.Signer, newer.Signer) || !Same(older.Issuer, newer.Issuer))
            return new ReviewSigner(older.Signer, newer.Signer, "new_signer",
                Same(older.Signer, newer.Signer) ? $"the issuer changed: {older.Issuer} -> {newer.Issuer}" : shared);
        var renewed = older.Thumbprint != newer.Thumbprint ? "the certificate was renewed: its thumbprint changed" : null;
        return new ReviewSigner(older.Signer, newer.Signer, "same_signer", renewed == null ? shared : shared == null ? renewed : $"{renewed}; {shared}");
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

    /// <summary>
    /// Reads one build: its hosts (strings of the image outside the certificate table and high-entropy windows, plus hosts decoded from assemblies) and its PE images,
    /// <paramref name="maxImages"/> images kept, each image counted once and normalized for time stamp and checksum; the counts of what was not read stay with the reading.
    /// </summary>
    public static BuildReading Read(PeFile? pe, byte[]? bytes, IReadOnlyList<HuntFact> facts, int undecoded, int functionLimits, CancellationToken ct, int maxImages = MaxImages)
    {
        var reading = new BuildReading { Pe = pe, Bytes = bytes, Undecoded = undecoded, FunctionLimits = functionLimits };
        if (pe == null || bytes == null) return reading;
        var hot = HuntFacts.HighEntropyWindows(bytes, ct);
        var bounds = new IndicatorList.ImageScanBounds(MaxScanStrings, PerPass: true, BothParities: true, pe.CertificateTable, at => HuntFacts.InHot(hot, at));
        var hits = IndicatorList.FromImageStrings("native", bytes, ct, bounds, out var report);
        var hosts = hits.Where(h => HostKinds.Contains(h.Type)).Select(h => new ReviewHost(h.Type, h.Value, h.Evidence))
            .Concat(facts.Where(f => HostKinds.Contains(f.Kind) && f.Evidence != IndicatorEvidence.String).Select(f => new ReviewHost(f.Kind, f.Value, f.Evidence)))
            .DistinctBy(h => (h.Kind, h.Value.Trim().ToLowerInvariant())).ToList();
        var (images, capped) = Images(bytes, maxImages, ct);
        return reading with { Hosts = hosts, HostsSkipped = report.Skipped, HostLimits = report.Limits, Images = images, ImagesCapped = capped };
    }

    /// <summary>The PE images inside a build past its own header, nested ones included, with the SHA-256 of their bytes and a key that ignores time stamp and checksum; capped when the image bound was hit.</summary>
    private static (List<(ReviewEmbedded, string)> Items, bool Capped) Images(byte[] bytes, int maxImages, CancellationToken ct)
    {
        var items = new List<(ReviewEmbedded, string)>();
        bool capped = false;
        void Walk(int start, int length, int depth)
        {
            // Scanning from byte 1 skips the image's own header and still covers its sections.
            int room = maxImages - items.Count;
            if (room <= 0 || length < 2) { capped |= room <= 0; return; }
            var found = Blob.CarvePe(bytes.AsSpan(start + 1, length - 1), room, ct);
            if (found.Count >= room) capped = true;
            foreach (var c in found)
            {
                int at = start + 1 + c.Offset;
                if (items.Count >= maxImages) { capped = true; return; }
                items.Add((new ReviewEmbedded($"0x{at:X}", c.Length, Blob.Sha256(bytes.AsSpan(at, c.Length)), c.Machine), NormalizedSha(bytes.AsSpan(at, c.Length))));
                if (depth < MaxImageDepth) Walk(at, c.Length, depth + 1);
            }
        }
        Walk(0, bytes.Length, 0);
        return (items, capped);
    }

    // Two builds of one program differ in the time stamp and the checksum with no other change.
    private static string NormalizedSha(ReadOnlySpan<byte> image)
    {
        var copy = image.ToArray();
        if (copy.Length > 0x40 && BinaryPrimitives.ReadInt32LittleEndian(copy.AsSpan(0x3C)) is var pe and > 0 && (long)pe + 24 + 68 <= copy.Length)
        {
            copy.AsSpan(pe + 8, 4).Clear();
            copy.AsSpan(pe + 24 + 64, 4).Clear();
        }
        return Blob.Sha256(copy);
    }

    /// <summary>The review of <paramref name="s"/>: each section, then the hold reasons found or the pass.</summary>
    public static UpdateReview Review(ReviewSources s, CancellationToken ct)
    {
        var sections = new List<ReviewSection>();
        var holds = new List<ReviewHold>();
        void Hold(string id, string evidence) => holds.Add(new ReviewHold(id, Reason(id), evidence));
        void Unknown(string section, string detail)
        {
            sections.Add(new ReviewSection(section, "unknown", detail));
            Hold("unread_section", $"{section}: {detail}");
        }
        // Partial in both builds is a note; a build that reads less than the old one holds.
        void Partial(string section, int oldLimits, int newLimits, string read, string detail)
        {
            if (oldLimits == 0 && newLimits == 0) { sections.Add(new ReviewSection(section, "read", read)); return; }
            bool worse = newLimits > oldLimits;
            sections.Add(new ReviewSection(section, "partial", $"{read}; {detail}{(worse ? "" : "; the old build is partial too")}"));
            if (worse) Hold("unread_section", $"{section} is partial in the new build: {detail}");
        }

        if (s.Matched == 0) Unknown("functions", "no function pair matched, so added and changed functions are unknown");
        else
            Partial("functions", s.Old.Undecoded + s.Old.FunctionLimits, s.New.Undecoded + s.New.FunctionLimits,
                $"{s.Added.Count} added or unmatched, {s.Changed.Count} changed; an added or changed function does not hold",
                $"{s.New.Undecoded} function(s) not decoded and {s.New.FunctionLimits} analysis limit(s) in the new build");

        if (s.MatchLimits.Count > 0)
        {
            var last = sections[^1];
            sections[^1] = last with { Status = "partial", Detail = $"{last.Detail}; {string.Join("; ", s.MatchLimits)}" };
        }

        IReadOnlyList<ReviewImport> imports = [];
        var (oldPe, newPe) = (s.Old.Pe, s.New.Pe);
        if (oldPe == null || newPe == null) Unknown("imports", "a build is not a PE image");
        else
        {
            int Issues(PeFile p) => p.Issues.Count(i => i.Area is "imports" or "delay imports");
            imports = AddedImports(oldPe.Imports, newPe.Imports);
            Partial("imports", Issues(oldPe), Issues(newPe), $"{imports.Count} added", "the import directory has parse issues");
            foreach (var i in imports.Where(i => HoldOf(i.Concern) != null))
                Hold(HoldOf(i.Concern)!, $"{i.Name} ({i.Concern})");
        }

        IReadOnlyList<ReviewHost> hosts = [];
        if (s.Old.Bytes == null || s.New.Bytes == null || oldPe == null || newPe == null) Unknown("hosts", "a build is not a PE image or is too large to read whole");
        else
        {
            hosts = AddedHosts(s.Old.Hosts, s.New.Hosts);
            Partial("hosts", s.Old.HostsSkipped + s.Old.HostLimits.Count, s.New.HostsSkipped + s.New.HostLimits.Count, $"{hosts.Count} added",
                $"{s.New.HostsSkipped} string(s) in high-entropy regions not read{(s.New.HostLimits.Count > 0 ? "; " + string.Join("; ", s.New.HostLimits) : "")}");
            foreach (var h in hosts) Hold("new_network_host", $"{h.Kind} {h.Value}");
        }

        IReadOnlyList<ReviewEmbedded> embedded = [];
        if (s.Old.Bytes == null || s.New.Bytes == null) Unknown("embedded files", "a build is too large to read whole");
        else
        {
            var before = s.Old.Images.Select(i => i.Key).ToHashSet(StringComparer.Ordinal);
            embedded = [.. s.New.Images.Where(i => !before.Contains(i.Key)).DistinctBy(i => i.Key).Select(i => i.Item)];
            Partial("embedded files", s.Old.ImagesCapped ? 1 : 0, s.New.ImagesCapped ? 1 : 0, $"{embedded.Count} added; encoded or compressed images are not read",
                $"the scan stopped at {MaxImages:N0} images");
            foreach (var e in embedded) Hold("new_embedded_executable", $"{e.Machine} image at {e.Offset}, {e.Size} bytes, sha256 {e.Sha256}");
        }

        var signer = Signer(oldPe?.Certificate, newPe?.Certificate);
        if (signer.Change == "unknown") Unknown("signer", signer.Detail ?? "unknown");
        else
        {
            sections.Add(new ReviewSection("signer", "read", signer.Change + (signer.Detail != null && signer.Change is "same_signer" or "signed" ? ", " + signer.Detail : "")));
            if (signer.Change == "new_signer") Hold("new_signer", $"{signer.Old} -> {signer.New}" + (signer.Detail != null ? $"; {signer.Detail}" : ""));
            if (signer.Change == "signature_lost") Hold("signature_lost", signer.Detail ?? $"{signer.Old} -> unsigned");
        }

        var version = VersionChanges(oldPe?.VersionInfo, newPe?.VersionInfo);
        if (oldPe == null || newPe == null) sections.Add(new ReviewSection("version resource", "unknown", "a build is not a PE image"));
        else if (new[] { oldPe, newPe }.SelectMany(p => p.Issues).Any(i => i.Area == "resources"))
            sections.Add(new ReviewSection("version resource", "partial", "the resource directory has parse issues"));
        else sections.Add(new ReviewSection("version resource", "read", $"{version.Count} field(s) changed"));

        var queries = $"{s.Hunts.Count} quer{(s.Hunts.Count == 1 ? "y" : "ies")}";
        sections.Add(s.HuntLimits.Count == 0 ? new ReviewSection("hunts", "read", queries)
            : new ReviewSection("hunts", "partial", $"{queries}; {string.Join("; ", s.HuntLimits)}"));
        return new UpdateReview(s.OldImage, s.NewImage, holds.Count == 0 ? "pass" : "hold", holds, [.. sections.Select(x => x.ToString())],
            [.. s.Added.Take(MaxListed)], s.Added.Count, [.. s.Changed.Take(MaxListed)], s.Changed.Count, imports, hosts, embedded, signer, version);
    }

    /// <summary>The value as one plain line: control characters and line breaks become spaces.</summary>
    public static string Line(string? value) => value == null ? "" : new string([.. value.Select(c => char.IsControl(c) || (int)c is 0x2028 or 0x2029 ? ' ' : c)]);

    // A value from a file reads as text in Markdown: one line, no markup characters.
    private static string Md(string? value) => Regex.Replace(Line(value), @"[\\`*_{}\[\]<>#|~!]", "\\$0");

    /// <summary>The verdict line: pass names no listed reason found and what it does not cover; hold counts its reasons.</summary>
    public static string VerdictText(UpdateReview r) => r.Verdict == "pass"
        ? "Verdict: pass. No hold reason in the table was found; an added or changed function does not hold, images encoded or compressed inside the build are not read, and this does not show the update is safe."
        : $"Verdict: hold. {r.Holds.Count} reason(s):\n" + string.Join('\n', r.Holds.Select(h => $"  {h.Id}: {Line(h.Evidence)}"));

    /// <summary>The review as Markdown: verdict first, then a section per fact, the hunting queries and the notes; values from the files are escaped.</summary>
    public static string Markdown(UpdateReview r, IReadOnlyList<Hunt> hunts, IReadOnlyList<string> notes)
    {
        var sb = new StringBuilder();
        sb.Append($"# Update review: {Md(r.OldImage)} -> {Md(r.NewImage)}\n\n## Verdict\n\n");
        sb.Append(r.Verdict == "pass" ? Md(VerdictText(r)) + "\n" : $"Verdict: hold. {r.Holds.Count} reason(s):\n\n" + string.Join('\n', r.Holds.Select(h => $"- {h.Id}: {Md(h.Evidence)}")) + "\n");
        sb.Append("\n## Sections read\n\n");
        foreach (var s in r.Sections) sb.Append($"- {Md(s)}\n");
        if (r.AddedTotal > MaxListed || r.ChangedTotal > MaxListed) sb.Append($"- Each function list holds the first {MaxListed} rows; view=changed and view=unmatched list all.\n");
        sb.Append("\n## Hold reasons\n\n| Id | Reason |\n|---|---|\n");
        foreach (var (id, reason) in HoldReasons) sb.Append($"| {id} | {reason} |\n");
        void Functions(string title, IReadOnlyList<ReviewFunction> rows, int total)
        {
            sb.Append($"\n## {title} ({total})\n\n");
            foreach (var f in rows) sb.Append($"- {Md(f.OldAddress ?? "-")} -> {Md(f.NewAddress ?? "-")} {Md(f.Name)}{(f.Reason != null ? $" ({Md(f.Reason)})" : "")}{(f.Diff != null ? $"; {Md(f.Diff)}" : "")}\n");
            if (total > rows.Count) sb.Append($"- {total - rows.Count} more\n");
        }
        Functions("Added or unmatched functions", r.Added, r.AddedTotal);
        Functions("Changed functions", r.Changed, r.ChangedTotal);
        sb.Append($"\n## New imports ({r.Imports.Count})\n\n");
        foreach (var i in r.Imports) sb.Append($"- {Md(i.Name)}{(i.Concern != null ? $" ({i.Concern})" : "")}\n");
        sb.Append($"\n## New hosts and addresses ({r.Hosts.Count})\n\n");
        foreach (var h in r.Hosts) sb.Append($"- {h.Kind} {Md(h.Value)} ({Md(h.Evidence)})\n");
        sb.Append($"\n## New embedded files ({r.Embedded.Count})\n\n");
        foreach (var e in r.Embedded) sb.Append($"- {Md(e.Machine)} image at {e.Offset}, {e.Size} bytes, sha256 {e.Sha256}\n");
        sb.Append($"\n## Signer\n\n- {r.Signer.Change}: {(r.Signer.Old == null ? "none" : Md(r.Signer.Old))} -> {(r.Signer.New == null ? "none" : Md(r.Signer.New))}{(r.Signer.Detail != null ? $"; {Md(r.Signer.Detail)}" : "")}\n");
        sb.Append($"\n## Version resource ({r.Version.Count} changed)\n\n");
        foreach (var v in r.Version) sb.Append($"- {Md(v.Field)}: {(v.Old == null ? "none" : Md(v.Old))} -> {(v.New == null ? "none" : Md(v.New))}\n");
        sb.Append($"\n## Hunting queries ({hunts.Count})\n\n");
        foreach (var h in hunts) sb.Append($"- {Md(h.Id)} ({Md(h.Table)}) {Md(h.Title)}\n");
        if (notes.Count > 0)
        {
            sb.Append("\n## Notes\n\n");
            foreach (var n in notes) sb.Append($"- {Md(n)}\n");
        }
        return sb.ToString();
    }

    /// <summary>The review, the ids and titles of the hunting queries and the notes as indented JSON.</summary>
    public static string Json(UpdateReview r, IReadOnlyList<Hunt> hunts, IReadOnlyList<string> notes) =>
        JsonSerializer.Serialize(new { Review = r, Hunts = hunts.Select(h => new { h.Id, h.Title, h.Table }), Notes = notes }, Indented);

    private static readonly JsonSerializerOptions Indented = new() { WriteIndented = true };
}
