using System.Text;

namespace Corvus.Core;

/// <summary>Why a member is listed in a save report. Every listed member carries one.</summary>
public enum SaveIssueReason
{
    // Written byte-for-byte as in the original.
    InvalidBody,
    MalformedSignature,

    // Written differently from the original, without an edit asking for it.
    UnreadableBody,
    Reencoded,
    WriterError,
    PrecompiledCodeDropped,
}

/// <summary>A member of a saved image the user should know about: what, where and why.</summary>
public sealed record SaveIssue(SaveIssueReason Reason, uint Token, string Member, string Detail)
{
    /// <summary>The saved bytes of this member differ from the original although no edit asked for it.</summary>
    public bool ChangesBytes => SaveManifest.Info(Reason).ChangesBytes;

    public override string ToString() => $"{Member}: {Detail} [{SaveManifest.CodeOf(Reason)}]";
}

/// <summary>
/// The outcome of writing a module: members kept as they were although the original is invalid there, and members the
/// writer could not keep. Everything else that no edit touched is written byte-for-byte as in the original.
/// </summary>
public sealed class SaveReport
{
    public static readonly SaveReport Empty = new([]);

    public SaveReport(IReadOnlyList<SaveIssue> issues) => Issues = issues;

    public IReadOnlyList<SaveIssue> Issues { get; }
    public IEnumerable<SaveIssue> Kept => Issues.Where(i => !i.ChangesBytes);
    public IEnumerable<SaveIssue> Changed => Issues.Where(i => i.ChangesBytes);
    public bool HasChanges => Issues.Any(i => i.ChangesBytes);

    private const int MaxListed = 50;

    /// <summary>The report as text for a tool result: the changed members first, each list capped, with counts per reason.</summary>
    public string Describe()
    {
        var sb = new StringBuilder();
        Append(sb, "Changed by the writer (no edit asked for it; the rest is as in the original):", Changed.ToList());
        Append(sb, "Kept byte-for-byte although invalid in the original (not editable or decompilable as such):", Kept.ToList());
        return sb.ToString();
    }

    private static void Append(StringBuilder sb, string title, List<SaveIssue> issues)
    {
        if (issues.Count == 0) return;
        var counts = issues.GroupBy(i => i.Reason).Select(g => $"{g.Count()} {SaveManifest.CodeOf(g.Key)}");
        sb.Append("\n\n").Append(title).Append(" (").Append(string.Join(", ", counts)).Append(')');
        foreach (var issue in issues.Take(MaxListed)) sb.Append("\n  ").Append(issue);
        if (issues.Count > MaxListed) sb.Append($"\n  … {issues.Count - MaxListed} more");
    }
}

/// <summary>
/// The contract of save_assembly: what is written as in the original and the closed set of reasons for which a member
/// is reported. docs/saving.md is generated from this class (see <see cref="Markdown"/>).
/// </summary>
public static class SaveManifest
{
    public sealed record ReasonInfo(SaveIssueReason Reason, string Code, bool ChangesBytes, string Description);

    public static readonly IReadOnlyList<ReasonInfo> Reasons =
    [
        new(SaveIssueReason.InvalidBody, "invalid-body", false,
            "the original method body is not valid IL (empty, an unknown opcode, an instruction or switch running past the end, a branch outside the code or into an instruction, a local or argument index out of range, exception clauses out of range or overlapping without nesting, code running past its end); it is written byte-for-byte as in the original"),
        new(SaveIssueReason.MalformedSignature, "malformed-signature", false,
            "the original signature blob of a method, field, property, member reference, type spec, method spec or local variable signature does not read back as written (malformed or non-canonical); it is written byte-for-byte as in the original"),
        new(SaveIssueReason.UnreadableBody, "unreadable-body", true,
            "the original method body cannot be read from the image (its RVA lies outside the sections, or its header, code or exception sections run past the end of its section); what could be decoded is written instead, or no body"),
        new(SaveIssueReason.Reencoded, "reencoded", true,
            "a method body, signature or heap that no edit touched reads back differently from the original after writing (found by comparing the written image with the original)"),
        new(SaveIssueReason.WriterError, "writer-error", true,
            "the writer reported an error for an edited or added member, or for no member in particular; the message says what it could not encode"),
        new(SaveIssueReason.PrecompiledCodeDropped, "precompiled-code-dropped", true,
            "the module's ReadyToRun code is not written: its headers have no room for the section the native writer adds (ReadyToRun builds for Linux and macOS), so the module is written as IL only; it runs as before, compiled at run time"),
    ];

    private static readonly Dictionary<SaveIssueReason, ReasonInfo> ByReason = Reasons.ToDictionary(r => r.Reason);

    public static ReasonInfo Info(SaveIssueReason reason) => ByReason[reason];

    public static string CodeOf(SaveIssueReason reason) => ByReason[reason].Code;

    /// <summary>docs/saving.md.</summary>
    public static string Markdown()
    {
        var sb = new StringBuilder();
        sb.Append("""
            # save_assembly: saving contract

            Generated from `SaveManifest` (src/Corvus/Core/SaveReport.cs); a test keeps the two in sync.

            ## What is written

            - **No edits:** the original file, byte for byte.
            - **With edits:** the module is written again by dnlib with all metadata rids, string, user-string and blob
              offsets preserved. Every method body that no edit changed is written with its original bytes (header, IL and
              exception sections), even when dnlib would encode it differently or cannot represent it at all; every
              signature that no edit changed points at its original blob. Edited and added members are encoded by dnlib.
            - **Checked after writing:** the written image is read back and compared with the original, method by method
              and signature by signature. Anything that no edit touched and that differs is reported; nothing differs
              silently. The comparison covers method bodies, the signature blobs of methods, fields, properties, member
              references, type specs, method specs and local variable signatures, and the #US and #Blob heaps; other
              metadata (names, attributes, resources) is written by dnlib from the edited model.
            - **Signatures:** an Authenticode signature is not carried over and a strong-name signature no longer matches
              (both cover the original bytes); a save with edits says so when the original had either.

            ## The report

            The save result lists members in two groups, each line `member: what and why [code]`:

            - **Changed by the writer:** bytes differ from the original although no edit asked for it.
            - **Kept byte-for-byte although invalid in the original:** nothing changed, but the member is not valid
              metadata or IL, so the editor and the decompiler cannot work with it as such.

            By default the save goes ahead and reports. With `strict=true`, a save with any member in the first group
            fails with the same list and writes nothing. A save that fails for any other reason (the writer throws, the
            file cannot be replaced) writes nothing either: the image goes to a temporary file that replaces the target
            only when complete.

            ## Matching a preview to the saved file

            Every edit reports a content digest: its dry run, the applied edit and `list_edits` show the same value for
            the same change on the same build. The save result gives the SHA-256 of the file written and `editList`,
            each edit it wrote with its id and digest, so a reviewer can check that the change previewed is the edit
            applied and that the edit is in the file. `save_native` does the same for byte patches, and reports
            `verified` after reading the file back (bytes outside the patches equal the original, relocations re-parse).

            ## Reasons

            | Code | Bytes changed | Meaning |
            |---|---|---|

            """);
        foreach (var r in Reasons) sb.Append($"| `{r.Code}` | {(r.ChangesBytes ? "yes" : "no")} | {r.Description} |\n");
        return sb.ToString();
    }
}
