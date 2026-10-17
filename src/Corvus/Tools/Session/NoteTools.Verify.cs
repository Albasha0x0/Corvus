using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Native;
using Corvus.Services;

namespace Corvus.Tools;

public sealed partial class NoteTools
{
    private const int MaxVerdictChars = 300;

    /// <summary>
    /// Evidence that links a saved record: last:N is kept (so the link outlives the session) and every link takes the
    /// record's tool and content hash.
    /// </summary>
    private NoteEvidence[]? Link(NoteEvidence[]? entries, RequestContext<CallToolRequestParams>? context)
    {
        if (entries == null || !entries.Any(e => !string.IsNullOrWhiteSpace(e.Result))) return entries;
        if (results == null) throw new ToolError(ErrorCode.Unsupported, "This server keeps no results, so a note cannot link one.", "pass {tool, args} or {text}");
        var recent = context?.Services?.GetService(typeof(RecentCalls)) as RecentCalls;
        return [.. entries.Select(e =>
        {
            if (string.IsNullOrWhiteSpace(e.Result)) return e;
            var item = EvidenceInput.Resolve(e.Result, results, recent);
            var id = item.Source.Kind == "kept" ? item.Source.Ref.Trim().ToLowerInvariant()
                : results.Keep(item.Text, new KeptOrigin(item.Source.Tool, item.Source.Arguments, null, item.Source.Inputs), item.Record);
            return e with { Result = id, Tool = item.Source.Tool, Args = null, ResultSha256 = EvidenceBundle.ContentSha256(item.Text, item.Record), Verdict = null };
        })];
    }

    /// <summary>
    /// Checks each linked record as read_result format=verify does and whether it names the note's anchor; a hypothesis
    /// becomes confirmed or refuted only from records that pass both, otherwise open.
    /// </summary>
    private async Task<(List<NoteEvidence> Evidence, string? Status)> Verify(Note note, RequestContext<CallToolRequestParams> context, CancellationToken ct)
    {
        var linked = note.Evidence.Where(e => e.Result != null).ToList();
        if (linked.Count == 0)
            throw new ToolError(ErrorCode.InvalidArgument, $"Note {note.Id} links no saved record to verify.", "addEvidence=[{result: \"last:1\", expect: \"supports\"}]");
        var checkedList = new List<NoteEvidence>();
        bool supported = false, refuted = false;
        foreach (var e in linked)
        {
            string verdict;
            try
            {
                var bundle = EvidenceBundle.Of(e.Result!, results!, null);
                var check = (await EvidenceBundle.Verify(bundle, context, results!, workspace, ct).ConfigureAwait(false))[0];
                var anchor = check.Matches ? Names(note.Anchor, bundle.Records[0]) : null;
                verdict = !check.Matches ? "differs: " + check.Detail
                    : anchor != null ? "does not name the note's anchor: " + anchor
                    : "verified: " + check.Detail;
                if (check.Matches && anchor == null)
                {
                    if (e.Expect == NoteEvidence.Refutes) refuted = true;
                    else supported = true;
                }
            }
            catch (ToolError x) { verdict = "not checked: " + x.Message; }
            checkedList.Add(e with { Verdict = Format.Clip($"{verdict} ({DateTime.UtcNow:yyyy-MM-dd})", MaxVerdictChars) });
        }
        // a refuting record outweighs supporting ones
        string? status = note.Kind != "hypothesis" ? null : refuted ? "refuted" : supported ? "confirmed" : "open";
        return (checkedList, status);
    }

    /// <summary>Null when the record names the anchor (always for anchors without an address), else what it misses.</summary>
    private string? Names(NoteAnchor anchor, EvidenceBundle.Record record)
    {
        if (anchor.Kind is not (NoteAnchor.Native or NoteAnchor.File) || anchor.Sha256 == null) return null;
        var (native, fn) = workspace.Read(() =>
        {
            var n = workspace.Natives.FirstOrDefault(x => string.Equals(x.OriginalSha256, anchor.Sha256, StringComparison.OrdinalIgnoreCase));
            return (n, n != null && anchor.Rva is { } rva ? code.Ready(n)?.FunctionAt(rva) : null);
        });
        if (native == null) return $"{anchor.Label} is not loaded here";
        bool In(uint rva) => anchor.Kind == NoteAnchor.File || (fn != null ? rva >= fn.Start && rva < fn.Start + Math.Max(1u, fn.Size) : rva == anchor.Rva);
        if (EvidenceBundle.NamedAddresses(record).Any(a => string.Equals(a.Sha256, anchor.Sha256, StringComparison.OrdinalIgnoreCase) && In(a.Rva))) return null;
        // a record without named addresses names the anchor in its text: its function name or address
        if (anchor.Kind == NoteAnchor.Native && anchor.Rva is { } at)
        {
            var va = NativeAddress.Va(native.Image, fn?.Start ?? at);
            var name = fn != null ? code.Ready(native)?.NameAt(fn.Start) ?? fn.Name : null;
            if (record.Text.Contains(va, StringComparison.OrdinalIgnoreCase) || name != null && record.Text.Contains(name, StringComparison.Ordinal)) return null;
            return $"neither {name ?? va} nor {va} appears in {record.Id}";
        }
        return $"{record.Id} names no address in {anchor.Label}";
    }
}
