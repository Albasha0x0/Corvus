using System.ComponentModel;
using dnlib.DotNet;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Native;
using Corvus.Services;

namespace Corvus.Tools;

/// <summary>Analyst notes kept per binary identity across sessions and server processes.</summary>
[McpServerToolType]
public sealed partial class NoteTools(AssemblyWorkspace workspace, NotesService notes, NativeCodeService code, MinidumpService dumps, ResultStore? results = null)
{
    public const string AnchorDescription =
        "<image>@<address>, <assembly>:<symbol or token>, image or assembly id, dump:<id or path>, or empty (session-wide).";

    public sealed record NoteList(
        [property: Description("Notes, newest first.")] IReadOnlyList<Note> Items,
        int Offset, int Total,
        [property: Description("How the filters were applied (e.g. the function an address was widened to).")] IReadOnlyList<string> Notes);

    private const string EvidenceDescription = "At most 10: {result: r-... or last:N, expect: supports|refutes}, {tool, args} of a call made here, or {text}.";

    [McpServerTool(Name = "record_note", Title = "Record a note", UseStructuredContent = true)]
    [Description("Record a finding, question, hypothesis or todo on a native address, .NET member, file or dump. Notes persist per user " +
                 "and follow the binary by SHA-256 or MVID.")]
    public Task<Note> RecordNote(
        [Description("At most 4,000 characters.")] string text,
        [Description("Default finding.")] string? kind = null,
        [Description("Default open.")] string? status = null,
        [Description(AnchorDescription)] string? anchor = null,
        [Description("At most 10.")] string[]? tags = null,
        [Description(EvidenceDescription)] NoteEvidence[]? evidence = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => Task.Run(() =>
    {
        var resolved = Anchor(anchor);
        return notes.Record(text, kind, status, resolved, tags, Evidence(Link(evidence, context)), context?.Server?.ClientInfo?.Name);
    }, cancellationToken);

    [McpServerTool(Name = "update_note", Title = "Update a note", UseStructuredContent = true)]
    [Description("Change a note's status, kind, text, tags or evidence. verify=true re-checks linked records and sets a hypothesis " +
                 "confirmed or refuted; a stale expectedRevision is a conflict.")]
    public Task<Note> UpdateNote(
        [Description("Note id.")] string id,
        [Description("The revision last read.")] int expectedRevision,
        [Description("New status.")] string? status = null,
        [Description("New kind.")] string? kind = null,
        [Description("Replacement text.")] string? text = null,
        [Description("Text appended on a new line.")] string? appendText = null,
        [Description("Tags to add.")] string[]? addTags = null,
        [Description("Tags to remove.")] string[]? removeTags = null,
        [Description(EvidenceDescription)] NoteEvidence[]? addEvidence = null,
        [Description("Re-check linked records after the other changes.")] bool verify = false,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => Task.Run(async () =>
    {
        var note = notes.Update((id ?? "").Trim(), expectedRevision, new NoteChange(status, text, appendText, addTags, removeTags, Evidence(Link(addEvidence, context)), kind));
        if (!verify) return note;
        var (evidence, verified) = await Verify(note, context, cancellationToken).ConfigureAwait(false);
        return notes.Update(note.Id, note.Revision, new NoteChange(verified, AddEvidence: evidence));
    }, cancellationToken);

    /// <summary>Checked evidence; a call this process has no result for keeps no hash, with a warning.</summary>
    private static List<NoteEvidence> Evidence(NoteEvidence[]? entries)
    {
        var unmatched = new List<string>();
        var list = NotesService.CheckEvidence(entries, unmatched);
        if (unmatched.Count > 0)
            ToolOutput.Warn($"no earlier call here of {string.Join(", ", unmatched.Distinct())} with those args: recorded without resultSha256 (make the call, then add it)");
        return list;
    }

    [McpServerTool(Name = "list_notes", Title = "List notes", UseStructuredContent = true, OutputSchemaType = typeof(NoteList))]
    [Description("Notes, newest first, filtered by status, kind, anchor, tag and text. A file anchor lists all its notes, an address " +
                 "its function's, a type its members' too.")]
    public Task<string> ListNotes(
        [Description("Default open; all for every status.")] string? status = null,
        [Description("Only this kind.")] string? kind = null,
        [Description(AnchorDescription)] string? anchor = null,
        [Description("Only notes with this tag.")] string? tag = null,
        [Description("Text substring (case-insensitive).")] string? text = null,
        [Description(ToolSupport.RowOffsetDescription)] int offset = 0,
        [Description("Notes per page.")] int limit = 50,
        [Description(ToolSupport.MaxTokensDescription)] int? maxTokens = null,
        CancellationToken cancellationToken = default) => Task.Run(() =>
    {
        var st = string.IsNullOrWhiteSpace(status) ? "open" : status.Trim().ToLowerInvariant();
        if (st != "all") NotesService.CheckStatus(st);
        var kd = string.IsNullOrWhiteSpace(kind) ? null : NotesService.CheckKind(kind);
        var info = new List<string>();
        var (keys, match) = Filter(anchor, info);
        var all = notes.All(keys)
            .Where(n => st == "all" || n.Status == st)
            .Where(n => kd == null || n.Kind == kd)
            .Where(n => match(n.Anchor))
            .Where(n => string.IsNullOrWhiteSpace(tag) || n.Tags.Contains(tag.Trim(), StringComparer.OrdinalIgnoreCase))
            .Where(n => string.IsNullOrWhiteSpace(text) || n.Text.Contains(text.Trim(), StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(n => n.Updated).ThenBy(n => n.Id, StringComparer.Ordinal).ToList();
        offset = Math.Max(0, offset);
        limit = ToolSupport.ClampLimit(limit, 500);
        var header = string.Concat(info.Select(i => $"Note: {i}\n"));
        return ToolOutput.List(all, offset, limit, Row, page => new NoteList(page, offset, all.Count, info), "note", header);
    }, cancellationToken);

    private static string Row(Note n) =>
        $"{n.Id} r{n.Revision}  {n.Kind}/{n.Status}  {n.Anchor.Label ?? n.Anchor.Kind}  {Format.Clip(n.Text.ReplaceLineEndings(" "), 300)}" +
        (n.Tags.Count > 0 ? $"  [{string.Join(", ", n.Tags)}]" : "") +
        string.Concat(n.Evidence.Select(e => $"\nevidence: {Format.Clip(e.ToString(), 200)}"));

    /// <summary>Resolves an anchor argument to the identity it is stored under.</summary>
    public NoteAnchor Anchor(string? anchor)
    {
        if (string.IsNullOrWhiteSpace(anchor)) return NoteAnchor.Global;
        var a = anchor.Trim();
        if (a.StartsWith("dump:", StringComparison.OrdinalIgnoreCase))
        {
            var target = a[5..].Trim();
            var path = dumps.PathOf(target) ?? (File.Exists(target) ? Path.GetFullPath(target) : null)
                ?? throw new ToolError(ErrorCode.NotFound, $"'{target}' is neither an open dump id nor a dump file.", "open_minidump first, or pass the .dmp path");
            return new NoteAnchor(NoteAnchor.Dump, Sha256: Sha256Of(path), Label: "dump:" + Path.GetFileName(path));
        }
        return workspace.Read(() =>
        {
            int at = a.LastIndexOf('@');
            if (at > 0 && workspace.FindNative(a[..at].Trim()) is { } native)
            {
                var image = native.Image;
                uint rva = NativeAddress.Parse(image, a[(at + 1)..], code.Ready(native) is { } index ? index.AddressesOfName : null);
                return new NoteAnchor(NoteAnchor.Native, Sha256: native.OriginalSha256, Rva: rva, Label: $"{native.Id}@{NativeAddress.Va(image, rva)}");
            }
            if (Member(a) is { } member)
                return new NoteAnchor(NoteAnchor.DotNet, Sha256: member.Assembly.OriginalSha256, Mvid: Mvid(member.Assembly),
                    Token: member.Member.MDToken.Raw, Label: $"{member.Assembly.Id}:{member.Label}");
            if (workspace.FindNative(a) is { } file) return new NoteAnchor(NoteAnchor.File, Sha256: file.OriginalSha256, Label: file.Id);
            if (TryAssembly(a) is { } asm) return new NoteAnchor(NoteAnchor.File, Sha256: asm.OriginalSha256, Label: asm.Id);
            throw new ToolError(ErrorCode.NotFound, $"The anchor '{a}' names no loaded image, assembly, member or dump.",
                "use '<image>@<address>', '<assembly>:<symbol>', an id from list_assemblies, 'dump:<id>', or leave it empty");
        });
    }

    internal static string Sha256Of(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 16);
        return Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(stream));
    }

    private static string Mvid(LoadedAssembly asm) =>
        asm.Module.Mvid?.ToString() ?? throw new ToolError(ErrorCode.Unsupported, $"{asm.Id} has no MVID; anchor the note to the file ({asm.Id}) instead.");

    /// <summary>'&lt;assembly&gt;:&lt;symbol&gt;' (the first single colon splits; '::' belongs to the symbol).</summary>
    private ResolvedSymbol? Member(string a)
    {
        for (int i = a.IndexOf(':'); i > 0; i = a.IndexOf(':', i + 2))
        {
            if (i + 1 < a.Length && a[i + 1] == ':') continue;
            if (TryAssembly(a[..i].Trim()) is not { } asm) return null;
            var symbol = a[(i + 1)..].Trim();
            if (SymbolResolver.TryParseToken(symbol, out uint token) && (token & 0x00FFFFFF) != 0 && MetadataUtil.Try(() => asm.Module.ResolveToken(token)) is IMemberDef byToken)
                return new ResolvedSymbol(asm, byToken);
            return SymbolResolver.ResolveOne(workspace, asm.Id, symbol);
        }
        return null;
    }

    private LoadedAssembly? TryAssembly(string id)
    {
        try { return workspace.Get(id); }
        catch (ToolError) { return null; }
    }

    /// <summary>The store keys to read and the per-note test for a list_notes anchor filter.</summary>
    private (IReadOnlyList<string>? Keys, Func<NoteAnchor, bool> Match) Filter(string? anchor, List<string> info)
    {
        if (string.IsNullOrWhiteSpace(anchor)) return (null, _ => true);
        var a = anchor.Trim();
        if (a.Equals("none", StringComparison.OrdinalIgnoreCase) || a.Equals("global", StringComparison.OrdinalIgnoreCase))
            return (["global"], n => n.Kind == NoteAnchor.None);
        var r = Anchor(a);
        switch (r.Kind)
        {
            case NoteAnchor.File:
                {
                    // The whole file: its file, address and member notes.
                    var mvid = workspace.Read(() => workspace.Assemblies.FirstOrDefault(x => x.OriginalSha256 == r.Sha256)?.Module.Mvid?.ToString());
                    var keys = new List<string> { r.Sha256!.ToLowerInvariant() };
                    if (mvid != null) keys.Add(new NoteAnchor(NoteAnchor.DotNet, Mvid: mvid).StoreKey);
                    return (keys, n => n.Sha256 == r.Sha256 || mvid != null && string.Equals(n.Mvid, mvid, StringComparison.OrdinalIgnoreCase));
                }
            case NoteAnchor.Native:
                {
                    var native = workspace.Read(() => workspace.Natives.FirstOrDefault(x => x.OriginalSha256 == r.Sha256));
                    uint start = r.Rva!.Value, end = start + 1;
                    if (native != null && code.Ready(native)?.FunctionAt(start) is { } fn)
                    {
                        (start, end) = (fn.Start, fn.Start + Math.Max(1u, fn.Size));
                        info.Add($"address widened to the function {fn.Name} [{NativeAddress.Va(native.Image, start)}, {NativeAddress.Va(native.Image, end)})");
                    }
                    else info.Add("the code index is not ready, so only notes at exactly this address are listed");
                    return ([r.StoreKey], n => n.Kind == NoteAnchor.Native && n.Rva >= start && n.Rva < end);
                }
            case NoteAnchor.DotNet:
                {
                    var tokens = workspace.Read(() =>
                    {
                        var set = new HashSet<uint> { r.Token!.Value };
                        var asm = workspace.Assemblies.FirstOrDefault(x => x.Module.Mvid?.ToString() == r.Mvid);
                        if (asm != null && MetadataUtil.Try(() => asm.Module.ResolveToken(r.Token.Value)) is TypeDef type)
                            foreach (var m in type.Methods.Cast<IMemberDef>().Concat(type.Fields).Concat(type.Properties).Concat(type.Events).Concat(type.NestedTypes))
                                set.Add(m.MDToken.Raw);
                        return set;
                    });
                    return ([r.StoreKey], n => n.Kind == NoteAnchor.DotNet && n.Token is { } t && tokens.Contains(t));
                }
            default:
                return ([r.StoreKey], n => n.Sha256 == r.Sha256);
        }
    }
}
