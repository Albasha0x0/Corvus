using System.ComponentModel;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Native.Annotations;
using Corvus.Services;
using static Corvus.Tools.ToolSupport;

namespace Corvus.Tools;

/// <summary>save_session / load_session: the analyst's work (edits, patches, names, notes) in one portable file.</summary>
[McpServerToolType]
public sealed class SessionFileTools(AssemblyWorkspace workspace, SessionService sessions, EditHistoryService history, NativeCodeService code,
    NativeEditService nativeEdits, NotesService? notes = null, NativeEngineService? engines = null, EditJournal? journal = null,
    Il2CppRawLoader? il2cppRaw = null, MinidumpService? dumps = null)
{
    public const string Loaded = "loaded", AlreadyLoaded = "already_loaded", WouldLoad = "would_load", Applied = "applied", WouldApply = "would_apply",
        AlreadyPresent = "already_present", Refused = "refused", NotFound = "not_found";

    public sealed record SessionSaved(string OutputPath, int Files, int EditedAssemblies, int Edits, int PatchedImages, int Patches, int Names, int Comments, int Notes);

    public sealed record SessionItem(
        [property: Description("file, il2cpp, dump, edits, patches, names, comments, journal or notes.")] string Kind,
        [property: Description("The id the session recorded.")] string Id,
        [property: Description("loaded, already_loaded, would_load, applied, would_apply, already_present, refused or not_found.")] string Outcome,
        [property: Description("How or why: recorded_path, relative_path, search_root, same_build, other_build, sha_mismatch, old_build_needed, " +
                               "user_name_exists, invalid_name, a patch refusal reason, ...")] string Reason,
        int Count, string Detail);

    public sealed record OutcomeCount(string Outcome, int Count);

    public sealed record SessionLoadReport(string Path, bool DryRun, string TargetBuild, IReadOnlyList<OutcomeCount> Outcomes,
        int Offset, int Total, IReadOnlyList<SessionItem> Items, IReadOnlyList<string> Notes);

    [McpServerTool(Name = "save_session", Title = "Save the session", UseStructuredContent = true, OutputSchemaType = typeof(SessionSaved))]
    [Description("Write session work to one JSON file: loaded files (path, relative path, SHA-256), .NET edits, native patches, names, " +
                 "comments, notes, Il2Cpp builds, open minidumps; load_session restores it anywhere.")]
    public Task<string> SaveSession(
        [Description("Output file path (.json).")] string outputPath,
        [Description("Replace the file if it exists.")] bool overwrite = false,
        [Description("Comma-separated: edits, patches, annotations, notes or all (default).")] string? include = null,
        CancellationToken cancellationToken = default) => Task.Run(() =>
    {
        var parts = SessionService.ParseInclude(include);
        if (string.IsNullOrWhiteSpace(outputPath)) throw new ToolError(ErrorCode.InvalidArgument, "An output path is required.", "pass outputPath, e.g. work.session.json");
        var doc = sessions.Build(outputPath, parts);
        var full = SafeFile.WriteAllText(outputPath, SessionService.Serialize(doc), overwrite);
        var saved = new SessionSaved(full, doc.Files.Count, doc.DotNet.Count, doc.DotNet.Sum(d => d.Script.Edits.Count), doc.Native.Count(n => n.Patches != null),
            doc.Native.Sum(n => n.Patches is { } p && p.TryGetProperty("patches", out var list) ? list.GetArrayLength() : 0),
            doc.Native.Sum(n => n.Annotations?.Names.Count ?? 0), doc.Native.Sum(n => n.Annotations?.Comments.Count ?? 0), doc.Notes?.Count ?? 0);
        return ToolOutput.With($"Saved the session to {full}: {Plural(saved.Files, "file")}, {Plural(saved.Edits, "edit")} in {Plural(saved.EditedAssemblies, "assembly")}, " +
            $"{Plural(saved.Patches, "patch")} in {Plural(saved.PatchedImages, "image")}, {Plural(saved.Names, "name")}, {Plural(saved.Comments, "comment")}, " +
            $"{Plural(saved.Notes, "note")}. load_session path={full} restores it.", saved);
    }, cancellationToken);

    [McpServerTool(Name = "load_session", Title = "Load a session", UseStructuredContent = true, OutputSchemaType = typeof(SessionLoadReport))]
    [Description("Restore a save_session file: find each file (recorded path, relative path, else SHA-256 under searchRoots), load it, apply names, " +
                 "comments (never over a user name), patches, edits and notes; one outcome per item. A changed file is refused unless " +
                 "targetBuild=other (native work then needs the old build under searchRoots).")]
    public Task<string> LoadSession(
        [Description("The session file.")] string path,
        [Description("Report only.")] bool dryRun = true,
        [Description("Default same.")] string? targetBuild = null,
        [Description(";-separated folders searched recursively for moved files, by SHA-256.")] string? searchRoots = null,
        [Description("Comma-separated: edits, patches, annotations, notes or all (default).")] string? include = null,
        [Description(ToolSupport.RowOffsetDescription)] int offset = 0,
        [Description("Items to return (max 2000).")] int limit = 200,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) =>
        OrderedProgress.Run(context, progress => Load(path, dryRun, targetBuild, searchRoots, include, offset, limit, progress, cancellationToken));

    private async Task<string> Load(string path, bool dryRun, string? targetBuild, string? searchRoots, string? include, int offset, int limit,
        IProgress<ProgressNotificationValue>? progress, CancellationToken ct)
    {
        var parts = SessionService.ParseInclude(include);
        var target = EditHistoryService.ParseTargetBuild(targetBuild);
        Report(progress, 0, 1, $"Reading {Path.GetFileName(path)}");
        var doc = await Task.Run(() => SessionService.Read(path), ct);
        // One step per recorded item: locating a moved file under searchRoots hashes files and can take long.
        int step = 1, steps = 2 + (doc.Il2Cpp?.Count ?? 0) + (doc.Dumps?.Count ?? 0) + doc.Files.Count + doc.Native.Count + (parts.Contains("edits") ? doc.DotNet.Count : 0);
        void Step(string message) => Report(progress, step++, steps, message);
        var sessionDir = Path.GetDirectoryName(Path.GetFullPath(path))!;
        var roots = (searchRoots ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
        var items = new List<SessionItem>();
        var notesOut = new List<string>();
        void Add(string kind, string id, string outcome, string reason, int count, string detail) => items.Add(new(kind, id, outcome, reason, count, detail));

        if (!dryRun)
            foreach (var d in doc.SearchDirectories.Where(Directory.Exists)) workspace.AddSearchDirectory(d);

        // Il2Cpp builds first: reading one loads its binary, which the files below then find loaded.
        foreach (var g in doc.Il2Cpp ?? [])
        {
            ct.ThrowIfCancellationRequested();
            Step($"Il2Cpp build {Path.GetFileName(g.Input.Path)}");
            if (LoadedId(g.BinarySha256) is { } binaryId)
            {
                Add("il2cpp", g.Input.Path, AlreadyLoaded, "same_build", 1, binaryId);
                continue;
            }
            var located = await Task.Run(() => SessionService.Locate(g.Input, sessionDir, roots, ct), ct);
            if (located.Path == null)
            {
                Add("il2cpp", g.Input.Path, located.Other != null ? Refused : NotFound, located.Other != null ? "sha_mismatch" : "not_found", 0,
                    located.Other != null ? $"{located.Other} has other bytes than the recorded sha256 {g.Input.Sha256}" : "the package or metadata was not found");
                continue;
            }
            if (dryRun)
            {
                Add("il2cpp", g.Input.Path, WouldLoad, located.How, 1, located.Path);
                continue;
            }
            try
            {
                var result = await Task.Run(() =>
                {
                    var build = WorkspaceTools.RawIl2CppBuild(located.Path, g.Slice)
                               ?? throw new ToolError(ErrorCode.NotFound, $"{located.Path} is no longer an Il2Cpp input.");
                    return (il2cppRaw ?? new Il2CppRawLoader(workspace)).Load(build, loadBinary: true, null, ct);
                }, ct);
                bool sameBinary = result.Binary?.OriginalSha256.Equals(g.BinarySha256, StringComparison.OrdinalIgnoreCase) == true;
                Add("il2cpp", g.Input.Path, Loaded, sameBinary ? located.How : "other_binary", result.Load.Loaded.Count,
                    $"{located.Path}: {result.Load.Loaded.Count} dummy assemblies" + (result.Binary != null ? $", binary {result.Binary.Id}" : "") +
                    (sameBinary ? "" : $"; the binary is not the recorded one (sha256 {g.BinarySha256}): names and patches of the recorded binary are not applied to it"));
            }
            catch (ToolError ex) { Add("il2cpp", g.Input.Path, Refused, ex.Code.ToString().ToLowerInvariant(), 0, ex.Message); }
        }

        // Minidumps: reopened under their file name.
        foreach (var d in doc.Dumps ?? [])
        {
            ct.ThrowIfCancellationRequested();
            Step($"minidump {d.File.Id}");
            if (dumps == null) { notesOut.Add("minidumps are not available in this server"); break; }
            if (dumps.OpenIds.FirstOrDefault(id => dumps.PathOf(id) is { } p && File.Exists(p) && SessionService.Locate(d.File with { Path = p, RelativePath = null }, sessionDir, [], ct).Path != null) is { } open)
            {
                Add("dump", d.File.Id, AlreadyLoaded, "same_build", 1, open);
                continue;
            }
            var located = await Task.Run(() => SessionService.Locate(d.File, sessionDir, roots, ct), ct);
            if (located.Path == null)
                Add("dump", d.File.Id, located.Other != null ? Refused : NotFound, located.Other != null ? "sha_mismatch" : "not_found", 0, located.Other ?? d.File.Path);
            else if (dryRun) Add("dump", d.File.Id, WouldLoad, located.How, 1, located.Path);
            else
            {
                try
                {
                    using var session = dumps.Open(located.Path, null);
                    Add("dump", d.File.Id, Loaded, located.How, 1, $"{located.Path} as {session.Id}");
                }
                catch (ToolError ex) { Add("dump", d.File.Id, Refused, ex.Code.ToString().ToLowerInvariant(), 0, ex.Message); }
            }
        }

        // Files: the same build where it can be found; under targetBuild=other, the build now at the recorded path (old: the same build, for matching).
        var current = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase); // recorded sha -> loaded id
        var old = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);     // recorded sha -> loaded id of the recorded build, when the target is another build
        var wouldLoad = new HashSet<string>(StringComparer.OrdinalIgnoreCase);         // dry run: recorded sha of files a real run loads
        foreach (var f in doc.Files)
        {
            ct.ThrowIfCancellationRequested();
            Step($"file {f.Id}");
            if (LoadedId(f.Sha256) is { } loadedId)
            {
                current[f.Sha256] = loadedId;
                Add("file", f.Id, AlreadyLoaded, "same_build", 1, loadedId);
                if (target == EditHistoryService.TargetBuild.Same) continue;
            }
            var located = await Task.Run(() => SessionService.Locate(f, sessionDir, roots, ct), ct);
            if (target == EditHistoryService.TargetBuild.Other && located.Other is { } otherPath)
            {
                current.Remove(f.Sha256);
                if (located.Path != null) old[f.Sha256] = Load(located.Path, dryRun, f) ?? f.Id;
                var id = Load(otherPath, dryRun, f);
                if (id != null) current[f.Sha256] = id;
                else if (dryRun) wouldLoad.Add(f.Sha256);
                Add("file", f.Id, dryRun ? WouldLoad : Loaded, "other_build", 1,
                    otherPath + (located.Path != null ? $"; the recorded build for matching: {located.Path}" : "; the recorded build was not found (native names and patches need it)"));
                continue;
            }
            if (current.ContainsKey(f.Sha256)) continue;
            if (located.Path is { } same)
            {
                var id = Load(same, dryRun, f);
                if (id != null) current[f.Sha256] = id;
                else if (dryRun) wouldLoad.Add(f.Sha256);
                Add("file", f.Id, dryRun ? WouldLoad : Loaded, located.How, 1, same);
            }
            else if (located.Other is { } changed)
                Add("file", f.Id, Refused, "sha_mismatch", 0, $"{changed} has other bytes than the recorded sha256 {f.Sha256}; targetBuild=other carries the work to it");
            else
                Add("file", f.Id, NotFound, "not_found", 0, $"{f.Path}: not there, not beside the session file, and no file with its SHA-256 under searchRoots");
        }

        // Native names and comments, then patches.
        foreach (var n in doc.Native)
        {
            ct.ThrowIfCancellationRequested();
            Step($"names and patches of {n.Id}");
            bool carried = old.ContainsKey(n.Sha256) || (target == EditHistoryService.TargetBuild.Other && !SameBuildLoaded(n.Sha256, current));
            if (parts.Contains("annotations") && n.Annotations is { } ann)
            {
                if (!carried) Annotations(n.Id, current.GetValueOrDefault(n.Sha256), ann, dryRun, Add);
                else if (old.GetValueOrDefault(n.Sha256) is { } oldId && current.GetValueOrDefault(n.Sha256) is { } newId && !dryRun)
                {
                    Annotations(n.Id, oldId, ann, dryRun, Add);
                    var report = await new NativeDiffTools(workspace, code, engines, nativeEdits).CarryNames(oldId, newId, false, 5, 0, null, false, false, default, ct);
                    Add("names", n.Id, report.Set > 0 ? Applied : AlreadyPresent, "other_build", report.Set,
                        $"{report.Set} of {report.Total} names and comments carried to {newId} through the function match; skipped: " +
                        string.Join(", ", report.SkippedBy.Select(r => $"{r.Reason} {r.Count}")));
                }
                else Add("names", n.Id, dryRun ? WouldApply : Refused, old.ContainsKey(n.Sha256) ? "other_build" : "old_build_needed", ann.Names.Count + ann.Comments.Count,
                    old.ContainsKey(n.Sha256) ? "carried through the function match when applied" : "the recorded build is needed to match functions; pass its folder in searchRoots");
            }
            if (parts.Contains("annotations") && n.Journal is { ValueKind: System.Text.Json.JsonValueKind.Array } recorded && !carried && !dryRun
                && current.GetValueOrDefault(n.Sha256) is { } journalId && workspace.Read(() => workspace.Natives.FirstOrDefault(x => x.Id == journalId)) is { } journaled)
            {
                var ids = nativeEdits.Journal.Import(journaled, System.Text.Json.Nodes.JsonNode.Parse(recorded.GetRawText())!.AsArray());
                Add("journal", n.Id, ids.Count > 0 ? Applied : AlreadyPresent, "same_build", ids.Count, $"{ids.Count} name, comment and engine edit(s) undoable on {journaled.Id} (list_native_edits)");
            }
            if (parts.Contains("patches") && n.Patches is { } patches)
            {
                var json = patches.GetRawText();
                string? from = carried ? old.GetValueOrDefault(n.Sha256) : current.GetValueOrDefault(n.Sha256);
                string? to = current.GetValueOrDefault(n.Sha256);
                int count = patches.TryGetProperty("patches", out var list) ? list.GetArrayLength() : 0;
                if (from == null || to == null || (dryRun && (!IsLoaded(from) || !IsLoaded(to))))
                {
                    Add("patches", n.Id, from == null && carried ? Refused : dryRun ? WouldApply : Refused, from == null && carried ? "old_build_needed" : dryRun ? "not_loaded" : "not_found",
                        count, from == null && carried ? "the recorded build is needed to match functions; pass its folder in searchRoots" : "the image is not loaded (a dry run loads nothing)");
                    continue;
                }
                try
                {
                    var report = await new NativePatchTools(workspace, code, nativeEdits, journal).CarryPatches(from, to, json, dryRun, cancellationToken: ct);
                    int ok = report.Carried;
                    Add("patches", n.Id, ok > 0 ? dryRun ? WouldApply : Applied : report.RefusedBy.All(r => r.Reason == "already_present") && report.Refused > 0 ? AlreadyPresent : Refused,
                        carried ? "other_build" : "same_build", ok, $"{ok} of {report.Patches} patch(es) on {to}" +
                        (report.Refused > 0 ? "; not applied: " + string.Join(", ", report.RefusedBy.Select(r => $"{r.Reason} {r.Count}")) : ""));
                }
                catch (ToolError ex) { Add("patches", n.Id, Refused, ex.Code.ToString().ToLowerInvariant(), 0, ex.Message); }
            }
        }

        // .NET edits.
        if (parts.Contains("edits"))
            foreach (var e in doc.DotNet)
            {
                ct.ThrowIfCancellationRequested();
                Step($"edits of {e.Id}");
                var to = current.GetValueOrDefault(e.Sha256);
                if (to == null || !IsLoaded(to))
                {
                    bool later = dryRun && (to != null || wouldLoad.Contains(e.Sha256));
                    Add("edits", e.Id, later ? WouldApply : Refused, later || to != null ? "not_loaded" : "not_found", e.Script.Edits.Count,
                        later || to != null ? "the assembly is not loaded (a dry run loads nothing)" : "the assembly was not found");
                    continue;
                }
                try
                {
                    var (_, ok, failed) = await Task.Run(() => workspace.Write(() =>
                        history.Apply(e.Script, $"session {e.Id}", to, dryRun, stopOnError: true, ct, target)), ct);
                    bool sameSha = workspace.Read(() => workspace.Get(to).OriginalSha256).Equals(e.Sha256, StringComparison.OrdinalIgnoreCase);
                    Add("edits", e.Id, failed > 0 ? Refused : dryRun ? WouldApply : Applied, failed > 0 ? "edit_failed" : sameSha ? "same_build" : "other_build",
                        ok, $"{ok} of {e.Script.Edits.Count} edit(s) on {to}" + (failed > 0 ? $"; {failed} failed: apply_edits with dryRun=true shows the errors" : ""));
                }
                catch (ToolError ex) { Add("edits", e.Id, Refused, ex.Code == ErrorCode.Conflict ? "sha_mismatch" : ex.Code.ToString().ToLowerInvariant(), 0, ex.Message); }
            }

        if (parts.Contains("notes") && doc.Notes is { Count: > 0 } list2)
        {
            if (notes == null) notesOut.Add("notes are not available in this server");
            else if (dryRun) Add("notes", "*", WouldApply, "import", list2.Count, $"{list2.Count} note(s)");
            else
            {
                var (added, updated, unchanged) = notes.Import(list2);
                Add("notes", "*", added + updated > 0 ? Applied : AlreadyPresent, "import", added + updated, $"{added} added, {updated} updated, {unchanged} already present");
            }
        }
        if (dryRun) notesOut.Add("items on files that are not loaded yet report would_apply without checking them");
        Report(progress, steps, steps, "Done");

        offset = Math.Max(0, offset);
        limit = ClampLimit(limit, 2000);
        var counts = items.GroupBy(i => i.Outcome).Select(g => new OutcomeCount(g.Key, g.Count())).OrderByDescending(c => c.Count).ThenBy(c => c.Outcome, StringComparer.Ordinal).ToList();
        var full = Path.GetFullPath(path);
        var build = target == EditHistoryService.TargetBuild.Same ? "same" : "other";
        var header = $"Session {full}, targetBuild={build}: {(counts.Count == 0 ? "nothing recorded" : string.Join(", ", counts.Select(c => $"{c.Outcome} {c.Count}")))}\n" +
                     string.Concat(notesOut.Select(n => $"Note: {n}\n")) + (dryRun ? "Nothing changed (dry run); pass dryRun=false to apply.\n" : "");
        return ToolOutput.List(items.Skip(offset).Take(limit).ToList(), offset, limit, items.Count,
            i => $"{i.Kind,-8} {i.Id}  {i.Outcome} ({i.Reason}), {i.Count}: {i.Detail}",
            page => new SessionLoadReport(full, dryRun, build, counts, offset, items.Count, page, notesOut), "item", header);
    }

    private string? LoadedId(string sha256) => workspace.Read(() =>
        workspace.Assemblies.FirstOrDefault(a => a.OriginalSha256.Equals(sha256, StringComparison.OrdinalIgnoreCase))?.Id
        ?? workspace.Natives.FirstOrDefault(n => n.OriginalSha256.Equals(sha256, StringComparison.OrdinalIgnoreCase))?.Id);

    private bool IsLoaded(string id) => workspace.Read(() => workspace.Natives.Any(n => n.Id == id) || workspace.Assemblies.Any(a => a.Id == id));

    private bool SameBuildLoaded(string sha256, Dictionary<string, string> current) =>
        current.TryGetValue(sha256, out var id) && LoadedId(sha256) == id;

    /// <summary>
    /// Loads <paramref name="file"/> (not in a dry run) as <paramref name="recorded"/> was: its raw layout and import overrides;
    /// returns its id: the native view for an image, else the assembly.
    /// </summary>
    private string? Load(string file, bool dryRun, SessionService.SessionFile recorded)
    {
        if (dryRun) return null;
        Func<Native.INativeImage, Native.EngineOverrides?>? overrides = recorded.Overrides is { } o ? o.Parse : null;
        if (recorded.Raw is { } raw)
        {
            var head = new byte[8];
            int read;
            using (var s = File.OpenRead(file)) read = s.ReadAtLeast(head, head.Length, throwOnEndOfStream: false);
            return workspace.LoadRaw(file, Native.RawLayout.Parse(raw.Arch, raw.Base, raw.Entry, new FileInfo(file).Length, head.AsSpan(0, read)), overrides).Id;
        }
        var (asm, native) = workspace.LoadAny(file, overrides: overrides);
        return asm?.Id ?? native?.Id;
    }

    /// <summary>Merges recorded names and comments into an image's user annotations; a different user name or comment wins.</summary>
    private void Annotations(string recordedId, string? id, SessionService.SessionAnnotations ann, bool dryRun, Action<string, string, string, string, int, string> add)
    {
        var native = id == null ? null : workspace.Read(() => workspace.Natives.FirstOrDefault(n => n.Id == id));
        if (native == null)
        {
            add("names", recordedId, dryRun && id == null ? WouldApply : Refused, id == null ? "not_loaded" : "not_found", ann.Names.Count + ann.Comments.Count,
                "the image is not loaded (a dry run loads nothing)");
            return;
        }
        var annotations = code.Annotations(native);
        var names = new List<(uint, string)>();
        var comments = new List<(uint, string)>();
        int present = 0, conflicting = 0, invalid = 0;
        foreach (var (key, value) in ann.Names)
        {
            if (SessionService.Rva(key) is not { } rva) { invalid++; continue; }
            string valid;
            try { valid = NativeName.Validate(value); }
            catch (ToolError) { invalid++; continue; }
            var existing = annotations.NameAt(rva);
            if (existing == valid) present++;
            else if (existing != null) conflicting++;
            else names.Add((rva, valid));
        }
        foreach (var (key, value) in ann.Comments)
        {
            if (SessionService.Rva(key) is not { } rva) { invalid++; continue; }
            var existing = annotations.CommentAt(rva);
            if (existing == value.Trim()) present++;
            else if (existing != null) conflicting++;
            else comments.Add((rva, value));
        }
        var pseudo = new List<(uint, string?)>();
        foreach (var (key, value) in ann.Pseudo ?? [])
        {
            if (SessionService.Rva(key) is not { } rva) { invalid++; continue; }
            var existing = annotations.PseudoCommentAt(rva);
            if (existing == value.Trim()) present++;
            else if (existing != null) conflicting++;
            else pseudo.Add((rva, value));
        }
        // a comment's engine kind goes with it (repeatable when none was recorded)
        var kinds = comments.Where(c => ann.CommentKinds?.GetValueOrDefault(SessionService.Hex(c.Item1)) != null)
            .Select(c => (c.Item1, (string?)ann.CommentKinds![SessionService.Hex(c.Item1)])).ToList();
        if (!dryRun && pseudo.Count > 0) workspace.Write(() => { annotations.Apply([], [], pseudo, allowDuplicate: true); return 0; });
        if (!dryRun && names.Count + comments.Count > 0)
            workspace.Write(() =>
            {
                annotations.SetMany(names, comments);
                if (kinds.Count > 0) annotations.Apply([], [.. comments.Select(c => (c.Item1, (string?)c.Item2))], [], allowDuplicate: true, kinds: kinds);
                if (code.Ready(native) is { } index)
                {
                    foreach (var (rva, name) in names) index.SetUserName(rva, name);
                    foreach (var (rva, text) in comments) index.SetUserComment(rva, text);
                }
                return 0;
            });
        int set = names.Count + comments.Count + pseudo.Count;
        add("names", recordedId, set > 0 ? dryRun ? WouldApply : Applied : conflicting + invalid > 0 ? Refused : AlreadyPresent,
            conflicting > 0 ? "user_name_exists" : invalid > 0 ? "invalid_name" : "same_build", set,
            $"{set} set, {present} already present, {conflicting} kept (a different user name or comment exists), {invalid} invalid, on {native.Id}");
    }
}
