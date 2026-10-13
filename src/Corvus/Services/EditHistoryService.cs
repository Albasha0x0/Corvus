using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using dnlib.DotNet;
using Corvus.Core;

namespace Corvus.Services;

/// <summary>
/// Edit history of an assembly: listing, before/after diffs, and JSON edit scripts that re-apply a patch set,
/// typically to a new build.
/// </summary>
public sealed class EditHistoryService(AssemblyWorkspace workspace, EditService edits, DecompilerService decompiler, AssemblyComparer comparer)
{
    public const string ScriptFormat = "corvus-edits/1";

    // Migration only: the format of edit scripts written before the rename, still read.
    private const string LegacyScriptFormat = "net-decompiler-edits/1";

    private static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    public sealed record ScriptEdit(string Kind, Dictionary<string, string?> Args, string Description);

    /// <summary>
    /// An edit script. Sha256 (of the file the edits were made on) and Identity (its assembly full name) bind it to a
    /// build; scripts written before they were recorded have neither and are accepted with a warning.
    /// </summary>
    public sealed record Script(string Format, string Assembly, string? Mvid, string? Sha256, string? Identity, DateTime Created, List<ScriptEdit> Edits)
    {
        /// <summary><see cref="ArityLabels"/> when generic methods are labeled Method<T>(...); absent in older scripts.</summary>
        public int Labels { get; init; }
    }

    /// <summary>Script labels name generic methods with their arity (Format.MemberLabel).</summary>
    public const int ArityLabels = 2;

    /// <summary>How apply_edits treats a script made for another build.</summary>
    public enum TargetBuild
    {
        /// <summary>Only the build the script was made from (same SHA-256); anything else is refused.</summary>
        Same,
        /// <summary>Any build: symbols are re-resolved by name, renamed targets followed through the source build when it is loaded.</summary>
        Other,
    }

    public static TargetBuild ParseTargetBuild(string? value) => (value ?? "same").Trim().ToLowerInvariant() switch
    {
        "same" or "" => TargetBuild.Same,
        "other" => TargetBuild.Other,
        _ => throw new ToolError(ErrorCode.InvalidArgument, $"targetBuild must be 'same' or 'other', not '{value}'.",
            "same: only the build the script was made from; other: carry the edits to another build"),
    };

    /// <summary>One item's failure with its code; an exception no edit classified is "internal" and names its type.</summary>
    internal static string FailureText(Exception ex) => ex is ToolError error
        ? $"({ToolError.CodeName(error.Code)}) {error.Message}" + (error.Remediation is { Length: > 0 } next ? $"\nNext: {next}" : "")
        : $"(internal) {ex.GetType().Name}: {ex.Message}\nNext: {ToolError.InternalNext}";

    public string List(LoadedAssembly asm)
    {
        if (asm.Edits.Count == 0)
            return $"{asm.Id} has no unsaved edits.";
        var sb = new StringBuilder($"{asm.Id}: {asm.Edits.Count} edit(s), in order (undo_edit takes the number):\n");
        foreach (var e in asm.Edits)
            sb.AppendLine($"  #{e.Number}  {e.Kind,-20} {e.Description}");
        return sb.ToString();
    }

    /// <summary>The edit script of <paramref name="asm"/>'s current edits, bound to its build; the caller holds the workspace lock.</summary>
    public Script BuildScript(LoadedAssembly asm)
    {
        var original = asm.GetOriginalView(workspace.DnlibContext).Module;
        return new Script(ScriptFormat, asm.AssemblyName, original.Mvid?.ToString(), asm.OriginalSha256, original.Assembly?.FullName ?? original.Name,
            DateTime.UtcNow, asm.Edits.Select(e => new ScriptEdit(e.Kind, e.Args.ToDictionary(kv => kv.Key, kv => kv.Value), e.Description)).ToList())
        { Labels = ArityLabels };
    }

    /// <summary>A script as JSON text (the export_edits file).</summary>
    public static string Serialize(Script script) => JsonSerializer.Serialize(script, Json);

    public static Script? Deserialize(JsonElement json) => json.Deserialize<Script>(Json);

    public string Export(LoadedAssembly asm, string path, bool overwrite = false) => Export(asm, path, overwrite, out _);

    /// <summary>What export_edits wrote: the file and the build it is bound to.</summary>
    public sealed record ExportedEdits(string OutputPath, int Edits, string? Sha256, string? Mvid, string? Identity);

    public string Export(LoadedAssembly asm, string path, bool overwrite, out ExportedEdits exported)
    {
        if (asm.Edits.Count == 0)
            throw new ToolError(ErrorCode.NotFound, $"{asm.Id} has no edits to export.");
        var script = BuildScript(asm);
        var full = SafeFile.WriteAllText(path, Serialize(script), overwrite);
        exported = new ExportedEdits(full, script.Edits.Count, script.Sha256, script.Mvid, script.Identity);
        return $"Exported {script.Edits.Count} edit(s) of {asm.Id} to {full}.\n" +
               $"Bound to the build: sha256 {script.Sha256}, MVID {script.Mvid ?? "(none)"}, {script.Identity}. " +
               "apply_edits refuses other builds unless targetBuild=other.";
    }

    public static Script ReadScript(string path)
    {
        var full = Path.GetFullPath(path);
        if (!File.Exists(full))
            throw Targets.FileNotFound(full);
        Script? script;
        try { script = JsonSerializer.Deserialize<Script>(File.ReadAllText(full), Json); }
        catch (JsonException ex) { throw new ToolError(ErrorCode.MalformedInput, $"{full} is not a valid edit script: {ex.Message}"); }
        if (script == null || script.Format is not (ScriptFormat or LegacyScriptFormat) || script.Edits == null)
            throw new ToolError(ErrorCode.MalformedInput, $"{full} is not an edit script (expected format '{ScriptFormat}').");
        return script;
    }

    /// <summary>
    /// Applies a script's edits in order. On the same original image (matching MVID) recorded tokens are used; on another
    /// build, symbols are resolved by name. With stopOnError, a failure rolls the assembly back to its state before the script.
    /// A script bound to a build (SHA-256) is refused on any other file unless <paramref name="target"/> is Other.
    /// </summary>
    public string Apply(string path, string? assembly, bool dryRun, bool stopOnError, CancellationToken ct, TargetBuild target = TargetBuild.Same) =>
        Run(path, assembly, dryRun, stopOnError, ct, target).Report;

    /// <summary><see cref="Apply(string, string?, bool, bool, CancellationToken, TargetBuild)"/> with each edit's outcome.</summary>
    public ApplyOutcome Run(string path, string? assembly, bool dryRun, bool stopOnError, CancellationToken ct, TargetBuild target = TargetBuild.Same) =>
        Run(ReadScript(path), Path.GetFileName(path), assembly, dryRun, stopOnError, ct, target);

    /// <summary><see cref="Apply(string, string?, bool, bool, CancellationToken, TargetBuild)"/> of a script read elsewhere (<paramref name="name"/> labels it).</summary>
    public (string Report, int Applied, int Failed) Apply(Script script, string name, string? assembly, bool dryRun, bool stopOnError, CancellationToken ct,
        TargetBuild target = TargetBuild.Same)
    {
        var outcome = Run(script, name, assembly, dryRun, stopOnError, ct, target);
        return (outcome.Report, outcome.RolledBack ? 0 : outcome.Items.Count(i => i.Error == null), outcome.Failed);
    }

    /// <summary>One script edit's outcome. Basis: observed (recorded token, same build), derived (resolved by name), inferred (followed to a renamed counterpart).</summary>
    public sealed record ApplyItem(int Index, string Description, string? EditId, string Basis, BatchError? Error, IReadOnlyList<string>? Remapped);

    /// <summary>A script run: the report text, every edit's outcome, and whether a failure rolled everything back.</summary>
    public sealed record ApplyOutcome(string Assembly, string Report, IReadOnlyList<ApplyItem> Items, bool RolledBack)
    {
        public int Failed => Items.Count(i => i.Error != null);
    }

    public ApplyOutcome Run(Script script, string name, string? assembly, bool dryRun, bool stopOnError, CancellationToken ct,
        TargetBuild target = TargetBuild.Same)
    {
        var asm = workspace.Get(assembly ?? script.Assembly);
        var original = asm.GetOriginalView(workspace.DnlibContext).Module;
        bool sameImage = script.Mvid != null && script.Mvid == original.Mvid?.ToString();
        string actualMvid = original.Mvid?.ToString() ?? "(none)", actualIdentity = original.Assembly?.FullName ?? original.Name;
        string buildCheck;
        if (script.Sha256 == null)
            buildCheck = "WARNING: the script predates build binding (no sha256/identity recorded), so it is not checked against this build" +
                         (script.Mvid == null ? "" : sameImage ? " (its MVID matches)" : $" (its MVID {script.Mvid} differs from this build's {actualMvid})") +
                         "; export it again to bind it.";
        else if (string.Equals(script.Sha256, asm.OriginalSha256, StringComparison.OrdinalIgnoreCase))
            buildCheck = $"same build (sha256 {Short(asm.OriginalSha256)} matches)";
        else
        {
            string mismatch = $"the script was made for sha256 {script.Sha256}, MVID {script.Mvid ?? "(none)"}, {script.Identity}; " +
                              $"{asm.Id} is sha256 {asm.OriginalSha256}, MVID {actualMvid}, {actualIdentity}" +
                              (sameImage ? " (same MVID: the file was changed after compiling, e.g. saved with edits or re-signed)" : "");
            if (target == TargetBuild.Same)
                throw new ToolError(ErrorCode.Conflict, $"The edit script {name} belongs to another build: {mismatch}.",
                    "load the build the script was made from (matching sha256), or pass targetBuild=other to carry the edits to this build deliberately " +
                    "(symbols re-resolved by name; load the source build too so renamed targets are followed); try it with dryRun=true first");
            buildCheck = $"different build, carried over (targetBuild=other): {mismatch}";
        }
        bool legacy = script.Labels < ArityLabels;
        var records = script.Edits.Select(e => new EditRecord(e.Kind, e.Args, e.Description, []) { LegacyLabels = legacy }).ToList();

        // On another build, renamed targets are located via the script's source build when it is loaded.
        var originalBuild = sameImage ? null : workspace.Assemblies.FirstOrDefault(a => a != asm && a.Module.Mvid?.ToString() == script.Mvid);
        var remapped = new List<string>();
        AssemblyComparer.Comparison? comparison = null;
        if (originalBuild != null)
            edits.Remap = (record, key) =>
            {
                ResolvedSymbol old;
                // By the recorded token first: the script's own renames may have been applied to that build, so the
                // recorded name (the name before the edit) may no longer exist there.
                if (SymbolResolver.TryParseToken(record.Arg(key + "Token") ?? "", out uint token) && (token & 0x00FFFFFF) != 0
                    && MetadataUtil.Try(() => originalBuild.Module.ResolveToken(token)) is IMemberDef byToken)
                    old = new ResolvedSymbol(originalBuild, byToken);
                else
                {
                    try { old = SymbolResolver.ResolveOne(workspace, originalBuild.Id, record.Arg(key)!, SymbolResolver.ParseKind(record.Arg(key + "Kind")), legacyLabels: record.LegacyLabels); }
                    catch (ToolError) { return null; }
                }
                // Matched against the source build as loaded: the script's own edits (stubs, patches, renames) may have
                // been applied to it, and a stubbed body no longer resembles its counterpart.
                var source = originalBuild.IsDirty ? originalBuild.GetOriginalView(workspace.DnlibContext) : originalBuild;
                comparison ??= comparer.Compare(source, asm, ct);
                if (!ReferenceEquals(source, originalBuild))
                {
                    if (old.Member.MDToken.Rid == 0 || MetadataUtil.Try(() => source.Module.ResolveToken(old.Member.MDToken.Raw)) is not IMemberDef unedited)
                        return null; // added by an edit: no counterpart in another build
                    old = new ResolvedSymbol(source, unedited);
                }
                var (match, how) = comparer.FindCounterpart(comparison, old.Member);
                if (match == null) return null;
                remapped.Add($"{old.Label} -> {Format.MemberLabel(match)} ({how})");
                return new ResolvedSymbol(asm, match);
            };
        var sb = new StringBuilder($"{(dryRun ? "Dry run of" : "Applying")} {records.Count} edit(s) from {name} to {asm.Id}" +
                                   $" ({(sameImage ? "same build: using recorded tokens" : originalBuild != null
                                       ? $"different build: resolving symbols by name, renamed ones through {originalBuild.Id} (the build the script was made from)"
                                       : "different build: resolving symbols by name")}):\n" +
                                   $"Build check: {buildCheck}\n");
        var allRemapped = new List<string>();
        // A dry run applies every edit for real and then rolls back, so it reports exactly what a real run would.
        var before = asm.Edits.ToList();
        var items = new List<ApplyItem>();
        int ok = 0, failed = 0;
        try
        {
            for (int i = 0; i < records.Count; i++)
            {
                ct.ThrowIfCancellationRequested();
                CallProgress.Report(i, records.Count, $"applying edit {i + 1} of {records.Count}: {records[i].Description}");
                try
                {
                    remapped.Clear();
                    int count = asm.Edits.Count;
                    edits.Apply(records[i], asm, sameImage, ct);
                    sb.AppendLine($"  #{i + 1} ok      {records[i].Description}");
                    foreach (var r in remapped) sb.AppendLine($"      target renamed in this build: {r}");
                    allRemapped.AddRange(remapped);
                    // A dry run's numbers are rolled back with its edits.
                    string? id = !dryRun && asm.Edits.Count > count ? new EditId(asm.Id, asm.Edits[^1].Number).ToString() : null;
                    items.Add(new ApplyItem(i + 1, records[i].Description, id, sameImage ? "observed" : remapped.Count > 0 ? "inferred" : "derived", null,
                        remapped.Count > 0 ? remapped.ToList() : null));
                    ok++;
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    failed++;
                    sb.AppendLine($"  #{i + 1} FAILED  {records[i].Description}");
                    sb.AppendLine(Indent(FailureText(ex), "      "));
                    if (!sameImage && originalBuild == null && ex.Message.Contains("not found", StringComparison.Ordinal))
                        sb.AppendLine($"      (load the build the script was made from, MVID {script.Mvid}, to follow renamed targets)");
                    items.Add(new ApplyItem(i + 1, records[i].Description, null, sameImage ? "observed" : "derived",
                        ex is ToolError error ? BatchError.From(error, "apply_edits") : BatchError.Internal(ex), null));
                    if (stopOnError && !dryRun)
                    {
                        edits.Rebuild(asm, before, ct);
                        sb.AppendLine($"Stopped; {asm.Id} was rolled back to its state before the script. Fix the edit (or pass continueOnError=true to skip failures).");
                        return new ApplyOutcome(asm.Id, sb.ToString(), items.Select(x => x with { EditId = null }).ToList(), RolledBack: true);
                    }
                }
            }
        }
        finally
        {
            edits.Remap = null;
            if (dryRun && asm.Edits.Count != before.Count)
                edits.Rebuild(asm, before, CancellationToken.None);
        }
        sb.AppendLine(dryRun
            ? $"{ok} would apply, {failed} would fail (dry run: every edit was applied and compiled, then rolled back; nothing changed)."
            : $"{ok} applied, {failed} failed.");
        if (!sameImage)
            sb.AppendLine($"Cross-build: {ok} edit(s) resolved by name, {allRemapped.Count} target(s) followed to a renamed counterpart" +
                          (originalBuild == null ? " (the source build is not loaded, so renamed targets could not be followed)." : "."));
        return new ApplyOutcome(asm.Id, sb.ToString(), items, RolledBack: false);
    }

    private static string Short(string sha256) => sha256.Length > 16 ? sha256[..16] + "…" : sha256;

    /// <summary>Unified diffs of the decompiled C# of every member an edit touched, original vs current.</summary>
    public string Diff(LoadedAssembly asm, int? number, CancellationToken ct) => Diff(asm, number, int.MaxValue, ct).Text;

    /// <summary>
    /// <see cref="Diff(LoadedAssembly, int?, CancellationToken)"/> up to the first member that takes the text past
    /// <paramref name="stopAfter"/> characters: a whole-assembly simplify touches thousands of members, each decompiled
    /// twice, and a page shows a few. Complete is false when members were left out.
    /// </summary>
    public (string Text, bool Complete) Diff(LoadedAssembly asm, int? number, int stopAfter, CancellationToken ct)
    {
        if (asm.Edits.Count == 0)
            return ($"{asm.Id} has no edits.", true);
        var selected = number != null ? [(number.Value, EditService.Find(asm, number))] : asm.Edits.Select(e => (e.Number, e)).ToList();

        var originalView = asm.GetOriginalView(workspace.DnlibContext);
        var sb = new StringBuilder();
        var done = new HashSet<string>(StringComparer.Ordinal);
        foreach (var (num, edit) in selected)
        {
            if (sb.Length > stopAfter) return (sb.ToString(), false);
            sb.AppendLine($"=== #{num} {edit.Kind}: {edit.Description}");
            if (edit.Touched.Count == 0)
            {
                sb.AppendLine("(no member-level diff for this edit)");
                continue;
            }
            foreach (var label in edit.Touched)
            {
                if (number == null && !done.Add(label)) continue; // already shown for an earlier edit
                if (sb.Length > stopAfter) return (sb.ToString(), false);
                sb.Append(CachedDiffMember(asm, originalView, label, ct));
            }
        }
        return (sb.ToString(), true);
    }

    private sealed class MemberDiffs(long key)
    {
        public long Key { get; } = key;
        public Dictionary<string, string> ByLabel { get; } = new(StringComparer.Ordinal);
    }

    // Per assembly state: the next page of a long diff reuses the members already shown.
    private readonly System.Runtime.CompilerServices.ConditionalWeakTable<LoadedAssembly, MemberDiffs> _memberDiffs = new();

    private string CachedDiffMember(LoadedAssembly asm, LoadedAssembly originalView, string label, CancellationToken ct)
    {
        // Decompiled text depends on the assembly's edits and on what else is loaded.
        long key = ((long)workspace.Generation << 32) | (uint)asm.Version;
        MemberDiffs cache;
        lock (_memberDiffs)
        {
            if (!_memberDiffs.TryGetValue(asm, out cache!) || cache.Key != key)
                _memberDiffs.AddOrUpdate(asm, cache = new MemberDiffs(key));
        }
        lock (cache)
            if (cache.ByLabel.TryGetValue(label, out var text)) return text;
        var diff = DiffMember(asm, originalView, label, ct);
        lock (cache) cache.ByLabel[label] = diff;
        return diff;
    }

    private string DiffMember(LoadedAssembly asm, LoadedAssembly originalView, string label, CancellationToken ct)
    {
        ResolvedSymbol current;
        try { current = SymbolResolver.ResolveOne(workspace, asm.Id, label); }
        catch (ToolError) { return $"(could not resolve {label} in the current state; it was renamed or removed by a later edit)\n"; }

        // Pre-existing members keep their token (written with PreserveAll); added members have rid 0.
        var original = current.Member.MDToken.Rid != 0 ? originalView.Module.ResolveToken(current.Member.MDToken.Raw) as IMemberDef : null;

        string after = Decompile(asm, current.Member, ct);
        string before = original == null ? "" : Decompile(originalView, original, ct);
        var beforeLabel = original == null ? "(did not exist)" : $"original {Format.MemberLabel(original)}";
        return TextDiff.Unified(before, after, beforeLabel, $"current {current.Label}") + "\n";
    }

    private string Decompile(LoadedAssembly asm, IMemberDef member, CancellationToken ct) =>
        member is TypeDef t ? decompiler.DecompileType(asm, t, ct) : decompiler.DecompileMembers(asm, [member], ct);

    /// <summary>The whole (multi-line) error message, indented; very long ones are cut after <see cref="MaxErrorLines"/> lines.</summary>
    private static string Indent(string message, string indent)
    {
        var lines = message.TrimEnd().ReplaceLineEndings("\n").Split('\n');
        var shown = lines.Take(MaxErrorLines).Select(l => indent + l);
        return string.Join("\n", lines.Length > MaxErrorLines ? shown.Append($"{indent}… {lines.Length - MaxErrorLines} more line(s)") : shown);
    }

    private const int MaxErrorLines = 40;
}
