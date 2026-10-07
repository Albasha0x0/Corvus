using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using dnlib.DotNet;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Services;

/// <summary>
/// The edit history of an assembly: listing, before/after diffs, and edit scripts (JSON) that re-apply a patch set —
/// typically to a new build of a game after an update.
/// </summary>
public sealed class EditHistoryService(AssemblyWorkspace workspace, EditService edits, DecompilerService decompiler)
{
    public const string ScriptFormat = "net-decompiler-edits/1";

    private static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    public sealed record ScriptEdit(string Kind, Dictionary<string, string?> Args, string Description);

    public sealed record Script(string Format, string Assembly, string? Mvid, DateTime Created, List<ScriptEdit> Edits);

    public string List(LoadedAssembly asm)
    {
        if (asm.Edits.Count == 0)
            return $"{asm.Id} has no unsaved edits.";
        var sb = new StringBuilder($"{asm.Id}: {asm.Edits.Count} edit(s), in order (undo_edit takes the number):\n");
        for (int i = 0; i < asm.Edits.Count; i++)
            sb.AppendLine($"  #{i + 1}  {asm.Edits[i].Kind,-20} {asm.Edits[i].Description}");
        return sb.ToString();
    }

    // ------------------------------------------------------------------ scripts

    public string Export(LoadedAssembly asm, string path)
    {
        if (asm.Edits.Count == 0)
            throw new ToolError($"{asm.Id} has no edits to export.");
        var original = asm.GetOriginalView(workspace.DnlibContext).Module;
        var script = new Script(ScriptFormat, asm.AssemblyName, original.Mvid?.ToString(), DateTime.UtcNow,
            asm.Edits.Select(e => new ScriptEdit(e.Kind, e.Args.ToDictionary(kv => kv.Key, kv => kv.Value), e.Description)).ToList());
        var full = Path.GetFullPath(path);
        Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        File.WriteAllText(full, JsonSerializer.Serialize(script, Json));
        return $"Exported {script.Edits.Count} edit(s) of {asm.Id} to {full}.";
    }

    public static Script ReadScript(string path)
    {
        var full = Path.GetFullPath(path);
        if (!File.Exists(full))
            throw new ToolError($"File not found: {full}");
        Script? script;
        try { script = JsonSerializer.Deserialize<Script>(File.ReadAllText(full), Json); }
        catch (JsonException ex) { throw new ToolError($"{full} is not a valid edit script: {ex.Message}"); }
        if (script == null || script.Format != ScriptFormat || script.Edits == null)
            throw new ToolError($"{full} is not a net-decompiler edit script (expected format '{ScriptFormat}').");
        return script;
    }

    /// <summary>
    /// Applies a script's edits in order. On the same original image (matching MVID) recorded tokens are used; on another
    /// build, symbols are resolved by name. With stopOnError, a failure rolls the assembly back to its state before the script.
    /// </summary>
    public string Apply(string path, string? assembly, bool dryRun, bool stopOnError, CancellationToken ct)
    {
        var script = ReadScript(path);
        var asm = workspace.Get(assembly ?? script.Assembly);
        var original = asm.GetOriginalView(workspace.DnlibContext).Module;
        bool sameImage = script.Mvid != null && script.Mvid == original.Mvid?.ToString();
        var records = script.Edits.Select(e => new EditRecord(e.Kind, e.Args, e.Description, [])).ToList();

        var sb = new StringBuilder($"{(dryRun ? "Dry run of" : "Applying")} {records.Count} edit(s) from {Path.GetFileName(path)} to {asm.Id}" +
                                   $" ({(sameImage ? "same build: using recorded tokens" : "different build: resolving symbols by name")}):\n");
        var before = asm.Edits.ToList();
        int ok = 0, failed = 0;
        for (int i = 0; i < records.Count; i++)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                var result = dryRun ? edits.Check(records[i], asm, sameImage) : edits.Apply(records[i], asm, sameImage, ct);
                sb.AppendLine($"  #{i + 1} ok      {records[i].Description}{(dryRun ? $" — {result}" : "")}");
                ok++;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                failed++;
                sb.AppendLine($"  #{i + 1} FAILED  {records[i].Description}\n      {FirstLine(ex.Message)}");
                if (stopOnError && !dryRun)
                {
                    edits.Rebuild(asm, before, ct);
                    sb.AppendLine($"Stopped; {asm.Id} was rolled back to its state before the script. Fix the edit (or pass stopOnError=false to skip failures).");
                    return sb.ToString();
                }
            }
        }
        sb.AppendLine($"{ok} applied{(dryRun ? " (dry run: targets checked only)" : "")}, {failed} failed.");
        return sb.ToString();
    }

    // ------------------------------------------------------------------ diffs

    /// <summary>Unified diffs of the decompiled C# of every member an edit touched, original vs current.</summary>
    public string Diff(LoadedAssembly asm, int? number, CancellationToken ct)
    {
        if (asm.Edits.Count == 0)
            return $"{asm.Id} has no edits.";
        var selected = number is { } n
            ? (n >= 1 && n <= asm.Edits.Count ? [(n, asm.Edits[n - 1])] : throw new ToolError($"Edit #{n} does not exist; {asm.Id} has {asm.Edits.Count} edit(s)."))
            : asm.Edits.Select((e, i) => (i + 1, e)).ToList();

        var originalView = asm.GetOriginalView(workspace.DnlibContext);
        var sb = new StringBuilder();
        var done = new HashSet<string>(StringComparer.Ordinal);
        foreach (var (num, edit) in selected)
        {
            sb.AppendLine($"=== #{num} {edit.Kind}: {edit.Description}");
            if (edit.Touched.Count == 0)
            {
                sb.AppendLine("(no member-level diff for this edit)");
                continue;
            }
            foreach (var label in edit.Touched)
            {
                if (number == null && !done.Add(label)) continue; // shown already for an earlier edit
                sb.Append(DiffMember(asm, originalView, label, ct));
            }
        }
        return sb.ToString();
    }

    private string DiffMember(LoadedAssembly asm, LoadedAssembly originalView, string label, CancellationToken ct)
    {
        ResolvedSymbol current;
        try { current = SymbolResolver.ResolveOne(workspace, asm.Id, label); }
        catch (ToolError) { return $"(could not resolve {label} in the current state; it was renamed or removed by a later edit)\n"; }

        // Members that existed before the edits keep their token (edits are written with PreserveAll); added ones have rid 0.
        var original = current.Member.MDToken.Rid != 0 ? originalView.Module.ResolveToken(current.Member.MDToken.Raw) as IMemberDef : null;

        string after = Decompile(asm, current.Member, ct);
        string before = original == null ? "" : Decompile(originalView, original, ct);
        var beforeLabel = original == null ? "(did not exist)" : $"original {Format.MemberLabel(original)}";
        return TextDiff.Unified(before, after, beforeLabel, $"current {current.Label}") + "\n";
    }

    private string Decompile(LoadedAssembly asm, IMemberDef member, CancellationToken ct) =>
        member is TypeDef t ? decompiler.DecompileType(asm, t, ct) : decompiler.DecompileMembers(asm, [member], ct);

    private static string FirstLine(string s)
    {
        int nl = s.IndexOf('\n');
        return nl >= 0 ? s[..nl] : s;
    }
}
