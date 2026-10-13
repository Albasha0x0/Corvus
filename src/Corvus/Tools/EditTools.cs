using System.ComponentModel;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Services;
using Corvus.Services.Simplify;
using static Corvus.Tools.ToolSupport;

namespace Corvus.Tools;

/// <summary>
/// In-memory edits: visible immediately in decompile/IL/search output, written to disk only by save_assembly. Each mutating
/// tool returns an <see cref="EditOutcome"/> naming the edit ids it recorded.
/// </summary>
[McpServerToolType]
public sealed class EditTools(AssemblyWorkspace workspace, EditService edits, EditHistoryService history, DecompilerService decompiler, OutputPager pager,
    EditJournal? journal = null, ResultStore? results = null)
{
    [McpServerTool(Name = "rename_symbol", Title = "Rename symbol", UseStructuredContent = true, OutputSchemaType = typeof(EditResult))]
    [Description("Rename a type, method, field, property (with its accessors) or event in memory. Other assemblies referencing the old name are not updated.")]
    public Task<string> RenameSymbol(
        [Description(SymbolDescription)] string symbol,
        [Description("New name (for a type: the simple name without namespace).")] string newName,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description("Restrict symbol resolution to this kind.")] string? kind = null,
        [Description(DryRunDefaultTrueDescription)] bool dryRun = true,
        CancellationToken cancellationToken = default) => Edit(workspace, dryRun, () =>
    {
        var sym = SymbolResolver.ResolveOne(workspace, assembly, symbol, SymbolResolver.ParseKind(kind));
        var (label, before) = (sym.Label, sym.Member.Name.String);
        return Outcome(sym.Assembly, dryRun, () => edits.Rename(sym, newName, dryRun), _ => [new EditChange("rename", label, before, newName)]);
    }, cancellationToken);

    [McpServerTool(Name = "rename_namespace", Title = "Rename namespace", UseStructuredContent = true, OutputSchemaType = typeof(EditResult))]
    [Description("Move every type of a namespace (optionally its sub-namespaces) to a new namespace, in memory.")]
    public Task<string> RenameNamespace(
        [Description(AssemblyDescription)] string assembly,
        [Description("Existing namespace ('' for the global namespace).")] string oldNamespace,
        [Description("New namespace.")] string newNamespace,
        [Description("Also rewrite namespaces that start with oldNamespace + '.'.")] bool includeSubNamespaces = false,
        [Description(DryRunDefaultTrueDescription)] bool dryRun = true,
        CancellationToken cancellationToken = default) => Edit(workspace, dryRun, () =>
    {
        var asm = workspace.Get(assembly);
        return Outcome(asm, dryRun, () => edits.RenameNamespace(asm, oldNamespace, newNamespace, includeSubNamespaces, dryRun),
            _ => [new EditChange("namespace", oldNamespace.Length == 0 ? "(global)" : oldNamespace, oldNamespace, newNamespace)]);
    }, cancellationToken);

    [McpServerTool(Name = "stub_method", Title = "Stub method (return constant)", UseStructuredContent = true, OutputSchemaType = typeof(EditResult))]
    [Description("Replace a method's body with 'return <value>;' (or 'return;' for void) in memory: force a check to return true, disable a call.")]
    public Task<string> StubMethod(
        [Description(SymbolDescription)] string method,
        [Description("true/false, an integer (decimal or 0x hex), a float, a \"quoted string\" or null; omit for void or default(T).")] string? value = null,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description(DryRunDefaultTrueDescription)] bool dryRun = true,
        CancellationToken cancellationToken = default) => Edit(workspace, dryRun, () =>
    {
        var sym = SymbolResolver.ResolveOne(workspace, assembly, method, SymbolKind.Method);
        return Outcome(sym.Assembly, dryRun, () => edits.StubMethod(sym, value, dryRun), _ => [new EditChange("body", sym.Label, After: $"return {value ?? "default"};")]);
    }, cancellationToken);

    [McpServerTool(Name = "patch_method_csharp", Title = "Replace method body with C#", UseStructuredContent = true, OutputSchemaType = typeof(EditResult))]
    [Description("Replace a method's body (methods, constructors, accessors) with C# compiled against the assembly; private members accessible, " +
                 "lambdas, LINQ, async and yield work. Errors name lines of your code.")]
    public Task<string> PatchMethodCSharp(
        [Description(SymbolDescription)] string method,
        [Description("The new body's statements only.")] string code,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description("Default true: preview the IL that would be written; pass dryRun=false to apply.")] bool dryRun = true,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => WithProgress(context, () => Edit(workspace, dryRun, () =>
    {
        var sym = SymbolResolver.ResolveOne(workspace, assembly, method, SymbolKind.Method);
        return Outcome(sym.Assembly, dryRun, () =>
        {
            var result = edits.PatchMethodCSharp(sym, code, dryRun, cancellationToken);
            return dryRun ? result : $"{result}\n\nDecompiled result:\n{decompiler.DecompileMembers(sym.Assembly, [sym.Member], cancellationToken)}";
        }, _ => [new EditChange("body", sym.Label)]);
    }, cancellationToken));

    [McpServerTool(Name = "add_members_csharp", Title = "Add members to a type (C#)", UseStructuredContent = true, OutputSchemaType = typeof(EditResult))]
    [Description("Add C# members (methods, fields, properties, events, constructors, nested types) to a class or struct; private members accessible. " +
                 "No field or property initializers.")]
    public Task<string> AddMembersCSharp(
        [Description("The type to extend. " + SymbolDescription)] string type,
        [Description("C# member declarations.")] string code,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description(DryRunDefaultTrueDescription)] bool dryRun = true,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => WithProgress(context, () => Edit(workspace, dryRun, () =>
    {
        var sym = SymbolResolver.ResolveOne(workspace, assembly, type, SymbolKind.Type);
        return Outcome(sym.Assembly, dryRun, () => edits.AddMembersCSharp(sym, code, dryRun, cancellationToken), Touched("member", sym.Label));
    }, cancellationToken));

    [McpServerTool(Name = "add_types_csharp", Title = "Add new types (C#)", UseStructuredContent = true, OutputSchemaType = typeof(EditResult))]
    [Description("Add C# types (with their namespace) to an assembly; they can use its internal types, and patch_method_csharp can call them.")]
    public Task<string> AddTypesCSharp(
        [Description(AssemblyDescription)] string assembly,
        [Description("C# source declaring the new types.")] string code,
        [Description(DryRunDefaultTrueDescription)] bool dryRun = true,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => WithProgress(context, () => Edit(workspace, dryRun, () =>
    {
        var asm = workspace.Get(assembly);
        return Outcome(asm, dryRun, () => edits.AddTypesCSharp(asm, code, dryRun, cancellationToken), Touched("type", asm.Id));
    }, cancellationToken));

    [McpServerTool(Name = "list_edits", Title = "List unsaved edits", UseStructuredContent = true, OutputSchemaType = typeof(EditList))]
    [Description("Unsaved edits of an assembly in order; each number (editId <assembly>#<n>) stays when other edits are undone.")]
    public Task<string> ListEdits(
        [Description(AssemblyDescription)] string assembly,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description("Max rows (default 200).")] int limit = 200,
        [Description(MaxTokensDescription)] int? maxTokens = null,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var asm = workspace.Get(assembly);
        var rows = asm.Edits.Select(e => new EditListItem(e.Number, new EditId(asm.Id, e.Number).ToString(), e.Kind, e.Description)).ToList();
        return ToolOutput.List(rows, offset, ClampLimit(limit), r => $"#{r.Number}  {r.Tool,-20} {r.Description}",
            page => new EditList(asm.Id, page, Math.Max(0, offset), rows.Count), "edit",
            rows.Count == 0 ? $"{asm.Id} has no unsaved edits.\n" : $"{asm.Id}, in order (undo_edit and diff_edits take the number):\n");
    }, cancellationToken);

    [McpServerTool(Name = "undo_edit", Title = "Undo an edit", UseStructuredContent = true, OutputSchemaType = typeof(EditResult))]
    [Description("Undo the last edit or one by number: the others are replayed on the original image; a conflict changes nothing.")]
    public Task<string> UndoEdit(
        [Description(AssemblyDescription)] string assembly,
        [Description("Edit number from list_edits (the #n of its editId); omit for the last.")] int? number = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => WithProgress(context, () => Write(workspace, () =>
    {
        var asm = workspace.Get(assembly);
        var text = edits.Undo(asm, number, cancellationToken, out var removed);
        var id = new EditId(asm.Id, removed.Number);
        return ToolOutput.Edit(new EditOutcome(true, false, [new EditChange("undo", id.ToString(), removed.Description)], [id]), $"[{asm.Id}] {text}");
    }, cancellationToken));

    [McpServerTool(Name = "revert_edits", Title = "Discard all edits", UseStructuredContent = true, OutputSchemaType = typeof(EditResult))]
    [Description("Discard every unsaved edit of an assembly; resultId keeps them as a script (read_result outputPath=x.json, apply_edits path=x.json).")]
    public Task<string> RevertEdits([Description(AssemblyDescription)] string assembly, CancellationToken cancellationToken = default) =>
        Write(workspace, () =>
        {
            var asm = workspace.Get(assembly);
            var discarded = asm.Edits.Select(e => new EditId(asm.Id, e.Number)).ToList();
            var script = asm.Edits.Count == 0 || results == null ? null
                : results.Keep(EditHistoryService.Serialize(history.BuildScript(asm)), new KeptOrigin("revert_edits", asm.Id, null, [new KeptInput(asm.Id, asm.OriginalSha256)]));
            var text = edits.RevertAll(asm, cancellationToken);
            if (script != null) text += $"\nThe discarded edits are kept as an edit script: read_result id={script} outputPath=<file>.json, then apply_edits path=<file>.json dryRun=false.";
            return ToolOutput.Edit(new EditOutcome(true, false, discarded.Select(d => new EditChange("undo", d.ToString())).ToList(), discarded) { ResultId = script },
                $"[{asm.Id}] {text}");
        }, cancellationToken);

    [McpServerTool(Name = "diff_edits", Title = "Diff edits (before/after C#)", UseStructuredContent = true, OutputSchemaType = typeof(TextPageRecord))]
    [Description("Unified diff of the decompiled C# of every member the edits touched (or one edit's), before and after. Review before save_assembly.")]
    public Task<string> DiffEdits(
        [Description(AssemblyDescription)] string assembly,
        [Description("Only this edit (number from list_edits).")] int? number = null,
        [Description(CharOffsetDescription)] int offset = 0,
        [Description(MaxTokensDescription)] int? maxTokens = null,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
        {
            var (text, complete) = history.Diff(workspace.Get(assembly), number, Math.Max(0, offset) + pager.MaxChars(maxTokens), cancellationToken);
            return pager.Page(text, offset, maxTokens, complete);
        }, cancellationToken);

    [McpServerTool(Name = "export_edits", Title = "Export edits as a script", UseStructuredContent = true, OutputSchemaType = typeof(EditHistoryService.ExportedEdits))]
    [Description("Save an assembly's edits as a JSON script bound to its build (SHA-256, MVID) for apply_edits.")]
    public Task<string> ExportEdits(
        [Description(AssemblyDescription)] string assembly,
        [Description("Output .json path.")] string outputPath,
        [Description("Replace outputPath if it exists.")] bool overwrite = false,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
        {
            var text = history.Export(workspace.Get(assembly), outputPath, overwrite, out var exported);
            return ToolOutput.Report(text, exported);
        }, cancellationToken);

    [McpServerTool(Name = "apply_edits", Title = "Apply an edit script", UseStructuredContent = true, OutputSchemaType = typeof(EditOutcome))]
    [Description("Replay an export_edits script, each edit with its outcome. Another build needs targetBuild=other: symbols by name, renames followed when " +
                 "the source build is loaded.")]
    public Task<string> ApplyEdits(
        [Description("The .json edit script.")] string path,
        [Description("Target assembly; omit for the one named in the script.")] string? assembly = null,
        [Description("Default true: apply every edit (compiled, stack-checked), report, roll back; pass dryRun=false to keep them.")] bool dryRun = true,
        [Description("Roll everything back on the first failure.")] bool stopOnError = true,
        [Description("same: only the script's build; other: another build, symbols re-resolved by name.")] string targetBuild = "same",
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => WithProgress(context, () => Write(workspace, () => // dry runs apply and roll back, so they also need the write lock
    {
        var run = history.Run(path, assembly, dryRun, stopOnError, cancellationToken, EditHistoryService.ParseTargetBuild(targetBuild));
        // A failure that rolled everything back, or a script whose every edit failed, applied nothing: an error with each edit's outcome.
        if (run.Items.Count > 0 && (run.RolledBack || run.Failed == run.Items.Count))
        {
            var first = run.Items.First(i => i.Error != null);
            throw new ToolError(ErrorCode.Failed,
                $"{(run.RolledBack ? $"Edit #{first.Index} failed and the script was rolled back" : $"All {run.Items.Count} edit(s) failed")}; nothing was applied. " +
                $"#{first.Index} ({first.Description}): {first.Error!.Message}",
                $"fix edit #{first.Index} of {Path.GetFileName(path)}{(run.RolledBack ? ", or pass stopOnError=false to apply the others" : "")}; then call apply_edits again")
            {
                Partial = new { applied = 0, failed = run.Failed, rolledBack = run.RolledBack, items = run.Items },
            };
        }
        if (!dryRun) journal?.Replayed(path);
        var ids = run.Items.Where(i => i.EditId != null).Select(i => EditId.TryParse(i.EditId, out var id) ? id : default).ToList();
        var changes = run.Items.Where(i => i.Error == null).Select(i => new EditChange("replay", i.Description)).ToList();
        return ToolOutput.Edit(new EditOutcome(!dryRun, dryRun, changes, ids) { Failed = run.Failed, Items = [.. run.Items] }, run.Report);
    }, cancellationToken));

    [McpServerTool(Name = "patch_method_il", Title = "Rewrite method body in IL", UseStructuredContent = true, OutputSchemaType = typeof(EditResult))]
    [Description("Rewrite a method body from IL text (stack-validated): edit get_il's lines and pass them back (syntax: guide edits). " +
                 "replace swaps the body; prepend runs before it and can branch to its IL_xxxx labels.")]
    public Task<string> PatchMethodIL(
        [Description(SymbolDescription)] string method,
        [Description("IL instructions, one per line.")] string il,
        [Description("replace or prepend.")] string mode = "replace",
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description(DryRunDefaultTrueDescription)] bool dryRun = true,
        CancellationToken cancellationToken = default) => Edit(workspace, dryRun, () =>
    {
        var sym = SymbolResolver.ResolveOne(workspace, assembly, method, SymbolKind.Method);
        return Outcome(sym.Assembly, dryRun, () => edits.PatchMethodIL(sym, il, mode, dryRun), _ => [new EditChange("body", sym.Label)]);
    }, cancellationToken);

    [McpServerTool(Name = "simplify_methods", Title = "Simplify method bodies", UseStructuredContent = true, OutputSchemaType = typeof(EditResult))]
    [Description("Clean transformed method bodies: fold (string decoders with constant inputs run in a safe IL interpreter), cfg (constant branches, " +
                 "dead code, flattened control flow), inline (forwarders, delegate call proxies). Bodies are stack-verified; what is left has a reason " +
                 "code (docs/simplify.md).")]
    public Task<string> SimplifyMethods(
        [Description("A method, or a type (nested types included). " + SymbolDescription + " Omit for the whole assembly.")] string? symbol = null,
        [Description(AssemblyFilterDescription + " Required when symbol is omitted.")] string? assembly = null,
        [Description("Passes to run; omit for all three.")] string[]? passes = null,
        [Description("Max evaluation call depth.")] int maxDepth = 8,
        [Description("Max IL instructions per evaluated call, nested calls included.")] int budget = 100_000,
        [Description(DryRunDefaultTrueDescription)] bool dryRun = true,
        [Description("Fold machine reads (paths, environment, names) against fixed stand-ins (docs/simplify.md).")]
        bool deterministicEnvironment = false,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => WithProgress(context, () => Edit(workspace, dryRun, () =>
    {
        var options = SimplifyOptions.Parse(passes == null ? null : string.Join(",", passes), maxDepth, budget, deterministicEnvironment);
        ResolvedSymbol? sym = null;
        LoadedAssembly asm;
        if (string.IsNullOrWhiteSpace(symbol))
        {
            if (string.IsNullOrWhiteSpace(assembly))
                throw new ToolError(ErrorCode.InvalidArgument, "Pass a method or type, or an assembly to simplify all of its methods.");
            asm = workspace.Get(assembly);
        }
        else
        {
            sym = SymbolResolver.ResolveOne(workspace, assembly, symbol);
            asm = sym.Assembly;
        }
        return Outcome(asm, dryRun, () => edits.SimplifyMethods(asm, sym, options, dryRun, cancellationToken), Touched("body", sym?.Label ?? asm.Id));
    }, cancellationToken));

    [McpServerTool(Name = "save_assembly", Title = "Save patched assembly", UseStructuredContent = true, OutputSchemaType = typeof(EditService.SavedFile))]
    [Description("Write an assembly with its edits to a new file, atomically (overwrite=true keeps a .bak; a file changed since load is refused). " +
                 "Untouched bodies keep their bytes; members the writer changed are listed with reason codes (docs/saving.md).")]
    public Task<string> SaveAssembly(
        [Description(AssemblyDescription)] string assembly,
        [Description("Output file path; a .wasm path writes Webcil (Blazor). Omit for '<original>.patched.dll'.")] string? outputPath = null,
        [Description("Allow replacing an existing file.")] bool overwrite = false,
        [Description("Write nothing when any member would be changed by the writer (default: save and list them).")] bool strict = false,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var asm = workspace.Get(assembly);
        var report = edits.Save(asm, outputPath, overwrite, strict, out var saved);
        journal?.Saved(asm);
        return ToolOutput.Report(report, saved);
    }, cancellationToken);

    /// <summary>
    /// Runs an edit and returns its outcome: the edits it recorded (none for a dry run), the changes <paramref name="changes"/>
    /// names (given the edits recorded), and the text with the edit ids and the pending count, or how to apply a preview.
    /// </summary>
    private static string Outcome(LoadedAssembly asm, bool dryRun, Func<string> edit, Func<IReadOnlyList<EditRecord>, IReadOnlyList<EditChange>> changes)
    {
        int before = asm.Edits.Count;
        var text = edit();
        var recorded = dryRun ? [] : asm.Edits.Skip(before).ToList();
        var ids = recorded.Select(e => new EditId(asm.Id, e.Number)).ToList();
        var tail = dryRun ? "\nNothing changed (dry run); pass dryRun=false to apply."
            : ids.Count == 0 ? $"\nNo edit recorded. Unsaved edits in {asm.Id}: {asm.Edits.Count}."
            : $"\nEdit {string.Join(", ", ids)}. Unsaved edits in {asm.Id}: {asm.Edits.Count}.";
        return ToolOutput.Edit(new EditOutcome(!dryRun && ids.Count > 0, dryRun, dryRun || ids.Count > 0 ? changes(recorded) : [], ids), $"[{asm.Id}] {text}{tail}");
    }

    /// <summary>Runs a long call with progress: one report at once (before any lock wait), then the phases its services report.</summary>
    internal static Task<string> WithProgress(RequestContext<CallToolRequestParams>? context, Func<Task<string>> run) =>
        OrderedProgress.Run(context!, async progress =>
        {
            progress.Report(new ProgressNotificationValue { Progress = 0, Message = "started" });
            using var scope = CallProgress.Begin((done, total, message) => progress.Report(new ProgressNotificationValue { Progress = done, Total = total, Message = message }));
            return await run();
        });

    /// <summary>The members an edit recorded as touched, or <paramref name="scope"/> for a preview.</summary>
    private static Func<IReadOnlyList<EditRecord>, IReadOnlyList<EditChange>> Touched(string kind, string scope) => recorded =>
        recorded.Count == 0 ? [new EditChange(kind, scope)] : recorded.SelectMany(e => e.Touched).Select(t => new EditChange(kind, t)).ToList();
}

/// <summary>One unsaved edit: its number, id and the tool that made it (diff_edits shows the members it touched).</summary>
public sealed record EditListItem(int Number, string EditId, string Tool, string Description);

public sealed record EditList(string Assembly, IReadOnlyList<EditListItem> Items, int Offset, int Total);

/// <summary>
/// The output schema of the single edits: the fields of <see cref="EditOutcome"/> a caller acts on (the record carries the
/// rest); kept small because every tool's schema is sent in tools/list.
/// </summary>
public sealed record EditResult(bool Applied, bool DryRun, IReadOnlyList<EditResult.Change> Changes, IReadOnlyList<string> EditIds)
{
    public sealed record Change(string Kind, string Target);

    /// <summary>Batch items that failed (engine declarations); absent otherwise.</summary>
    public int? Failed { get; init; }
}
