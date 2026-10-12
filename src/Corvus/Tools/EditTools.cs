using System.ComponentModel;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Services;
using Corvus.Services.Simplify;
using static Corvus.Tools.ToolSupport;

namespace Corvus.Tools;

/// <summary>
/// In-memory edits: visible immediately in decompile/IL/search output, written to disk only by save_assembly.
/// </summary>
[McpServerToolType]
public sealed class EditTools(AssemblyWorkspace workspace, EditService edits, EditHistoryService history, DecompilerService decompiler, OutputPager pager,
    EditJournal? journal = null)
{
    [McpServerTool(Name = "rename_symbol", Title = "Rename symbol")]
    [Description("Rename a type, method, field, property (with its accessors) or event in memory. Other assemblies referencing the old name are not updated.")]
    public Task<string> RenameSymbol(
        [Description(SymbolDescription)] string symbol,
        [Description("New name (for a type: the simple name without namespace).")] string newName,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description("Restrict symbol resolution to this kind.")] string? kind = null,
        [Description(DryRunDescription)] bool dryRun = false,
        CancellationToken cancellationToken = default) => Edit(workspace, dryRun, () =>
    {
        var sym = SymbolResolver.ResolveOne(workspace, assembly, symbol, SymbolResolver.ParseKind(kind));
        return $"[{sym.Assembly.Id}] {edits.Rename(sym, newName, dryRun)}{Pending(sym.Assembly, dryRun)}";
    }, cancellationToken);

    [McpServerTool(Name = "rename_namespace", Title = "Rename namespace")]
    [Description("Move every type of a namespace (optionally its sub-namespaces) to a new namespace, in memory.")]
    public Task<string> RenameNamespace(
        [Description(AssemblyDescription)] string assembly,
        [Description("Existing namespace ('' for the global namespace).")] string oldNamespace,
        [Description("New namespace.")] string newNamespace,
        [Description("Also rewrite namespaces that start with oldNamespace + '.'.")] bool includeSubNamespaces = false,
        [Description(DryRunDescription)] bool dryRun = false,
        CancellationToken cancellationToken = default) => Edit(workspace, dryRun, () =>
    {
        var asm = workspace.Get(assembly);
        return $"[{asm.Id}] {edits.RenameNamespace(asm, oldNamespace, newNamespace, includeSubNamespaces, dryRun)}{Pending(asm, dryRun)}";
    }, cancellationToken);

    [McpServerTool(Name = "stub_method", Title = "Stub method (return constant)")]
    [Description("Replace a method's body with 'return <value>;' (or 'return;' for void) in memory: force a check to return true, disable a call.")]
    public Task<string> StubMethod(
        [Description(SymbolDescription)] string method,
        [Description("true/false, an integer (decimal or 0x hex), a float, a \"quoted string\" or null; omit for void or default(T).")] string? value = null,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description(DryRunDescription)] bool dryRun = false,
        CancellationToken cancellationToken = default) => Edit(workspace, dryRun, () =>
    {
        var sym = SymbolResolver.ResolveOne(workspace, assembly, method, SymbolKind.Method);
        return $"[{sym.Assembly.Id}] {edits.StubMethod(sym, value, dryRun)}{Pending(sym.Assembly, dryRun)}";
    }, cancellationToken);

    [McpServerTool(Name = "patch_method_csharp", Title = "Replace method body with C#")]
    [Description("Replace a method's body with C# statements compiled against the assembly and its references (private / internal members accessible). " +
                 "Methods, constructors and accessors; lambdas, LINQ, local functions, async and yield work. Compile errors give lines relative to your code. " +
                 "Returns the decompiled result.")]
    public Task<string> PatchMethodCSharp(
        [Description(SymbolDescription)] string method,
        [Description("The new body's statements only.")] string code,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description(DryRunDescription + " Shows the IL that would be written.")] bool dryRun = false,
        CancellationToken cancellationToken = default) => Edit(workspace, dryRun, () =>
    {
        var sym = SymbolResolver.ResolveOne(workspace, assembly, method, SymbolKind.Method);
        var result = edits.PatchMethodCSharp(sym, code, dryRun, cancellationToken);
        if (dryRun) return $"[{sym.Assembly.Id}] {result}";
        var after = decompiler.DecompileMembers(sym.Assembly, [sym.Member], cancellationToken);
        return $"[{sym.Assembly.Id}] {result}{Pending(sym.Assembly, dryRun)}\n\nDecompiled result:\n{after}";
    }, cancellationToken);

    [McpServerTool(Name = "add_members_csharp", Title = "Add members to a type (C#)")]
    [Description("Add members written in C# to an existing class or struct: methods, fields, properties, events, constructors, nested types; " +
                 "compiled against the assembly (private / internal members accessible). Field and property initializers are not supported (initialize from a method).")]
    public Task<string> AddMembersCSharp(
        [Description("The type to extend. " + SymbolDescription)] string type,
        [Description("C# member declarations.")] string code,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description(DryRunDescription)] bool dryRun = false,
        CancellationToken cancellationToken = default) => Edit(workspace, dryRun, () =>
    {
        var sym = SymbolResolver.ResolveOne(workspace, assembly, type, SymbolKind.Type);
        return $"[{sym.Assembly.Id}] {edits.AddMembersCSharp(sym, code, dryRun, cancellationToken)}{Pending(sym.Assembly, dryRun)}";
    }, cancellationToken);

    [McpServerTool(Name = "add_types_csharp", Title = "Add new types (C#)")]
    [Description("Add classes, structs, interfaces, enums or delegates written in C# (with their namespace) to an assembly; they can use its private / internal types. " +
                 "patch_method_csharp then calls into them from existing methods.")]
    public Task<string> AddTypesCSharp(
        [Description(AssemblyDescription)] string assembly,
        [Description("C# source declaring the new types.")] string code,
        [Description(DryRunDescription)] bool dryRun = false,
        CancellationToken cancellationToken = default) => Edit(workspace, dryRun, () =>
    {
        var asm = workspace.Get(assembly);
        return $"[{asm.Id}] {edits.AddTypesCSharp(asm, code, dryRun, cancellationToken)}{Pending(asm, dryRun)}";
    }, cancellationToken);

    [McpServerTool(Name = "list_edits", Title = "List unsaved edits")]
    [Description("The unsaved edits of an assembly, numbered in order (for undo_edit and diff_edits).")]
    public Task<string> ListEdits([Description(AssemblyDescription)] string assembly, CancellationToken cancellationToken = default) =>
        Read(workspace, () => history.List(workspace.Get(assembly)), cancellationToken);

    [McpServerTool(Name = "undo_edit", Title = "Undo an edit")]
    [Description("Undo the last edit or any earlier one by number: the remaining edits are re-applied to the original image; " +
                 "if one depended on the undone edit, nothing changes and the conflict is reported.")]
    public Task<string> UndoEdit(
        [Description(AssemblyDescription)] string assembly,
        [Description("Edit number from list_edits; omit for the last.")] int? number = null,
        CancellationToken cancellationToken = default) => Write(workspace, () =>
            edits.Undo(workspace.Get(assembly), number, cancellationToken), cancellationToken);

    [McpServerTool(Name = "revert_edits", Title = "Discard all edits")]
    [Description("Discard every unsaved edit of an assembly (export_edits first keeps them as a script).")]
    public Task<string> RevertEdits([Description(AssemblyDescription)] string assembly, CancellationToken cancellationToken = default) =>
        Write(workspace, () => edits.RevertAll(workspace.Get(assembly), cancellationToken), cancellationToken);

    [McpServerTool(Name = "diff_edits", Title = "Diff edits (before/after C#)")]
    [Description("Unified diff of the decompiled C# of every member the edits touched (or one edit's), before and after. Review before save_assembly.")]
    public Task<string> DiffEdits(
        [Description(AssemblyDescription)] string assembly,
        [Description("Only this edit (number from list_edits).")] int? number = null,
        [Description(OffsetDescription)] int offset = 0,
        [Description(MaxCharsDescription)] int? maxChars = null,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
        {
            var (text, complete) = history.Diff(workspace.Get(assembly), number, Math.Max(0, offset) + pager.MaxChars(maxChars), cancellationToken);
            return pager.Page(text, offset, maxChars, complete);
        }, cancellationToken);

    [McpServerTool(Name = "export_edits", Title = "Export edits as a script")]
    [Description("Save an assembly's edits as a JSON edit script bound to its build (SHA-256, MVID, identity), for apply_edits on that build or, " +
                 "with targetBuild=other, on another one.")]
    public Task<string> ExportEdits(
        [Description(AssemblyDescription)] string assembly,
        [Description("Output .json path.")] string path,
        [Description("Replace path if it exists.")] bool overwrite = false,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
            history.Export(workspace.Get(assembly), path, overwrite), cancellationToken);

    [McpServerTool(Name = "apply_edits", Title = "Apply an edit script")]
    [Description("Replay a JSON edit script (export_edits) onto an assembly; each edit reports ok/FAILED. On its own build recorded tokens are used; another build is " +
                 "refused unless targetBuild=other, which re-resolves symbols by name (following renames when the source build is loaded) and lists what was remapped. " +
                 "Scripts without a build binding apply with a warning.")]
    public Task<string> ApplyEdits(
        [Description("The .json edit script.")] string path,
        [Description("Target assembly; omit for the one named in the script.")] string? assembly = null,
        [Description("Apply every edit for real (compiled, stack-checked), report, then roll back.")] bool dryRun = false,
        [Description("Roll everything back on the first failure.")] bool stopOnError = true,
        [Description("same: only the script's build; other: another build, symbols re-resolved by name.")] string targetBuild = "same",
        CancellationToken cancellationToken = default) => Write(workspace, () => // dry runs apply and roll back, so they also need the write lock
    {
        var report = history.Apply(path, assembly, dryRun, stopOnError, cancellationToken, EditHistoryService.ParseTargetBuild(targetBuild));
        if (!dryRun) journal?.Replayed(path);
        return report;
    }, cancellationToken);

    [McpServerTool(Name = "patch_method_il", Title = "Rewrite method body in IL")]
    [Description("Rewrite a method body from IL text, in memory (stack-validated first). Easiest: edit get_il's lines and pass them back (header lines ignored; " +
                 "/* token */ comments resolve operands exactly). Lines: '[label:] opcode [operand]'; operands are numbers, \"strings\", labels, switch (L1, L2), " +
                 "arg / local index or name, members ('Ns.Type::Method(int)') or tokens; '.local <type>' adds a local. " +
                 "mode=replace swaps the whole body (no try/catch); prepend inserts before the original code and can branch to its IL_xxxx labels.")]
    public Task<string> PatchMethodIL(
        [Description(SymbolDescription)] string method,
        [Description("IL instructions, one per line.")] string il,
        [Description("replace or prepend.")] string mode = "replace",
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description(DryRunDescription)] bool dryRun = false,
        CancellationToken cancellationToken = default) => Edit(workspace, dryRun, () =>
    {
        var sym = SymbolResolver.ResolveOne(workspace, assembly, method, SymbolKind.Method);
        return $"[{sym.Assembly.Id}] {edits.PatchMethodIL(sym, il, mode, dryRun)}{Pending(sym.Assembly, dryRun)}";
    }, cancellationToken);

    [McpServerTool(Name = "simplify_methods", Title = "Simplify method bodies")]
    [Description("Compiler-style cleanup of method bodies in memory, for transformed code. Passes: fold (string decoder calls with constant inputs run in a " +
                 "safe IL interpreter and become literals), cfg (constant branches and switches, dead code, flattened control flow made sequential), " +
                 "inline (forwarders and static delegate call proxies call their real target). Each body is stack-verified or left unchanged; " +
                 "everything left alone is reported with a reason code (guide edits topic, docs/simplify.md). 5 s and 16 MB simulated memory per method. " +
                 "Preview without editing: decompile_member / decompile_type simplified=true.")]
    public Task<string> SimplifyMethods(
        [Description("A method, or a type (nested types included). " + SymbolDescription + " Omit for the whole assembly.")] string? symbol = null,
        [Description(AssemblyFilterDescription + " Required when symbol is omitted.")] string? assembly = null,
        [Description("Comma-separated passes: fold, cfg, inline (default: all).")] string? passes = null,
        [Description("Max evaluation call depth (default 8).")] int? maxDepth = null,
        [Description("Max IL instructions per evaluated call, nested calls included (default 100000).")] int? budget = null,
        [Description(DryRunDescription)] bool dryRun = false,
        [Description("Evaluate machine reads (module path, directories, special folders, environment, machine / user names) against fixed stand-ins " +
                     "(docs/simplify.md), so code depending on them folds; results then hold for that environment. Without it they are reported (external-io).")] bool deterministicEnvironment = false,
        CancellationToken cancellationToken = default) => Edit(workspace, dryRun, () =>
    {
        var options = SimplifyOptions.Parse(passes, maxDepth, budget, deterministicEnvironment);
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
        return $"[{asm.Id}] {edits.SimplifyMethods(asm, sym, options, dryRun, cancellationToken)}{Pending(asm, dryRun)}";
    }, cancellationToken);

    [McpServerTool(Name = "save_assembly", Title = "Save patched assembly")]
    [Description("Write an assembly with its edits to a new file, atomically. Overwriting needs overwrite=true; the original is first copied to '<file>.bak', " +
                 "and one changed on disk since load is refused. Bodies and signatures no edit touched keep their original bytes; the result lists, with reason " +
                 "codes (docs/saving.md), members 'Changed by the writer' without an edit asking for it and those 'Kept byte-for-byte although invalid in the original'.")]
    public Task<string> SaveAssembly(
        [Description(AssemblyDescription)] string assembly,
        [Description("Output file path; a .wasm path writes Webcil (Blazor). Omit for '<original>.patched.dll'.")] string? outputPath = null,
        [Description("Allow replacing an existing file.")] bool overwrite = false,
        [Description("Write nothing when any member would be changed by the writer (default: save and list them).")] bool strict = false,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var asm = workspace.Get(assembly);
        var report = edits.Save(asm, outputPath, overwrite, strict);
        journal?.Saved(asm);
        return report;
    }, cancellationToken);

    private static string Pending(LoadedAssembly asm, bool dryRun) => dryRun ? "" : $"\nUnsaved edits in {asm.Id}: {asm.Edits.Count}.";
}
