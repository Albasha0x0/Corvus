using System.ComponentModel;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Services;
using static NetDecompilerMcp.Tools.ToolSupport;

namespace NetDecompilerMcp.Tools;

/// <summary>
/// In-memory edits: visible immediately in decompile/IL/search output, written to disk only by save_assembly.
/// </summary>
[McpServerToolType]
public sealed class EditTools(AssemblyWorkspace workspace, EditService edits, EditHistoryService history, DecompilerService decompiler, OutputPager pager)
{
    [McpServerTool(Name = "rename_symbol", Title = "Rename symbol", Destructive = false, OpenWorld = false)]
    [Description("Rename a type, method, field, property (with its accessors) or event in memory — e.g. to give obfuscated names meaning. Other assemblies that reference the old name are not updated.")]
    public Task<string> RenameSymbol(
        [Description(SymbolDescription)] string symbol,
        [Description("New name (for a type: the simple name without namespace).")] string newName,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description("Restrict symbol resolution to: type, method, field, property, event.")] string? kind = null,
        [Description(DryRunDescription)] bool dryRun = false,
        CancellationToken cancellationToken = default) => Edit(workspace, dryRun, () =>
    {
        var sym = SymbolResolver.ResolveOne(workspace, assembly, symbol, SymbolResolver.ParseKind(kind));
        return $"[{sym.Assembly.Id}] {edits.Rename(sym, newName, dryRun)}{Pending(sym.Assembly, dryRun)}";
    }, cancellationToken);

    [McpServerTool(Name = "rename_namespace", Title = "Rename namespace", Destructive = false, OpenWorld = false)]
    [Description("Move every type in a namespace (optionally including sub-namespaces) to a new namespace, in memory.")]
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

    [McpServerTool(Name = "stub_method", Title = "Stub method (return constant)", Destructive = false, OpenWorld = false)]
    [Description("Replace a method's body with 'return <value>;' (or 'return;' for void) in memory — force a check to return true, disable a call. " +
                 "value: true/false, an integer (decimal or 0x hex), a float, a \"quoted string\", null, or default (omit).")]
    public Task<string> StubMethod(
        [Description("Method. " + SymbolDescription)] string method,
        [Description("Return value; omit for void methods or default(T).")] string? value = null,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description(DryRunDescription)] bool dryRun = false,
        CancellationToken cancellationToken = default) => Edit(workspace, dryRun, () =>
    {
        var sym = SymbolResolver.ResolveOne(workspace, assembly, method, SymbolKind.Method);
        return $"[{sym.Assembly.Id}] {edits.StubMethod(sym, value, dryRun)}{Pending(sym.Assembly, dryRun)}";
    }, cancellationToken);

    [McpServerTool(Name = "patch_method_csharp", Title = "Replace method body with C#", Destructive = false, OpenWorld = false)]
    [Description("Replace a method's body with C# statements, compiled against the assembly and its references (private/internal members are accessible, like in dnSpy's Edit Method). " +
                 "Pass only the body (statements), e.g. 'if (amount < 0) return; _health -= amount;'. Works for methods, constructors and property/indexer/event accessors. " +
                 "Lambdas, LINQ, local functions, async/await and yield work: the compiler-generated helpers are copied into the assembly. " +
                 "Compile errors are reported with line numbers relative to your code. Returns the decompiled result. Persisted only by save_assembly.")]
    public Task<string> PatchMethodCSharp(
        [Description("Method. " + SymbolDescription)] string method,
        [Description("C# statements forming the new body.")] string code,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description(DryRunDescription + " Compiles and shows the IL that would be written.")] bool dryRun = false,
        CancellationToken cancellationToken = default) => Edit(workspace, dryRun, () =>
    {
        var sym = SymbolResolver.ResolveOne(workspace, assembly, method, SymbolKind.Method);
        var result = edits.PatchMethodCSharp(sym, code, dryRun, cancellationToken);
        if (dryRun) return $"[{sym.Assembly.Id}] {result}";
        var after = decompiler.DecompileMembers(sym.Assembly, [sym.Member], cancellationToken);
        return $"[{sym.Assembly.Id}] {result}{Pending(sym.Assembly, dryRun)}\n\nDecompiled result:\n{after}";
    }, cancellationToken);

    [McpServerTool(Name = "add_members_csharp", Title = "Add members to a type (C#)", Destructive = false, OpenWorld = false)]
    [Description("Add new members written in C# to an existing class or struct: methods (incl. overloads), fields, properties, events, constructors, nested types. " +
                 "Code is compiled against the assembly (private/internal members accessible; lambdas/async/LINQ fine). " +
                 "Example: 'public int Twice(int x) { return x * 2; }  private static int _counter;'. Field/property initializers are not supported (initialize from a method). " +
                 "Persisted only by save_assembly.")]
    public Task<string> AddMembersCSharp(
        [Description("Type to extend. " + SymbolDescription)] string type,
        [Description("C# member declarations.")] string code,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description(DryRunDescription + " Compiles and lists what would be added.")] bool dryRun = false,
        CancellationToken cancellationToken = default) => Edit(workspace, dryRun, () =>
    {
        var sym = SymbolResolver.ResolveOne(workspace, assembly, type, SymbolKind.Type);
        return $"[{sym.Assembly.Id}] {edits.AddMembersCSharp(sym, code, dryRun, cancellationToken)}{Pending(sym.Assembly, dryRun)}";
    }, cancellationToken);

    [McpServerTool(Name = "add_types_csharp", Title = "Add new types (C#)", Destructive = false, OpenWorld = false)]
    [Description("Add new classes, structs, interfaces, enums or delegates written in C# (with their namespace) to an assembly. They can use the assembly's own types, including private/internal ones. " +
                 "Combine with patch_method_csharp to call into the new code from existing methods. Persisted only by save_assembly.")]
    public Task<string> AddTypesCSharp(
        [Description(AssemblyDescription)] string assembly,
        [Description("C# source declaring the new types (e.g. 'namespace Mods { public static class Cheats { ... } }').")] string code,
        [Description(DryRunDescription + " Compiles and lists what would be added.")] bool dryRun = false,
        CancellationToken cancellationToken = default) => Edit(workspace, dryRun, () =>
    {
        var asm = workspace.Get(assembly);
        return $"[{asm.Id}] {edits.AddTypesCSharp(asm, code, dryRun, cancellationToken)}{Pending(asm, dryRun)}";
    }, cancellationToken);

    [McpServerTool(Name = "list_edits", Title = "List unsaved edits", ReadOnly = true, OpenWorld = false)]
    [Description("The unsaved in-memory edits of an assembly, numbered in the order they were applied (numbers are used by undo_edit and diff_edits).")]
    public Task<string> ListEdits([Description(AssemblyDescription)] string assembly, CancellationToken cancellationToken = default) =>
        Read(workspace, () => history.List(workspace.Get(assembly)), cancellationToken);

    [McpServerTool(Name = "undo_edit", Title = "Undo an edit", Destructive = false, OpenWorld = false)]
    [Description("Undo one edit — the last one by default, or any earlier one by number (from list_edits). The assembly is rebuilt from its original image " +
                 "and the remaining edits are re-applied; if one of them depended on the undone edit, nothing changes and the conflict is reported.")]
    public Task<string> UndoEdit(
        [Description(AssemblyDescription)] string assembly,
        [Description("Edit number (1-based, from list_edits). Omit to undo the last edit.")] int? number = null,
        CancellationToken cancellationToken = default) => Write(workspace, () =>
            edits.Undo(workspace.Get(assembly), number, cancellationToken), cancellationToken);

    [McpServerTool(Name = "revert_edits", Title = "Discard all edits", Destructive = true, OpenWorld = false)]
    [Description("Discard every unsaved edit of an assembly (back to the image it was loaded from). Use export_edits first to keep them as a script.")]
    public Task<string> RevertEdits([Description(AssemblyDescription)] string assembly, CancellationToken cancellationToken = default) =>
        Write(workspace, () => edits.RevertAll(workspace.Get(assembly), cancellationToken), cancellationToken);

    [McpServerTool(Name = "diff_edits", Title = "Diff edits (before/after C#)", ReadOnly = true, OpenWorld = false)]
    [Description("Unified diff of the decompiled C# before and after the edits: every member touched by every edit, or one edit by number. Review this before save_assembly.")]
    public Task<string> DiffEdits(
        [Description(AssemblyDescription)] string assembly,
        [Description("Only this edit (1-based, from list_edits). Omit for all edits.")] int? number = null,
        [Description(OffsetDescription)] int offset = 0,
        [Description(MaxCharsDescription)] int? maxChars = null,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
            pager.Page(history.Diff(workspace.Get(assembly), number, cancellationToken), offset, maxChars), cancellationToken);

    [McpServerTool(Name = "export_edits", Title = "Export edits as a script", OpenWorld = false)]
    [Description("Save the edits of an assembly as a JSON edit script. apply_edits can replay it later — e.g. on the next build after an update, where symbols are re-resolved by name.")]
    public Task<string> ExportEdits(
        [Description(AssemblyDescription)] string assembly,
        [Description("Output .json path.")] string path,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
            history.Export(workspace.Get(assembly), path), cancellationToken);

    [McpServerTool(Name = "apply_edits", Title = "Apply an edit script", Destructive = false, OpenWorld = false)]
    [Description("Replay a JSON edit script (from export_edits) onto an assembly. On the same build, recorded tokens are used; on a different build, symbols are re-resolved by name and each edit reports ok/FAILED. " +
                 "dryRun applies every edit for real (C# compiled, IL stack-checked) and then rolls back, so it reports exactly what would fail, with the full compiler errors. " +
                 "With stopOnError (default) a failure rolls the assembly back to its state before the script.")]
    public Task<string> ApplyEdits(
        [Description("Path to the .json edit script.")] string path,
        [Description("Target assembly. Omit to use the assembly named in the script.")] string? assembly = null,
        [Description("Apply and compile every edit, report, then roll back: nothing changes.")] bool dryRun = false,
        [Description("Roll back everything on the first failure (default true).")] bool stopOnError = true,
        CancellationToken cancellationToken = default) => Write(workspace, () => // a dry run applies and rolls back: needs the write lock too
            history.Apply(path, assembly, dryRun, stopOnError, cancellationToken), cancellationToken);

    [McpServerTool(Name = "patch_method_il", Title = "Rewrite method body in IL", Destructive = false, OpenWorld = false)]
    [Description("Rewrite a method body from IL text, in memory. Easiest: get_il the method, edit the instruction lines, pass them back (header lines are ignored; the /* token */ comments resolve operands exactly). " +
                 "Line syntax: '[label:] opcode [operand]'. Operands: numbers, \"strings\", labels, switch (L1, L2), arg/local index or name, members as 'Ns.Type::Method(int, string)' (framework members included) or tokens. '.local <type>' adds a local. " +
                 "mode=replace swaps the whole body (no try/catch); mode=prepend inserts before the original code and can branch to its IL_xxxx labels. Stack-validated before applying.")]
    public Task<string> PatchMethodIL(
        [Description("Method. " + SymbolDescription)] string method,
        [Description("IL instructions, one per line.")] string il,
        [Description("replace (default) or prepend.")] string mode = "replace",
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description(DryRunDescription)] bool dryRun = false,
        CancellationToken cancellationToken = default) => Edit(workspace, dryRun, () =>
    {
        var sym = SymbolResolver.ResolveOne(workspace, assembly, method, SymbolKind.Method);
        return $"[{sym.Assembly.Id}] {edits.PatchMethodIL(sym, il, mode, dryRun)}{Pending(sym.Assembly, dryRun)}";
    }, cancellationToken);

    [McpServerTool(Name = "save_assembly", Title = "Save patched assembly", Destructive = true, OpenWorld = false)]
    [Description("Write an assembly with its in-memory edits to disk. Default output: '<name>.patched.dll' next to the original. " +
                 "Replacing an existing file requires overwrite=true; when that file is the original, it is first copied to '<file>.bak'. Writes atomically.")]
    public Task<string> SaveAssembly(
        [Description(AssemblyDescription)] string assembly,
        [Description("Output file path. Omit for '<original>.patched.dll'.")] string? outputPath = null,
        [Description("Allow replacing an existing file.")] bool overwrite = false,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
            edits.Save(workspace.Get(assembly), outputPath, overwrite), cancellationToken);

    private static string Pending(LoadedAssembly asm, bool dryRun) => dryRun ? "" : $"\nUnsaved edits in {asm.Id}: {asm.Edits.Count}.";
}
