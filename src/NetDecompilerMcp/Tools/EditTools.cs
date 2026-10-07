using System.ComponentModel;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Services;
using static NetDecompilerMcp.Tools.ToolSupport;

namespace NetDecompilerMcp.Tools;

/// <summary>
/// In-memory edits. They show up immediately in decompile/IL output and are written to disk only by save_assembly.
/// </summary>
[McpServerToolType]
public sealed class EditTools(AssemblyWorkspace workspace, EditService edits)
{
    [McpServerTool(Name = "rename_symbol")]
    [Description("Rename a type, method, field, property (and its accessors) or event in memory — e.g. to give obfuscated names meaning. Visible in later decompilation; persisted only by save_assembly. Other assemblies that reference the old name are not updated.")]
    public Task<string> RenameSymbol(
        [Description(SymbolDescription)] string symbol,
        [Description("New name (for a type: the simple name without namespace).")] string newName,
        [Description(AssemblyDescription)] string? assembly = null,
        [Description("Restrict symbol resolution to: type, method, field, property, event.")] string? kind = null,
        [Description("Preview the change without applying it.")] bool dryRun = false,
        CancellationToken cancellationToken = default) => Write(workspace, () =>
    {
        var sym = SymbolResolver.ResolveOne(workspace, assembly, symbol, SymbolResolver.ParseKind(kind));
        return $"[{sym.Assembly.Id}] {edits.Rename(sym, newName, dryRun)}. Unsaved edits: {sym.Assembly.Edits.Count}.";
    }, cancellationToken);

    [McpServerTool(Name = "rename_namespace")]
    [Description("Move every type in a namespace (optionally including sub-namespaces) to a new namespace, in memory.")]
    public Task<string> RenameNamespace(
        [Description("Assembly id, name or path.")] string assembly,
        [Description("Existing namespace ('' for the global namespace).")] string oldNamespace,
        [Description("New namespace.")] string newNamespace,
        [Description("Also rewrite namespaces that start with oldNamespace + '.'.")] bool includeSubNamespaces = false,
        [Description("Preview the change without applying it.")] bool dryRun = false,
        CancellationToken cancellationToken = default) => Write(workspace, () =>
    {
        var asm = workspace.Get(assembly);
        return $"[{asm.Id}] {edits.RenameNamespace(asm, oldNamespace, newNamespace, includeSubNamespaces, dryRun)}.";
    }, cancellationToken);

    [McpServerTool(Name = "stub_method")]
    [Description("Replace a method's body with 'return <value>;' (or 'return;' for void) in memory — e.g. force a check to return true, disable a call. " +
                 "value: true/false, an integer (decimal or 0x hex), a float, a \"quoted string\", null, or default (omit). Persisted only by save_assembly.")]
    public Task<string> StubMethod(
        [Description("Method. " + SymbolDescription)] string method,
        [Description("Return value; omit for void methods or default(T).")] string? value = null,
        [Description(AssemblyDescription)] string? assembly = null,
        [Description("Preview the change without applying it.")] bool dryRun = false,
        CancellationToken cancellationToken = default) => Write(workspace, () =>
    {
        var sym = SymbolResolver.ResolveOne(workspace, assembly, method, SymbolKind.Method);
        return $"[{sym.Assembly.Id}] {edits.StubMethod(sym, value, dryRun)}. Unsaved edits: {sym.Assembly.Edits.Count}.";
    }, cancellationToken);

    [McpServerTool(Name = "patch_method_il")]
    [Description("Rewrite a method body from IL text, in memory. Easiest workflow: get_il the method, edit the instruction lines, pass them back here " +
                 "(header lines are ignored; the /* token */ comments get_il prints resolve operands exactly). " +
                 "Syntax per line: '[label:] opcode [operand]'. Operands: numbers, \"strings\", labels, switch (L1, L2), arg/local index or name, " +
                 "members as 'Ns.Type::Method(int, string)' or tokens. '.local <type>' adds a local. " +
                 "mode=replace swaps the whole body (no try/catch support); mode=prepend inserts before the original code, which can branch to original IL_xxxx labels. " +
                 "The result is stack-validated; use dryRun=true to preview. Persisted only by save_assembly.")]
    public Task<string> PatchMethodIL(
        [Description("Method. " + SymbolDescription)] string method,
        [Description("IL instructions, one per line.")] string il,
        [Description("replace (default) or prepend.")] string mode = "replace",
        [Description(AssemblyDescription)] string? assembly = null,
        [Description("Preview the change without applying it.")] bool dryRun = false,
        CancellationToken cancellationToken = default) => Write(workspace, () =>
    {
        var sym = SymbolResolver.ResolveOne(workspace, assembly, method, SymbolKind.Method);
        return $"[{sym.Assembly.Id}] {edits.PatchMethodIL(sym, il, mode, dryRun)}";
    }, cancellationToken);

    [McpServerTool(Name = "save_assembly", Destructive = true)]
    [Description("Write an assembly (with its in-memory edits) to disk. Default output is '<name>.patched.dll' next to the original. " +
                 "Overwriting an existing file requires overwrite=true; when that file is the original, it is first copied to '<file>.bak'.")]
    public Task<string> SaveAssembly(
        [Description("Assembly id, name or path.")] string assembly,
        [Description("Output file path. Omit for '<original>.patched.dll'.")] string? outputPath = null,
        [Description("Allow replacing an existing file.")] bool overwrite = false,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var asm = workspace.Get(assembly);
        return edits.Save(asm, outputPath, overwrite);
    }, cancellationToken);
}
