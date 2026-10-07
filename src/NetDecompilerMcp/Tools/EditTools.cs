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
public sealed class EditTools(AssemblyWorkspace workspace, EditService edits, DecompilerService decompiler)
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
                 "Compile errors are reported with line numbers relative to your code. Lambdas, local functions, async/await, yield and LINQ need compiler-generated types and are rejected — use loops/if-chains or patch_method_il. " +
                 "Returns the decompiled result. Persisted only by save_assembly.")]
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
