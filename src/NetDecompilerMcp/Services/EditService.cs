using System.Globalization;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Services;

/// <summary>
/// In-memory edits on the dnlib module. Nothing touches disk until <see cref="Save"/>.
/// Every applied edit is recorded as an <see cref="EditRecord"/> with the inputs needed to apply it again, which is what
/// undo (<see cref="Undo"/>: rebuild from the original image and replay the rest) and edit scripts are built on.
/// Callers must hold the workspace write lock (AssemblyWorkspace.Write), or the read lock for dry runs.
/// </summary>
public sealed class EditService(AssemblyWorkspace workspace, IlAssembler assembler, CSharpPatcher csharp)
{
    // ------------------------------------------------------------------ rename

    public string Rename(ResolvedSymbol symbol, string newName, bool dryRun = false)
    {
        if (string.IsNullOrWhiteSpace(newName))
            throw new ToolError("New name is empty.");
        var member = symbol.Member;
        var oldLabel = symbol.Label;
        if (dryRun)
            return $"Dry run — would rename {symbol.Kind} {oldLabel} -> {newName}" +
                   (member is PropertyDef or EventDef ? " (accessor methods renamed to match)" : "");
        switch (member)
        {
            case TypeDef t:
                t.Name = newName;
                break;
            case MethodDef m:
                if (m.IsConstructor) throw new ToolError("Constructors cannot be renamed.");
                m.Name = newName;
                break;
            case PropertyDef p:
                p.Name = newName;
                // Keep accessor names consistent so the decompiler still shows a property.
                foreach (var g in p.GetMethods) g.Name = "get_" + newName;
                foreach (var s in p.SetMethods) s.Name = "set_" + newName;
                break;
            case EventDef e:
                e.Name = newName;
                if (e.AddMethod != null) e.AddMethod.Name = "add_" + newName;
                if (e.RemoveMethod != null) e.RemoveMethod.Name = "remove_" + newName;
                break;
            case FieldDef f:
                f.Name = newName;
                break;
            default:
                throw new ToolError($"Cannot rename {member.GetType().Name}.");
        }
        var description = $"rename {symbol.Kind} {oldLabel} -> {newName}";
        var args = SymbolArgs("symbol", symbol, oldLabel);
        args["newName"] = newName;
        symbol.Assembly.RecordEdit(new EditRecord("rename_symbol", args, description, [Format.MemberLabel(member)]));
        return description;
    }

    public string RenameNamespace(LoadedAssembly asm, string oldNamespace, string newNamespace, bool includeSubNamespaces, bool dryRun = false)
    {
        // Top-level types only carry a namespace.
        var targets = asm.Module.Types
            .Where(t => t.Namespace == oldNamespace || (includeSubNamespaces && t.Namespace.String.StartsWith(oldNamespace + ".", StringComparison.Ordinal)))
            .ToList();
        int count = targets.Count;
        if (count == 0)
            throw new ToolError($"No types in namespace '{oldNamespace}' in {asm.Id}.");
        if (dryRun)
            return $"Dry run — would move {count} types: " + string.Join(", ", targets.Take(30).Select(t => t.FullName)) + (count > 30 ? ", …" : "");
        foreach (var t in targets)
            t.Namespace = newNamespace + t.Namespace.String[oldNamespace.Length..];

        var description = $"rename namespace {oldNamespace} -> {newNamespace} ({count} types)";
        asm.RecordEdit(new EditRecord("rename_namespace", new Dictionary<string, string?>
        {
            ["oldNamespace"] = oldNamespace,
            ["newNamespace"] = newNamespace,
            ["includeSubNamespaces"] = includeSubNamespaces ? "true" : "false",
        }, description, []));
        return description;
    }

    // ------------------------------------------------------------------ stub

    /// <summary>
    /// Replaces a method body with "return value;" (or "return;" for void).
    /// value: true/false, integers, floats, "string" literals, null, or default.
    /// </summary>
    public string StubMethod(ResolvedSymbol symbol, string? value, bool dryRun = false)
    {
        var m = RequireBodyMethod(symbol);
        var body = new CilBody { InitLocals = true };
        var ret = m.ReturnType.RemovePinnedAndModifiers();
        var il = body.Instructions;
        string shown;

        if (ret.ElementType == ElementType.Void)
        {
            if (!string.IsNullOrWhiteSpace(value) && value != "default")
                throw new ToolError($"{symbol.Label} returns void; omit the value.");
            shown = "return;";
        }
        else
        {
            shown = "return " + (value ?? "default") + ";";
            EmitValue(il, body, ret, value?.Trim());
        }
        il.Add(OpCodes.Ret.ToInstruction());
        if (dryRun)
            return $"Dry run — {symbol.Label} would become: {shown}\n" + Listing(il);

        Apply(m, body);
        var description = $"stub {symbol.Label} => {shown}";
        var args = SymbolArgs("method", symbol);
        args["value"] = value;
        symbol.Assembly.RecordEdit(new EditRecord("stub_method", args, description, [symbol.Label]));
        return description;
    }

    private static void EmitValue(IList<Instruction> il, CilBody body, TypeSig ret, string? value)
    {
        bool isDefault = value is null or "" or "default";
        var inv = CultureInfo.InvariantCulture;

        switch (ret.ElementType)
        {
            case ElementType.Boolean:
                il.Add(OpCodes.Ldc_I4.ToInstruction(isDefault ? 0 : ParseBool(value!) ? 1 : 0));
                return;
            case ElementType.Char:
            case ElementType.I1: case ElementType.U1:
            case ElementType.I2: case ElementType.U2:
            case ElementType.I4: case ElementType.U4:
                il.Add(OpCodes.Ldc_I4.ToInstruction(isDefault ? 0 : unchecked((int)ParseInteger(value!, ret.ElementType == ElementType.Char))));
                return;
            case ElementType.I8: case ElementType.U8:
                il.Add(OpCodes.Ldc_I8.ToInstruction(isDefault ? 0L : ParseInteger(value!, false)));
                return;
            case ElementType.R4:
                il.Add(OpCodes.Ldc_R4.ToInstruction(isDefault ? 0f : float.Parse(value!.TrimEnd('f', 'F'), inv)));
                return;
            case ElementType.R8:
                il.Add(OpCodes.Ldc_R8.ToInstruction(isDefault ? 0d : double.Parse(value!.TrimEnd('d', 'D'), inv)));
                return;
            case ElementType.String:
                if (isDefault || value == "null") il.Add(OpCodes.Ldnull.ToInstruction());
                else il.Add(OpCodes.Ldstr.ToInstruction(Unquote(value!)));
                return;
        }

        bool isValueType = ret.IsValueType || ret.IsGenericParameter;
        if (!isValueType)
        {
            if (!isDefault && value != "null")
                throw new ToolError($"Only null/default can be returned for reference type {Format.Type(ret)}.");
            il.Add(OpCodes.Ldnull.ToInstruction());
            return;
        }
        if (!isDefault)
            throw new ToolError($"Only 'default' is supported for {Format.Type(ret)}.");
        // default(T) for structs / generic parameters: initobj a local and return it.
        var local = body.Variables.Add(new Local(ret));
        il.Add(OpCodes.Ldloca.ToInstruction(local));
        il.Add(OpCodes.Initobj.ToInstruction(ret.ToTypeDefOrRef()));
        il.Add(OpCodes.Ldloc.ToInstruction(local));
    }

    private static bool ParseBool(string v) => v.ToLowerInvariant() switch
    {
        "true" or "1" => true,
        "false" or "0" => false,
        _ => throw new ToolError($"'{v}' is not a bool (use true/false)."),
    };

    private static long ParseInteger(string v, bool allowChar)
    {
        if (allowChar && v.Length == 3 && v[0] == '\'' && v[2] == '\'') return v[1];
        if (v.StartsWith("0x", StringComparison.OrdinalIgnoreCase) &&
            ulong.TryParse(v[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var hex))
            return unchecked((long)hex);
        if (long.TryParse(v, NumberStyles.Integer, CultureInfo.InvariantCulture, out var d)) return d;
        if (ulong.TryParse(v, NumberStyles.Integer, CultureInfo.InvariantCulture, out var u)) return unchecked((long)u);
        throw new ToolError($"'{v}' is not an integer.");
    }

    private static string Unquote(string v) =>
        v.Length >= 2 && v[0] == '"' && v[^1] == '"' ? System.Text.RegularExpressions.Regex.Unescape(v[1..^1]) : v;

    // ------------------------------------------------------------------ IL patch

    /// <summary>
    /// Replaces (mode=replace) or prefixes (mode=prepend) a method body with IL assembled from text.
    /// Everything is validated before the method is touched; dryRun only reports the resulting body.
    /// </summary>
    public string PatchMethodIL(ResolvedSymbol symbol, string il, string mode, bool dryRun)
    {
        var m = RequireBodyMethod(symbol);
        bool prepend = mode.Trim().ToLowerInvariant() switch
        {
            "replace" or "" => false,
            "prepend" or "prefix" or "insert" => true,
            _ => throw new ToolError($"Unknown mode '{mode}'. Use replace or prepend."),
        };

        var oldBody = MetadataUtil.SafeBody(m);
        if (prepend && oldBody == null)
            throw new ToolError($"{symbol.Label} has no existing body to prepend to; use mode=replace.");
        // the body as loaded from the file is not IL (encrypted / dumped before decryption) and no edit has replaced it yet
        if (prepend && symbol.Assembly.BodyHealth.IsInvalid(m) && !symbol.Assembly.Edits.Any(e => e.Description.Contains(symbol.Label, StringComparison.Ordinal)))
            throw new ToolError($"The body of {symbol.Label} is not valid IL (encrypted, or dumped from memory before decryption): there is no code to " +
                                "prepend to. Use mode=replace (or patch_method_csharp / stub_method), or load the decrypted image.");

        var assembled = assembler.Assemble(m, il, oldBody?.Instructions);
        MethodUtils.SimplifyBranches(assembled.Instructions); // only our new instructions: the original body stays untouched until applied
        var final = prepend ? assembled.Instructions.Concat(oldBody!.Instructions).ToList() : assembled.Instructions;
        var handlers = prepend ? oldBody!.ExceptionHandlers.ToList() : new List<ExceptionHandler>();

        if (final.Count == 0 || !IsTerminator(final[^1].OpCode))
            throw new ToolError("The patched body must end with ret, throw, rethrow or an unconditional branch.");
        if (!dnlib.DotNet.Writer.MaxStackCalculator.GetMaxStack(final, handlers, out uint maxStack))
            throw new ToolError("Stack imbalance: the IL leaves the evaluation stack inconsistent (check pushes/pops before branches and ret).");

        string listing;
        try
        {
            new CilBody(true, final, handlers, new List<Local>()).UpdateInstructionOffsets();
            listing = Listing(final);
        }
        finally
        {
            oldBody?.UpdateInstructionOffsets(); // offsets of the shared original instructions were recomputed above
        }
        if (dryRun)
            return $"Dry run — {symbol.Label} would become ({final.Count} instructions, maxstack {maxStack}" +
                   $"{(assembled.NewLocals.Count > 0 ? $", +{assembled.NewLocals.Count} locals" : "")}):\n{listing}";

        var body = oldBody ?? new CilBody();
        if (!prepend) body.ExceptionHandlers.Clear();
        body.Instructions.Clear();
        foreach (var instr in final) body.Instructions.Add(instr);
        foreach (var local in assembled.NewLocals) body.Variables.Add(local);
        Apply(m, body);

        var description = $"patch IL ({(prepend ? "prepend" : "replace")}, {assembled.Instructions.Count} instructions) {symbol.Label}";
        var args = SymbolArgs("method", symbol);
        args["il"] = il;
        args["mode"] = prepend ? "prepend" : "replace";
        symbol.Assembly.RecordEdit(new EditRecord("patch_method_il", args, description, [symbol.Label]));
        return $"{description}\nNew body:\n{Listing(body.Instructions)}";
    }

    private static bool IsTerminator(OpCode op) =>
        op.FlowControl is FlowControl.Return or FlowControl.Throw or FlowControl.Branch;

    // ------------------------------------------------------------------ C# edits

    /// <summary>Replaces a method body with C# statements (lambdas, async, LINQ and local functions included).</summary>
    public string PatchMethodCSharp(ResolvedSymbol symbol, string code, bool dryRun, CancellationToken ct)
    {
        RequireBodyMethod(symbol);
        var outcome = MergeSafely(symbol.Assembly, dryRun, target => csharp.PatchMethod(symbol, code, target, ct), ct);
        var helpers = (outcome.Added.Count > 0 ? $"\nCompiler-generated helpers added: {string.Join(", ", outcome.Added.Take(10))}" : "") + Relaxed(outcome);
        if (dryRun)
            return $"Dry run — compiled OK; {symbol.Label} would become:\n{outcome.Listing}{helpers}";

        var description = $"patch C# {symbol.Label}";
        var args = SymbolArgs("method", symbol);
        args["code"] = code;
        symbol.Assembly.RecordEdit(new EditRecord("patch_method_csharp", args, description, [symbol.Label]));
        return description + helpers;
    }

    /// <summary>Adds C# member declarations (methods, fields, properties, events, constructors, nested types) to a type.</summary>
    public string AddMembersCSharp(ResolvedSymbol typeSymbol, string code, bool dryRun, CancellationToken ct)
    {
        var outcome = MergeSafely(typeSymbol.Assembly, dryRun, target => csharp.AddMembers(typeSymbol, code, target, ct), ct);
        var visible = UserVisible(outcome.Added);
        if (dryRun)
            return $"Dry run — compiled OK; would add to {typeSymbol.Label}: {string.Join(", ", visible)}";

        var description = $"add members to {typeSymbol.Label}: {string.Join(", ", visible.Select(ShortName))}";
        var args = SymbolArgs("type", typeSymbol);
        args["code"] = code;
        typeSymbol.Assembly.RecordEdit(new EditRecord("add_members_csharp", args, description, visible));
        return description + Relaxed(outcome);
    }

    /// <summary>Adds new types written in C# to the assembly.</summary>
    public string AddTypesCSharp(LoadedAssembly asm, string code, bool dryRun, CancellationToken ct)
    {
        var outcome = MergeSafely(asm, dryRun, target => csharp.AddTypes(asm, code, target, ct), ct);
        var visible = UserVisible(outcome.Added).Where(a => !a.Contains("::")).ToList();
        if (dryRun)
            return $"Dry run — compiled OK; would add to {asm.Id}: {string.Join(", ", visible)}";

        var description = $"add types: {string.Join(", ", visible)}";
        asm.RecordEdit(new EditRecord("add_types_csharp", new Dictionary<string, string?> { ["code"] = code }, description, visible));
        return description + Relaxed(outcome);
    }

    /// <summary>
    /// Runs a C# merge on a scratch copy of the module first (validation; enough for a dry run), then on the real
    /// module. If the real merge fails half-way, the assembly is rebuilt from its recorded edits so nothing half-applied remains.
    /// </summary>
    private CSharpPatcher.Outcome MergeSafely(LoadedAssembly asm, bool dryRun, Func<ModuleDef, CSharpPatcher.Outcome> merge, CancellationToken ct)
    {
        CSharpPatcher.Outcome preview;
        using (var scratch = ModuleDefMD.Load(asm.GetImageBytes(), workspace.DnlibContext))
        {
            scratch.EnableTypeDefFindCache = true;
            preview = merge(scratch);
        }
        if (dryRun) return preview;
        try
        {
            return merge(asm.Module);
        }
        catch
        {
            Rebuild(asm, asm.Edits.ToList(), ct);
            throw;
        }
    }

    private static string Relaxed(CSharpPatcher.Outcome outcome) =>
        outcome.Relaxed.Count == 0 ? "" : "\nAccessibility relaxed so the code passes runtime access checks:\n  " + string.Join("\n  ", outcome.Relaxed);

    private static List<string> UserVisible(IEnumerable<string> labels) =>
        labels.Where(l => !l.Contains('<')).ToList();

    private static string ShortName(string label)
    {
        int sep = label.IndexOf("::", StringComparison.Ordinal);
        return sep >= 0 ? label[(sep + 2)..] : label;
    }

    // ------------------------------------------------------------------ replay / undo

    /// <summary>Applies a recorded edit again (undo, edit scripts). <paramref name="preferTokens"/> when replaying on the same original image.</summary>
    public string Apply(EditRecord record, LoadedAssembly asm, bool preferTokens, CancellationToken ct) => record.Kind switch
    {
        "rename_symbol" => Rename(Recorded(asm, record, "symbol", preferTokens), Required(record, "newName")),
        "rename_namespace" => RenameNamespace(asm, Required(record, "oldNamespace"), Required(record, "newNamespace"), record.Arg("includeSubNamespaces") == "true"),
        "stub_method" => StubMethod(Recorded(asm, record, "method", preferTokens), record.Arg("value")),
        "patch_method_il" => PatchMethodIL(Recorded(asm, record, "method", preferTokens), Required(record, "il"), record.Arg("mode") ?? "replace", false),
        "patch_method_csharp" => PatchMethodCSharp(Recorded(asm, record, "method", preferTokens), Required(record, "code"), false, ct),
        "add_members_csharp" => AddMembersCSharp(Recorded(asm, record, "type", preferTokens), Required(record, "code"), false, ct),
        "add_types_csharp" => AddTypesCSharp(asm, Required(record, "code"), false, ct),
        _ => throw new ToolError($"Unknown edit kind '{record.Kind}'."),
    };

    /// <summary>Undoes one edit (1-based number; default the last) by rebuilding from the original image and replaying the others.</summary>
    public string Undo(LoadedAssembly asm, int? number, CancellationToken ct)
    {
        var records = asm.Edits.ToList();
        if (records.Count == 0)
            throw new ToolError($"{asm.Id} has no edits to undo.");
        int index = (number ?? records.Count) - 1;
        if (index < 0 || index >= records.Count)
            throw new ToolError($"Edit #{index + 1} does not exist; {asm.Id} has {records.Count} edit(s) (see list_edits).");
        var removed = records[index];
        records.RemoveAt(index);
        Rebuild(asm, records, ct);
        return $"Undid #{index + 1} ({removed.Description}). {asm.Id} now has {records.Count} edit(s).";
    }

    /// <summary>Discards all edits (back to the image the assembly was loaded from).</summary>
    public string RevertAll(LoadedAssembly asm, CancellationToken ct)
    {
        int count = asm.Edits.Count;
        Rebuild(asm, [], ct);
        return $"Reverted {asm.Id} to its loaded state ({count} edit(s) discarded).";
    }

    /// <summary>
    /// Resets the module to the original image and replays <paramref name="records"/>. On failure the previous module and
    /// edit list are restored unchanged. Caller holds the write lock.
    /// </summary>
    public void Rebuild(LoadedAssembly asm, IReadOnlyList<EditRecord> records, CancellationToken ct)
    {
        var (previousModule, previousEdits) = asm.ResetToOriginal(workspace.DnlibContext);
        for (int i = 0; i < records.Count; i++)
        {
            try
            {
                Apply(records[i], asm, preferTokens: true, ct);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                asm.RestoreState(previousModule, previousEdits);
                // numbered as list_edits showed it before (undoing an earlier edit shifts the replayed ones)
                int number = previousEdits.IndexOf(records[i]) is >= 0 and var at ? at + 1 : i + 1;
                var reason = ex.Message.TrimEnd().Replace("Nothing was changed.", "").TrimEnd();
                throw new ToolError($"Edit #{number} ({records[i].Description}) could not be re-applied: {reason}\nNothing was changed.");
            }
        }
        previousModule.Dispose();
    }

    // ------------------------------------------------------------------ helpers

    private static Dictionary<string, string?> SymbolArgs(string key, ResolvedSymbol symbol, string? label = null) => new()
    {
        [key] = label ?? symbol.Label,
        [key + "Kind"] = symbol.Kind,
        [key + "Token"] = Format.Token(symbol.Member),
    };

    private ResolvedSymbol Recorded(LoadedAssembly asm, EditRecord record, string key, bool preferTokens)
    {
        if (preferTokens && SymbolResolver.TryParseToken(record.Arg(key + "Token") ?? "", out uint token)
            && (token & 0x00FFFFFF) != 0 && asm.Module.ResolveToken(token) is IMemberDef def)
            return new ResolvedSymbol(asm, def);
        return SymbolResolver.ResolveOne(workspace, asm.Id, Required(record, key), SymbolResolver.ParseKind(record.Arg(key + "Kind")));
    }

    private static string Required(EditRecord record, string key) =>
        record.Arg(key) ?? throw new ToolError($"Edit '{record.Kind}' is missing its '{key}' argument.");

    private static MethodDef RequireBodyMethod(ResolvedSymbol symbol)
    {
        if (symbol.Member is not MethodDef m)
            throw new ToolError($"{symbol.Label} is a {symbol.Kind}, not a method.");
        if (m.IsAbstract || m.IsPinvokeImpl || m.IsRuntime || m.IsInternalCall)
            throw new ToolError($"{symbol.Label} has no IL body (abstract/extern/runtime).");
        return m;
    }

    private static void Apply(MethodDef m, CilBody body)
    {
        body.SimplifyBranches();
        body.OptimizeBranches();
        body.UpdateInstructionOffsets();
        m.Body = body;
        m.ImplAttributes &= ~(MethodImplAttributes.InternalCall | MethodImplAttributes.Runtime);
    }

    private static string Listing(IEnumerable<Instruction> instructions) => string.Join("\n", instructions.Select(i => "  " + i));

    // ------------------------------------------------------------------ save

    /// <summary>
    /// Writes the (edited) module. Refuses to overwrite the original file unless asked;
    /// when overwriting, the original is first copied to &lt;file&gt;.bak.
    /// </summary>
    public string Save(LoadedAssembly asm, string? outputPath, bool overwrite)
    {
        var target = Path.GetFullPath(string.IsNullOrWhiteSpace(outputPath)
            ? Path.Combine(Path.GetDirectoryName(asm.FilePath)!, Path.GetFileNameWithoutExtension(asm.FilePath) + ".patched" + Path.GetExtension(asm.FilePath))
            : outputPath);

        bool isOriginal = string.Equals(target, asm.FilePath, StringComparison.OrdinalIgnoreCase);
        if (File.Exists(target) && !overwrite)
            throw new ToolError($"{target} already exists. Pass overwrite=true to replace it{(isOriginal ? " (the original will be backed up to .bak)" : "")}.");

        Directory.CreateDirectory(Path.GetDirectoryName(target)!);
        string? backup = null;
        if (isOriginal)
        {
            backup = target + ".bak";
            if (!File.Exists(backup)) File.Copy(target, backup);
        }

        var temp = target + ".tmp-" + Environment.ProcessId;
        try
        {
            File.WriteAllBytes(temp, asm.GetImageBytes());
            File.Move(temp, target, overwrite: true);
        }
        finally
        {
            if (File.Exists(temp)) File.Delete(temp);
        }

        return $"Wrote {target} ({new FileInfo(target).Length:N0} bytes, {asm.Edits.Count} edit(s)).{(backup != null ? $" Original backed up to {backup}." : "")}";
    }
}
