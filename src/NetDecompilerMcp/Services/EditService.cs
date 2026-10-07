using System.Globalization;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Services;

/// <summary>
/// In-memory edits on the dnlib module. Nothing touches disk until <see cref="Save"/>.
/// Callers must hold the workspace write lock (AssemblyWorkspace.Write).
/// </summary>
public sealed class EditService(IlAssembler assembler, CSharpPatcher csharp)
{
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
        symbol.Assembly.RecordEdit(description);
        return $"{description}\nNew body:\n{Listing(body.Instructions)}";
    }

    /// <summary>Replaces a method body with C# statements compiled against the assembly (see <see cref="CSharpPatcher"/>).</summary>
    public string PatchMethodCSharp(ResolvedSymbol symbol, string code, bool dryRun, CancellationToken ct)
    {
        var m = RequireBodyMethod(symbol);
        var compiled = csharp.Compile(symbol, code, ct);
        if (!dnlib.DotNet.Writer.MaxStackCalculator.GetMaxStack(compiled.Body.Instructions, compiled.Body.ExceptionHandlers, out _))
            throw new ToolError("Internal: the compiled body failed stack validation; nothing was changed.");
        if (dryRun)
            return $"Dry run — compiled OK; {symbol.Label} would become ({compiled.Body.Instructions.Count} IL instructions):\n{compiled.Listing}";

        Apply(m, compiled.Body);
        var description = $"patch C# {symbol.Label}";
        symbol.Assembly.RecordEdit(description);
        return description;
    }

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

    private static bool IsTerminator(OpCode op) =>
        op.FlowControl is FlowControl.Return or FlowControl.Throw or FlowControl.Branch;

    public string Rename(ResolvedSymbol symbol, string newName, bool dryRun = false)
    {
        ValidateName(newName);
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
        symbol.Assembly.RecordEdit(description);
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
        asm.RecordEdit(description);
        return description;
    }

    /// <summary>
    /// Replaces a method body with "return value;" (or "return;" for void).
    /// value: true/false, integers, floats, "string" literals, null, or default.
    /// </summary>
    public string StubMethod(ResolvedSymbol symbol, string? value, bool dryRun = false)
    {
        if (symbol.Member is not MethodDef m)
            throw new ToolError($"{symbol.Label} is a {symbol.Kind}, not a method.");
        if (m.IsAbstract || m.IsPinvokeImpl || m.IsRuntime || m.IsInternalCall)
            throw new ToolError($"{symbol.Label} has no IL body to replace (abstract/extern/runtime).");

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
            EmitValue(il, body, ret, value?.Trim(), m.Module);
        }
        il.Add(OpCodes.Ret.ToInstruction());
        if (dryRun)
            return $"Dry run — {symbol.Label} would become: {shown}\n" + string.Join("\n", il.Select(i => "  " + i));

        Apply(m, body);
        var description = $"stub {symbol.Label} => {shown}";
        symbol.Assembly.RecordEdit(description);
        return description;
    }

    private static void EmitValue(IList<Instruction> il, CilBody body, TypeSig ret, string? value, ModuleDef module)
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

    private static void ValidateName(string name)
    {
        if (string.IsNullOrWhiteSpace(name))
            throw new ToolError("New name is empty.");
    }

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
            using (var fs = File.Create(temp))
                asm.Write(fs);
            File.Move(temp, target, overwrite: true);
        }
        finally
        {
            if (File.Exists(temp)) File.Delete(temp);
        }

        var edits = asm.Edits.Count;
        return $"Wrote {target} ({new FileInfo(target).Length:N0} bytes, {edits} edit(s)).{(backup != null ? $" Original backed up to {backup}." : "")}";
    }
}
