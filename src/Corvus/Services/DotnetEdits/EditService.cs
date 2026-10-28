using System.Globalization;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Corvus.Core;
using Corvus.Services.Simplify;

namespace Corvus.Services;

/// <summary>In-memory edits recorded as replayable <see cref="EditRecord"/>s, written only by <see cref="Save"/>;
/// callers hold the write lock, or the read lock for dry runs.</summary>
public sealed partial class EditService(AssemblyWorkspace workspace, IlAssembler assembler, CSharpPatcher csharp)
{
    public string Rename(ResolvedSymbol symbol, string newName, bool dryRun = false)
    {
        if (string.IsNullOrWhiteSpace(newName))
            throw new ToolError(ErrorCode.InvalidArgument, "New name is empty.");
        var member = symbol.Member;
        var oldLabel = symbol.Label;
        if (member is TypeDef generic) newName = KeepArity(generic.Name, newName);
        var args = SymbolArgs("symbol", symbol, oldLabel);
        args["newName"] = newName;
        if (Previewed(dryRun, "rename_symbol", args))
            return $"Dry run — would rename {symbol.Kind} {oldLabel} -> {newName}" +
                   (member is PropertyDef or EventDef ? " (accessor methods renamed to match)" : "");
        switch (member)
        {
            case TypeDef t:
                t.Name = newName;
                break;
            case MethodDef m:
                if (m.IsConstructor) throw new ToolError(ErrorCode.Unsupported, "Constructors cannot be renamed.");
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
                throw new ToolError(ErrorCode.Unsupported, $"Cannot rename {member.GetType().Name}.");
        }
        var description = $"rename {symbol.Kind} {oldLabel} -> {newName}";
        symbol.Assembly.RecordEdit(new EditRecord("rename_symbol", args, description, [Format.MemberLabel(member)]));
        return description;
    }

    /// <summary>Keeps a generic type's arity suffix (`N), which reflection names and later C# edits depend on.</summary>
    internal static string KeepArity(string oldName, string newName)
    {
        int tick = oldName.LastIndexOf('`');
        if (tick < 0 || !int.TryParse(oldName.AsSpan(tick + 1), NumberStyles.None, CultureInfo.InvariantCulture, out _)) return newName;
        var arity = oldName[tick..];
        int newTick = newName.LastIndexOf('`');
        if (newTick < 0 || !int.TryParse(newName.AsSpan(newTick + 1), NumberStyles.None, CultureInfo.InvariantCulture, out _))
            return newName + arity;
        if (newName[newTick..] != arity)
            throw new ToolError(ErrorCode.InvalidArgument, $"'{newName}' changes the generic arity of {oldName}; a rename keeps {arity}.",
                $"pass newName '{newName[..newTick]}' (the suffix {arity} is kept)");
        return newName;
    }

    public string RenameNamespace(LoadedAssembly asm, string oldNamespace, string newNamespace, bool includeSubNamespaces, bool dryRun = false)
    {
        // Only top-level types carry a namespace.
        var targets = asm.Module.Types
            .Where(t => t.Namespace == oldNamespace || (includeSubNamespaces && t.Namespace.String.StartsWith(oldNamespace + ".", StringComparison.Ordinal)))
            .ToList();
        int count = targets.Count;
        if (count == 0)
            throw new ToolError(ErrorCode.NotFound, $"No types in namespace '{oldNamespace}' in {asm.Id}.");
        var args = new Dictionary<string, string?>
        {
            ["oldNamespace"] = oldNamespace,
            ["newNamespace"] = newNamespace,
            ["includeSubNamespaces"] = includeSubNamespaces ? "true" : "false",
        };
        if (Previewed(dryRun, "rename_namespace", args))
            return $"Dry run — would move {count} types: " + string.Join(", ", targets.Take(30).Select(t => t.FullName)) + (count > 30 ? ", …" : "");
        foreach (var t in targets)
            t.Namespace = newNamespace + t.Namespace.String[oldNamespace.Length..];

        var description = $"rename namespace {oldNamespace} -> {newNamespace} ({count} types)";
        asm.RecordEdit(new EditRecord("rename_namespace", args, description, []));
        return description;
    }

    /// <summary>Replaces a method body with "return value;": a bool, number, "string", null or default.</summary>
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
                throw new ToolError(ErrorCode.InvalidArgument, $"{symbol.Label} returns void; omit the value.");
            shown = "return;";
        }
        else
        {
            shown = "return " + (value ?? "default") + ";";
            EmitValue(il, body, ret, value?.Trim());
        }
        il.Add(OpCodes.Ret.ToInstruction());
        var args = SymbolArgs("method", symbol);
        args["value"] = value;
        if (Previewed(dryRun, "stub_method", args))
            return $"Dry run — {symbol.Label} would become: {shown}\n" + Listing(il);

        Apply(m, body);
        var description = $"stub {symbol.Label} => {shown}";
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
                throw new ToolError(ErrorCode.Unsupported, $"Only null/default can be returned for reference type {Format.Type(ret)}.");
            il.Add(OpCodes.Ldnull.ToInstruction());
            return;
        }
        if (!isDefault)
            throw new ToolError(ErrorCode.Unsupported, $"Only 'default' is supported for {Format.Type(ret)}.");
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
        _ => throw new ToolError(ErrorCode.InvalidArgument, $"'{v}' is not a bool (use true/false)."),
    };

    private static long ParseInteger(string v, bool allowChar)
    {
        if (allowChar && v.Length == 3 && v[0] == '\'' && v[2] == '\'') return v[1];
        if (v.StartsWith("0x", StringComparison.OrdinalIgnoreCase) &&
            ulong.TryParse(v[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var hex))
            return unchecked((long)hex);
        if (long.TryParse(v, NumberStyles.Integer, CultureInfo.InvariantCulture, out var d)) return d;
        if (ulong.TryParse(v, NumberStyles.Integer, CultureInfo.InvariantCulture, out var u)) return unchecked((long)u);
        throw new ToolError(ErrorCode.InvalidArgument, $"'{v}' is not an integer.");
    }

    private static string Unquote(string v) =>
        v.Length >= 2 && v[0] == '"' && v[^1] == '"' ? System.Text.RegularExpressions.Regex.Unescape(v[1..^1]) : v;

    /// <summary>Replaces or prepends a method body with assembled IL, validated before the method changes.</summary>
    public string PatchMethodIL(ResolvedSymbol symbol, string il, string mode, bool dryRun)
    {
        var m = RequireBodyMethod(symbol);
        bool prepend = mode.Trim().ToLowerInvariant() switch
        {
            "replace" or "" => false,
            "prepend" or "prefix" or "insert" => true,
            _ => throw new ToolError(ErrorCode.InvalidArgument, $"Unknown mode '{mode}'. Use replace or prepend."),
        };

        var oldBody = MetadataUtil.SafeBody(m);
        if (prepend && oldBody == null)
            throw new ToolError(ErrorCode.InvalidArgument, $"{symbol.Label} has no existing body to prepend to; use mode=replace.");
        if (prepend && symbol.Assembly.BodyHealth.IsInvalid(m) && !symbol.Assembly.Edits.Any(e => e.Description.Contains(symbol.Label, StringComparison.Ordinal)))
            throw new ToolError(ErrorCode.Unsupported, $"The body of {symbol.Label} is not valid IL (encrypted, or dumped before decryption): there is nothing to prepend to; use mode=replace, patch_method_csharp or stub_method, or load the decrypted image.");

        var assembled = assembler.Assemble(m, il, oldBody?.Instructions);
        MethodUtils.SimplifyBranches(assembled.Instructions); // new instructions only; the original body is untouched until applied
        var final = prepend ? assembled.Instructions.Concat(oldBody!.Instructions).ToList() : assembled.Instructions;
        var handlers = prepend ? oldBody!.ExceptionHandlers.ToList() : new List<ExceptionHandler>();

        if (final.Count == 0 || !IsTerminator(final[^1].OpCode))
            throw new ToolError(ErrorCode.InvalidArgument, "The patched body must end with ret, throw, rethrow or an unconditional branch.");
        if (!dnlib.DotNet.Writer.MaxStackCalculator.GetMaxStack(final, handlers, out uint maxStack))
            throw new ToolError(ErrorCode.InvalidArgument, "Stack imbalance: the IL leaves the evaluation stack inconsistent (check pushes/pops before branches and ret).");

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
        var args = SymbolArgs("method", symbol);
        args["il"] = il;
        args["mode"] = prepend ? "prepend" : "replace";
        if (Previewed(dryRun, "patch_method_il", args))
            return $"Dry run — {symbol.Label} would become ({final.Count} instructions, maxstack {maxStack}" +
                   $"{(assembled.NewLocals.Count > 0 ? $", +{assembled.NewLocals.Count} locals" : "")}):\n{listing}";

        var body = oldBody ?? new CilBody();
        if (!prepend) body.ExceptionHandlers.Clear();
        body.Instructions.Clear();
        foreach (var instr in final) body.Instructions.Add(instr);
        foreach (var local in assembled.NewLocals) body.Variables.Add(local);
        Apply(m, body);

        var description = $"patch IL ({(prepend ? "prepend" : "replace")}, {assembled.Instructions.Count} instructions) {symbol.Label}";
        symbol.Assembly.RecordEdit(new EditRecord("patch_method_il", args, description, [symbol.Label]));
        return $"{description}\nNew body:\n{Listing(body.Instructions)}";
    }

    private static bool IsTerminator(OpCode op) =>
        op.FlowControl is FlowControl.Return or FlowControl.Throw or FlowControl.Branch;

    /// <summary>Replaces a method body with C# statements (lambdas, async, LINQ and local functions included).</summary>
    public string PatchMethodCSharp(ResolvedSymbol symbol, string code, bool dryRun, CancellationToken ct)
    {
        RequireBodyMethod(symbol);
        CSharpPatcher.Outcome outcome;
        try
        {
            outcome = MergeSafely(symbol.Assembly, dryRun, target => csharp.PatchMethod(symbol, code, target, ct), ct);
        }
        catch (ToolError ex)
        {
            var withNext = CSharpPatcher.WithPatchNext(ex, symbol);
            if (ReferenceEquals(withNext, ex)) throw;
            throw withNext;
        }
        var helpers = (outcome.Added.Count > 0 ? $"\nCompiler-generated helpers added: {string.Join(", ", outcome.Added.Take(10))}" : "") + Relaxed(outcome);
        var args = SymbolArgs("method", symbol);
        args["code"] = code;
        if (Previewed(dryRun, "patch_method_csharp", args))
            return $"Dry run — compiled OK; {symbol.Label} would become:\n{outcome.Listing}{helpers}";

        var description = $"patch C# {symbol.Label}";
        symbol.Assembly.RecordEdit(new EditRecord("patch_method_csharp", args, description, [symbol.Label]));
        return description + helpers;
    }

    /// <summary>Adds C# member declarations (methods, fields, properties, events, constructors, nested types) to a type.</summary>
    public string AddMembersCSharp(ResolvedSymbol typeSymbol, string code, bool dryRun, CancellationToken ct)
    {
        var outcome = MergeSafely(typeSymbol.Assembly, dryRun, target => csharp.AddMembers(typeSymbol, code, target, ct), ct);
        var visible = UserVisible(outcome.Added);
        var args = SymbolArgs("type", typeSymbol);
        args["code"] = code;
        if (Previewed(dryRun, "add_members_csharp", args))
            return $"Dry run — compiled OK; would add to {typeSymbol.Label}: {string.Join(", ", visible)}";

        var description = $"add members to {typeSymbol.Label}: {string.Join(", ", visible.Select(ShortName))}";
        typeSymbol.Assembly.RecordEdit(new EditRecord("add_members_csharp", args, description, visible));
        return description + Relaxed(outcome);
    }

    public string AddTypesCSharp(LoadedAssembly asm, string code, bool dryRun, CancellationToken ct)
    {
        var outcome = MergeSafely(asm, dryRun, target => csharp.AddTypes(asm, code, target, ct), ct);
        var visible = UserVisible(outcome.Added).Where(a => !a.Contains("::")).ToList();
        var args = new Dictionary<string, string?> { ["code"] = code };
        if (Previewed(dryRun, "add_types_csharp", args))
            return $"Dry run — compiled OK; would add to {asm.Id}: {string.Join(", ", visible)}";

        var description = $"add types: {string.Join(", ", visible)}";
        asm.RecordEdit(new EditRecord("add_types_csharp", args, description, visible));
        return description + Relaxed(outcome);
    }

    /// <summary>Runs a C# edit up to its scratch merge under the shared lock, leaving the compile work in the open
    /// <see cref="ReuseCompiles"/> scope; code errors are thrown.</summary>
    public void Prepare(Func<string> edit)
    {
        Preparing.Value = true;
        try { edit(); }
        catch (PreparedSignal) { }
        finally { Preparing.Value = false; }
    }

    /// <summary>Opens a scope in which a prepared edit and its merge share compile work; see <see cref="CSharpPatcher.ReuseCompiles"/>.</summary>
    public IDisposable ReuseCompiles() => csharp.ReuseCompiles();

    private static readonly AsyncLocal<bool> Preparing = new();

    /// <summary>Ends a prepared edit after its scratch merge, before anything is recorded.</summary>
    private sealed class PreparedSignal : Exception;

    /// <summary>Merges into a scratch copy, then the module; a failed real merge rebuilds from the recorded edits.</summary>
    private CSharpPatcher.Outcome MergeSafely(LoadedAssembly asm, bool dryRun, Func<ModuleDef, CSharpPatcher.Outcome> merge, CancellationToken ct)
    {
        // A replayed edit merges once; a rebuild in progress rolls back a failure itself.
        if (_replaying && !dryRun)
        {
            if (_rebuilding) return merge(asm.Module);
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
        CSharpPatcher.Outcome preview;
        // Join the scope a Prepare call left its compile work in.
        using var reuse = csharp.ReuseCompiles(join: true);
        CallProgress.Report(1, 3, $"compiling against {asm.Id} (decompiled context, references)");
        using (var scratch = MetadataRows.Load(asm.GetImageBytes(), workspace.DnlibContext))
        {
            scratch.EnableTypeDefFindCache = true;
            preview = merge(scratch);
        }
        if (Preparing.Value) throw new PreparedSignal();
        if (dryRun) return preview;
        CallProgress.Report(2, 3, $"applying to {asm.Id}");
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

    /// <summary>Labels without compiler-generated names ('&lt;' starting a name); a generic method's "&lt;T&gt;" is kept.</summary>
    private static List<string> UserVisible(IEnumerable<string> labels) =>
        labels.Where(l => !GeneratedName().IsMatch(l)).ToList();

    [System.Text.RegularExpressions.GeneratedRegex(@"(^|[/.:])<")]
    private static partial System.Text.RegularExpressions.Regex GeneratedName();

    private static string ShortName(string label)
    {
        int sep = label.IndexOf("::", StringComparison.Ordinal);
        return sep >= 0 ? label[(sep + 2)..] : label;
    }

    /// <summary>Simplifies a method, a type's methods, or the whole assembly when <paramref name="symbol"/> is null.</summary>
    public string SimplifyMethods(LoadedAssembly asm, ResolvedSymbol? symbol, SimplifyOptions options, bool dryRun, CancellationToken ct)
    {
        var scope = symbol?.Label ?? asm.Id;
        var methods = SimplifyScope(asm, symbol);
        if (asm.HasUnreadableBodies)
        {
            var (unreadable, total) = asm.BodyCensus;
            return $"{(dryRun ? "Dry run — simplify" : "Simplify")} {scope} ({options.Label()}): 0 of {methods.Count} method(s) {(dryRun ? "would change" : "changed")}.\n" +
                   $"Nothing is rewritten: {unreadable} of {total} method bodies of {asm.AssemblyName} are not IL; they are restored at run time, " +
                   "so a rewritten image would not run. [unreadable-bodies]";
        }
        var simplifier = new MethodSimplifier(asm.Module, options);
        var changes = simplifier.Run(methods, ct, (done, total) => CallProgress.Report(done, total, $"{done} of {total} methods simplified"));
        var changed = changes.Where(c => c.Changed).ToList();
        var report = SimplifyReport(changes, methods.Count, dryRun, simplifier.ExtendedInitializers);
        var header = dryRun
            ? $"Dry run — simplify {scope} ({options.Label()}): {changed.Count} of {methods.Count} method(s) would change."
            : $"Simplified {scope} ({options.Label()}): {changed.Count} of {methods.Count} method(s) changed.";
        var args = symbol == null ? new Dictionary<string, string?>() : SymbolArgs("symbol", symbol);
        args["passes"] = options.Describe();
        args["maxDepth"] = options.EffectiveLimits.MaxDepth.ToString(CultureInfo.InvariantCulture);
        args["budget"] = options.EffectiveLimits.InstructionBudget.ToString(CultureInfo.InvariantCulture);
        if (options.DeterministicEnvironment) args["deterministicEnvironment"] = "true";
        if (changed.Count == 0 || Previewed(dryRun, "simplify_methods", args)) return header + report;

        foreach (var c in changed) c.Method.Body = c.NewBody!;
        var description = $"simplify {scope} ({options.Label()}): {changed.Count} method(s)";
        asm.RecordEdit(new EditRecord("simplify_methods", args, description, changed.Select(c => Format.MemberLabel(c.Method)).ToList()));
        return header + report;
    }

    private static List<MethodDef> SimplifyScope(LoadedAssembly asm, ResolvedSymbol? symbol)
    {
        static IEnumerable<MethodDef> OfType(TypeDef t) => t.Methods.Concat(t.NestedTypes.SelectMany(OfType));
        return (symbol?.Member switch
        {
            null => asm.Module.GetTypes().SelectMany(t => t.Methods),
            TypeDef t => OfType(t),
            MethodDef m => [m],
            PropertyDef p => p.GetMethods.Concat(p.SetMethods).Concat(p.OtherMethods),
            EventDef e => new[] { e.AddMethod, e.RemoveMethod, e.InvokeMethod }.OfType<MethodDef>().Concat(e.OtherMethods),
            _ => throw new ToolError(ErrorCode.InvalidArgument, $"{symbol.Label} is a {symbol.Kind}; pass a method, a type, or omit the symbol for the whole assembly."),
        }).Where(m => m.HasBody).ToList();
    }

    private const int MaxReportedIssues = 50;
    private const int MaxReportedMethods = 200;

    private static string SimplifyReport(List<MethodChange> changes, int total, bool dryRun, IReadOnlyList<ExtendedInitializer> extended)
    {
        var sb = new System.Text.StringBuilder();
        var changed = changes.Where(c => c.Changed).ToList();
        foreach (var c in changed.Take(MaxReportedMethods))
        {
            sb.Append($"\n{Format.MemberLabel(c.Method)}  [{c.InstructionsBefore} -> {c.InstructionsAfter} instructions]");
            foreach (var f in c.Folded) sb.Append("\n  folded ").Append(f);
            foreach (var i in c.Inlined) sb.Append("\n  inlined ").Append(i);
            foreach (var d in c.Delegates) sb.Append("\n  resolved ").Append(d);
            var flow = new List<string>();
            if (c.ConstantBranches > 0) flow.Add($"folded {c.ConstantBranches} constant branch(es)");
            if (c.CollapsedChains > 0) flow.Add($"collapsed {c.CollapsedChains} branch chain(s)");
            if (c.Dispatchers > 0) flow.Add($"normalized {c.Dispatchers} switch dispatcher(s) ({c.Transitions} transition(s) go straight to their case)");
            if (c.RemovedBlocks > 0) flow.Add($"removed {c.RemovedBlocks} unreachable block(s) ({c.RemovedInstructions} instructions)");
            if (c.RemovedHandlers > 0) flow.Add($"removed {c.RemovedHandlers} exception handler(s)");
            if (c.RemovedStores > 0) flow.Add($"removed {c.RemovedStores} dead store(s)");
            if (c.RemovedLoads > 0) flow.Add($"removed {c.RemovedLoads} repeated load(s) kept only for their effect");
            if (c.ConstantReads > 0) flow.Add($"replaced {c.ConstantReads} read(s) of locals through their address by constants");
            if (flow.Count > 0) sb.Append("\n  ").Append(string.Join(", ", flow));
        }
        if (changed.Count > MaxReportedMethods)
            sb.Append($"\n… {changed.Count - MaxReportedMethods} more changed method(s) (narrow the scope to a type or method for details)");

        var bailouts = changes.SelectMany(c => c.Bailouts.Select(b => $"{Format.MemberLabel(c.Method)} {b}")).ToList();
        AppendList(sb, "Not folded (evaluation bailed out; the call is kept):", bailouts);
        var skipped = changes.SelectMany(c => c.Skipped.Select(s => $"{Format.MemberLabel(c.Method)} {s}")).ToList();
        AppendList(sb, "Not rewritten (the code is kept; the other passes still apply):", skipped);
        var rejected = changes.Where(c => c.Rejected != null).Select(c => $"{Format.MemberLabel(c.Method)}: {c.Rejected}").ToList();
        AppendList(sb, "Left unchanged:", rejected);
        AppendList(sb, "Extended tier (type initializers that ran past the instruction budget while committing new state; accounted apart):",
            extended.Select(e => $"{e.Type}: {e.Instructions:N0} instructions, " + (e.Completed ? "completed" : $"stopped: {e.Stop}")).ToList());
        if (changed.Count == 0 && bailouts.Count == 0 && skipped.Count == 0 && rejected.Count == 0)
            sb.Append($"\nNothing to simplify in {total} method(s){(dryRun ? "" : "; no edit recorded")}.");
        // Totals first: a report past the budget keeps its head.
        else if (total > 1)
            sb.Insert(0, "\n" + SimplifyTotals(changes, extended) + "\n");
        return sb.ToString();
    }

    /// <summary>One line totalling a run's effects and fallbacks by reason code.</summary>
    internal static string SimplifyTotals(List<MethodChange> changes, IReadOnlyList<ExtendedInitializer>? extended = null)
    {
        var changed = changes.Where(c => c.Changed).ToList();
        var effects = new List<string>();
        void Add(int n, string what)
        {
            if (n > 0) effects.Add($"{n} {what}");
        }
        Add(changed.Sum(c => c.Folded.Count), "call(s) folded");
        Add(changed.Sum(c => c.Inlined.Count), "forwarder call(s) inlined");
        Add(changed.Sum(c => c.Delegates.Count), "delegate call(s) resolved");
        Add(changed.Sum(c => c.ConstantBranches), "constant branch(es) folded");
        Add(changed.Sum(c => c.Dispatchers), $"dispatcher(s) normalized ({changed.Sum(c => c.Transitions)} transition(s))");
        Add(changed.Sum(c => c.RemovedBlocks), "unreachable block(s) removed");
        Add(changed.Sum(c => c.RemovedHandlers), "handler(s) removed");
        Add(changed.Sum(c => c.RemovedStores), "dead store(s) removed");
        Add(changed.Sum(c => c.RemovedLoads), "repeated load(s) removed");
        Add(changed.Sum(c => c.ConstantReads), "constant read(s) through an address replaced");
        Add(extended?.Count(e => e.Completed) ?? 0, "type initializer(s) completed in the extended tier");
        var fallbacks = changes
            .SelectMany(c => c.Bailouts.Concat(c.Skipped).Select(f => f.Reason).Concat(c.Rejected is { } r ? [r.Reason] : Array.Empty<FallbackReason>()))
            .GroupBy(SimplifyManifest.CodeOf).OrderByDescending(g => g.Count()).ThenBy(g => g.Key, StringComparer.Ordinal)
            .Select(g => $"{g.Key} {g.Count()}").ToList();
        return $"Totals: {changed.Count} of {changes.Count} method(s) changed" +
               (effects.Count > 0 ? "; " + string.Join(", ", effects) : "") +
               (fallbacks.Count > 0 ? $". Fallbacks: {string.Join(", ", fallbacks)}" : "") + ".";
    }

    private static void AppendList(System.Text.StringBuilder sb, string title, List<string> items)
    {
        if (items.Count == 0) return;
        sb.Append("\n\n").Append(title);
        foreach (var item in items.Take(MaxReportedIssues)) sb.Append("\n  ").Append(item);
        if (items.Count > MaxReportedIssues) sb.Append($"\n  … {items.Count - MaxReportedIssues} more");
    }

    /// <summary>Maps a recorded symbol missing by name to its counterpart in another build; null when there is none.</summary>
    internal Func<EditRecord, string, ResolvedSymbol?>? Remap { get; set; }

    // Set while recorded edits are replayed (Apply) and while an assembly is rebuilt from its edits (Rebuild).
    [ThreadStatic] private static bool _replaying, _rebuilding;

    /// <summary>Re-applies a recorded edit. <paramref name="preferTokens"/>: replaying on the same original image.</summary>
    public string Apply(EditRecord record, LoadedAssembly asm, bool preferTokens, CancellationToken ct)
    {
        bool outer = _replaying;
        _replaying = true;
        try { return ApplyRecord(record, asm, preferTokens, ct); }
        finally { _replaying = outer; }
    }

    private string ApplyRecord(EditRecord record, LoadedAssembly asm, bool preferTokens, CancellationToken ct) => record.Kind switch
    {
        "rename_symbol" => Rename(Recorded(asm, record, "symbol", preferTokens), Required(record, "newName")),
        "rename_namespace" => RenameNamespace(asm, Required(record, "oldNamespace"), Required(record, "newNamespace"), record.Arg("includeSubNamespaces") == "true"),
        "stub_method" => StubMethod(Recorded(asm, record, "method", preferTokens), record.Arg("value")),
        "patch_method_il" => PatchMethodIL(Recorded(asm, record, "method", preferTokens), Required(record, "il"), record.Arg("mode") ?? "replace", false),
        "patch_method_csharp" => PatchMethodCSharp(Recorded(asm, record, "method", preferTokens), Required(record, "code"), false, ct),
        "add_members_csharp" => AddMembersCSharp(Recorded(asm, record, "type", preferTokens), Required(record, "code"), false, ct),
        "add_types_csharp" => AddTypesCSharp(asm, Required(record, "code"), false, ct),
        "simplify_methods" => SimplifyMethods(asm, record.Arg("symbol") == null ? null : Recorded(asm, record, "symbol", preferTokens),
            SimplifyOptions.Parse(record.Arg("passes"), IntArg(record, "maxDepth"), IntArg(record, "budget"), record.Arg("deterministicEnvironment") == "true"), false, ct),
        _ => throw new ToolError(ErrorCode.MalformedInput, $"Unknown edit kind '{record.Kind}'."),
    };

    /// <summary>The recorded edit with this number (its editId); the last when null.</summary>
    public static EditRecord Find(LoadedAssembly asm, int? number)
    {
        if (asm.Edits.Count == 0)
            throw new ToolError(ErrorCode.NotFound, $"{asm.Id} has no unsaved edits.", $"list_edits assembly={asm.Id} lists them once there are some");
        return number is not { } n ? asm.Edits[^1]
            : asm.Edits.FirstOrDefault(e => e.Number == n)
              ?? throw new ToolError(ErrorCode.NotFound, $"{asm.Id} has no edit #{n}; its edits are {string.Join(", ", asm.Edits.Select(e => "#" + e.Number))}.",
                  $"list_edits assembly={asm.Id} shows each edit's number");
    }

    /// <summary>Undoes one edit (by number; default the last) by rebuilding from the original image and replaying the others, which keep their numbers.</summary>
    public string Undo(LoadedAssembly asm, int? number, CancellationToken ct) => Undo(asm, number, ct, out _);

    public string Undo(LoadedAssembly asm, int? number, CancellationToken ct, out EditRecord removed)
    {
        removed = Find(asm, number);
        var records = asm.Edits.ToList();
        records.Remove(removed);
        Rebuild(asm, records, ct);
        return $"Undid #{removed.Number} ({removed.Description}). {asm.Id} now has {records.Count} edit(s).";
    }

    /// <summary>Discards all edits (back to the image the assembly was loaded from).</summary>
    public string RevertAll(LoadedAssembly asm, CancellationToken ct)
    {
        int count = asm.Edits.Count;
        Rebuild(asm, [], ct);
        return $"Reverted {asm.Id} to its loaded state ({count} edit(s) discarded).";
    }

    /// <summary>Resets to the original image and replays <paramref name="records"/>, restoring the previous state on
    /// failure; caller holds the write lock.</summary>
    public void Rebuild(LoadedAssembly asm, IReadOnlyList<EditRecord> records, CancellationToken ct)
    {
        var (previousModule, previousEdits) = asm.ResetToOriginal(workspace.DnlibContext);
        bool outer = _rebuilding;
        _rebuilding = true;
        try
        {
            ReplayAll(asm, records, previousModule, previousEdits, ct);
        }
        catch (OperationCanceledException)
        {
            asm.RestoreState(previousModule, previousEdits); // a cancelled undo or revert changes nothing
            throw;
        }
        finally { _rebuilding = outer; }
        previousModule.Dispose();
    }

    private void ReplayAll(LoadedAssembly asm, IReadOnlyList<EditRecord> records, ModuleDefMD previousModule, List<EditRecord> previousEdits, CancellationToken ct)
    {
        for (int i = 0; i < records.Count; i++)
        {
            CallProgress.Report(i, records.Count, $"replaying edit {i + 1} of {records.Count}: {records[i].Description}");
            try
            {
                int count = asm.Edits.Count;
                Apply(records[i], asm, preferTokens: true, ct);
                if (asm.Edits.Count > count) asm.Renumber(records[i].Number);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                asm.RestoreState(previousModule, previousEdits);
                int number = records[i].Number > 0 ? records[i].Number : i + 1;
                var reason = ex.Message.TrimEnd().Replace("Nothing was changed.", "").TrimEnd();
                throw new ToolError(ErrorCode.Conflict, $"Edit #{number} ({records[i].Description}) could not be re-applied: {reason}\nNothing was changed.");
            }
        }
    }

    /// <summary>True for a dry run, after offering the record it would make (its digest is reported).</summary>
    private static bool Previewed(bool dryRun, string kind, Dictionary<string, string?> args)
    {
        if (dryRun) EditPreview.Offer(new EditRecord(kind, args, "", []));
        return dryRun;
    }

    private static Dictionary<string, string?> SymbolArgs(string key, ResolvedSymbol symbol, string? label = null) => new()
    {
        [key] = label ?? symbol.Label,
        [key + "Kind"] = symbol.Kind,
        [key + "Token"] = Format.Token(symbol.Member),
        [key + "Signature"] = Signature(symbol.Member),
    };

    /// <summary>A method or indexer signature without tokens, to tell overloads apart on another build; null for others.</summary>
    internal static string? Signature(IMemberDef member) => (member switch { MethodDef m => (MethodBaseSig?)m.MethodSig, PropertyDef p => p.PropertySig, _ => null }) is { } sig
        ? $"{sig.GenParamCount}:{sig.RetType?.FullName}({string.Join(",", sig.Params.Select(t => t?.FullName))})"
        : null;

    private ResolvedSymbol Recorded(LoadedAssembly asm, EditRecord record, string key, bool preferTokens)
    {
        if (preferTokens && SymbolResolver.TryParseToken(record.Arg(key + "Token") ?? "", out uint token)
            && (token & 0x00FFFFFF) != 0 && asm.Module.ResolveToken(token) is IMemberDef def)
            return new ResolvedSymbol(asm, def);
        try
        {
            var label = Required(record, key);
            var all = SymbolResolver.Resolve(workspace, asm.Id, label, SymbolResolver.ParseKind(record.Arg(key + "Kind")), legacyLabels: record.LegacyLabels);
            // Overloads share a label: the recorded token, often stable between builds, picks one.
            if (all.Count > 1 && SymbolResolver.TryParseToken(record.Arg(key + "Token") ?? "", out uint recorded)
                && all.Where(r => r.Member.MDToken.Raw == recorded).ToList() is [var byToken])
                return byToken;
            // On another build the token may name another member; the recorded signature, when the script has one, does not.
            if (all.Count > 1 && record.Arg(key + "Signature") is { } signature)
            {
                if (all.Where(r => Signature(r.Member) == signature).ToList() is [var bySignature]) return bySignature;
            }
            else if (all.Count > 1 && record.LegacyLabels)
                throw new ToolError(ErrorCode.Ambiguous, $"'{label}' names {all.Count} members in {asm.Id}: the script predates generic arity in labels and " +
                    "recorded no signature or matching token:\n" + string.Join("\n", all.Take(30).Select(r => "  " + r)),
                    "load the script's source build too, or export the script again from it");
            return SymbolResolver.Single(all, label);
        }
        catch (ToolError) when (Remap?.Invoke(record, key) is { } renamed)
        {
            return renamed; // renamed or moved; matched by content against the original build
        }
    }

    private static int? IntArg(EditRecord record, string key) =>
        int.TryParse(record.Arg(key), NumberStyles.Integer, CultureInfo.InvariantCulture, out int v) ? v : null;

    private static string Required(EditRecord record, string key) =>
        record.Arg(key) ?? throw new ToolError(ErrorCode.MalformedInput, $"Edit '{record.Kind}' is missing its '{key}' argument.");

    private static MethodDef RequireBodyMethod(ResolvedSymbol symbol)
    {
        if (symbol.Member is not MethodDef m)
            throw new ToolError(ErrorCode.InvalidArgument, $"{symbol.Label} is a {symbol.Kind}, not a method.");
        if (m.IsAbstract || m.IsPinvokeImpl || m.IsRuntime || m.IsInternalCall)
            throw new ToolError(ErrorCode.Unsupported, $"{symbol.Label} has no IL body (abstract/extern/runtime).", NoBodyNext(m));
        if (m.MethodSig is not { RetType: not null } sig || sig.Params.Any(p => p == null))
            throw new ToolError(ErrorCode.MalformedInput, $"{symbol.Label} has a signature that cannot be read (malformed metadata); it cannot be patched.");
        return m;
    }

    /// <summary>Where the code of a method without IL lives, and the edit that reaches it.</summary>
    private static string NoBodyNext(MethodDef m) => m switch
    {
        { IsPinvokeImpl: true, ImplMap: { } map } =>
            $"the body is native: '{map.Name}' in {map.Module?.Name ?? "its library"}; load that library, find the export with list_exports and patch it with patch_bytes (or patch the managed callers, find_references)",
        { IsPinvokeImpl: true } => "the body is native: load the library it binds to, find the export with list_exports and patch it with patch_bytes",
        { IsAbstract: true } => "an abstract method has no code: patch its implementations (find_references kind=overrides)",
        _ => "the runtime implements this method: patch its managed callers instead (find_references)",
    };

    private static void Apply(MethodDef m, CilBody body)
    {
        body.SimplifyBranches();
        body.OptimizeBranches();
        body.UpdateInstructionOffsets();
        m.Body = body;
        m.ImplAttributes &= ~(MethodImplAttributes.InternalCall | MethodImplAttributes.Runtime);
    }

    private static string Listing(IList<Instruction> instructions)
    {
        // Unwritten bodies have no offsets; assign them for the preview.
        uint offset = 0;
        foreach (var i in instructions) { i.Offset = offset; offset += (uint)i.GetSize(); }
        return string.Join("\n", instructions.Select(i => "  " + i));
    }

    /// <summary>Writes the module, keeping untouched data as in the original; replacing the original needs replaceOriginal and
    /// backs it up to &lt;file&gt;.bak. <paramref name="strict"/> refuses any unrequested change. A failed save writes nothing.</summary>
    public string Save(LoadedAssembly asm, string? outputPath, bool overwrite, bool strict = false, bool replaceOriginal = false, bool versioned = false) =>
        Save(asm, outputPath, overwrite, strict, out _, replaceOriginal, versioned);

    /// <summary>What save_assembly wrote.</summary>
    public sealed record SavedFile(string OutputPath, long Bytes, string Sha256, int Edits, string? Backup)
    {
        /// <summary>The edits written, with the digests their dry runs and applied edits reported.</summary>
        public IReadOnlyList<SavedEdit> EditList { get; init; } = [];
    }

    public string Save(LoadedAssembly asm, string? outputPath, bool overwrite, bool strict, out SavedFile saved, bool replaceOriginal = false, bool versioned = false)
    {
        bool moved = false;
        var (target, isOriginal) = SaveTarget.Resolve(string.IsNullOrWhiteSpace(outputPath)
            ? OutputRoots.Default(asm.FilePath, Path.GetFileNameWithoutExtension(asm.FilePath) + ".patched" + Path.GetExtension(asm.FilePath), out moved)
            : outputPath, asm.FilePath, asm.OriginalSha256, overwrite, asm.SavedOverOriginalSha256, replaceOriginal, versioned);

        byte[] image;
        SaveReport report;
        try
        {
            (image, report) = asm.IsDirty ? asm.GetImage() : (asm.OriginalBytes, asm.SurveyOriginal());
        }
        // Other writer exceptions are server faults and reach the client as internal.
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new ToolError(ErrorCode.IoError, $"Could not write {asm.Id}: {ex.GetType().Name}: {ex.Message.TrimEnd('.')}. Nothing was written.");
        }
        if (strict && report.HasChanges)
            throw new ToolError(ErrorCode.Conflict, $"Not saved (strict=true): {report.Changed.Count()} member(s) would differ from the original without an edit. " +
                                $"Nothing was written; save without strict to accept the changes listed.{report.Describe()}");

        // A .wasm target is written as Webcil, to replace the file in a _framework folder.
        bool webcil = target.EndsWith(".wasm", StringComparison.OrdinalIgnoreCase);
        if (webcil) image = Webcil.FromPe(image);
        string? backup = isOriginal ? SaveTarget.Backup(target, asm.OriginalBytes) : null;
        SafeFile.WriteAllBytes(target, image, overwrite || isOriginal);
        saved = new SavedFile(target, image.LongLength, Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(image)), asm.Edits.Count, backup)
            { EditList = [.. asm.Edits.Select(e => new SavedEdit(new EditId(asm.Id, e.Number), e.ContentDigest()))] };
        if (isOriginal) asm.SavedOverOriginalSha256 = saved.Sha256;

        var kept = asm.IsDirty ? "everything no edit touched is as in the original" : "no edits: the original bytes";
        return $"Wrote {target} ({new FileInfo(target).Length:N0} bytes, {asm.Edits.Count} edit(s); {kept})." +
               (moved ? $" The loaded file's folder is outside the output roots, so the default copy went to the exports folder; pass outputPath under a root, or set {OutputRoots.Variable}." : "") +
               $"{(backup != null ? $" Original backed up to {backup}." : "")}" +
               (webcil ? " Written as Webcil; update or remove this file's integrity hash in blazor.boot.json or dotnet.boot.js." : "") +
               (saved.EditList.Count > 0 ? $"\nEdits written: {string.Join(", ", saved.EditList.Select(e => $"{e.Id} ({e.Digest})"))}." : "") +
               $"{report.Describe()}{(asm.IsDirty ? SignatureNotes(asm) : "")}";
    }

    /// <summary>What an edit does to the file's signatures: they cover the original bytes, so none survives a change.</summary>
    private static string SignatureNotes(LoadedAssembly asm)
    {
        var notes = new List<string>();
        try
        {
            using var pe = new System.Reflection.PortableExecutable.PEReader(new MemoryStream(asm.OriginalBytes, writable: false));
            if (pe.PEHeaders.PEHeader?.CertificateTableDirectory.Size > 0)
                notes.Add("The original is Authenticode-signed; the signature covers the original bytes, so the saved file is unsigned.");
        }
        catch (BadImageFormatException) { }
        if (asm.Module.Assembly?.PublicKey is { IsNullOrEmpty: false } && (asm.Module.Cor20HeaderFlags & dnlib.DotNet.MD.ComImageFlags.StrongNameSigned) != 0)
            notes.Add("The strong-name signature no longer matches: .NET Framework refuses it where strong names are verified unless " +
                      "re-signed with the original key or skipped (sn -Vr); .NET does not verify them.");
        return notes.Count == 0 ? "" : "\n\nSignatures:\n" + string.Join("\n", notes.Select(n => "  " + n));
    }
}
