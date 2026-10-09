using System.Text;
using dnlib.DotNet.Emit;

namespace NetDecompilerMcp.Services.Simplify;

/// <summary>Why an evaluation stopped, a rewrite was skipped, or a method was left unchanged. Every fallback carries one.</summary>
public enum FallbackReason
{
    // The interpreter: the code is outside the supported subset.
    UnsupportedInstruction,
    UnsupportedCall,
    NoBody,
    OtherModule,
    Generic,
    ExceptionHandling,
    InstanceObject,
    UnsupportedValue,
    MutableStatic,
    StaticInitializer,
    UnmodeledInstance,
    VirtualDispatch,
    CacheDependent,
    WritableStream,
    ExternalIo,
    RuntimeError,
    PlatformDependent,
    InvalidCode,

    // Resource limits. These are not cached: the same code may evaluate when reached with more budget left.
    CallDepth,
    InstructionBudget,
    MemoryLimit,
    TimeLimit,

    // One rewrite skipped; the rest of the method is still simplified.
    FlattenedShape,
    DelegateTarget,

    // Whole methods.
    OriginalUnverifiable,
    UnreadableBodies,
    ResultUnverifiable,
    Unexpected,
}

/// <summary>
/// The contract of the simplification engine: the IL instructions and framework calls the interpreter evaluates, and the
/// closed set of reasons for which evaluation stops or a rewrite is refused. Anything not listed stops evaluation and
/// leaves the code as it was. docs/simplify.md is generated from this class (see <see cref="Markdown"/>).
/// </summary>
public static class SimplifyManifest
{
    public sealed record ReasonInfo(FallbackReason Reason, string Code, string Description, bool Transient = false);

    public static readonly IReadOnlyList<ReasonInfo> Reasons =
    [
        new(FallbackReason.UnsupportedInstruction, "unsupported-instruction", "an IL instruction that is not in the instruction table below"),
        new(FallbackReason.UnsupportedCall, "unsupported-call", "a call to a framework or other method that is neither an intrinsic nor IL of the same module (I/O, reflection, threading, ...)"),
        new(FallbackReason.NoBody, "no-body", "the callee has no IL body: P/Invoke, internal call, runtime-implemented or abstract"),
        new(FallbackReason.OtherModule, "other-module", "the callee or a static field belongs to another module, whose code may differ at run time"),
        new(FallbackReason.Generic, "generic", "a generic method of another module or an instance generic method, a member of a generic type, or a type argument that is not a closed type"),
        new(FallbackReason.ExceptionHandling, "exception-handling", "the callee has exception handlers, or the code throws"),
        new(FallbackReason.InstanceObject, "instance-object", "uses an object the evaluation did not create (an instance passed in from outside, or a delegate bound to an object) or calls an instance method on such an object"),
        new(FallbackReason.UnsupportedValue, "unsupported-value", "a value the interpreter does not model: Nullable<T> boxes, unboxing as another type, unmanaged pointers, typed references, structs of other modules or with explicit layout, arrays of structs, type tokens"),
        new(FallbackReason.MutableStatic, "mutable-static", "reads a static field that is not readonly, writes a static field outside a static constructor, or modifies an object held in a static field"),
        new(FallbackReason.UnmodeledInstance, "unmodeled-instance", "creates an instance of a class outside the modelled subset: a class with a finalizer or events, a generic class, a class whose base class belongs to another assembly (exceptions, framework classes), an interop class (COM import, explicit layout), or a hierarchy deeper than 8 levels"),
        new(FallbackReason.VirtualDispatch, "virtual-dispatch", "a call on a modelled instance that does not resolve to one method of the module: a framework method or the framework implementation of a virtual method (ToString, Equals, ...), an abstract method, or an interface method the class does not implement in the module"),
        new(FallbackReason.CacheDependent, "cache-dependent", "a static Dictionary or List the code reads is not a cache whose contents cannot change the result: called again on the state the first call left, the call gives another result; or the collection is used other than through its own methods (passed on, stored, returned, its address taken), is visible to other assemblies, is written outside its type's initialization, or compares keys with a custom comparer"),
        new(FallbackReason.WritableStream, "writable-stream", "writes to a stream (Write, WriteByte, SetLength, Flush, CopyTo) or creates an empty MemoryStream to write into; the evaluator only reads streams"),
        new(FallbackReason.ExternalIo, "external-io", "reads what differs between runs or machines: files (File, FileStream, Directory, StreamReader over a path), the network (System.Net), another assembly's resources, the entry assembly, the module's own path, the base and current directories, special folders, environment variables, the machine and user names (the deterministicEnvironment option pins these; see below), or a key or IV an algorithm object generated"),
        new(FallbackReason.StaticInitializer, "static-initializer", "the static constructor of a type the code needs cannot be evaluated, or the code can run while it runs. Inside that static constructor itself, a call uses the state as it stands at the call when the constructor reaches the call at most once (on no loop, in no handler) and runs up to it; otherwise it is kept"),
        new(FallbackReason.RuntimeError, "runtime-error", "the code would throw at run time: division by zero, checked overflow, index out of range, null reference, invalid cast, invalid argument"),
        new(FallbackReason.PlatformDependent, "platform-dependent", "the result would differ between platforms or cultures: native int values outside the 32-bit range, out-of-range float to integer conversion, culture-sensitive formatting, path syntax (System.IO.Path; Windows semantics under deterministicEnvironment)"),
        new(FallbackReason.InvalidCode, "invalid-code", "the evaluated code is not valid IL: stack underflow, mismatched operand types, a branch outside the method, execution past its end"),
        new(FallbackReason.CallDepth, "call-depth", "nested calls exceed the depth limit (maxDepth)", Transient: true),
        new(FallbackReason.InstructionBudget, "instruction-budget", "the evaluation, including nested calls and static constructors, executed more instructions than the budget allows, or the method's total budget ran out; for a type initializer, the extended tier stopped it (no new state committed in a window, its ceiling or its time limit)", Transient: true),
        new(FallbackReason.MemoryLimit, "memory-limit", "the evaluation allocated more simulated memory (arrays, strings, builders) than the limit", Transient: true),
        new(FallbackReason.TimeLimit, "time-limit", "simplifying the method took longer than its time limit; the method is left unchanged", Transient: true),
        new(FallbackReason.FlattenedShape, "flattened-shape", "flattened control flow (a loop over a switch on a state) whose dispatcher cannot be removed: run through per state, some way into it does not select the same case on every run (the state depends on arguments or other unknown values, or on the path taken), code outside it reads a value of the state that depends on the path taken and that a store inside the dispatcher can reach (reads no such store reaches stay as they are), the state's address is taken, the dispatcher or a case is in another protected region, or the analysis exceeds its limits (1,024 states); the dispatcher is kept as it is and the other passes still apply to the method"),
        new(FallbackReason.DelegateTarget, "delegate-target", "a call through a static delegate field whose target is not known to be the same on every run: the field is written outside its type's initialization or is accessible to other assemblies, the initialization cannot be evaluated (the message says why), the delegate is bound to an object other than a field-less instance that a static field accessible at the call holds, or calls an instance method directly, its dynamic method does more than pass its arguments on, or the delegate is not loaded right before its arguments; the call is kept"),
        new(FallbackReason.OriginalUnverifiable, "original-unverifiable", "the original body does not pass the stack verifier, so it is not rewritten"),
        new(FallbackReason.UnreadableBodies, "unreadable-bodies", "a quarter or more of the module's method bodies cannot be read as IL: they are stored in another form on disk and restored at run time (an integrity check). Bodies that happen to decode are not the code that runs, and a rewritten image would not run, so no method of the module is rewritten"),
        new(FallbackReason.ResultUnverifiable, "result-unverifiable", "the rewritten body did not pass the stack verifier; the method is left unchanged"),
        new(FallbackReason.Unexpected, "unexpected", "an unexpected error while reading or rewriting the body (malformed metadata or a defect); the method is left unchanged"),
    ];

    private static readonly Dictionary<FallbackReason, ReasonInfo> ByReason = Reasons.ToDictionary(r => r.Reason);

    public static ReasonInfo Info(FallbackReason reason) => ByReason[reason];

    public static string CodeOf(FallbackReason reason) => ByReason[reason].Code;

    public sealed record InstructionGroup(string Name, string Notes, IReadOnlyList<Code> Codes);

    /// <summary>The instructions the interpreter evaluates. Every other instruction stops evaluation (unsupported-instruction).</summary>
    public static readonly IReadOnlyList<InstructionGroup> Instructions =
    [
        new("Constants and stack", "", [
            Code.Nop, Code.Ldc_I4, Code.Ldc_I4_S, Code.Ldc_I4_M1, Code.Ldc_I4_0, Code.Ldc_I4_1, Code.Ldc_I4_2, Code.Ldc_I4_3,
            Code.Ldc_I4_4, Code.Ldc_I4_5, Code.Ldc_I4_6, Code.Ldc_I4_7, Code.Ldc_I4_8, Code.Ldc_I8, Code.Ldc_R4, Code.Ldc_R8,
            Code.Ldnull, Code.Ldstr, Code.Dup, Code.Pop]),
        new("Prefixes", "no effect on the evaluated result; after constrained., callvirt gets the value's address as its receiver", [Code.Tailcall, Code.Volatile, Code.Unaligned, Code.Readonly, Code.Constrained]),
        new("Arguments and locals", "struct values are copied on load and store; ldarga / ldloca give managed pointers", [
            Code.Ldarg, Code.Ldarg_S, Code.Ldarg_0, Code.Ldarg_1, Code.Ldarg_2, Code.Ldarg_3, Code.Starg, Code.Starg_S, Code.Ldarga, Code.Ldarga_S,
            Code.Ldloc, Code.Ldloc_S, Code.Ldloc_0, Code.Ldloc_1, Code.Ldloc_2, Code.Ldloc_3, Code.Stloc, Code.Stloc_S,
            Code.Stloc_0, Code.Stloc_1, Code.Stloc_2, Code.Stloc_3, Code.Ldloca, Code.Ldloca_S]),
        new("Arithmetic and bit operations",
            "int32, int64 and native int; native int results must be the same on 32- and 64-bit platforms; float32 operands are computed in single precision as the JIT does; division by zero and checked overflow stop evaluation", [
            Code.Add, Code.Sub, Code.Mul, Code.Div, Code.Div_Un, Code.Rem, Code.Rem_Un, Code.And, Code.Or, Code.Xor, Code.Shl, Code.Shr, Code.Shr_Un,
            Code.Add_Ovf, Code.Add_Ovf_Un, Code.Sub_Ovf, Code.Sub_Ovf_Un, Code.Mul_Ovf, Code.Mul_Ovf_Un, Code.Neg, Code.Not, Code.Ckfinite]),
        new("Comparisons", "references compare by identity or against null", [Code.Ceq, Code.Cgt, Code.Cgt_Un, Code.Clt, Code.Clt_Un]),
        new("Conversions",
            "exact ECMA-335 semantics: truncation, sign / zero extension, overflow checks of conv.ovf; out-of-range float to integer conversion (undefined) stops evaluation", [
            Code.Conv_I1, Code.Conv_I2, Code.Conv_I4, Code.Conv_I8, Code.Conv_U1, Code.Conv_U2, Code.Conv_U4, Code.Conv_U8, Code.Conv_I, Code.Conv_U,
            Code.Conv_R4, Code.Conv_R8, Code.Conv_R_Un, Code.Conv_Ovf_I1, Code.Conv_Ovf_I2, Code.Conv_Ovf_I4, Code.Conv_Ovf_I8, Code.Conv_Ovf_U1,
            Code.Conv_Ovf_U2, Code.Conv_Ovf_U4, Code.Conv_Ovf_U8, Code.Conv_Ovf_I, Code.Conv_Ovf_U, Code.Conv_Ovf_I1_Un, Code.Conv_Ovf_I2_Un,
            Code.Conv_Ovf_I4_Un, Code.Conv_Ovf_I8_Un, Code.Conv_Ovf_U1_Un, Code.Conv_Ovf_U2_Un, Code.Conv_Ovf_U4_Un, Code.Conv_Ovf_U8_Un,
            Code.Conv_Ovf_I_Un, Code.Conv_Ovf_U_Un]),
        new("Branches", "loops run within the shared instruction budget", [
            Code.Br, Code.Br_S, Code.Brtrue, Code.Brtrue_S, Code.Brfalse, Code.Brfalse_S, Code.Beq, Code.Beq_S, Code.Bne_Un, Code.Bne_Un_S,
            Code.Bge, Code.Bge_S, Code.Bge_Un, Code.Bge_Un_S, Code.Bgt, Code.Bgt_S, Code.Bgt_Un, Code.Bgt_Un_S, Code.Ble, Code.Ble_S,
            Code.Ble_Un, Code.Ble_Un_S, Code.Blt, Code.Blt_S, Code.Blt_Un, Code.Blt_Un_S, Code.Switch, Code.Ret]),
        new("Exception regions",
            "try blocks run as plain code and leave runs the finally handlers it exits; nothing is ever caught: code that throws stops evaluation, so catch and fault handlers never run; exception filters are not modelled", [
            Code.Leave, Code.Leave_S, Code.Endfinally]),
        new("Arrays", "one-dimensional arrays of primitives, strings and other references; at most 1M elements", [
            Code.Newarr, Code.Ldlen, Code.Ldelema, Code.Ldelem_I1, Code.Ldelem_U1, Code.Ldelem_I2, Code.Ldelem_U2, Code.Ldelem_I4, Code.Ldelem_U4,
            Code.Ldelem_I8, Code.Ldelem_I, Code.Ldelem_R4, Code.Ldelem_R8, Code.Ldelem_Ref, Code.Ldelem, Code.Stelem_I1, Code.Stelem_I2,
            Code.Stelem_I4, Code.Stelem_I8, Code.Stelem_I, Code.Stelem_R4, Code.Stelem_R8, Code.Stelem_Ref, Code.Stelem]),
        new("Stack memory", "localloc (stackalloc) gives a zeroed buffer of at most 1M bytes; pointers into it move by add / sub, and ldind / stind read and write it little-endian", [
            Code.Localloc]),
        new("Indirect access", "through managed pointers to arguments, locals, array elements, struct fields and static fields, and through pointers into stack memory", [
            Code.Ldind_I1, Code.Ldind_U1, Code.Ldind_I2, Code.Ldind_U2, Code.Ldind_I4, Code.Ldind_U4, Code.Ldind_I8, Code.Ldind_I,
            Code.Ldind_R4, Code.Ldind_R8, Code.Ldind_Ref, Code.Stind_I1, Code.Stind_I2, Code.Stind_I4, Code.Stind_I8, Code.Stind_I,
            Code.Stind_R4, Code.Stind_R8, Code.Stind_Ref]),
        new("Objects and value types", "structs defined in the same module (sequential or auto layout), enums and primitives; instances of the module's classes (see unmodeled-instance) created by the evaluated code, with their fields, constructors, and instance and virtual methods dispatched within the module; new object(); a field of a class that nothing in the module writes (and no other assembly can) reads as its default on every object, which folds conditions on it even where the object itself cannot be evaluated (the load is kept: it still throws on null)", [
            Code.Ldobj, Code.Stobj, Code.Initobj, Code.Ldfld, Code.Ldflda, Code.Stfld]),
        new("Static state",
            "static fields of the same module that are readonly, or that only the type's initialization writes and other assemblies cannot, after evaluating the type's static constructor once; an instance with no fields held there (a lambda class's singleton) cannot change, so any code may read it; writes only inside static constructors (by stsfld or FieldInfo.SetValue); ldtoken of fields, types and methods", [
            Code.Ldsfld, Code.Ldsflda, Code.Stsfld, Code.Ldtoken]),
        new("Collections",
            "Dictionary<K, V> (keys: numbers and strings) and List<T>: construction, Add, indexers, TryGetValue, ContainsKey, Remove, Count, Clear, Contains, IndexOf, Insert, RemoveAt, ToArray, and foreach over them in the order of addition (a dictionary after a removal is not enumerated); Monitor.Enter / Exit (lock) succeed at once. A static collection the code only uses through its own methods, written only by its type's initialization, counts as a cache: each evaluation starts from the state the initialization left, and the call made again on the state it leaves must give the same result (see cache-dependent). System.Collections.SortedList with boxed integer keys of one type: construction, Add, the indexer, ContainsKey / Contains, Count, GetByIndex, GetKey, IndexOfKey, Remove, Clear (string keys: the default comparer orders them by the current culture). Enum.GetValues of the module's enums, sorted by unsigned value",
            []),
        new("Resources and streams",
            "the module's own embedded resources: Assembly.GetManifestResourceNames and GetManifestResourceStream (the executing, calling or a type's own assembly); read-only streams over them or over byte arrays (MemoryStream): Read, ReadByte, Length, Position, Seek, Close; BinaryReader (bytes, integers, floats, strings with a 7-bit length) and StreamReader (UTF-8 or an explicit encoding, byte-order marks detected as the CLR does) over them. The same resource reads the same bytes on every run; its bytes count against the simulated memory. ResourceManager over the module's own assembly: GetString reads the neutral resources (the embedded baseName.resources) for the invariant culture, or for the current UI culture under the deterministic environment; a lazily created ResourceManager in a static field (the generated Resources class) reads as an equivalent manager when every store builds one from the same base name and only its getters read it. A static field that only methods nothing can call write (no callers, not callable by other assemblies, friends included) holds its default",
            []),
        new("Boxing", "box gives an immutable object holding the value (box of a reference, as for a type argument that is a class, leaves it as it is); unbox.any and unbox take the value back out of a box of the same type, or of an enum and its underlying integer type; unbox.any of a reference type is castclass; Nullable<T> is not boxed", [
            Code.Box, Code.Unbox, Code.Unbox_Any]),
        new("Sizes", "sizeof of primitive and enum types; native-size types differ between platforms", [Code.Sizeof]),
        new("Type tests", "System.Object, System.String, System.Text.StringBuilder and System.Text.Encoding targets", [Code.Isinst, Code.Castclass]),
        new("Calls",
            "intrinsics (below), and static methods and struct methods with IL bodies in the same module; static generic methods of the module with closed type arguments (!!n in parameter, local and operand types replaced by the instantiation's); newobj of strings, StringBuilder and module structs; delegates of static methods (ldftn and the delegate constructor, Delegate.CreateDelegate) and of instance methods bound to an instance with no fields and of dynamic methods, invoked through Invoke", [
            Code.Call, Code.Callvirt, Code.Newobj, Code.Ldftn]),
    ];

    public static readonly IReadOnlySet<Code> SupportedInstructions = Instructions.SelectMany(g => g.Codes).ToHashSet();

    /// <summary>Framework methods evaluated by the interpreter, as dnlib full names.</summary>
    public static IReadOnlyList<string> Intrinsics => IlEvaluator.IntrinsicNames.Order(StringComparer.Ordinal).ToList();

    public static readonly IReadOnlyList<(string Name, string Value)> Limits =
    [
        ("maxDepth", $"{new EvaluationLimits().MaxDepth} frames, the evaluated call included (tool parameter, 1-64)"),
        ("budget", $"{new EvaluationLimits().InstructionBudget:N0} instructions per evaluation, shared by nested calls and the static constructors they trigger (tool parameter)"),
        ("method budget", $"{new EvaluationLimits().MethodInstructionBudget:N0} instructions across all evaluations of one method"),
        ("memory", $"{new EvaluationLimits().MemoryLimit / (1024 * 1024)} MB of simulated allocations per evaluation, static state included"),
        ("time", $"{new EvaluationLimits().MethodTimeLimit.TotalSeconds:0} s per method, all passes included"),
        ("arrays and strings", "1M elements / characters"),
        ("initializer tier", "a static constructor run (with everything it calls) whose budget runs out gets one more window of the budget's size, " +
                             "observed (its writes are tracked from then on; a run that ends or stops there without progress for what it ran fails as " +
                             "without the tier: budget exhausted, not reported, not remembered), and each further window while " +
                             $"the window just finished committed new state: per {IlEvaluator.ProgressRatio:N0} instructions, at least one location got a value " +
                             "it did not hold (an array element, a static field, a field of an object; a collection or builder that grew), each location " +
                             "counted once per window, so loops that only change locals or the same few locations earn nothing; and a fingerprint of every " +
                             "location the run wrote differs from its value at the end of each earlier window (a run whose state comes back is a cycle). " +
                             $"Up to {new EvaluationLimits().InitializerInstructionCeiling:N0} instructions and " +
                             $"{new EvaluationLimits().InitializerTimeLimit.TotalSeconds:0} s per run, accounted apart: the evaluation that triggered it " +
                             "gets its budget back and the method's total budget and time are not charged. Reports list the runs that used it; a failed " +
                             "run is remembered. Other evaluations keep the defaults above"),
    ];

    /// <summary>docs/simplify.md.</summary>
    public static string Markdown()
    {
        var sb = new StringBuilder();
        sb.Append("""
            # simplify_methods: engine contract

            Generated from `SimplifyManifest` (src/NetDecompilerMcp/Services/Simplify/SimplifyManifest.cs); a test keeps the two in sync.

            The engine rewrites copies of method bodies and keeps a rewrite only when the result passes the stack verifier. Every
            evaluation that leaves the supported subset stops at that point and leaves the code as it was; every skipped rewrite and
            every method left unchanged is reported with one of the reasons below.

            ## Interpreter instructions

            | Group | Instructions | Notes |
            |---|---|---|

            """);
        foreach (var g in Instructions)
            sb.Append($"| {g.Name} | {string.Join(" ", g.Codes.Select(c => "`" + c.ToOpCode().Name + "`"))} | {g.Notes} |\n");
        sb.Append("\nEvery other instruction stops evaluation with `unsupported-instruction`.\n\n## Intrinsics\n\nFramework methods evaluated directly (deterministic and culture-independent for the values they accept):\n\n");
        foreach (var name in Intrinsics) sb.Append($"- `{name}`\n");
        sb.Append("\n## Limits\n\n| Limit | Default |\n|---|---|\n");
        foreach (var (name, value) in Limits) sb.Append($"| {name} | {value} |\n");
        sb.Append("""

            ## Deterministic environment (opt-in)

            Off unless simplify_methods is called with `deterministicEnvironment: true`. Initialization code often reads what differs
            between machines: the module's own path (to read its own file), the application's directories, special folders,
            environment variables. Without the option these reads stop evaluation (`external-io`, or `platform-dependent` for path
            syntax). With it, they read the fixed stand-ins below, the way a test host pins Environment.GetFolderPath, so
            evaluation is the same on every run and every machine; whatever folds from them holds for that stand-in environment,
            which the report header names. The clock, random numbers and the network are never pinned.

            | Read | Stand-in |
            |---|---|

            """);
        foreach (var (member, value) in EnvironmentStandIns.Table("{module file name}")) sb.Append($"| {member} | {value} |\n");
        sb.Append("\n## Fallback reasons\n\n| Code | Meaning |\n|---|---|\n");
        foreach (var r in Reasons) sb.Append($"| `{r.Code}` | {r.Description}{(r.Transient ? " (resource limit)" : "")} |\n");
        return sb.ToString();
    }
}
