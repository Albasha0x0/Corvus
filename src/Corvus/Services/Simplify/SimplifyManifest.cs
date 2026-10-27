using System.Text;
using dnlib.DotNet.Emit;

namespace Corvus.Services.Simplify;

/// <summary>Why an evaluation stopped, a rewrite was skipped, or a method was left unchanged.</summary>
public enum FallbackReason
{
    // The code is outside the interpreter's subset.
    UnsupportedInstruction,
    UnsupportedCall,
    NoBody,
    NativeCode,
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

    // Resource limits are not cached, since more budget may let the same code evaluate.
    CallDepth,
    InstructionBudget,
    MemoryLimit,
    TimeLimit,

    // One rewrite skipped; the rest of the method is simplified.
    FlattenedShape,
    DelegateTarget,

    // Whole methods.
    OriginalUnverifiable,
    UnreadableBodies,
    ResultUnverifiable,
    Unexpected,
}

/// <summary>The simplification engine's contract: evaluated instructions and intrinsics, limits and fallback reasons; generates docs/simplify.md.</summary>
public static class SimplifyManifest
{
    public sealed record ReasonInfo(FallbackReason Reason, string Code, string Description, bool Transient = false);

    public static readonly IReadOnlyList<ReasonInfo> Reasons =
    [
        new(FallbackReason.UnsupportedInstruction, "unsupported-instruction", "an IL instruction that is not in the instruction table below"),
        new(FallbackReason.UnsupportedCall, "unsupported-call", "a call to a framework or other method that is neither an intrinsic nor IL of the same module (I/O, reflection, threading, ...)"),
        new(FallbackReason.NoBody, "no-body", "the callee has no IL body: P/Invoke, internal call, runtime-implemented or abstract"),
        new(FallbackReason.NativeCode, "native-code", "a native method of the module that the evaluator does not run: not static, not 32-bit integers in and out, not a 32-bit x86 image, or code outside the native subset (see Native routines); the message names the instruction and its offset"),
        new(FallbackReason.OtherModule, "other-module", "the callee or a static field belongs to another module, whose code may differ at run time"),
        new(FallbackReason.Generic, "generic", "a generic method of another module or an instance generic method, a member of a generic type, or a type argument that is not a closed type"),
        new(FallbackReason.ExceptionHandling, "exception-handling", "the callee has exception handlers, or the code throws"),
        new(FallbackReason.InstanceObject, "instance-object", "uses an object the evaluation did not create (an instance passed in from outside, or a delegate bound to an object) or calls an instance method on such an object"),
        new(FallbackReason.UnsupportedValue, "unsupported-value", "a value the interpreter does not model: a Nullable<T> box, an unbox as another type, an unmanaged pointer, a typed reference, a struct of another module or with explicit layout, an array of structs, a type token"),
        new(FallbackReason.MutableStatic, "mutable-static", "reads a static field that is not readonly, writes one outside its type's static constructor (see Static state for the exception), or modifies an object a static field holds"),
        new(FallbackReason.UnmodeledInstance, "unmodeled-instance", "creates an instance of a class outside the modelled subset: with a finalizer or events, generic, derived from another assembly's class, an interop class (COM import, explicit layout), or more than 8 levels deep"),
        new(FallbackReason.VirtualDispatch, "virtual-dispatch", "a call on a modelled instance that does not resolve to one method of the module: a framework method or override (ToString, Equals, ...), an abstract method, or an interface method the module does not implement"),
        new(FallbackReason.CacheDependent, "cache-dependent", "a static Dictionary or List the code reads can change the result: a repeated call on the state the first left gives another result; or the collection is used other than through its own methods (passed on, stored, returned, its address taken), is visible to other assemblies, is written outside its type's initialization, or has a custom key comparer"),
        new(FallbackReason.WritableStream, "writable-stream", "writes to a stream (Write, WriteByte, SetLength, Flush, CopyTo) or creates an empty MemoryStream to write into; the evaluator only reads streams"),
        new(FallbackReason.ExternalIo, "external-io", "reads what differs between runs or machines: files, the network, another assembly's resources, the entry assembly, the module's own path, the base and current directories, special folders, environment variables, the machine and user names (deterministicEnvironment pins these; see below), or a generated key or IV"),
        new(FallbackReason.StaticInitializer, "static-initializer", "the static constructor of a type the code needs cannot be evaluated, or the code can run during it. Inside that constructor, a call it reaches at most once (on no loop, in no handler) uses the state at the call; otherwise it is kept"),
        new(FallbackReason.RuntimeError, "runtime-error", "the code would throw at run time: division by zero, checked overflow, index out of range, null reference, invalid cast, invalid argument"),
        new(FallbackReason.PlatformDependent, "platform-dependent", "the result would differ between platforms or cultures: native int values outside the 32-bit range, an out-of-range float to integer conversion, culture-sensitive formatting, path syntax (Windows semantics under deterministicEnvironment)"),
        new(FallbackReason.InvalidCode, "invalid-code", "the evaluated code is not valid IL: stack underflow, mismatched operand types, a branch outside the method, execution past its end"),
        new(FallbackReason.CallDepth, "call-depth", "nested calls exceed the depth limit (maxDepth)", Transient: true),
        new(FallbackReason.InstructionBudget, "instruction-budget", "the evaluation, nested calls and static constructors included, ran past its budget, or the method's total budget ran out; a type initializer was stopped by the initializer tier (see Limits)", Transient: true),
        new(FallbackReason.MemoryLimit, "memory-limit", "the evaluation allocated more simulated memory (arrays, strings, builders) than the limit", Transient: true),
        new(FallbackReason.TimeLimit, "time-limit", "simplifying the method took longer than its time limit; the method is left unchanged", Transient: true),
        new(FallbackReason.FlattenedShape, "flattened-shape", "flattened control flow (a loop over a switch on a state) whose dispatcher cannot be removed: a path into it selects different cases on different runs (the state depends on unknown values or the path taken), code outside it reads a path-dependent state value a store inside it can reach, the state's address is taken, the dispatcher or a case is in another protected region, or the analysis passes 1,024 states; the dispatcher is kept and the other passes still apply"),
        new(FallbackReason.DelegateTarget, "delegate-target", "a call through a static delegate field whose target can differ between runs: the field is written outside its type's initialization or other assemblies can access it, the initialization cannot be evaluated (the message says why), the delegate is bound to an object other than a field-less instance a reachable static field holds, or calls an instance method directly, its dynamic method does more than pass its arguments on, or it is not loaded right before its arguments; the call is kept"),
        new(FallbackReason.OriginalUnverifiable, "original-unverifiable", "the original body does not pass the stack verifier, so it is not rewritten"),
        new(FallbackReason.UnreadableBodies, "unreadable-bodies", "a quarter or more of the module's method bodies cannot be read as IL: they are stored in another form and restored at run time. Bodies that decode are not the code that runs, and a rewritten image would not run, so no method is rewritten"),
        new(FallbackReason.ResultUnverifiable, "result-unverifiable", "the rewritten body did not pass the stack verifier; the method is left unchanged"),
        new(FallbackReason.Unexpected, "unexpected", "an unexpected error while reading or rewriting the body (malformed metadata or a defect); the method is left unchanged"),
    ];

    private static readonly Dictionary<FallbackReason, ReasonInfo> ByReason = Reasons.ToDictionary(r => r.Reason);

    public static ReasonInfo Info(FallbackReason reason) => ByReason[reason];

    public static string CodeOf(FallbackReason reason) => ByReason[reason].Code;

    public sealed record InstructionGroup(string Name, string Notes, IReadOnlyList<Code> Codes);

    /// <summary>The instructions the interpreter evaluates; any other stops evaluation with unsupported-instruction.</summary>
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
            "static fields of the same module that are readonly, or that only the type's initialization writes and other assemblies cannot, after evaluating the type's static constructor once; an instance with no fields held there (a lambda class's singleton) cannot change, so any code may read it; so may an array or builder held there when every load of the field outside the initialization only reads it (element and length reads, read-only intrinsics, module methods that only read the parameter, and calls through static delegate fields whose delegate, as its type's initialization leaves it, passes the object on unchanged to such a method or intrinsic); writes only inside static constructors (by stsfld or FieldInfo.SetValue). A static field of a type B that the static constructor of one other type A writes is modelled when every read is ordered against that write: other assemblies cannot access it, A has a static constructor that runs precisely (not beforefieldinit) and cannot run during B's, and the field is read only by B's initialization (before the write), A's (in its own order) or A's own methods that cannot run during A's initialization (after it); the write runs B's initialization first, as the access does at run time; otherwise the write and the reads keep their mutable-static bail-outs; ldtoken of fields, types and methods", [
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
            "intrinsics (below), and static methods and struct methods with IL bodies in the same module; static generic methods of the module with closed type arguments (!!n in parameter, local and operand types replaced by the instantiation's); newobj of strings, StringBuilder and module structs; delegates of static methods (ldftn and the delegate constructor, Delegate.CreateDelegate) and of instance methods bound to an instance with no fields and of dynamic methods, invoked through Invoke. A dynamic method's code is built with ILGenerator.Emit or given to its DynamicILInfo (SetCode, with tokens from GetTokenFor, numbered as the runtime numbers them, decoded when the delegate is created); both ways accept the same instructions: arguments, constants, strings, members and types, but no locals, labels, switch tables, floating-point constants, signatures or exception handlers", [
            Code.Call, Code.Callvirt, Code.Newobj, Code.Ldftn]),
    ];

    public static readonly IReadOnlySet<Code> SupportedInstructions = Instructions.SelectMany(g => g.Codes).ToHashSet();

    /// <summary>Framework methods evaluated by the interpreter, as dnlib full names.</summary>
    public static IReadOnlyList<string> Intrinsics => IlEvaluator.IntrinsicNames.Order(StringComparer.Ordinal).ToList();

    /// <summary>The native methods <see cref="NativeRoutine"/> runs.</summary>
    public const string NativeRoutines =
        "A call to a native method of the module (native code in the image itself, not a P/Invoke import) is run as x86 machine code " +
        "when the method is static, takes and returns 32-bit integers, and the image runs as a 32-bit x86 process (x86 machine, 32-bit " +
        "required or preferred). The code runs on concrete values from its first byte, with the arguments where a 32-bit caller leaves " +
        "them, until ret gives eax; each instruction counts against the budget, and at most 4,096 bytes of code are read. Instructions: " +
        NativeRoutine.Subset + ". Memory is the routine's own stack frame (4 KB below the return address) and its arguments. Registers " +
        "the caller left and stack memory not yet written are unknown: a result, branch or address that depends on them, an absolute " +
        "address, an instruction outside the list, or esp not back at the return address at ret stops evaluation (`native-code`).";

    public static readonly IReadOnlyList<(string Name, string Value)> Limits =
    [
        ("maxDepth", $"{new EvaluationLimits().MaxDepth} frames, the evaluated call included (tool parameter, 1-64)"),
        ("budget", $"{new EvaluationLimits().InstructionBudget:N0} instructions per evaluation, shared by nested calls and the static constructors they trigger (tool parameter)"),
        ("method budget", $"{new EvaluationLimits().MethodInstructionBudget:N0} instructions across all evaluations of one method"),
        ("memory", $"{new EvaluationLimits().MemoryLimit / (1024 * 1024)} MB of simulated allocations per evaluation, static state included"),
        ("time", $"{new EvaluationLimits().MethodTimeLimit.TotalSeconds:0} s of CPU time per method, all passes included, and at most {MethodMeter.WallFactor} times that of wall time"),
        ("arrays and strings", "1M elements / characters"),
        ("initializer tier", "a static constructor run whose budget runs out gets one more budget-sized window, with its writes tracked; a run " +
                             "that makes no progress there fails as without the tier (budget exhausted, not reported, not remembered). Each further window " +
                             $"needs new state from the last: per {IlEvaluator.ProgressRatio:N0} instructions, one location (array element, static or object " +
                             "field, a grown collection or builder) took a new value, each location counted once per window, and the written state differs " +
                             "from every earlier window's end (a repeat is a cycle). " +
                             $"Up to {new EvaluationLimits().InitializerInstructionCeiling:N0} instructions, " +
                             $"{new EvaluationLimits().InitializerTimeLimit.TotalSeconds:0} s of CPU time and {MethodMeter.WallFactor} times that of wall time per run, " +
                             "charged to neither the triggering evaluation nor the method. Reports list the runs that used it; a failed run is remembered"),
    ];

    /// <summary>Renders docs/simplify.md.</summary>
    public static string Markdown()
    {
        var sb = new StringBuilder();
        sb.Append("""
            # simplify_methods: engine contract

            Generated from `SimplifyManifest` (src/Corvus/Services/Simplify/SimplifyManifest.cs); a test keeps the two in sync.

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
        sb.Append("\n## Native routines\n\n").Append(NativeRoutines).Append('\n');
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
