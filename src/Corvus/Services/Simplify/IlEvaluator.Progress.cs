using System.Diagnostics;
using System.Runtime.CompilerServices;
using dnlib.DotNet;
using Corvus.Core;

namespace Corvus.Services.Simplify;

/// <summary>A type initializer run that went past the instruction budget into the extended tier.</summary>
public sealed record ExtendedInitializer(string Type, long Instructions, bool Completed, string? Stop);

/// <summary>
/// The extended tier for type initializers: a run that exhausts the instruction budget while committing new state gets
/// further budget windows. Rules and limits: SimplifyManifest's "initializer tier" entry (docs/simplify.md).
/// </summary>
internal sealed partial class IlEvaluator
{
    /// <summary>Instructions per changed location a window must commit to earn the next one.</summary>
    internal const int ProgressRatio = 1024;

    private int _window; // numbers windows (across runs): a location counts once per window
    private long _progress; // locations changed in the current window
    private ulong _state; // fingerprint of the locations the current run wrote
    private readonly HashSet<ulong> _windowStates = new();
    private long _tierGranted; // instructions granted beyond the budget in the current run
    private TimeSpan _runStart, _runWallStart; // thread CPU and wall time when the current initializer run began
    private long _budgetAtRun; // the evaluation's budget when the current initializer run began
    private string? _tierStop; // why the tier stopped granting windows
    private readonly Dictionary<FieldDef, int> _staticStamps = new();
    private readonly List<ExtendedInitializer> _extended = new();

    /// <summary>Initializer runs that used the extended tier, in the order they ended.</summary>
    public IReadOnlyList<ExtendedInitializer> ExtendedInitializers => _extended;

    private bool InTier => _tierGranted > 0;

    private bool _observed; // the current run went past the budget: its writes are tracked from then on

    private bool Tracking => _observed && _cctorDepth > 0;

    /// <summary>
    /// The current run is in its observed window: it went past the budget and has not yet shown progress. Whatever ends
    /// the run now, it ends as it would have without the tier: its budget ran out.
    /// </summary>
    private bool InProbation => _observed && _tierGranted <= limits.InstructionBudget;

    /// <summary>Called before the outermost static constructor run starts (<see cref="_cctorDepth"/> is 0).</summary>
    private void BeginInitializerRun()
    {
        _window++;
        _progress = 0;
        _state = 0;
        _windowStates.Clear();
        _tierGranted = 0;
        _tierStop = null;
        _observed = false;
        _runStart = ThreadCpuTime.Now();
        _runWallStart = Stopwatch.GetElapsedTime(0);
        _budgetAtRun = _budget;
    }

    /// <summary>
    /// Called after the outermost static constructor run ends. Returns whether the run used the extended tier and failed:
    /// past its observed window the run draws on the tier, not on what the evaluation had left, so it would fail the
    /// same way again (the caller remembers the failure even when its reason is a resource limit). A run that failed in
    /// its observed window failed for lack of budget, as without the tier: it is neither reported nor remembered.
    /// </summary>
    private bool EndInitializerRun(TypeDef type, bool completed)
    {
        if (!InTier) return false;
        bool probation = InProbation;
        try
        {
            if (!completed && probation)
            {
                _budget = Math.Min(_budget, 0);
                return false;
            }
            long executed = _budgetAtRun + _tierGranted - Math.Max(_budget, 0);
            _extended.Add(new ExtendedInitializer(type.FullName, executed, completed, completed ? null : _tierStop ?? "evaluation left the supported subset"));
            Meter?.Exclude(ThreadCpuTime.Now() - _runStart, Stopwatch.GetElapsedTime(0) - _runWallStart);
            _budget = _budgetAtRun; // the run is the tier's: the evaluation that triggered it is not charged
            return !completed;
        }
        finally
        {
            _tierGranted = 0;
            _tierStop = null;
            _observed = false;
        }
    }

    /// <summary>The budget ran out: grants the next window when the run is an initializer making progress.</summary>
    private bool ExtendBudget()
    {
        if (_cctorDepth == 0) return false;
        long window = limits.InstructionBudget;
        if (!_observed)
        {
            // The first window past the budget is observed: what it commits decides whether the run goes on.
            _observed = true;
            return Grant(window);
        }
        if (_progress < Math.Max(1, window / ProgressRatio))
        {
            if (!InProbation) _tierStop = $"its last {window:N0} instructions committed no new state";
            return false;
        }
        if (!_windowStates.Add(_state))
        {
            _tierStop = "its state returned to that at the end of an earlier window (a cycle)";
            return false;
        }
        return Grant(window);
    }

    private bool Grant(long window)
    {
        if (_budgetAtRun + _tierGranted + window > limits.InitializerInstructionCeiling)
        {
            _tierStop = $"it reached the ceiling of {limits.InitializerInstructionCeiling:N0} instructions";
            return false;
        }
        _tierGranted += window;
        _budget += window;
        _window++;
        _progress = 0;
        return true;
    }

    /// <summary>
    /// The outermost initializer run completed. In its observed window it must have made progress for what it ran
    /// there: otherwise it completes only thanks to the tier, and fails as it would have without it.
    /// </summary>
    private void PassObservation()
    {
        if (!InProbation) return;
        long used = limits.InstructionBudget - Math.Max(_budget, 0);
        if (_progress < Math.Max(1, used / ProgressRatio)) throw BudgetExhausted();
    }

    /// <summary>A failure of the outermost run: in its observed window, the budget running out is what stopped it.</summary>
    private EvaluationBailout InitializerFailure(EvaluationBailout failure) => InTier && InProbation ? BudgetExhausted() : failure;

    private EvaluationBailout BudgetExhausted() => _methodBudgetBound
        ? Bail(FallbackReason.InstructionBudget, $"the method's total instruction budget of {limits.MethodInstructionBudget:N0} is exhausted")
        : Bail(FallbackReason.InstructionBudget, $"instruction budget of {limits.InstructionBudget:N0} exhausted");

    private void CheckTierTime()
    {
        var wallLimit = limits.InitializerTimeLimit * MethodMeter.WallFactor;
        if (ThreadCpuTime.Now() - _runStart > limits.InitializerTimeLimit)
            _tierStop = $"it ran longer than the time limit of {limits.InitializerTimeLimit.TotalSeconds:0} s of CPU time";
        else if (Stopwatch.GetElapsedTime(0) - _runWallStart > wallLimit)
            _tierStop = $"it ran longer than {wallLimit.TotalSeconds:0} s of wall time";
        else return;
        throw TierExhausted();
    }

    private EvaluationBailout TierExhausted() =>
        Bail(FallbackReason.InstructionBudget, $"the type initializer ran past the instruction budget in the extended tier for initializers that make progress, and stopped: {_tierStop}");

    /// <summary>The elements of a range before a write to it, when the run is tracked.</summary>
    private object?[]? Before(ArrayObject array, int start, int count)
    {
        if (!Tracking) return null;
        start = Math.Max(start, 0);
        count = Math.Clamp(count, 0, array.Data.Length - start);
        var values = new object?[count];
        for (int i = 0; i < count; i++) values[i] = NaturalElement(array.Data, start + i);
        return values;
    }

    private void Committed(ArrayObject array, int start, object?[]? before)
    {
        if (before == null) return;
        for (int i = 0; i < before.Length; i++) Committed(array, Math.Max(start, 0) + i, before[i]);
    }

    private void Committed(ArrayObject array, int index, object? before)
    {
        if (!Tracking) return;
        var after = NaturalElement(array.Data, index);
        if (Same(before, after)) return;
        Changed(array, (ulong)index, before, after);
        var stamps = array.Stamps ??= new int[array.Data.Length];
        if (stamps[index] == _window) return;
        stamps[index] = _window;
        _progress++;
    }

    private void Committed(InstanceObject obj, FieldDef field, object? before)
    {
        if (!Tracking) return;
        var after = obj.Fields.GetValueOrDefault(field);
        if (Same(before, after)) return;
        Changed(obj, (ulong)field.MDToken.Raw, before, after);
        var stamps = obj.Stamps ??= new Dictionary<FieldDef, int>();
        if (stamps.GetValueOrDefault(field) == _window) return;
        stamps[field] = _window;
        _progress++;
    }

    private void Committed(FieldDef field, object? before)
    {
        if (!Tracking) return;
        var after = _statics.GetValueOrDefault(field);
        if (Same(before, after)) return;
        Changed(field, 0, before, after);
        if (_staticStamps.GetValueOrDefault(field) == _window) return;
        _staticStamps[field] = _window;
        _progress++;
    }

    /// <summary>A collection or a builder went from <paramref name="before"/> to <paramref name="after"/> entries or characters.</summary>
    private void Resized(HeapObject owner, long before, long after)
    {
        if (!Tracking || before == after) return;
        Changed(owner, ulong.MaxValue, before, after);
        if (after > before) _progress += after - before;
    }

    private void Changed(object owner, ulong slot, object? before, object? after)
    {
        ulong location = Mix((ulong)RuntimeHelpers.GetHashCode(owner), slot);
        _state ^= Mix(location, Hash(before)) ^ Mix(location, Hash(after));
    }

    private static bool Same(object? a, object? b) => a is StructValue || b is StructValue ? Hash(a) == Hash(b) : Equals(a, b);

    private static ulong Hash(object? v) => v switch
    {
        null => 0,
        int i => Mix(1, (ulong)i),
        long l => Mix(2, (ulong)l),
        nint n => Mix(3, (ulong)n),
        float f => Mix(4, BitConverter.SingleToUInt32Bits(f)),
        double d => Mix(5, BitConverter.DoubleToUInt64Bits(d)),
        string s => Mix(6, (ulong)(uint)s.GetHashCode()),
        StructValue s => s.Fields.Aggregate(Mix(7, (ulong)RuntimeHelpers.GetHashCode(s.Type)), (h, f) => Mix(h, Hash(f))),
        _ => Mix(8, (ulong)RuntimeHelpers.GetHashCode(v)),
    };

    private static ulong Mix(ulong a, ulong b)
    {
        ulong x = (a ^ 0x9E3779B97F4A7C15) * 0xBF58476D1CE4E5B9 + b;
        x ^= x >> 31;
        x *= 0x94D049BB133111EB;
        return x ^ (x >> 29);
    }
}
