using System.Diagnostics;
using System.Globalization;
using System.Reflection;
using Xunit.Sdk;

namespace Corvus.Tests;

/// <summary>
/// Takes machine-wide permits for a test class's heavy resource (<see cref="MachinePermits"/>) while the class runs. A
/// class needs one through this attribute on it, an enclosing class or a test method; <see cref="IdaFactAttribute"/> and
/// <see cref="GhidraFactAttribute"/> tests need their engine's without it.
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true)]
public sealed class PermitAttribute(string resource) : Attribute
{
    public string Resource { get; } = resource;
}

/// <summary>
/// Machine-wide permits for heavy resources, shared by every test process on the machine (lanes' runs and the background
/// run alike), so engines and real programs stay bounded however many runs start. A permit is a slot file opened for
/// exclusive use: a process that crashes releases its permits with its handles.
/// </summary>
public static class MachinePermits
{
    /// <summary>Permits per resource.</summary>
    public static readonly IReadOnlyDictionary<string, int> Counts = new Dictionary<string, int>
    {
        ["engine-ida"] = 2, ["engine-ghidra"] = 2, ["live"] = 2, ["reference-tool"] = 4,
    };

    private static readonly TimeSpan Poll = TimeSpan.FromMilliseconds(200);
    private static readonly object LogLock = new();

    /// <summary>The folder of the slot files, in the machine's temporary folder rather than the run's own.</summary>
    public static string Folder => Path.Combine(LeakGuard.SharedTemp, "corvus-test-data", "permits");

    /// <summary>
    /// The resources a test collection's runnable cases need, in name order; empty when none does or every case is
    /// skipped. Throws for a resource without a count.
    /// </summary>
    public static IReadOnlyList<string> Needed(IEnumerable<IXunitTestCase> testCases)
    {
        var needed = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var testCase in testCases.Where(t => string.IsNullOrEmpty(t.SkipReason)))
        {
            var method = testCase.Method.ToRuntimeMethod();
            if (method.IsDefined(typeof(IdaFactAttribute))) needed.Add("engine-ida");
            if (method.IsDefined(typeof(GhidraFactAttribute))) needed.Add("engine-ghidra");
            foreach (var permit in method.GetCustomAttributes<PermitAttribute>()) needed.Add(permit.Resource);
            for (var type = testCase.TestMethod.TestClass.Class.ToRuntimeType(); type != null; type = type.DeclaringType)
                foreach (var permit in type.GetCustomAttributes<PermitAttribute>(false)) needed.Add(permit.Resource);
        }
        foreach (var resource in needed.Where(r => !Counts.ContainsKey(r)))
            throw new ArgumentException($"No permit count for '{resource}' (MachinePermits.Counts).");
        return [.. needed];
    }

    /// <summary>
    /// Waits for one permit of each resource, taken in the order given (name order, so two holders never wait on each
    /// other), and returns them as one handle with the time waited. Cancellation releases what was taken and throws.
    /// </summary>
    public static Task<(IDisposable Held, TimeSpan Waited)> TakeAsync(IReadOnlyList<string> resources, CancellationToken cancellation = default) =>
        TakeAsync(resources, Folder, Counts, cancellation);

    internal static async Task<(IDisposable Held, TimeSpan Waited)> TakeAsync(IReadOnlyList<string> resources, string folder,
        IReadOnlyDictionary<string, int> counts, CancellationToken cancellation)
    {
        var watch = Stopwatch.StartNew();
        var held = new Held();
        try
        {
            foreach (var resource in resources)
            {
                var dir = Path.Combine(folder, resource);
                Directory.CreateDirectory(dir);
                FileStream? slot;
                while ((slot = TryTake(dir, counts[resource])) == null) await Task.Delay(Poll, cancellation);
                held.Slots.Add(slot);
            }
        }
        catch
        {
            held.Dispose();
            throw;
        }
        return (held, watch.Elapsed);
    }

    /// <summary>
    /// Appends a wait to the file CORVUS_PERMIT_LOG names (test.ps1 adds the waits to the run's time record): one
    /// tab-separated line of resources, seconds and collection. Nothing without the variable.
    /// </summary>
    public static void Record(IReadOnlyList<string> resources, TimeSpan waited, string collection)
    {
        if (Environment.GetEnvironmentVariable("CORVUS_PERMIT_LOG") is not { Length: > 0 } log) return;
        var line = string.Join('\t', string.Join(',', resources), waited.TotalSeconds.ToString("0.###", CultureInfo.InvariantCulture), collection);
        lock (LogLock) File.AppendAllLines(log, [line]);
    }

    private static FileStream? TryTake(string dir, int count)
    {
        for (var i = 0; i < count; i++)
        {
            try { return new FileStream(Path.Combine(dir, $"slot-{i}"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
        return null;
    }

    private sealed class Held : IDisposable
    {
        public readonly List<FileStream> Slots = [];

        public void Dispose()
        {
            foreach (var slot in Slots) slot.Dispose();
            Slots.Clear();
        }
    }
}
