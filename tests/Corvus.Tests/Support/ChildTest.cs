using System.Diagnostics;
using System.Globalization;
using System.Reflection;
using System.Runtime.CompilerServices;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>Runs a test body in its own process, for whole-process measurements other tests would disturb; the child's output reaches the parent test.</summary>
public static class ChildTest
{
    /// <summary>Set in the child, where <see cref="Rerun"/> returns false and the body runs.</summary>
    public const string Variable = "CORVUS_CHILD_TEST";

    private const string Flag = "--child-test";

    /// <summary>
    /// In the test process: runs <paramref name="method"/> of <paramref name="test"/>'s class with
    /// <paramref name="args"/> in a child process, fails the test when the child fails or outlives
    /// <paramref name="limit"/> (default 60 minutes), and returns true, so the caller returns. In the child: returns false.
    /// <paramref name="environment"/> adds variables the child starts with.
    /// </summary>
    public static bool Rerun(object test, ITestOutputHelper output, object?[]? args = null, TimeSpan? limit = null,
        IReadOnlyDictionary<string, string>? environment = null, [CallerMemberName] string method = "")
    {
        if (Environment.GetEnvironmentVariable(Variable) == "1") return false;
        var info = new ProcessStartInfo(Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") ?? "dotnet")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (var a in (string[])["exec", typeof(ChildTest).Assembly.Location, Flag, test.GetType().FullName!, method,
                     .. (args ?? []).Select(a => Convert.ToString(a, CultureInfo.InvariantCulture) ?? "")])
            info.ArgumentList.Add(a);
        info.Environment[Variable] = "1";
        foreach (var (name, value) in environment ?? new Dictionary<string, string>()) info.Environment[name] = value;
        // The child is a run of its own: its temporary folder sits beside this run's, not inside it.
        foreach (var name in new[] { "TMP", "TEMP", "TMPDIR" }) info.Environment[name] = LeakGuard.SharedTemp;
        using var child = Process.Start(info)!;
        var errors = new List<string>();
        child.OutputDataReceived += (_, e) => { if (e.Data != null) output.WriteLine(e.Data); };
        child.ErrorDataReceived += (_, e) => { if (e.Data != null) lock (errors) errors.Add(e.Data); };
        child.BeginOutputReadLine();
        child.BeginErrorReadLine();
        if (!child.WaitForExit(limit ?? TimeSpan.FromMinutes(60)))
        {
            child.Kill(entireProcessTree: true);
            child.WaitForExit();
            Assert.Fail($"{method} ran past {limit ?? TimeSpan.FromMinutes(60)} in its child process (pid {child.Id})");
        }
        child.WaitForExit();
        lock (errors) Assert.True(child.ExitCode == 0, $"{method} failed in its child process (exit code {child.ExitCode}):\n{string.Join("\n", errors)}");
        return true;
    }

    /// <summary>Entry point: runs a named test method in a child (exit 0 on pass), or the --perf-regressions, --located-tools, --alone-classes or stack-read commands.</summary>
    public static int Main(string[] args)
    {
        int code = args switch
        {
            [Flag, var typeName, var methodName, .. var rest] => Run(typeName, methodName, rest),
            [PerfRegressions.Flag, .. var trxPaths] => PerfRegressions.Main(trxPaths),
            [LocatedTools.Flag] => LocatedTools.Main(),
            [AloneClasses.Flag] => AloneClasses.Main(),
            [ThreadPoolSnapshot.Flag, .. var read] => ThreadPoolSnapshot.Main(read),
            _ => 2,
        };
        // Exit now: a foreground thread the test started must not keep the child running.
        Environment.Exit(code);
        return code;
    }

    private static int Run(string typeName, string methodName, string[] rest)
    {
        try
        {
            var type = typeof(ChildTest).Assembly.GetType(typeName, throwOnError: true)!;
            var method = type.GetMethod(methodName, BindingFlags.Public | BindingFlags.Instance)!;
            var parameters = method.GetParameters();
            var values = parameters.Select((p, i) => Convert.ChangeType(rest[i], p.ParameterType, CultureInfo.InvariantCulture)).ToArray();
            var output = new ConsoleOutput();
            var ctor = type.GetConstructor([typeof(ITestOutputHelper)]);
            var test = ctor != null ? ctor.Invoke([output]) : Activator.CreateInstance(type)!;
            try
            {
                if (method.Invoke(test, values) is Task task) task.GetAwaiter().GetResult();
            }
            finally
            {
                if (test is IAsyncDisposable asyncDisposable) asyncDisposable.DisposeAsync().AsTask().GetAwaiter().GetResult();
                else if (test is IDisposable disposable) disposable.Dispose();
            }
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine((ex is TargetInvocationException { InnerException: { } inner } ? inner : ex).ToString());
            return 1;
        }
    }

    private sealed class ConsoleOutput : ITestOutputHelper
    {
        public void WriteLine(string message) => Console.Out.WriteLine(message);

        public void WriteLine(string format, params object[] args) => Console.Out.WriteLine(format, args);
    }
}
