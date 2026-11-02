using System.Security.Cryptography;

namespace Corvus.Relay;

/// <summary>Runs the relay from the publish folder's own copy when its relay code differs from the running host.</summary>
public static class RelayHandoff
{
    /// <summary>Set for the staged host, so it never hands off again.</summary>
    public const string GuardVariable = "CORVUS_RELAY_HOST_HANDOFF";

    /// <summary>Runs a program with the console inherited and returns its exit code.</summary>
    public delegate int Runner(string program, IReadOnlyList<string> args, IReadOnlyDictionary<string, string> environment);

    /// <summary>The content hash of the main assembly in <paramref name="directory"/>; null when it holds none or it cannot be read.</summary>
    public static string? HostId(string directory)
    {
        try
        {
            var main = Path.Combine(directory, RelayBuilds.ProgramDll);
            return File.Exists(main) ? Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(main)))[..12] : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }
    }

    /// <summary>Whether <paramref name="target"/> holds a complete build whose main assembly differs from the one in <paramref name="host"/>; false when either is unknown.</summary>
    public static bool Differs(string host, string target) =>
        RelayBuilds.ReadMarker(target) != null && HostId(target) is { } theirs && HostId(host) is { } ours && theirs != ours;

    /// <summary>
    /// Stages the build in <paramref name="options"/>.Target as a host copy and runs it with <paramref name="args"/>;
    /// returns its exit code, or null to keep the current host (no differing build, already handed off, or staging failed).
    /// </summary>
    public static int? TryHandOff(RelayOptions options, IReadOnlyList<string> args, string host, TextWriter log, Runner run, Func<string, string, bool, string>? stage = null)
    {
        if (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable(GuardVariable))) return null;
        if (!Differs(host, options.Target)) return null;
        var marker = RelayBuilds.ReadMarker(options.Target);
        string staged;
        try
        {
            var exe = Path.Combine(options.Target, RelayBuilds.ProgramName);
            var program = File.Exists(exe) ? exe : Path.Combine(options.Target, RelayBuilds.ProgramDll);
            staged = (stage ?? RelayBuilds.StageHost)(program, options.StateDirectory, false);
            if (RelayBuilds.ReadMarker(options.Target) != marker) throw new IOException("a publish ran while the host was copied");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            log.WriteLine($"corvus relay: cannot stage the newer host, keeping this one: {ex.Message}");
            return null;
        }
        var environment = new Dictionary<string, string> { [GuardVariable] = "1" };
        if (Path.GetFileName(staged).Equals(RelayBuilds.ProgramDll, StringComparison.OrdinalIgnoreCase))
            return run(Native.Providers.Worker.WorkerPool.DotnetHost(), [staged, .. args], environment);
        return run(staged, args, environment);
    }

    /// <summary>Runs a program as a child that ends with this process, relays this process's standard streams to it byte for byte and returns its exit code.</summary>
    public static int RunInherited(string program, IReadOnlyList<string> args, IReadOnlyDictionary<string, string> environment)
    {
        var start = new Native.Providers.ChildProcessStart(program, args)
        {
            OwnProgram = true,
            WorkingDirectory = Environment.CurrentDirectory,
            Environment = environment.ToDictionary(e => e.Key, e => (string?)e.Value),
        };
        using var child = Native.Providers.ChildProcess.Start(start);
        // The client's end of input closes the child's, which ends the relay.
        var input = new Thread(() =>
        {
            Pump(Console.OpenStandardInput(), child.StandardInput);
            try { child.StandardInput.Dispose(); }
            catch (IOException) { }
        }) { IsBackground = true, Name = "relay handoff input" };
        var output = new Thread(() => Pump(child.StandardOutput, Console.OpenStandardOutput())) { IsBackground = true, Name = "relay handoff output" };
        var error = new Thread(() => Pump(child.StandardError, Console.OpenStandardError())) { IsBackground = true, Name = "relay handoff error" };
        input.Start();
        output.Start();
        error.Start();
        child.Exited.Wait();
        output.Join(TimeSpan.FromSeconds(5));
        error.Join(TimeSpan.FromSeconds(5));
        return child.ExitCode ?? 1;
    }

    /// <summary>Copies <paramref name="from"/> to <paramref name="to"/> until either end closes, flushing each read.</summary>
    private static void Pump(Stream from, Stream to)
    {
        var buffer = new byte[64 * 1024];
        try
        {
            int n;
            while ((n = from.Read(buffer, 0, buffer.Length)) > 0)
            {
                to.Write(buffer, 0, n);
                to.Flush();
            }
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException) { }
    }
}
