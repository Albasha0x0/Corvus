using System.Reflection.PortableExecutable;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Ida;

namespace Corvus.Setup;

/// <summary>Read-only checks behind status: each client's registered command started as the client would, engines and a target file.</summary>
internal static class Doctor
{
    public const string Healthy = "healthy", NotRegistered = "not_registered", OtherCopy = "other_copy", MissingProgram = "missing_program",
        Disabled = "disabled", StaleCatalog = "stale_catalog", StartFailed = "start_failed", SlowStart = "slow_start",
        MissingEngine = "missing_engine", ConfigUnreadable = "config_unreadable", MissingTarget = "missing_target", UnsupportedTarget = "unsupported_target",
        LegacyName = "legacy_name", Relay = "relay";

    /// <summary>States that make a client fail; the others are informational.</summary>
    public static bool Fails(string? state) => state is MissingProgram or StaleCatalog or StartFailed or SlowStart or ConfigUnreadable;

    public static readonly string[] Engines = ["ida", "python", "ghidra"];

    /// <summary>Fills a client row's state, message and self-test; <paramref name="tests"/> caches one start per command, args and env.</summary>
    public static void Check(ClientReport row, SetupEnvironment env, ServerLaunch ours, Dictionary<string, ServerReport> tests)
    {
        var client = row.Client!;
        if (row.Registered is not { } entry)
        {
            var preview = client.Target.Preview(ClientCatalog.ServerName, ClientCatalog.LaunchFor(client, ours));
            if (preview.Action == SetupAction.Blocked && File.Exists(client.Target.Path))
                Set(row, ConfigUnreadable, $"configuration unreadable: {preview.Reason}", "Fix the file, or remove it and run: corvus install");
            else
                Set(row, NotRegistered, "not registered (run: corvus install)", $"corvus install --client {client.Id}");
            return;
        }
        bool own = SameCommand(entry.Command, ours.Command);
        // A bare name is looked up on PATH by the start itself.
        if (entry.Command.IndexOfAny(['/', '\\']) >= 0 && !File.Exists(entry.Command))
        {
            Set(row, MissingProgram, $"registered with a missing program: {entry.Command} (run: corvus install)", $"corvus install --client {client.Id}");
            return;
        }
        var relay = Corvus.Relay.RelayCli.TargetOf(entry.Args);
        if (relay != null && !Directory.Exists(relay))
        {
            Set(row, MissingProgram, $"registered as the development relay for {relay}, which does not exist", $"publish there, or corvus install --client {client.Id} to register the server");
            return;
        }
        var server = row.Server = Test(new ServerLaunch(entry.Command, entry.Args), entry.Env, tests);
        var deadline = client.Target is CodexTomlTarget ? entry.StartupTimeout ?? CodexTomlTarget.DefaultStartupSeconds : (double?)null;
        if (!server.Ok)
            Set(row, StartFailed, $"registered, but the server does not start: {server.Detail}", "Run the registered command by hand to see the error; check its args and env.");
        else if (deadline is { } limit && server.Seconds > limit)
            Set(row, SlowStart, $"registered, but it started in {server.Seconds:0.0} s and {client.Name} waits {limit:0} s",
                $"corvus install --client {client.Id} (it sets startup_timeout_sec = {CodexTomlTarget.SafeStartupSeconds})");
        else if (own && server.MatchesThisBuild != true)
            Set(row, StaleCatalog, $"registered, but its tool catalog differs from this build: {string.Join("; ", server.Differences)}", "corvus install");
        else if (entry.Disabled)
            Set(row, Disabled, "registered (disabled: the client does not start it)", $"corvus install --client {client.Id} --enable");
        else if (relay != null)
            Set(row, Relay, $"registered as the development relay for {relay} (build {Corvus.Relay.RelayBuilds.IdOf(Corvus.Relay.RelayBuilds.ReadMarker(relay))}; {server.Detail})",
                null);
        else if (!own)
            Set(row, OtherCopy, $"registered with another copy: {entry.Command} (version {server.Version})", $"corvus install --client {client.Id} to use this copy.");
        else
            Set(row, Healthy, $"registered ({server.Detail})", null);
        if (client.Target.DisabledInProjects(ClientCatalog.ServerName) is { Count: > 0 } projects)
        {
            row.Message += $"; off in projects {string.Join(", ", projects)}";
            row.Remediation ??= $"corvus install --client {client.Id} --enable";
        }
    }

    /// <summary>Marks a registration under the old name: a working one is legacy_name, a failing one keeps its state.</summary>
    public static void MarkLegacy(ClientReport row)
    {
        var note = $"registered as {ClientCatalog.LegacyServerName}, the name before the rename; corvus install renames it";
        if (Fails(row.State)) row.Message += $" ({note})";
        else Set(row, LegacyName, $"{note} ({row.Message})", "corvus install");
    }

    /// <summary>Starts the server once per distinct (command, args, env) in <paramref name="tests"/>.</summary>
    public static ServerReport Test(ServerLaunch launch, IReadOnlyDictionary<string, string> env, Dictionary<string, ServerReport> tests)
    {
        var key = string.Join("\0", [launch.Command, .. launch.Args, "\0", .. env.OrderBy(e => e.Key, StringComparer.Ordinal).Select(e => e.Key + "=" + e.Value)]);
        if (!tests.TryGetValue(key, out var server))
            tests[key] = server = ServerReport.From(SelfTest.Run(launch, TimeSpan.FromSeconds(60), env));
        return server;
    }

    private static void Set(ClientReport row, string state, string message, string? remediation)
    {
        row.State = state;
        row.Message = message;
        row.Remediation = remediation;
    }

    private static bool SameCommand(string a, string b) =>
        a.Equals(b, OperatingSystem.IsLinux() ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase);

    /// <summary>One engine: ida, python or ghidra; <paramref name="deep"/> starts IDA's worker and reports its version.</summary>
    public static CheckReport Engine(SetupEnvironment env, string name, bool deep) => name switch
    {
        "ida" => FromAvailability("ida", env.Ida(deep)),
        "python" => env.Python() is var (python, log) && python != null
            ? new CheckReport("python", true, Healthy, python, null)
            : new CheckReport("python", false, MissingEngine, $"no usable 64-bit Python {PythonLocator.MinimumVersion}+ ({(log.Count == 0 ? "none found" : string.Join("; ", log))})",
                $"Install 64-bit Python 3, or set {IdaProvider.PythonVariable} to its executable."),
        _ => Ghidra(env),
    };

    private static CheckReport FromAvailability(string name, ProviderAvailability a) =>
        a.IsAvailable
            ? new CheckReport(name, true, Healthy, string.Join(", ", a.Details.Select(d => $"{d.Key} {d.Value}")), null)
            : new CheckReport(name, false, MissingEngine, a.Reason ?? "not available", a.Remediation);

    /// <summary>Only what a Ghidra install needs to be found: its folder (CORVUS_GHIDRA_DIR) and a Java runtime.</summary>
    private static CheckReport Ghidra(SetupEnvironment env)
    {
        if (env.Set("CORVUS_GHIDRA_DIR") is not { } dir)
            return new CheckReport("ghidra", false, MissingEngine, "CORVUS_GHIDRA_DIR is not set", "Set CORVUS_GHIDRA_DIR to a Ghidra install folder.");
        var headless = Path.Combine(dir, "support", env.Os == HostOs.Windows ? "analyzeHeadless.bat" : "analyzeHeadless");
        if (!File.Exists(headless))
            return new CheckReport("ghidra", false, MissingEngine, $"{dir} is not a Ghidra install (no {Path.GetRelativePath(dir, headless)})", "Point CORVUS_GHIDRA_DIR at the folder that holds ghidraRun.");
        var javaName = env.Os == HostOs.Windows ? "java.exe" : "java";
        var java = env.Set("JAVA_HOME") is { } home && File.Exists(Path.Combine(home, "bin", javaName)) ? Path.Combine(home, "bin", javaName) : env.FindTool("java");
        return java == null
            ? new CheckReport("ghidra", false, MissingEngine, $"Ghidra at {dir}, but no Java runtime (JAVA_HOME or java on PATH)", "Install a JDK supported by this Ghidra version and set JAVA_HOME.")
            : new CheckReport("ghidra", true, Healthy, $"install_dir {dir}, java {java}", null);
    }

    /// <summary>What a file is, from its first bytes and headers (nothing is loaded), and which engines read it.</summary>
    public static CheckReport Target(SetupEnvironment env, string path)
    {
        if (Directory.Exists(path)) return new CheckReport(path, true, Healthy, "a folder: load_assembly loads the assemblies in it", null);
        if (!File.Exists(path)) return new CheckReport(path, false, MissingTarget, "no such file", null);
        byte[] head;
        try
        {
            using var stream = File.OpenRead(path);
            head = new byte[8];
            head = head[..stream.ReadAtLeast(head, head.Length, throwOnEndOfStream: false)];
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return new CheckReport(path, false, MissingTarget, $"cannot read it: {ex.Message}", null);
        }
        ReadOnlySpan<byte> h = head;
        if (h.StartsWith("MZ"u8)) return Pe(env, path);
        if (h.StartsWith("PK\x03\x04"u8)) return new CheckReport(path, true, Healthy, "a ZIP container (.apk, .nupkg, ...): list_assemblies and unpack_container read it", null);
        if (h.StartsWith("MDMP"u8)) return new CheckReport(path, true, Healthy, "a Windows minidump: open_minidump reads it", null);
        if (h.StartsWith((ReadOnlySpan<byte>)[0xAF, 0x1B, 0xB1, 0xFA])) return new CheckReport(path, true, Healthy, "AOT metadata (global-metadata.dat): load_assembly reads it with GameAssembly beside it", null);
        if (h.StartsWith((ReadOnlySpan<byte>)[0x7F, (byte)'E', (byte)'L', (byte)'F']) || h.StartsWith((ReadOnlySpan<byte>)[0xCF, 0xFA, 0xED, 0xFE]) || h.StartsWith((ReadOnlySpan<byte>)[0xCA, 0xFE, 0xBA, 0xBE]))
            return new CheckReport(path, false, UnsupportedTarget, "an ELF or Mach-O binary; only PE images are analyzed", null);
        return new CheckReport(path, false, UnsupportedTarget, "not a PE image, container, minidump or AOT metadata", "summarize_file reports what it contains.");
    }

    private static CheckReport Pe(SetupEnvironment env, string path)
    {
        try
        {
            using var stream = File.OpenRead(path);
            using var pe = new PEReader(stream);
            var headers = pe.PEHeaders;
            var machine = headers.CoffHeader.Machine;
            if (pe.HasMetadata)
                return new CheckReport(path, true, Healthy, $"a .NET assembly ({machine}): the built-in decompiler reads it", null);
            bool ours = machine is Machine.I386 or Machine.Amd64;
            var ida = env.Ida(false);
            var engines = ours ? "the built-in x86/x64 engine" + (ida.IsAvailable ? ", and IDA" : "") : ida.IsAvailable ? "IDA" : "no engine here (IDA is needed)";
            return new CheckReport(path, ours || ida.IsAvailable, ours || ida.IsAvailable ? Healthy : MissingEngine, $"a native PE image ({machine}): {engines}",
                ours || ida.IsAvailable ? null : ida.Remediation);
        }
        catch (BadImageFormatException ex)
        {
            return new CheckReport(path, false, UnsupportedTarget, $"a damaged PE image: {ex.Message}", "summarize_file reports what it contains.");
        }
    }

    /// <summary>The real IDA probe: availability, or with <paramref name="deep"/> a started idalib worker.</summary>
    public static ProviderAvailability ProbeIda(bool deep)
    {
        using var provider = new IdaProvider();
        return deep ? provider.ProbeAsync().GetAwaiter().GetResult() : provider.CheckAvailability();
    }

    /// <summary>The real Python search, as IDA's provider does it.</summary>
    public static (string? Python, List<string> Log) FindPython()
    {
        var preferred = new List<(string, string)>();
        if (Environment.GetEnvironmentVariable(IdaProvider.PythonVariable) is { Length: > 0 } configured) preferred.Add((configured, IdaProvider.PythonVariable));
        if (IdaInstallation.ConfiguredPythonDirectory() is { } idaPython) preferred.Add((idaPython, "IDA Python3TargetDLL"));
        var log = new List<string>();
        var found = PythonLocator.Find(preferred, log);
        return (found == null ? null : $"{found.Executable} ({found.Version}, {found.Source})", log);
    }
}
