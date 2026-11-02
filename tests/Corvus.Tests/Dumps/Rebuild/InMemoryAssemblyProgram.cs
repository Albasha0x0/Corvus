using System.Diagnostics;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;

namespace Corvus.Tests;

/// <summary>
/// A program that loads a second assembly from a byte array, then writes a
/// full-memory minidump of itself; built once per test run.
/// </summary>
internal static class InMemoryAssemblyProgram
{
    /// <summary>The type the byte-array assembly defines.</summary>
    public const string LoadedType = "Sample.LoadedFromBytes";

    /// <summary>The constant its method returns.</summary>
    public const int LoadedValue = 20211;

    private const string LoadedSource = """
        namespace Sample;

        public static class LoadedFromBytes
        {
            public static int Value() => 20211;
        }
        """;

    private const string HostSource = """
        using System;
        using System.Diagnostics;
        using System.IO;
        using System.Reflection;
        using System.Runtime.InteropServices;

        namespace Host;

        public static class Program
        {
            [DllImport("dbghelp.dll", SetLastError = true)]
            private static extern bool MiniDumpWriteDump(IntPtr process, int processId, IntPtr file, int type, IntPtr exception, IntPtr user, IntPtr callback);

            public static int Main(string[] args)
            {
                var assembly = Assembly.Load(Convert.FromBase64String("@IMAGE@"));
                var value = (int)assembly.GetType("Sample.LoadedFromBytes").GetMethod("Value").Invoke(null, null);
                if (value != 20211) return 2;
                using var file = new FileStream(args[0], FileMode.Create, FileAccess.ReadWrite);
                var self = Process.GetCurrentProcess();
                // Full memory, handle data, thread info, full memory info.
                var ok = MiniDumpWriteDump(self.Handle, self.Id, file.SafeFileHandle.DangerousGetHandle(), 0x2 | 0x4 | 0x1000 | 0x800, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
                GC.KeepAlive(assembly);
                return ok ? 0 : Marshal.GetLastWin32Error();
            }
        }
        """;

    private static readonly Lazy<string> Folder = new(() =>
        LeakGuard.DeleteAtEnd(Path.Combine(Path.GetTempPath(), "corvus-test-inmemory-" + Guid.NewGuid().ToString("N"))));

    private static readonly Lazy<string> Program = new(Build);

    /// <summary>Why the program cannot run here; null where it can.</summary>
    public static string? Unavailable =>
        OperatingSystem.IsWindows() ? null : "The dump is written with MiniDumpWriteDump, which needs Windows.";

    /// <summary>
    /// Runs the program and returns the path of the full-memory minidump it
    /// writes into <paramref name="dir"/>; throws where it cannot run.
    /// </summary>
    public static string WriteDump(TempDir dir)
    {
        if (Unavailable is { } reason) throw new PlatformNotSupportedException(reason);
        var dump = dir.File("in-memory-assembly.dmp");
        var psi = new ProcessStartInfo("dotnet") { UseShellExecute = false, RedirectStandardError = true, RedirectStandardOutput = true, CreateNoWindow = true };
        psi.ArgumentList.Add(Program.Value);
        psi.ArgumentList.Add(dump);
        var (code, log) = Tools.Run(psi, 120_000);
        if (code != 0 || !File.Exists(dump)) throw new InvalidOperationException($"The program wrote no dump (exit {code}): {log}");
        return dump;
    }

    private static string Build()
    {
        var image = Roslyn.Compile("Loaded", LoadedSource, new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary, optimizationLevel: OptimizationLevel.Release));
        var host = Roslyn.Compile("InMemoryHost", HostSource.Replace("@IMAGE@", Convert.ToBase64String(image), StringComparison.Ordinal),
            new CSharpCompilationOptions(OutputKind.ConsoleApplication, optimizationLevel: OptimizationLevel.Debug));
        Directory.CreateDirectory(Folder.Value);
        var dll = Path.Combine(Folder.Value, "InMemoryHost.dll");
        File.WriteAllBytes(dll, host);
        File.WriteAllText(Path.Combine(Folder.Value, "InMemoryHost.runtimeconfig.json"),
            System.Text.Json.JsonSerializer.Serialize(new
            {
                runtimeOptions = new { tfm = $"net{Environment.Version.Major}.0", framework = new { name = "Microsoft.NETCore.App", version = Environment.Version.ToString() } },
            }));
        return dll;
    }
}
