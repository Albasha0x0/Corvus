using System.Diagnostics;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;

namespace Corvus.Tests;

/// <summary>
/// A program that emits a dynamic assembly, runs its methods, then writes a
/// full-memory minidump of itself; built once per test run.
/// </summary>
internal static class DynamicAssemblyProgram
{
    /// <summary>The name of the emitted assembly.</summary>
    public const string EmittedAssembly = "EmittedSample";

    /// <summary>The type the emitted assembly defines.</summary>
    public const string EmittedType = "Emitted.Calculator";

    /// <summary>The constant the first emitted method returns.</summary>
    public const int EmittedValue = 20212;

    /// <summary>The string literal the second emitted method loads.</summary>
    public const string EmittedLiteral = "emitted-literal";

    private const string HostSource = """
        using System;
        using System.Diagnostics;
        using System.IO;
        using System.Reflection;
        using System.Reflection.Emit;
        using System.Runtime.InteropServices;

        namespace Host;

        public static class Program
        {
            [DllImport("dbghelp.dll", SetLastError = true)]
            private static extern bool MiniDumpWriteDump(IntPtr process, int processId, IntPtr file, int type, IntPtr exception, IntPtr user, IntPtr callback);

            public static int Main(string[] args)
            {
                var assembly = AssemblyBuilder.DefineDynamicAssembly(new AssemblyName("EmittedSample"), AssemblyBuilderAccess.Run);
                var module = assembly.DefineDynamicModule("EmittedSample");
                var type = module.DefineType("Emitted.Calculator", TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed);
                var value = type.DefineMethod("Value", MethodAttributes.Public | MethodAttributes.Static, typeof(int), Type.EmptyTypes);
                var il = value.GetILGenerator();
                il.Emit(OpCodes.Ldc_I4, 20212);
                il.Emit(OpCodes.Ret);
                var describe = type.DefineMethod("Describe", MethodAttributes.Public | MethodAttributes.Static, typeof(string), Type.EmptyTypes);
                il = describe.GetILGenerator();
                il.Emit(OpCodes.Call, value);
                il.Emit(OpCodes.Pop);
                il.Emit(OpCodes.Ldstr, "emitted-literal");
                il.Emit(OpCodes.Ret);
                var created = type.CreateType();
                if ((int)created.GetMethod("Value").Invoke(null, null) != 20212) return 2;
                if ((string)created.GetMethod("Describe").Invoke(null, null) != "emitted-literal") return 3;
                using var file = new FileStream(args[0], FileMode.Create, FileAccess.ReadWrite);
                var self = Process.GetCurrentProcess();
                // Full memory, handle data, thread info, full memory info.
                var ok = MiniDumpWriteDump(self.Handle, self.Id, file.SafeFileHandle.DangerousGetHandle(), 0x2 | 0x4 | 0x1000 | 0x800, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
                GC.KeepAlive(created);
                return ok ? 0 : Marshal.GetLastWin32Error();
            }
        }
        """;

    private static readonly Lazy<string> Folder = new(() =>
        LeakGuard.DeleteAtEnd(Path.Combine(Path.GetTempPath(), "corvus-test-dynamic-" + Guid.NewGuid().ToString("N"))));

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
        var dump = dir.File("dynamic-assembly.dmp");
        var psi = new ProcessStartInfo("dotnet") { UseShellExecute = false, RedirectStandardError = true, RedirectStandardOutput = true, CreateNoWindow = true };
        psi.ArgumentList.Add(Program.Value);
        psi.ArgumentList.Add(dump);
        var (code, log) = Tools.Run(psi, 120_000);
        if (code != 0 || !File.Exists(dump)) throw new InvalidOperationException($"The program wrote no dump (exit {code}): {log}");
        return dump;
    }

    private static string Build()
    {
        var host = Roslyn.Compile("DynamicHost", HostSource,
            new CSharpCompilationOptions(OutputKind.ConsoleApplication, optimizationLevel: OptimizationLevel.Debug));
        Directory.CreateDirectory(Folder.Value);
        var dll = Path.Combine(Folder.Value, "DynamicHost.dll");
        File.WriteAllBytes(dll, host);
        File.WriteAllText(Path.Combine(Folder.Value, "DynamicHost.runtimeconfig.json"),
            System.Text.Json.JsonSerializer.Serialize(new
            {
                runtimeOptions = new { tfm = $"net{Environment.Version.Major}.0", framework = new { name = "Microsoft.NETCore.App", version = Environment.Version.ToString() } },
            }));
        return dll;
    }
}
