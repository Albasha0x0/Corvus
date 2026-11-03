using System.Diagnostics;
using System.Globalization;

namespace Corvus.Tests;

/// <summary>Where a built program wrote code at run time, and the dump it left.</summary>
internal sealed record RuntimeWritesResult(string Dump, string Program, ulong Address, ulong Size);

/// <summary>
/// A program that copies a small function into a section with no raw data,
/// makes it executable, calls it and waits; <see cref="Dump"/> returns its dump.
/// </summary>
internal static class RuntimeWritesProgram
{
    /// <summary>The bytes the program copies: mov eax, 42; ret (the same encoding in x86 and x64).</summary>
    public static readonly byte[] Function = [0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3];

    /// <summary>The section the program's buffer lands in.</summary>
    public const string SectionName = "rtbuf";

    /// <summary>The section's size in bytes.</summary>
    public const int SectionSize = 8192;

    /// <summary>Prints "ready", the buffer address and its size; writes a full-memory dump to the first argument.</summary>
    public const string Source = """
        #include <windows.h>
        #include <dbghelp.h>
        #include <stdio.h>
        #include <string.h>
        #pragma comment(lib, "dbghelp.lib")

        #pragma bss_seg("rtbuf")
        static unsigned char buffer[8192];
        #pragma bss_seg()

        static const unsigned char function[] = { 0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3 };

        int main(int argc, char** argv)
        {
            DWORD old;
            int (*call)(void) = (int (*)(void))buffer;
            memcpy(buffer, function, sizeof function);
            if (!VirtualProtect(buffer, sizeof buffer, PAGE_EXECUTE_READWRITE, &old)) return 2;
            if (call() != 42) return 3;
            if (argc > 1)
            {
                HANDLE f = CreateFileA(argv[1], GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                if (f == INVALID_HANDLE_VALUE) return 4;
                MINIDUMP_TYPE type = (MINIDUMP_TYPE)(MiniDumpWithFullMemory | MiniDumpWithFullMemoryInfo |
                    MiniDumpWithThreadInfo | MiniDumpWithUnloadedModules);
                BOOL ok = MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), f, type, NULL, NULL, NULL);
                CloseHandle(f);
                if (!ok) return 5;
            }
            printf("ready %llx %u\n", (unsigned long long)(ULONG_PTR)buffer, (unsigned)sizeof buffer);
            fflush(stdout);
            getchar();
            return 0;
        }
        """;

    /// <summary>
    /// Builds the program for <paramref name="target"/>, runs it until it prints
    /// "ready", and returns its dump; the program is ended by pid.
    /// </summary>
    public static RuntimeWritesResult Dump(TempDir dir, LiveTarget target)
    {
        var exe = target.Build(dir, "runtimewrites", Source);
        var dump = dir.File("runtimewrites-" + target.Name + ".dmp");
        var psi = new ProcessStartInfo(exe) { RedirectStandardOutput = true, RedirectStandardInput = true, UseShellExecute = false, CreateNoWindow = true };
        psi.ArgumentList.Add(dump);
        using var process = Process.Start(psi)!;
        try
        {
            var line = process.StandardOutput.ReadLine();
            Assert.True(line != null && line.StartsWith("ready ", StringComparison.Ordinal), $"no ready line (exit code {(process.HasExited ? process.ExitCode : -1)})");
            var parts = line.Split(' ');
            Assert.True(File.Exists(dump), "no dump written");
            return new(dump, exe, ulong.Parse(parts[1], NumberStyles.HexNumber, CultureInfo.InvariantCulture), ulong.Parse(parts[2], CultureInfo.InvariantCulture));
        }
        finally
        {
            if (!process.HasExited) process.Kill();
        }
    }
}
