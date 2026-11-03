using System.Diagnostics;
using System.Globalization;

namespace Corvus.Tests;

/// <summary>Where a built program wrote code at run time, and the dump it left.</summary>
internal sealed record RuntimeWritesResult(
    string Dump, string Program, ulong Address, ulong Size,
    ulong Table, ulong[] TableEntries, ulong Stubs, int StubCount, int StubStride,
    ulong Patched, int PatchLength, ulong FirstStub, ulong SecondStub, ulong Export);

/// <summary>
/// A program that copies a small function into a section with no raw data,
/// makes it executable and calls it, fills a table of export addresses, writes
/// stubs into that section and patches one of its functions through two stubs,
/// then waits; <see cref="Dump"/> returns its dump and the addresses.
/// </summary>
internal static class RuntimeWritesProgram
{
    /// <summary>The bytes the program copies: mov eax, 42; ret (the same encoding in x86 and x64).</summary>
    public static readonly byte[] Function = [0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3];

    /// <summary>The section the program's buffer lands in.</summary>
    public const string SectionName = "rtbuf";

    /// <summary>The section's size in bytes.</summary>
    public const int SectionSize = 8192;

    /// <summary>The number of stubs written into the section.</summary>
    public const int StubCount = 200;

    /// <summary>The distance between stubs in bytes.</summary>
    public const int StubStride = 16;

    /// <summary>The offset of the first stub in the section.</summary>
    public const int StubOffset = 256;

    /// <summary>
    /// Prints "ready", the buffer address and size, the table address and its
    /// entries, the stub run, the patched function, both chain stubs and the
    /// export; writes a full-memory dump to the first argument.
    /// </summary>
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

        #define STUBS 200
        #define STRIDE 16
        #define STUB_OFFSET 256

        static void* table[8];

        // Writes a jump to target: mov rax, imm64; jmp rax on x64, push imm32; ret on x86.
        static int emit_jump(unsigned char* p, void* target)
        {
        #ifdef _WIN64
            p[0] = 0x48; p[1] = 0xB8;
            memcpy(p + 2, &target, 8);
            p[10] = 0xFF; p[11] = 0xE0;
            return 12;
        #else
            p[0] = 0x68;
            memcpy(p + 1, &target, 4);
            p[5] = 0xC3;
            return 6;
        #endif
        }

        __declspec(noinline) static int patched_function(int x)
        {
            volatile int a = x * 3;
            volatile int b = a + 7;
            volatile int c = b ^ x;
            volatile int d = c - a;
            return d + b;
        }

        int main(int argc, char** argv)
        {
            DWORD old;
            int (*call)(void) = (int (*)(void))buffer;
            memcpy(buffer, function, sizeof function);
            if (!VirtualProtect(buffer, sizeof buffer, PAGE_EXECUTE_READWRITE, &old)) return 2;
            if (call() != 42) return 3;

            HMODULE k32 = GetModuleHandleA("kernel32.dll");
            HMODULE nt = GetModuleHandleA("ntdll.dll");
            if (!k32 || !nt) return 6;
            table[0] = (void*)GetProcAddress(k32, "GetTickCount");
            table[1] = (void*)GetProcAddress(k32, "GetCurrentProcessId");
            table[2] = (void*)GetProcAddress(k32, "Sleep");
            table[3] = (void*)GetProcAddress(nt, "NtClose");
            table[4] = (void*)GetProcAddress(nt, "RtlGetCurrentPeb");
            table[5] = (void*)GetProcAddress(nt, "NtYieldExecution");
            table[6] = (void*)GetProcAddress(k32, "GetCurrentThreadId");
            table[7] = NULL;
            for (int i = 0; i < 7; i++) if (!table[i]) return 7;

            for (int i = 0; i < STUBS; i++)
                emit_jump(buffer + STUB_OFFSET + i * STRIDE, table[i % 7]);

            unsigned char* second = (unsigned char*)VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (!second) return 8;
            unsigned char* first = second + 64;
            emit_jump(second, table[0]);
            emit_jump(first, second);
            unsigned char* patched = (unsigned char*)patched_function;
            if (!VirtualProtect(patched, 16, PAGE_EXECUTE_READWRITE, &old)) return 9;
            int patch = emit_jump(patched, first);
            FlushInstructionCache(GetCurrentProcess(), patched, patch);
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
            printf("ready %llx %u %llx %llx %llx %llx %llx %llx %llx %llx",
                (unsigned long long)(ULONG_PTR)buffer, (unsigned)sizeof buffer,
                (unsigned long long)(ULONG_PTR)table, (unsigned long long)(ULONG_PTR)(buffer + STUB_OFFSET),
                (unsigned long long)(ULONG_PTR)patched, (unsigned long long)patch,
                (unsigned long long)(ULONG_PTR)first, (unsigned long long)(ULONG_PTR)second,
                (unsigned long long)(ULONG_PTR)table[0], (unsigned long long)7);
            for (int i = 0; i < 7; i++) printf(" %llx", (unsigned long long)(ULONG_PTR)table[i]);
            printf("\n");
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
            ulong Hex(int i) => ulong.Parse(parts[i], NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            var entries = Enumerable.Range(11, (int)Hex(10)).Select(Hex).ToArray();
            return new(dump, exe, Hex(1), ulong.Parse(parts[2], CultureInfo.InvariantCulture), Hex(3), entries, Hex(4), StubCount, StubStride, Hex(5), (int)Hex(6), Hex(7), Hex(8), Hex(9));
        }
        finally
        {
            if (!process.HasExited) process.Kill();
        }
    }
}
