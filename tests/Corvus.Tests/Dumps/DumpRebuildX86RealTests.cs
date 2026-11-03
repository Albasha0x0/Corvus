using System.Diagnostics;
using System.Runtime.InteropServices;
using Corvus.Native;
using Corvus.Native.Code;
using Corvus.Native.Dump;
using Corvus.Native.Dump.Rebuild;
using Corvus.Native.Pe;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>The modules of a real 32-bit program are rebuilt from its full-memory dump and compared with their files.</summary>
[Trait("Speed", "Slow")]
[Permit("live")]
[Collection(ExternalToolEnvironmentCollection.Name)]
public sealed class DumpRebuildX86RealTests(ITestOutputHelper output) : IDisposable
{
    private const string DumperSource = """
        #include <windows.h>
        #include <dbghelp.h>
        #pragma comment(lib, "dbghelp.lib")

        int main(int argc, char** argv)
        {
            HANDLE f = CreateFileA(argv[1], GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (f == INVALID_HANDLE_VALUE) return 2;
            MINIDUMP_TYPE type = (MINIDUMP_TYPE)(MiniDumpWithFullMemory | MiniDumpWithFullMemoryInfo |
                MiniDumpWithThreadInfo | MiniDumpWithUnloadedModules);
            BOOL ok = MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), f, type, NULL, NULL, NULL);
            CloseHandle(f);
            return ok ? 0 : 3;
        }
        """;

    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private string DumpProgram()
    {
        var exe = LiveTarget.WinX86.Build(_dir, "dumper", DumperSource);
        var dump = _dir.File("x86.dmp");
        var psi = new ProcessStartInfo(exe) { UseShellExecute = false, CreateNoWindow = true };
        psi.ArgumentList.Add(dump);
        using var process = Process.Start(psi)!;
        try { Assert.True(process.WaitForExit(60_000), "the program did not exit"); }
        finally { if (!process.HasExited) process.Kill(); }
        Assert.True(process.ExitCode == 0 && File.Exists(dump), $"no dump written (exit code {process.ExitCode})");
        return dump;
    }

    /// <summary>Executable sections of the rebuilt file against the file's own, by raw range.</summary>
    private static string? CodeDifference(PeFile rebuilt, byte[] rebuiltBytes, PeFile file, byte[] fileBytes)
    {
        foreach (var s in file.Sections.Where(s => s.IsExecutable && s.RawSize > 0))
        {
            var other = rebuilt.Sections.FirstOrDefault(r => r.Name == s.Name && r.Rva == s.Rva);
            if (other == null) return $"{s.Name} is missing";
            int length = (int)Math.Min(s.RawSize, Math.Min(fileBytes.Length - s.RawOffset, rebuiltBytes.Length - other.RawOffset));
            var a = fileBytes.AsSpan((int)s.RawOffset, length);
            var b = rebuiltBytes.AsSpan((int)other.RawOffset, length);
            int at = a.CommonPrefixLength(b);
            if (at < length || other.RawSize != s.RawSize)
                return $"{s.Name} differs at +0x{at:X} of 0x{s.RawSize:X}";
        }
        return null;
    }

    private static List<(uint Start, uint End, uint Size, FunctionFlags Flags)> Functions(PeFile image) =>
        [.. NativeCodeIndex.Build(image).Functions.Select(f => (f.Start, f.End, f.Size, f.Flags)).OrderBy(f => f.Start)];

    // Writable sections hold values the program wrote at run time, and the
    // index follows pointers in them; the file's values are laid over them.
    private static PeFile WithFileData(PeFile rebuilt, byte[] rebuiltBytes, PeFile file, byte[] fileBytes)
    {
        var bytes = (byte[])rebuiltBytes.Clone();
        foreach (var s in file.Sections.Where(s => (s.Access & SectionAccess.Write) != 0 && s.RawSize > 0))
        {
            var other = rebuilt.Sections.FirstOrDefault(r => r.Name == s.Name && r.Rva == s.Rva);
            if (other == null) continue;
            int length = (int)Math.Min(s.RawSize, Math.Min(fileBytes.Length - s.RawOffset, bytes.Length - other.RawOffset));
            fileBytes.AsSpan((int)s.RawOffset, length).CopyTo(bytes.AsSpan((int)other.RawOffset));
        }
        return PeFile.FromBytes(bytes, rebuilt.Path);
    }

    private static string? FunctionDifference(PeFile rebuilt, PeFile file)
    {
        var a = Functions(file);
        var b = Functions(rebuilt);
        if (a.Count != b.Count) return $"{a.Count} functions in the file, {b.Count} rebuilt";
        for (int i = 0; i < a.Count; i++)
            if (a[i] != b[i]) return $"function {i} at 0x{a[i].Start:X} is {a[i]} in the file, {b[i]} rebuilt";
        return null;
    }

    [Fact]
    public void A_rebuilt_32_bit_program_matches_its_files_in_code_and_functions()
    {
        if (!OperatingSystem.IsWindows() || RuntimeInformation.ProcessArchitecture != Architecture.X64 || !VisualStudio.HasVcVars) return;
        if (LiveTarget.WinX86.Missing is { } missing) { output.WriteLine(missing); return; }

        using var dump = MinidumpFile.Open(DumpProgram());
        Assert.NotEmpty(dump.Modules);
        // The dump records System32 paths; a 64-bit reader resolves them to 64-bit files.
        var options = RebuildOptions.Default with
        {
            Base = BaseMode.Preferred,
            ImageDirectories = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64"),
        };
        var failures = new List<string>();
        int compared = 0;
        foreach (var module in dump.Modules)
        {
            var rebuilt = ModuleRebuild.Rebuild(dump, RebuildTarget.Of(module), options, CancellationToken.None);
            var path = rebuilt.Disk is { SameBuild: true } disk ? disk.File : null;
            if (rebuilt.Bytes == null || path == null)
            {
                string why = rebuilt.Refused ?? "no file of the same build";
                output.WriteLine($"{module.FileName}: not compared ({why})");
                failures.Add($"{module.FileName}: not compared ({why})");
                continue;
            }
            var fileBytes = File.ReadAllBytes(path);
            var file = PeFile.FromBytes(fileBytes, path);
            var rebuiltFile = PeFile.FromBytes(rebuilt.Bytes, module.FileName);
            string? patches = rebuilt.Checks.FirstOrDefault(c => c.Name == "loader patches") is { State: not "failed" } ? null : "loader patches failed";
            string? code = CodeDifference(rebuiltFile, rebuilt.Bytes, file, fileBytes);
            string? functions = FunctionDifference(WithFileData(rebuiltFile, rebuilt.Bytes, file, fileBytes), file);
            output.WriteLine($"{module.FileName}: patches {(patches ?? "ok")}, code {(code ?? "equal")}, functions {(functions ?? "equal")}");
            compared++;
            foreach (var problem in new[] { patches, code, functions }.OfType<string>()) failures.Add($"{module.FileName}: {problem}");
        }
        Assert.True(compared >= 3, $"{compared} modules compared");
        Assert.True(failures.Count == 0, string.Join(Environment.NewLine, failures));
    }
}
