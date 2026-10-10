using System.Diagnostics;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native.Dump;
using NetDecompilerMcp.Native.Pdb;
using NetDecompilerMcp.Native.Pe;

namespace NetDecompilerMcp.Tests;

public class InputFileTests
{
    [PosixFact]
    public void FifoIsRefusedWithoutBlocking()
    {
        using var dir = new TempDir();
        var fifo = dir.File("pipe.dll");
        using (var mk = Process.Start(new ProcessStartInfo("mkfifo", [fifo]) { UseShellExecute = false })!) mk.WaitForExit();
        Assert.True(File.Exists(fifo));

        using var ws = new AssemblyWorkspace();
        Action[] loads =
        [
            () => ws.Load(fifo),
            () => ws.LoadAny(fifo),
            () => PeFile.Open(fifo),
            () => MsfFile.Open(fifo),
            () => MinidumpFile.Open(fifo),
        ];
        foreach (var load in loads)
        {
            var task = Task.Run(() => Assert.Throws<ToolError>(load));
            Assert.True(task.Wait(TimeSpan.FromSeconds(20)), "the load blocked on the FIFO");
            Assert.Equal(ErrorCode.InvalidArgument, task.Result.Code);
            Assert.Contains("FIFO", task.Result.Message);
        }
    }

    [WindowsFact("Device paths are a Windows namespace.")]
    public void WindowsDevicePathIsRefused()
    {
        using var ws = new AssemblyWorkspace();
        var error = Assert.Throws<ToolError>(() => ws.Load(@"\\.\NUL"));
        Assert.Equal(ErrorCode.InvalidArgument, error.Code);
        Assert.Contains("a device", error.Message);
    }

    [Fact]
    public void DirectoryIsRefusedWhereAFileIsExpected()
    {
        using var dir = new TempDir();
        using var ws = new AssemblyWorkspace();
        Assert.Contains("is a directory", Assert.Throws<ToolError>(() => ws.Load(dir.Path)).Message);
        Assert.Contains("is a directory", Assert.Throws<ToolError>(() => PeFile.Open(dir.Path)).Message);
        Assert.Contains("is a directory", Assert.Throws<ToolError>(() => MsfFile.Open(dir.Path)).Message);
    }

    [Fact]
    public void LoadedPathsDedupeByTheFileSystemsCaseRule()
    {
        bool ignoresCase = OperatingSystem.IsWindows() || OperatingSystem.IsMacOS();
        Assert.Equal(ignoresCase ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal, InputFiles.PathComparison);

        using var dir = new TempDir();
        var lower = dir.File("fixture.dll");
        var upper = dir.File("FIXTURE.dll");
        File.Copy(Env.FixturePath, lower);
        using var ws = new AssemblyWorkspace();
        var first = ws.Load(lower);
        if (ignoresCase)
            Assert.Same(first, ws.Load(upper));
        else
        {
            File.Copy(Env.FixturePath, upper); // a distinct file on a case-sensitive file system
            Assert.NotSame(first, ws.Load(upper));
        }
    }
}

/// <summary>A fact that runs only on Linux and macOS.</summary>
public sealed class PosixFactAttribute : FactAttribute
{
    public PosixFactAttribute(string reason = "Needs POSIX FIFOs (mkfifo).")
    {
        if (OperatingSystem.IsWindows()) Skip = reason;
    }
}
