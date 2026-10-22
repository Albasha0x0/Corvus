using Corvus.Core;
using Corvus.Mcp;

namespace Corvus.Tests;

/// <summary>File system exceptions become tool errors by their type, whatever the JIT left of their stack.</summary>
public class FileSystemErrorTests
{
    [Fact]
    public void Exceptions_without_a_stack_are_classified_by_type()
    {
        // Never thrown, so no frame at all: the case of System.IO inlined into the caller.
        Assert.Equal(ErrorCode.IoError, ArgumentCheck.FileSystemError(new IOException("sharing violation"))?.Code);
        Assert.Equal(ErrorCode.IoError, ArgumentCheck.FileSystemError(new UnauthorizedAccessException("denied"))?.Code);
        Assert.Equal(ErrorCode.NotFound, ArgumentCheck.FileSystemError(new FileNotFoundException("gone"))?.Code);
        Assert.Equal(ErrorCode.NotFound, ArgumentCheck.FileSystemError(new DirectoryNotFoundException("gone"))?.Code);
        Assert.Equal(ErrorCode.InvalidArgument, ArgumentCheck.FileSystemError(new PathTooLongException())?.Code);
        Assert.Equal(ErrorCode.InvalidArgument, ArgumentCheck.FileSystemError(new ArgumentException("Null character in path.", "path"))?.Code);
    }

    [Fact]
    public void Other_exceptions_stay_internal()
    {
        Assert.Null(ArgumentCheck.FileSystemError(new ArgumentOutOfRangeException("index")));
        Assert.Null(ArgumentCheck.FileSystemError(new ArgumentException("bad value")));
        Assert.Null(ArgumentCheck.FileSystemError(new InvalidOperationException("state")));
        Assert.Null(ArgumentCheck.FileSystemError(new NotSupportedException("seek")));
    }

    [Fact]
    public async Task A_locked_file_is_an_io_error_with_tiered_compilation_off()
    {
        // Every method is compiled optimized on first call, as tier 1 does after repeated calls in a Release build.
        using var dir = new TempDir();
        var path = Path.Combine(dir.Path, "locked.bin");
        File.WriteAllBytes(path, new byte[64]);
        await using var client = await McpProtocolTests.StartServerAsync(null, null, ["--no-watch", "--no-index", ServerOptions.InProcessParsingOption],
            new Dictionary<string, string?> { ["DOTNET_TieredCompilation"] = "0" });
        using (new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            var error = McpProtocolTests.ErrorJson(await client.CallToolAsync("summarize_file", new Dictionary<string, object?> { ["path"] = path }));
            Assert.Equal("io_error", error.GetProperty("code").GetString());
        }
    }
}
