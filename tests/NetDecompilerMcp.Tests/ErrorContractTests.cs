using NetDecompilerMcp.Core;
using NetDecompilerMcp.Mcp;

namespace NetDecompilerMcp.Tests;

/// <summary>docs/errors.md matches the error codes; every code has a distinct name and a meaning.</summary>
public class ErrorContractTests
{
    [Fact]
    public void EveryCodeIsNamedAndExplained()
    {
        var codes = Enum.GetValues<ErrorCode>();
        Assert.Equal(codes.Length, codes.Select(ToolError.CodeName).Distinct().Count());
        Assert.All(codes.Where(c => c != ErrorCode.Failed), c => Assert.NotEqual("failed", ToolError.CodeName(c)));
        Assert.All(codes.Where(c => c != ErrorCode.Failed), c => Assert.NotEqual("Not classified.", ToolError.Meaning(c)));
        Assert.Contains("cancelled", codes.Select(ToolError.CodeName));
        Assert.Contains("changed_on_disk", codes.Select(ToolError.CodeName));
    }

    [Fact]
    public void ErrorDocumentIsCurrent()
    {
        var root = AppContext.BaseDirectory;
        while (!File.Exists(Path.Combine(root, "NetDecompilerMcp.slnx"))) root = Path.GetDirectoryName(root) ?? throw new InvalidOperationException("repository root not found");
        var path = Path.Combine(root, "docs", "errors.md");
        var expected = ErrorResult.ContractMarkdown().ReplaceLineEndings("\n");
        if (Environment.GetEnvironmentVariable("NDM_UPDATE_DOCS") == "1") File.WriteAllText(path, expected);
        Assert.True(File.Exists(path) && File.ReadAllText(path).ReplaceLineEndings("\n") == expected,
            "docs/errors.md is out of date: run the tests once with NDM_UPDATE_DOCS=1");
    }
}
