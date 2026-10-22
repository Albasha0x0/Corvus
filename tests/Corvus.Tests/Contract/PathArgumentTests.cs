using System.Text.Json;
using System.Text.Json.Nodes;
using Corvus.Core;
using Corvus.Mcp;

namespace Corvus.Tests;

/// <summary>Path arguments are checked before any file API sees them.</summary>
public class PathArgumentTests
{
    private static readonly Dictionary<string, JsonObject> Schemas =
        Catalog.OfThisBuild().Tools.ToDictionary(t => (string)t["name"]!, t => t["inputSchema"]!.AsObject());

    private static JsonElement Schema(string tool) => JsonSerializer.SerializeToElement(Schemas[tool]);

    private static Dictionary<string, JsonElement> Args(params (string Name, object? Value)[] args) =>
        args.ToDictionary(a => a.Name, a => JsonSerializer.SerializeToElement(a.Value));

    [Theory]
    [InlineData("a\0b")]
    [InlineData("out\tname.dll")]
    public void A_control_character_is_a_path_problem(string path) =>
        Assert.Equal("it contains a control character", InputFiles.PathProblem(path));

    [Fact]
    public void A_name_past_the_length_limit_is_a_path_problem()
    {
        var path = Path.Combine(Path.GetTempPath(), new string('n', InputFiles.MaxNameLength + 1) + ".dll");
        Assert.Contains($"the limit is {InputFiles.MaxNameLength}", InputFiles.PathProblem(path));
        Assert.Null(InputFiles.PathProblem(Path.Combine(Path.GetTempPath(), new string('n', InputFiles.MaxNameLength))));
    }

    [Fact]
    public void Windows_reserved_characters_are_path_problems_but_prefixes_and_drives_are_not()
    {
        if (!OperatingSystem.IsWindows()) return;
        Assert.Equal("'<' is not allowed in a Windows file name", InputFiles.PathProblem(@"C:\out\bad<>|?*name.dll"));
        Assert.Equal("':' is not allowed in a Windows file name", InputFiles.PathProblem(@"C:\out\a:b.dll"));
        Assert.Null(InputFiles.PathProblem(@"C:\out\app.dll"));
        Assert.Null(InputFiles.PathProblem(@"\\?\C:\out\app.dll"));
        Assert.Null(InputFiles.PathProblem(@"\\?\UNC\host\share\app.dll"));
        Assert.Null(InputFiles.PathProblem(@"\\.\pipe\name"));
    }

    [Fact]
    public void A_malformed_output_path_is_rejected_naming_the_parameter()
    {
        var name = Path.Combine(Path.GetTempPath(), "a\0b.dll");
        var error = Assert.Throws<ToolError>(() => ArgumentCheck.Apply(Schema("save_assembly"), Args(("assembly", "x"), ("outputPath", name)), "save_assembly"));
        Assert.Equal(ErrorCode.InvalidArgument, error.Code);
        Assert.Equal("parameter 'outputPath' is not a valid path: it contains a control character.", error.Message);

        var longName = Path.Combine(Path.GetTempPath(), new string('n', 300) + ".dll");
        var tooLong = Assert.Throws<ToolError>(() => ArgumentCheck.Apply(Schema("get_resource"), Args(("assembly", "x"), ("name", "r"), ("outputPath", longName)), "get_resource"));
        Assert.StartsWith("parameter 'outputPath' is not a valid path: a name in it is 304 characters long", tooLong.Message);
    }

    public static TheoryData<string, string> PathParametersOfEveryTool()
    {
        var data = new TheoryData<string, string>();
        foreach (var (tool, schema) in Schemas)
            foreach (var (name, property) in schema["properties"]!.AsObject())
                if (ArgumentCheck.PathParameters.Contains(name) && property!.ToJsonString().Contains("\"string\""))
                    data.Add(tool, name);
        return data;
    }

    [Theory]
    [MemberData(nameof(PathParametersOfEveryTool))]
    public void Every_path_parameter_rejects_malformed_and_overlong_names(string tool, string parameter)
    {
        foreach (var path in new[] { Path.Combine(Path.GetTempPath(), "a\0b"), Path.Combine(Path.GetTempPath(), new string('n', 300)) })
        {
            var error = Assert.Throws<ToolError>(() => ArgumentCheck.Apply(Schema(tool), Args((parameter, path)), tool));
            Assert.Equal(ErrorCode.InvalidArgument, error.Code);
            Assert.StartsWith($"parameter '{parameter}' is not a valid path: ", error.Message);
        }
    }

    [Fact]
    public void A_writer_given_a_malformed_path_names_the_problem_and_a_hint_without_echoing_it()
    {
        var path = Path.Combine(Path.GetTempPath(), "a\0b.dll");
        var error = Assert.Throws<ToolError>(() => SafeFile.FullPath(path));
        Assert.Equal("invalid output path: it contains a control character.", error.Message);
        Assert.Equal("Pass an absolute path without invalid characters.", error.Remediation);
        var tooLong = Assert.Throws<ToolError>(() => SafeFile.FullPath(Path.Combine(Path.GetTempPath(), new string('n', 300))));
        Assert.Equal("Pass a shorter path.", tooLong.Remediation);
        Assert.DoesNotContain(new string('n', 300), tooLong.Message);
    }

    [Fact]
    public void An_empty_optional_path_counts_as_not_given()
    {
        var args = Args(("path", "  "));
        ArgumentCheck.Apply(Schema("list_assemblies"), args, "list_assemblies");
        Assert.False(args.ContainsKey("path"));
    }

    [Fact]
    public void An_empty_required_path_is_rejected_naming_the_parameter()
    {
        var error = Assert.Throws<ToolError>(() => ArgumentCheck.Apply(Schema("load_assembly"), Args(("path", "")), "load_assembly"));
        Assert.Equal(ErrorCode.InvalidArgument, error.Code);
        Assert.Equal("parameter 'path' is empty.", error.Message);
    }

    [Fact]
    public void Each_image_directory_is_checked()
    {
        var good = Path.GetTempPath();
        var error = Assert.Throws<ToolError>(() => ArgumentCheck.Apply(Schema("open_minidump"), Args(("path", Path.Combine(good, "a.dmp")), ("imageDirectories", $"{good};{good}a\0b")), "open_minidump"));
        Assert.StartsWith("parameter 'imageDirectories' is not a valid path", error.Message);
    }
}
