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

    // The host name is reserved (RFC 2606), so a path to it never resolves even if opened.
    private const string Share = @"\\corvus-remote.invalid\share\";

    [Fact]
    public void Network_and_device_paths_are_named_and_local_ones_pass()
    {
        if (!OperatingSystem.IsWindows()) return;
        string? Problem(string path, bool allow = false) => InputFiles.RemoteProblem(Path.GetFullPath(path), allow);
        Assert.Equal("a network path", Problem(Share + "a.dll"));
        Assert.Equal("a network path", Problem("//corvus-remote.invalid/share/a.dll"));
        Assert.Equal("a network path", Problem(@"\\?\UNC\corvus-remote.invalid\share\a.dll"));
        Assert.Equal("a device path", Problem(@"\\?\GLOBALROOT\Device\HarddiskVolume1\a.dll"));
        Assert.Equal("a device path", Problem(@"\\.\pipe\corvus"));
        Assert.Equal("a device path", Problem(@"\\.\PhysicalDrive0", allow: true));
        Assert.Null(Problem(Share + "a.dll", allow: true));
        Assert.Null(Problem(Path.Combine(Path.GetTempPath(), "a.dll")));
        Assert.Null(Problem(@"\\?\" + Path.Combine(Path.GetTempPath(), "a.dll")));
    }

    [Fact]
    public void A_local_link_to_a_share_is_a_network_path()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var dir = new TempDir();
        var file = Path.Combine(dir.Path, "a.dll");
        var folder = Path.Combine(dir.Path, "linked");
        try
        {
            File.CreateSymbolicLink(file, Share + "a.dll");
            Directory.CreateSymbolicLink(folder, Share.TrimEnd('\\'));
        }
        // Creating a symbolic link needs Developer Mode or the privilege; without it there is nothing to check.
        catch (IOException) { return; }
        catch (UnauthorizedAccessException) { return; }
        Assert.Equal("a network path", InputFiles.RemoteProblem(file, false));
        Assert.Equal("a network path", InputFiles.RemoteProblem(Path.Combine(folder, "b.dll"), false));
        Assert.Equal("parameter 'path' is a network path; only files on this machine are opened.",
            Assert.Throws<ToolError>(() => ArgumentCheck.Apply(Schema("load_assembly"), Args(("path", file)), "load_assembly")).Message);
    }

    [Theory]
    [MemberData(nameof(PathParametersOfEveryTool))]
    public void Every_path_parameter_refuses_a_network_path_before_the_tool_runs(string tool, string parameter)
    {
        if (!OperatingSystem.IsWindows()) return;
        var error = Assert.Throws<ToolError>(() => ArgumentCheck.Apply(Schema(tool), Args((parameter, Share + "a.dll")), tool));
        Assert.Equal((ErrorCode.InvalidArgument, $"parameter '{parameter}' is a network path; only files on this machine are opened."), (error.Code, error.Message));
        Assert.Contains(ServerOptions.AllowRemotePathsOption, error.Remediation);
    }

    public static TheoryData<string, string> TargetParametersOfEveryTool()
    {
        var data = new TheoryData<string, string>();
        foreach (var (tool, schema) in Schemas)
            foreach (var (name, property) in schema["properties"]!.AsObject())
                if (ArgumentCheck.IsTarget(tool, name) && property!.ToJsonString().Contains("\"string\""))
                    data.Add(tool, name);
        return data;
    }

    [Theory]
    [MemberData(nameof(TargetParametersOfEveryTool))]
    public void Every_id_or_path_parameter_refuses_a_network_path_and_keeps_ids(string tool, string parameter)
    {
        if (!OperatingSystem.IsWindows()) return;
        var error = Assert.Throws<ToolError>(() => ArgumentCheck.Apply(Schema(tool), Args((parameter, Share + "a.dll")), tool));
        Assert.Equal($"parameter '{parameter}' is a network path; only files on this machine are opened.", error.Message);
        ArgumentCheck.Apply(Schema(tool), Args((parameter, "app.dll#2")), tool);
    }

    // Parameters whose description names a path or file but that hold no path on this machine.
    private static readonly HashSet<string> NotLocalPaths = new(StringComparer.Ordinal)
    {
        // Paths on a device or inside an archive or project.
        "pull_android_file.remotePath", "get_android_resource.name", "load_assembly.program", "live_break.at",
        // Search text, filters and patterns.
        "search_container.query", "list_assemblies.filter", "compare_folders.exclude", "bucket_minidumps.pattern", "symbolize_stack_text.text",
        // Note anchors name a loaded file by id or by the path it was loaded from.
        "record_note.anchor", "list_notes.anchor",
        // Choices of a mode.
        "live_timeline.category", "search_bytes.memory", "load_assembly.entry", "find_method_by_address.kind", "compare_native_images.engine",
    };

    [Fact]
    public void Every_parameter_described_as_a_path_is_checked_as_one()
    {
        var unchecked_ = new List<string>();
        foreach (var (tool, schema) in Schemas)
            foreach (var (name, property) in schema["properties"]!.AsObject())
                if (property!.ToJsonString() is var json && json.Contains("\"string\"")
                    && System.Text.RegularExpressions.Regex.IsMatch((string?)property["description"] ?? "", @"\b(path|file|folder|directory)\b", System.Text.RegularExpressions.RegexOptions.IgnoreCase)
                    && !ArgumentCheck.PathParameters.Contains(name) && !ArgumentCheck.IsTarget(tool, name) && !NotLocalPaths.Contains($"{tool}.{name}"))
                    unchecked_.Add($"{tool}.{name}: {(string?)property["description"]}");
        Assert.True(unchecked_.Count == 0, string.Join("\n", unchecked_));
    }

    [Fact]
    public void Every_output_parameter_in_the_catalog_is_in_the_output_set()
    {
        var missing = new List<string>();
        foreach (var (tool, schema) in Schemas)
            foreach (var (name, property) in schema["properties"]!.AsObject())
                if (property!.ToJsonString().Contains("\"string\"") && IsOutput(name, (string?)property["description"] ?? "")
                    && !ArgumentCheck.OutputPathParameters.Contains(name))
                    missing.Add($"{tool}.{name}: {(string?)property["description"]}");
        Assert.True(missing.Count == 0, string.Join("\n", missing));
        Assert.All(ArgumentCheck.OutputPathParameters, name => Assert.Contains(Schemas.Values, s => s["properties"]!.AsObject().ContainsKey(name)));
        Assert.Empty(ArgumentCheck.InputPathParameters.Intersect(ArgumentCheck.OutputPathParameters));
    }

    private static bool IsOutput(string name, string description) =>
        name.StartsWith("output", StringComparison.Ordinal)
        || (ArgumentCheck.PathParameters.Contains(name) || System.Text.RegularExpressions.Regex.IsMatch(name, "(Path|Directory|Dir|File|Folder)$"))
           && System.Text.RegularExpressions.Regex.IsMatch(description, @"(?i)\b(output|write|writes|written|saves?|saved|png|dump file)\b");

    [Fact]
    public void Provenance_does_not_hash_a_device_or_a_network_path()
    {
        var device = OperatingSystem.IsWindows() ? @"\\.\NUL" : "/dev/zero";
        var clock = System.Diagnostics.Stopwatch.StartNew();
        Assert.Null(ToolOutput.Input(device, null));
        Assert.Null(ToolOutput.Input(Share + "a.dll", null));
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(5), $"{clock.Elapsed}");
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
