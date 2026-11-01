using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Xunit;

namespace Corvus.Tests.DotnetEdits;

public class CSharpFormatErrorsTests
{
    // Reproduces 90 identical locationless CS0009 diagnostics hiding other errors (674146995).
    [Fact]
    public void Identical_reference_errors_print_once_and_distinct_errors_remain()
    {
        var tree = CSharpSyntaxTree.ParseText("class C { int a = x; int b = y; }");
        var compilation = CSharpCompilation.Create("t", [tree]);
        var same = Diagnostic.Create(
            new DiagnosticDescriptor("CS0009", "t", "Metadata file 'm.dll' could not be opened", "c", DiagnosticSeverity.Error, true),
            Location.None);
        var bad = compilation.GetDiagnostics().Where(d => d.Severity == DiagnosticSeverity.Error).ToList();
        Assert.True(bad.Count >= 2);

        var text = Services.CSharpPatcher.FormatErrors([.. Enumerable.Repeat(same, 90), .. bad], tree, []);

        Assert.Equal(1, text.Split("CS0009").Length - 1);
        Assert.Contains($"({bad.Count + 1} error(s))", text);
        Assert.Contains("CS0103", text);
    }

    [Fact]
    public void Same_error_at_two_locations_is_kept_twice()
    {
        var tree = CSharpSyntaxTree.ParseText("class C { int a = x; int b = x; }");
        var compilation = CSharpCompilation.Create("t", [tree]);
        var bad = compilation.GetDiagnostics().Where(d => d.Id == "CS0103").ToList();
        Assert.Equal(2, bad.Count);

        var text = Services.CSharpPatcher.FormatErrors(bad, tree, []);

        Assert.Contains("(2 error(s))", text);
    }

    // Controlled condition: 25 distinct locationless errors, each repeated twice.
    [Fact]
    public void The_line_cap_counts_distinct_errors_only()
    {
        var tree = CSharpSyntaxTree.ParseText("class C { }");
        var errors = Enumerable.Range(0, 25).Select(i => Diagnostic.Create(
            new DiagnosticDescriptor("CS0009", "t", $"Metadata file 'm{i}.dll' could not be opened", "c", DiagnosticSeverity.Error, true),
            Location.None)).ToList();

        var text = Services.CSharpPatcher.FormatErrors([.. errors, .. errors], tree, []);

        Assert.Contains("(25 error(s))", text);
        Assert.Contains("\u2026 5 more", text);
    }
}
