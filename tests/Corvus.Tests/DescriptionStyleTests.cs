using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Corvus.Core;
using Corvus.Mcp;

namespace Corvus.Tests;

/// <summary>S8.3 wording of tool and parameter descriptions: what a tool returns first, no machine paths or notes to self.</summary>
[Collection(InProcessCatalogCollection.Name)]
public partial class DescriptionStyleTests
{
    private static readonly List<JsonNode> Tools = Catalog.OfThisBuild(Toolsets.All).Tools;

    private static IEnumerable<(string Where, string Text)> Texts() => Tools.SelectMany(t =>
        new[] { ((string)t["name"]!, (string?)t["description"] ?? "") }.Concat(
            (t["inputSchema"]!["properties"] as JsonObject ?? []).Select(p => ($"{t["name"]}.{p.Key}", (string?)p.Value?["description"] ?? ""))));

    /// <summary>A user's home or profile folder, or a drive other than C: (C:\symbols is the conventional symbol cache).</summary>
    [GeneratedRegex(@"(?i)\b[a-z]:[\\/](users|documents and settings)\b|/home/\w|/Users/\w|AppData[\\/]|\b[d-z]:[\\/]")]
    private static partial Regex MachinePath();

    [GeneratedRegex(@"\b(TODO|FIXME|XXX|HACK)\b")]
    private static partial Regex NoteToSelf();

    [Fact]
    public void NoMachinePathsOrNotesToSelf()
    {
        foreach (var (where, text) in Texts())
        {
            Assert.False(MachinePath().IsMatch(text), $"{where}: a machine-specific path: {text}");
            Assert.False(NoteToSelf().IsMatch(text), $"{where}: a note to self: {text}");
        }
    }

    [Fact]
    public void LongRunningSuffixOnlyFromToolEffects()
    {
        foreach (var tool in Tools)
        {
            var name = (string)tool["name"]!;
            var description = (string?)tool["description"] ?? "";
            Assert.True(description.EndsWith(ToolEffects.LongRunningSuffix, StringComparison.Ordinal) == ToolEffects.Of(name).LongRunning,
                $"{name}: the long-running suffix must match ToolEffects");
            Assert.True(description.IndexOf("Long-running", StringComparison.Ordinal) is var i && (i < 0 || i == description.Length - ToolEffects.LongRunningSuffix.Length + 2),
                $"{name}: a hand-written long-running note (ToolEffects adds the suffix)");
        }
    }

    /// <summary>The first word says what comes back or what is done: a capitalized verb or noun, not "This tool", "Use" or "Tool".</summary>
    [Fact]
    public void FirstSentenceSaysWhatTheToolReturns()
    {
        var violations = new Dictionary<string, string>();
        foreach (var tool in Tools)
        {
            var description = (string?)tool["description"] ?? "";
            var first = description.Split(' ', 2)[0];
            if (description.Length == 0 || !char.IsUpper(description[0]) || first is "This" or "Use" or "Tool" or "A" or "An" or "The" or "Note:" or "Note")
                violations[(string)tool["name"]!] = $"starts '{string.Concat(description.Take(40))}'";
        }
        Ratchet.Check("description-first-sentence", "a description starts with what the tool returns or does (S8.3)", violations);
    }

    [Fact]
    public void EveryParameterIsDescribed()
    {
        var violations = Texts().Where(t => t.Where.Contains('.') && string.IsNullOrWhiteSpace(t.Text)).ToDictionary(t => t.Where, _ => "no description");
        Ratchet.Check("parameter-described", "every parameter has a description (S7)", violations);
    }
}
