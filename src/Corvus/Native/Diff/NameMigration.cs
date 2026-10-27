using Corvus.Native.Annotations;
using Corvus.Native.Code;

namespace Corvus.Native.Diff;

/// <summary>A name or comment of the old build to carry over.</summary>
public sealed record MigrationSource(string Kind, NativeNameSource Source, uint OldRva, string Value)
{
    /// <summary>A comment's engine kind (eol, pre, plate); null: repeatable.</summary>
    public string? CommentKind { get; init; }
}

/// <summary>What happens to one name or comment: set at the new address, or skipped with a reason code.</summary>
public sealed record MigrationStep(MigrationSource Item, uint? NewRva, string Value, bool Set, string Reason, int? Tier, double Confidence, string Detail);

/// <summary>Options of <see cref="NameMigration.Plan"/>.</summary>
public sealed record MigrationOptions
{
    /// <summary>Weakest match tier accepted for addresses in functions (1 = names and identical bytes only, 5 = all).</summary>
    public int MinTier { get; init; } = 5;
    /// <summary>Least mapping confidence accepted (0-1).</summary>
    public double MinScore { get; init; }
}

/// <summary>Plans carrying names and comments to a new build's user layer; never replaces a user name or comment there.</summary>
public static class NameMigration
{
    /// <summary>The kind of a user's decompiler comment (the others: name, comment).</summary>
    public const string PseudoComment = "pseudo_comment";

    /// <summary>The user's names and, with <paramref name="comments"/>, disassembly comments (with their kinds) and decompiler comments.</summary>
    public static List<MigrationSource> UserItems(NativeAnnotations annotations, bool comments = true)
    {
        var items = annotations.Names().Select(x => new MigrationSource("name", NativeNameSource.User, x.Rva, x.Name)).ToList();
        if (!comments) return items;
        items.AddRange(annotations.Comments().Select(x => new MigrationSource("comment", NativeNameSource.User, x.Rva, x.Comment) { CommentKind = annotations.CommentKindAt(x.Rva) }));
        items.AddRange(annotations.PseudoComments().Select(x => new MigrationSource(PseudoComment, NativeNameSource.User, x.Rva, x.Comment)));
        return items;
    }

    /// <summary>Records the set steps in one change; returns the names and comments set, for the code indexes.</summary>
    public static (List<(uint Rva, string? Name)> Names, List<(uint Rva, string? Text)> Comments) Apply(NativeAnnotations annotations, IEnumerable<MigrationStep> steps)
    {
        var set = steps.Where(s => s.Set && s.NewRva != null).ToList();
        var names = set.Where(s => s.Item.Kind == "name").Select(s => (s.NewRva!.Value, (string?)s.Value)).ToList();
        var comments = set.Where(s => s.Item.Kind == "comment").ToList();
        var lines = comments.Select(s => (s.NewRva!.Value, (string?)s.Value)).ToList();
        annotations.Apply(names, lines, [.. set.Where(s => s.Item.Kind == PseudoComment).Select(s => (s.NewRva!.Value, (string?)s.Value))],
            allowDuplicate: true, kinds: [.. comments.Select(s => (s.NewRva!.Value, s.Item.CommentKind))]);
        return (names, lines);
    }

    public static List<MigrationStep> Plan(AddressMapper mapper, IReadOnlyList<MigrationSource> items, NativeCodeIndex newIndex,
        NativeAnnotations newAnnotations, MigrationOptions options, CancellationToken ct) =>
        Plan(mapper.Map, items, newIndex, newAnnotations, options, ct);

    /// <summary>As the build form, with <paramref name="map"/> placing each item's address in the new build.</summary>
    public static List<MigrationStep> Plan(Func<uint, CancellationToken, MappedAddress> map, IReadOnlyList<MigrationSource> items, NativeCodeIndex newIndex,
        NativeAnnotations newAnnotations, MigrationOptions options, CancellationToken ct)
    {
        var steps = new List<MigrationStep>(items.Count);
        var usedNames = new Dictionary<string, uint>(StringComparer.Ordinal);
        foreach (var (rva, name) in newAnnotations.Names()) usedNames.TryAdd(name, rva);
        var plannedNames = new Dictionary<uint, MigrationSource>();
        var plannedComments = new Dictionary<uint, MigrationSource>();
        var plannedPseudo = new Dictionary<uint, MigrationSource>();

        // User items first, so they win over imported names landing on the same address.
        foreach (var item in items.OrderByDescending(i => i.Source.Rank()).ThenBy(i => i.OldRva))
        {
            ct.ThrowIfCancellationRequested();
            var mapped = map(item.OldRva, ct);
            int? tier = mapped.Pair?.Tier;
            MigrationStep Skip(string reason, string detail, string? value = null) =>
                new(item, mapped.NewRva, value ?? item.Value, false, reason, tier, mapped.Confidence, detail);

            if (mapped.NewRva is not { } at) { steps.Add(Skip(mapped.Reason, mapped.Detail)); continue; }
            if (tier is { } t && t > options.MinTier) { steps.Add(Skip("below_min_tier", $"matched in tier {t} ({MatchResult.TierNames[t]}); minTier is {options.MinTier}")); continue; }
            if (mapped.Confidence < options.MinScore) { steps.Add(Skip("below_min_score", $"confidence {mapped.Confidence:0.###} < minScore {options.MinScore:0.###}")); continue; }

            if (item.Kind is "comment" or PseudoComment)
            {
                var existing = item.Kind == PseudoComment ? newAnnotations.PseudoCommentAt(at) : newAnnotations.CommentAt(at);
                if (existing == item.Value.Trim()) { steps.Add(Skip("same_comment", "the new build already has this comment")); continue; }
                if (existing != null) { steps.Add(Skip("user_comment_exists", $"the new build has another comment there: \"{Clip(existing)}\"")); continue; }
                var planned = item.Kind == PseudoComment ? plannedPseudo : plannedComments;
                if (planned.TryGetValue(at, out var first)) { steps.Add(Skip("duplicate_target", $"the comment from {first.OldRva:X} already lands there")); continue; }
                planned[at] = item;
                steps.Add(new(item, at, item.Value, true, mapped.Reason, tier, mapped.Confidence, mapped.Detail));
                continue;
            }

            string value = item.Value;
            if (item.Source != NativeNameSource.User)
            {
                value = NativeName.Identifier(item.Value);
                if (value.Length > NativeName.MaxLength) value = value[..NativeName.MaxLength];
            }
            try { value = NativeName.Validate(value); }
            catch (Core.ToolError e) { steps.Add(Skip("invalid_name", e.Message, value)); continue; }

            var userName = newAnnotations.NameAt(at);
            if (userName == value) { steps.Add(Skip("same_name", "the new build already has this user name", value)); continue; }
            if (userName != null) { steps.Add(Skip("user_name_exists", $"the new build is named '{userName}' there by the user", value)); continue; }
            if (newIndex.Sourced.NameAt(at) is { } inEffect && item.Source != NativeNameSource.User)
            {
                if (inEffect.Name == item.Value || inEffect.Name == value) { steps.Add(Skip("same_name", $"the new build's {inEffect.Source.Id()} layer has this name", value)); continue; }
                if (inEffect.Source.Rank() >= item.Source.Rank()) { steps.Add(Skip("new_has_own_name", $"the new build's {inEffect.Source.Id()} layer names it '{inEffect.Name}'", value)); continue; }
            }
            if (usedNames.TryGetValue(value, out var other) && other != at) { steps.Add(Skip("name_in_use", $"'{value}' is a user name at rva 0x{other:X} in the new build", value)); continue; }
            if (plannedNames.TryGetValue(at, out var earlier)) { steps.Add(Skip("duplicate_target", $"the name from rva 0x{earlier.OldRva:X} already lands there", value)); continue; }
            plannedNames[at] = item;
            usedNames[value] = at;
            steps.Add(new(item, at, value, true, mapped.Reason, tier, mapped.Confidence,
                value != item.Value ? $"{mapped.Detail}; name made an identifier from '{Clip(item.Value)}'" : mapped.Detail));
        }
        return steps;
    }

    private static string Clip(string s) => s.Length <= 80 ? s : s[..77] + "...";
}
