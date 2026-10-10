using NetDecompilerMcp.Native.Annotations;
using NetDecompilerMcp.Native.Providers;

namespace NetDecompilerMcp.Native.Diff;

/// <summary>
/// One user type of the old build and what happens to it: <see cref="Kind"/> declarations, type, local or stack_var;
/// <see cref="Apply"/> adds it to a layer of the new build (null when skipped).
/// </summary>
public sealed record UserTypeStep(string Kind, uint? OldRva, uint? NewRva, string Value, bool Set, string Reason, int? Tier, double Confidence, string Detail,
    Func<UserTypeLayer, UserTypeLayer>? Apply);

/// <summary>
/// Plans carrying the user's engine types to a new build: declarations as they are, types by mapped address, and a
/// function's locals and stack members by its matched start. Never replaces a user type of the new build.
/// </summary>
public static class UserTypeMigration
{
    public static List<UserTypeStep> Plan(AddressMapper mapper, UserTypeLayer old, UserTypeLayer target, MigrationOptions options, CancellationToken ct)
    {
        var steps = new List<UserTypeStep>();
        foreach (var d in old.Declarations)
        {
            var value = Clip(d.ReplaceLineEndings(" "));
            steps.Add(target.Declarations.Contains(d, StringComparer.Ordinal)
                ? new("declarations", null, null, value, false, "same_declarations", null, 1, "the new build already has these declarations", null)
                : new("declarations", null, null, value, true, "copied", null, 1, "declarations have no address", l => l.WithDeclarations(d)));
        }

        // a mapped address passes the tier and score limits, else the reason it does not
        (uint? At, MappedAddress Mapped, string? Skip, string Detail) Map(uint rva, bool functionStart)
        {
            ct.ThrowIfCancellationRequested();
            var m = mapper.Map(rva, ct);
            if (m.NewRva == null) return (null, m, m.Reason, m.Detail);
            if (m.Pair?.Tier is { } t && t > options.MinTier) return (null, m, "below_min_tier", $"matched in tier {t} ({MatchResult.TierNames[t]}); minTier is {options.MinTier}");
            if (m.Confidence < options.MinScore) return (null, m, "below_min_score", $"confidence {m.Confidence:0.###} < minScore {options.MinScore:0.###}");
            if (functionStart && m.Reason != "function_start") return (null, m, "not_a_function_start", $"{m.Reason}: {m.Detail}");
            return (m.NewRva, m, null, m.Detail);
        }

        UserTypeStep Step(string kind, uint oldRva, (uint? At, MappedAddress Mapped, string? Skip, string Detail) map, string value, string? skip, string detail,
            Func<UserTypeLayer, UserTypeLayer>? apply) =>
            new(kind, oldRva, map.Mapped.NewRva, value, skip == null, skip ?? map.Mapped.Reason, map.Mapped.Pair?.Tier, map.Mapped.Confidence, detail, skip == null ? apply : null);

        foreach (var (rva, type) in old.Types.OrderBy(t => t.Key))
        {
            var map = Map(rva, functionStart: false);
            if (map.At is not { } at) { steps.Add(Step("type", rva, map, type, map.Skip, map.Detail, null)); continue; }
            var existing = target.Types.GetValueOrDefault(at);
            steps.Add(existing == type ? Step("type", rva, map, type, "same_type", "the new build already has this user type", null)
                : existing != null ? Step("type", rva, map, type, "user_type_exists", $"the new build has the user type '{Clip(existing)}' there", null)
                : Step("type", rva, map, type, null, map.Detail, l => l.WithType(at, type)));
        }

        foreach (var function in old.StackVars.Keys.Union(old.Locals.Keys).Order())
        {
            var map = Map(function, functionStart: true);
            foreach (var s in old.StackVars.GetValueOrDefault(function) ?? [])
            {
                var value = $"+0x{s.Offset:X} {s.Name}{(s.Type != null ? " : " + s.Type : "")}";
                if (map.At is not { } at) { steps.Add(Step("stack_var", function, map, value, map.Skip, map.Detail, null)); continue; }
                var moved = s with { Function = at };
                var existing = target.StackVars.GetValueOrDefault(at)?.FirstOrDefault(e => e.Offset == s.Offset);
                steps.Add(existing == moved ? Step("stack_var", function, map, value, "same_stack_var", "the new build already has this stack variable", null)
                    : existing != null ? Step("stack_var", function, map, value, "user_stack_var_exists", $"the new build has the user stack variable {existing.Name} there", null)
                    : Step("stack_var", function, map, value, null, map.Detail, l => l.WithStackVar(moved)));
            }
            foreach (var e in old.Locals.GetValueOrDefault(function) ?? [])
            {
                var value = $"{e.Local}{(e.Name != null ? " -> " + e.Name : "")}{(e.Type != null ? " : " + e.Type : "")}";
                if (map.At is not { } at) { steps.Add(Step("local", function, map, value, map.Skip, map.Detail, null)); continue; }
                var moved = e with { Function = at };
                var existing = target.Locals.GetValueOrDefault(at)?.FirstOrDefault(x => (e.Stack != null && x.Stack == e.Stack) || x.Local == e.Local);
                steps.Add(existing == moved ? Step("local", function, map, value, "same_local", "the new build already has this local edit", null)
                    : existing != null ? Step("local", function, map, value, "user_local_exists", $"the new build has a user edit of {existing.Local} there", null)
                    : Step("local", function, map, value, null, map.Detail, l => l.WithLocal(moved)));
            }
        }
        return steps;
    }

    /// <summary>The new build's layer with the steps that are set applied.</summary>
    public static UserTypeLayer Apply(UserTypeLayer layer, IEnumerable<UserTypeStep> steps)
    {
        foreach (var s in steps)
            if (s.Apply != null) layer = s.Apply(layer);
        return layer;
    }

    private static string Clip(string s) => s.Length <= 80 ? s : s[..77] + "...";
}
