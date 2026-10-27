using Corvus.Native.Annotations;
using Corvus.Native.Providers;

namespace Corvus.Native.Diff;

/// <summary>One user type of the old build and its outcome; <see cref="Apply"/> adds it to the new layer (null when skipped).</summary>
public sealed record UserTypeStep(string Kind, uint? OldRva, uint? NewRva, string Value, bool Set, string Reason, int? Tier, double Confidence, string Detail,
    Func<UserTypeLayer, UserTypeLayer>? Apply);

/// <summary>Plans carrying the user's engine types to a new build; never replaces a user type there.</summary>
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

        foreach (var r in old.TypeEdits)
        {
            var value = r.NewName != null ? $"{r.Name} renamed to {r.NewName}" : $"{r.Name} deleted";
            var existing = target.TypeEdits.FirstOrDefault(e => e.Name == r.Name);
            steps.Add(existing == r ? new("type_edit", null, null, value, false, "same_type_edit", null, 1, "the new build already has this type edit", null)
                : existing != null ? new("type_edit", null, null, value, false, "user_type_edit_exists", null, 1, "the new build has its own edit of this type", null)
                : new("type_edit", null, null, value, true, "copied", null, 1, "type edits have no address", l => l.WithTypeEdit(r)));
        }

        foreach (var e in old.ToBatch().EnumMembers)
        {
            var value = $"{e.Enum}::{e.Member}{(e.Value is { } v ? " = " + v.ToString(System.Globalization.CultureInfo.InvariantCulture) : " removed")}";
            var existing = target.EnumMembers.GetValueOrDefault((e.Enum, e.Member));
            steps.Add(existing == e ? new("enum_member", null, null, value, false, "same_enum_member", null, 1, "the new build already has this enum member edit", null)
                : existing != null ? new("enum_member", null, null, value, false, "user_enum_member_exists", null, 1, "the new build has its own edit of this member", null)
                : new("enum_member", null, null, value, true, "copied", null, 1, "enum members have no address", l => l.WithEnumMember(e)));
        }

        foreach (var f in old.Fields)
        {
            var value = $"{f.Type}.{f.Key}{(f.FieldType != null ? ": " + f.FieldType : " removed")}";
            var existing = target.Fields.FirstOrDefault(e => e.Type == f.Type && e.Key == f.Key);
            steps.Add(existing == f ? new("field", null, null, value, false, "same_field", null, 1, "the new build already has this member edit", null)
                : existing != null ? new("field", null, null, value, false, "user_field_exists", null, 1, "the new build has its own edit of this member", null)
                : new("field", null, null, value, true, "copied", null, 1, "struct members have no address", l => l.WithField(f)));
        }

        // A mapped address passes the tier and score limits, else the reason it does not.
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

        // Analysis edits keep their order and length.
        foreach (var a in old.Analysis)
        {
            var value = $"{a.Kind}{(a.Type != null ? " " + a.Type : "")}{(a.End is { } e ? $" ({e - a.Rva} bytes)" : "")}";
            var map = Map(a.Rva, functionStart: false);
            if (map.At is not { } at) { steps.Add(Step("analysis", a.Rva, map, value, map.Skip, map.Detail, null)); continue; }
            var moved = a with { Rva = at, End = a.End is { } end ? at + (end - a.Rva) : null };
            var existing = target.Analysis.FirstOrDefault(x => x.Rva == at);
            steps.Add(existing == moved ? Step("analysis", a.Rva, map, value, "same_analysis", "the new build already has this analysis edit", null)
                : existing != null ? Step("analysis", a.Rva, map, value, "user_analysis_exists", $"the new build has the analysis edit '{existing.Kind}' there", null)
                : Step("analysis", a.Rva, map, value, null, map.Detail, l => l.WithAnalysis(moved)));
        }

        foreach (var o in old.Operands.OrderBy(o => o.Key).Select(o => o.Value))
        {
            var value = $"operand {o.Operand} {o.Display}{(o.Detail != null ? " " + o.Detail : "")}";
            var map = Map(o.Rva, functionStart: false);
            if (map.At is not { } at) { steps.Add(Step("operand", o.Rva, map, value, map.Skip, map.Detail, null)); continue; }
            var moved = o with { Rva = at };
            var existing = target.Operands.GetValueOrDefault((at, o.Operand));
            steps.Add(existing == moved ? Step("operand", o.Rva, map, value, "same_operand", "the new build already shows this operand so", null)
                : existing != null ? Step("operand", o.Rva, map, value, "user_operand_exists", $"the new build shows the operand as {existing.Display}", null)
                : Step("operand", o.Rva, map, value, null, map.Detail, l => l.WithOperand(moved)));
        }

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
                var value = s.Delete ? $"+0x{s.Offset:X} deleted" : $"+0x{s.Offset:X} {s.Name}{(s.Type != null ? " : " + s.Type : "")}";
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
