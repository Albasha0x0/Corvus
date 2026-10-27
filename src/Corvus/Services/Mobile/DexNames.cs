using System.Text;
using System.Text.RegularExpressions;
using Corvus.Core;
using Corvus.Core.Mobile;

namespace Corvus.Services.Mobile;

/// <summary>Original names of a renamed package from an R8 / ProGuard mapping.txt, Kotlin @Metadata or SourceFile; ids stay the package's own.</summary>
public sealed partial class DexNames
{
    /// <summary>A recovered class name and where it came from (mapping, kotlin metadata, source file).</summary>
    public sealed record ClassName(string Name, string Basis);

    // Renamed descriptor to name.
    private readonly Dictionary<string, ClassName> _classes = new(StringComparer.Ordinal);
    // Original descriptor to renamed.
    private readonly Dictionary<string, string> _original = new(StringComparer.Ordinal);
    // Renamed member id to original id.
    private readonly Dictionary<string, string> _members = new(StringComparer.Ordinal);
    // Original class->name to renamed ids.
    private readonly Dictionary<string, List<string>> _byName = new(StringComparer.Ordinal);

    public string? Mapping { get; private init; }
    public int MappedClasses { get; private set; }
    public int MappedMembers { get; private set; }
    public List<string> Notes { get; } = [];

    /// <summary>Times <see cref="Read"/> built the set of the package's field descriptors: once, at the first field line.</summary>
    internal int FieldSetBuilds { get; private set; }

    public bool IsEmpty => _classes.Count == 0 && _members.Count == 0;

    /// <summary>The original descriptor (mapping or Kotlin metadata) of a renamed one, else null.</summary>
    public string? Descriptor(string renamed) =>
        _classes.TryGetValue(renamed, out var c) && c.Basis != "source file" ? c.Name : null;

    public ClassName? Class(string renamed) => _classes.GetValueOrDefault(renamed);

    /// <summary>The original id of a renamed field or method id, else null.</summary>
    public string? Member(string renamedId) => _members.GetValueOrDefault(renamedId);

    /// <summary>A type descriptor with every class in it named by its original (arrays kept).</summary>
    public string Type(string descriptor)
    {
        int dims = 0;
        while (dims < descriptor.Length && descriptor[dims] == '[') dims++;
        return dims < descriptor.Length && descriptor[dims] == 'L' && Descriptor(descriptor[dims..]) is { } o ? descriptor[..dims] + o : descriptor;
    }

    /// <summary>The Java form with original names (com.example.Foo.compute(int) : String); null when nothing in it is renamed.</summary>
    public string? Display(string idOrDescriptor)
    {
        int arrow = idOrDescriptor.IndexOf("->", StringComparison.Ordinal);
        if (arrow < 0)
            return _classes.TryGetValue(idOrDescriptor, out var c)
                ? c.Basis == "mapping" ? DexFile.JavaName(c.Name) : $"{(c.Name.StartsWith('L') ? DexFile.JavaName(c.Name) : c.Name)} ({c.Basis})"
                : null;
        var original = _members.GetValueOrDefault(idOrDescriptor);
        var owner = idOrDescriptor[..arrow];
        if (original == null && Descriptor(owner) == null) return null;
        var id = original ?? Type(owner) + idOrDescriptor[arrow..];
        int a = id.IndexOf("->", StringComparison.Ordinal);
        var rest = id[(a + 2)..];
        var cls = DexFile.JavaName(id[..a]);
        int paren = rest.IndexOf('(');
        if (paren >= 0)
        {
            int close = rest.IndexOf(')');
            var parameters = DexIndex.SplitParameters(rest[(paren + 1)..close]).Select(p => DexFile.JavaName(Type(p)));
            return $"{cls}.{rest[..paren]}({string.Join(", ", parameters)}) : {DexFile.JavaName(Type(rest[(close + 1)..]))}";
        }
        int colon = rest.IndexOf(':');
        return colon < 0 ? null : $"{cls}.{rest[..colon]} : {DexFile.JavaName(Type(rest[(colon + 1)..]))}";
    }

    /// <summary>The package's own id of a class or member given by original name; unchanged when nothing matches.
    /// Overloads of one original name stay a name for the caller to resolve.</summary>
    public string Translate(string spec)
    {
        spec = spec.Trim();
        foreach (var d in DexIndex.ToDescriptor(spec))
            if (_original.TryGetValue(d, out var obf)) return obf;
        int arrow = spec.IndexOf("->", StringComparison.Ordinal);
        int open = spec.IndexOf('(');
        var head = open >= 0 ? spec[..open] : spec;
        int sep = arrow > 0 ? arrow : head.IndexOf("::", StringComparison.Ordinal) is var c and > 0 ? c : head.LastIndexOf('.');
        if (sep <= 0) return spec;
        var owner = head[..sep];
        var name = head[(sep + (head[sep] == '.' ? 1 : 2))..];
        int colon = name.IndexOf(':');
        if (colon >= 0) name = name[..colon];
        foreach (var d in DexIndex.ToDescriptor(owner))
        {
            if (!_original.TryGetValue(d, out var obfOwner) && !_byName.ContainsKey(d + "->" + name)) continue;
            if (!_byName.TryGetValue(d + "->" + name, out var ids)) return obfOwner + "::" + name + (open >= 0 ? spec[open..] : "");
            if (ids.Count == 1) return ids[0];
            if (open >= 0)
            {
                // Parameters are given in original names.
                var wanted = spec[open..];
                var match = ids.Where(id => _members.TryGetValue(id, out var o) && (o.EndsWith(wanted, StringComparison.Ordinal) || Display(id)?.Contains(Java(wanted), StringComparison.Ordinal) == true)).ToList();
                if (match.Count == 1) return match[0];
            }
            throw new ToolError(ErrorCode.Ambiguous, $"{spec} names {ids.Count} members: {string.Join(", ", ids.Take(20).Select(i => $"{i} ({Display(i)})"))}.",
                "pass the exact id, or the parameters: Class::name(int, String)") { Details = new { candidates = ids.Take(50).ToList() } };
        }
        return spec;
    }

    private static string Java(string parameters) => parameters.Trim().Replace(" ", "", StringComparison.Ordinal).Replace(",", ", ", StringComparison.Ordinal);

    /// <summary>Parses mapping.txt against <paramref name="index"/>; of lines sharing a line range and renamed name, the last is the method.</summary>
    public static DexNames Read(string mappingPath, DexIndex index, CancellationToken ct)
    {
        var full = InputFiles.RequireRegularFile(mappingPath, "mapping.txt");
        if (!File.Exists(full)) throw Targets.FileNotFound(full);
        var names = new DexNames { Mapping = full };
        var classLines = new List<(string Original, string Renamed, List<string> Members)>();
        List<string>? current = null;
        int lineNo = 0, bad = 0;
        foreach (var raw in File.ReadLines(full))
        {
            if ((++lineNo & 0xFFFF) == 0) ct.ThrowIfCancellationRequested();
            if (raw.Length == 0 || raw.TrimStart().StartsWith('#')) continue;
            if (raw[0] is ' ' or '\t')
            {
                current?.Add(raw.Trim());
                continue;
            }
            int arrow = raw.IndexOf(" -> ", StringComparison.Ordinal);
            if (arrow <= 0 || !raw.TrimEnd().EndsWith(':')) { bad++; current = null; continue; }
            current = [];
            classLines.Add((raw[..arrow].Trim(), raw[(arrow + 4)..].TrimEnd().TrimEnd(':').Trim(), current));
        }
        foreach (var (original, renamed, _) in classLines)
        {
            var o = FromJava(original);
            var x = FromJava(renamed);
            names._original.TryAdd(o, x);
            if (o != x) names._classes[x] = new ClassName(o, "mapping");
        }
        int classesFound = 0, members = 0, membersFound = 0;
        HashSet<string>? fields = null;
        foreach (var (original, renamed, lines) in classLines)
        {
            ct.ThrowIfCancellationRequested();
            var owner = FromJava(renamed);
            var originalOwner = FromJava(original);
            if (index.Classes.ContainsKey(owner)) classesFound++;
            for (int i = 0; i < lines.Count; i++)
            {
                var m = MemberLine().Match(lines[i]);
                if (!m.Success) { bad++; continue; }
                var (range, type, name, parameters, obfName) = (m.Groups[1].Value, m.Groups[2].Value, m.Groups[3].Value, m.Groups[4], m.Groups[5].Value);
                bool method = parameters.Success;
                // An inlined frame shares the next line's range and renamed name; a qualified name is from another class.
                if (method && range.Length > 0 && i + 1 < lines.Count && MemberLine().Match(lines[i + 1]) is { Success: true } next
                    && next.Groups[1].Value == range && next.Groups[5].Value == obfName) continue;
                if (name.Contains('.', StringComparison.Ordinal)) continue;
                members++;
                string id, originalId;
                if (method)
                {
                    var ps = parameters.Value.Length == 0 ? [] : parameters.Value.Split(',', StringSplitOptions.TrimEntries);
                    var originalSig = "(" + string.Concat(ps.Select(FromJava)) + ")" + FromJava(type);
                    var obfSig = "(" + string.Concat(ps.Select(p => names.Renamed(FromJava(p)))) + ")" + names.Renamed(FromJava(type));
                    id = $"{owner}->{obfName}{obfSig}";
                    originalId = $"{originalOwner}->{name}{originalSig}";
                    if (index.Methods.ContainsKey(id)) membersFound++;
                }
                else
                {
                    id = $"{owner}->{obfName}:{names.Renamed(FromJava(type))}";
                    originalId = $"{originalOwner}->{name}:{FromJava(type)}";
                    if (fields == null)
                    {
                        fields = [.. index.Classes.Values.SelectMany(e => e.File.ClassData(e.Class).Fields.Select(f => e.File.Field(f.FieldIndex).Descriptor))];
                        names.FieldSetBuilds++;
                    }
                    if (fields.Contains(id)) membersFound++;
                }
                if (id == originalId) continue;
                if (!names._members.TryAdd(id, originalId)) continue;
                var key = originalOwner + "->" + name;
                if (!names._byName.TryGetValue(key, out var list)) names._byName[key] = list = [];
                list.Add(id);
            }
        }
        names.MappedClasses = classesFound;
        names.MappedMembers = membersFound;
        names.Notes.Add($"{Path.GetFileName(full)}: {classLines.Count:N0} classes and {members:N0} members; {classesFound:N0} classes and {membersFound:N0} members are defined in this package"
                        + (bad > 0 ? $"; {bad:N0} lines not read" : "") + ".");
        names.Recover(index);
        return names;
    }

    /// <summary>Only the names recovered from the package itself (no mapping).</summary>
    public static DexNames Recovered(DexIndex index)
    {
        var names = new DexNames();
        names.Recover(index);
        return names;
    }

    private string Renamed(string descriptor)
    {
        int dims = 0;
        while (dims < descriptor.Length && descriptor[dims] == '[') dims++;
        return dims < descriptor.Length && descriptor[dims] == 'L' && _original.TryGetValue(descriptor[dims..], out var x) ? descriptor[..dims] + x : descriptor;
    }

    /// <summary>Names unmapped renamed-looking classes from Kotlin @Metadata d2, else the SourceFile stem (a hint, not an id).</summary>
    private void Recover(DexIndex index)
    {
        int kotlin = 0, source = 0;
        foreach (var (descriptor, e) in index.Classes)
        {
            if (_classes.ContainsKey(descriptor) || !LooksRenamed(descriptor)) continue;
            var annotations = e.File.Annotations(e.Class).Class;
            if (annotations.FirstOrDefault(a => a.Type == "Lkotlin/Metadata;") is { } m
                && m.Elements.FirstOrDefault(x => x.Name == "d2").Value?.Value is IReadOnlyList<DexValue> d2
                && d2.Count > 0 && d2[0].Value is string first && first.Length > 2 && first[0] == 'L' && first[^1] == ';' && first != descriptor
                && (m.Elements.FirstOrDefault(x => x.Name == "k").Value?.Value is not int k || k == 1))
            {
                _classes[descriptor] = new ClassName(first, "kotlin metadata");
                _original.TryAdd(first, descriptor);
                kotlin++;
                continue;
            }
            var file = e.Class.SourceFile;
            if (file is { Length: > 0 } && !descriptor.Contains('$', StringComparison.Ordinal) && file != "SourceFile" && !file.StartsWith("r8-map-id-", StringComparison.Ordinal)
                && (file.EndsWith(".java", StringComparison.Ordinal) || file.EndsWith(".kt", StringComparison.Ordinal)))
            {
                var stem = file[..file.LastIndexOf('.')];
                if (!descriptor.EndsWith("/" + stem + ";", StringComparison.Ordinal) && descriptor != "L" + stem + ";")
                {
                    _classes[descriptor] = new ClassName(stem, "source file");
                    source++;
                }
            }
        }
        if (kotlin + source > 0)
            Notes.Add($"Recovered from the package: {kotlin} class name(s) from Kotlin @Metadata, {source} from the source file attribute (a hint, marked).");
    }

    /// <summary>A class whose simple name is one to three lowercase letters or digits, as R8 and ProGuard name them.</summary>
    internal static bool LooksRenamed(string descriptor)
    {
        var simple = descriptor.TrimEnd(';');
        simple = simple[(Math.Max(simple.LastIndexOf('/'), simple.LastIndexOf('$')) + 1)..];
        return simple.Length is > 0 and <= 3 && simple.All(c => char.IsAsciiLetterLower(c) || char.IsAsciiDigit(c));
    }

    /// <summary>"int", "java.lang.String[]", "com.a.B$C" as a descriptor.</summary>
    private static string FromJava(string java)
    {
        java = java.Trim();
        int dims = 0;
        while (java.EndsWith("[]", StringComparison.Ordinal)) { java = java[..^2]; dims++; }
        var core = java switch
        {
            "void" => "V", "boolean" => "Z", "byte" => "B", "char" => "C", "short" => "S", "int" => "I", "long" => "J", "float" => "F", "double" => "D",
            _ => "L" + java.Replace('.', '/') + ";",
        };
        return new string('[', dims) + core;
    }

    // Matches "1:3:int compute(int,java.lang.String):10:12 -> a" and "java.lang.String name -> b".
    [GeneratedRegex(@"^(?:(\d+:\d+):)?(\S+)\s+([^\s(]+)(?:\(([^)]*)\))?(?::\d+(?::\d+)?)?\s+->\s+(\S+)$")]
    private static partial Regex MemberLine();

    /// <summary>Comments naming the originals of the classes and members a smali text refers to, one per line that has any.</summary>
    public string Annotate(string smali)
    {
        var sb = new StringBuilder(smali.Length + 1024);
        string? current = null;
        foreach (var line in smali.Split('\n'))
        {
            sb.Append(line);
            var t = line.TrimStart();
            string? comment = null;
            // A method's disassembly starts "# Lpkg/C;->m()V in classes.dex".
            if (current == null && t.StartsWith("# L", StringComparison.Ordinal) && t.IndexOf("->", StringComparison.Ordinal) is var arrow and > 0) current = t[2..arrow];
            if (t.StartsWith(".class ", StringComparison.Ordinal)) { current = t.Split(' ')[^1]; comment = Display(current); }
            else if (current != null && t.StartsWith(".method ", StringComparison.Ordinal)) comment = Display(current + "->" + t.Split(' ')[^1]);
            else if (current != null && t.StartsWith(".field ", StringComparison.Ordinal))
            {
                var decl = t.Split(' ').First(p => p.Contains(':', StringComparison.Ordinal));
                comment = Display(current + "->" + decl);
            }
            else if (t.Length > 0 && t[0] != '#' && t[0] != '.')
            {
                var parts = new List<string>();
                foreach (Match m in Reference().Matches(t))
                    if (Display(m.Value) is { } d && !parts.Contains(d)) parts.Add(d);
                if (parts.Count > 0) comment = string.Join("; ", parts);
            }
            if (comment != null && !t.StartsWith('#')) sb.Append("  # = ").Append(comment);
            sb.Append('\n');
        }
        if (sb.Length > 0) sb.Length--;
        return sb.ToString();
    }

    // A member id or class descriptor in an instruction's operands.
    [GeneratedRegex(@"L[^;\s,{}]+;(?:->[^\s(:,]+(?:\([^)\s]*\)\S+|:\S+))?")]
    private static partial Regex Reference();
}
