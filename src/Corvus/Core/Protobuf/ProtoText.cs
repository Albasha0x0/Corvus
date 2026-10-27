using System.Globalization;
using System.Text;

namespace Corvus.Core.Protobuf;

/// <summary>.proto source for a <see cref="ProtoFile"/> that protoc compiles back to the same descriptor.</summary>
public static class ProtoText
{
    private static readonly string[] TypeNames =
    [
        "", "double", "float", "int64", "uint64", "int32", "fixed64", "fixed32", "bool", "string", "group", "message", "bytes", "uint32", "enum",
        "sfixed32", "sfixed64", "sint32", "sint64",
    ];

    private const int MaxField = 536_870_911;

    public static string Write(ProtoFile file)
    {
        var w = new StringBuilder();
        w.Append("// ").Append(file.Name).Append(" (rebuilt from an embedded FileDescriptorProto)\n");
        if (file.UnknownOptions > 0) w.Append($"// {file.UnknownOptions} custom option(s) not shown: their extension definitions are not in this descriptor\n");
        w.Append(file.Syntax == "editions" && file.Edition is { } edition ? $"edition = \"{EditionName(edition)}\";\n" : $"syntax = \"{file.Syntax}\";\n");
        if (file.Package != null) w.Append("\npackage ").Append(file.Package).Append(";\n");
        if (file.Dependencies.Count + file.OptionDependencies.Count > 0)
        {
            w.Append('\n');
            foreach (var d in file.OptionDependencies) w.Append("import option ").Append(Quote(d)).Append(";\n");
            for (int i = 0; i < file.Dependencies.Count; i++)
                w.Append("import ").Append(file.PublicDependencies.Contains(i) ? "public " : file.WeakDependencies.Contains(i) ? "weak " : "").Append(Quote(file.Dependencies[i])).Append(";\n");
        }
        if (file.Options.Count > 0)
        {
            w.Append('\n');
            foreach (var o in file.Options) w.Append("option ").Append(o.Name).Append(" = ").Append(o.Value).Append(";\n");
        }
        var syntax = file.Syntax;
        foreach (var m in file.Messages) { w.Append('\n'); Message(w, m, 0, syntax); }
        foreach (var e in file.Enums) { w.Append('\n'); Enum(w, e, 0); }
        foreach (var s in file.Services) { w.Append('\n'); Service(w, s); }
        Extends(w, file.Extensions, 0, syntax, null);
        return w.ToString();
    }

    private static string EditionName(int edition) => edition switch
    {
        998 => "proto2", 999 => "proto3", 1000 => "2023", 1001 => "2024",
        _ => edition.ToString(CultureInfo.InvariantCulture),
    };

    private static string Visibility(int v) => v switch { 1 => "local ", 2 => "export ", _ => "" };

    private static void Indent(StringBuilder w, int depth) => w.Append(' ', depth * 2);

    private static void Message(StringBuilder w, ProtoMessage m, int depth, string syntax, ProtoField? group = null)
    {
        Indent(w, depth);
        if (group != null) w.Append(group.Label == 0 ? "" : Label(group, syntax)).Append("group ").Append(m.Name).Append(" = ").Append(group.Number).Append(FieldOptions(group, syntax)).Append(" {\n");
        else w.Append(Visibility(m.Visibility)).Append("message ").Append(m.Name).Append(" {\n");
        int inner = depth + 1;
        foreach (var o in m.Options) { Indent(w, inner); w.Append("option ").Append(o.Name).Append(" = ").Append(o.Value).Append(";\n"); }
        var nestedByName = m.Nested.ToDictionary(n => n.Name, StringComparer.Ordinal);
        // Map entries and groups, written with their field.
        var inline = new HashSet<string>(StringComparer.Ordinal);
        var oneofsWritten = new HashSet<int>();
        foreach (var f in m.Fields)
        {
            if (f.OneofIndex is { } k && !f.Proto3Optional)
            {
                if (!oneofsWritten.Add(k)) continue;
                Indent(w, inner);
                w.Append("oneof ").Append(k < m.Oneofs.Count ? m.Oneofs[k] : $"oneof_{k}").Append(" {\n");
                foreach (var of in m.Fields.Where(x => x.OneofIndex == k && !x.Proto3Optional)) Field(w, of, inner + 1, syntax, nestedByName, inline, inOneof: true);
                Indent(w, inner);
                w.Append("}\n");
                continue;
            }
            Field(w, f, inner, syntax, nestedByName, inline, inOneof: false);
        }
        foreach (var e in m.Enums) Enum(w, e, inner);
        foreach (var n in m.Nested.Where(n => !inline.Contains(n.Name))) Message(w, n, inner, syntax);
        Extends(w, m.Extensions, inner, syntax, nestedByName);
        foreach (var (start, end) in m.ExtensionRanges)
        {
            Indent(w, inner);
            w.Append("extensions ").Append(Range(start, end - 1)).Append(";\n");
        }
        if (m.ReservedRanges.Count > 0)
        {
            Indent(w, inner);
            w.Append("reserved ").AppendJoin(", ", m.ReservedRanges.Select(r => Range(r.Start, r.End - 1))).Append(";\n");
        }
        if (m.ReservedNames.Count > 0)
        {
            Indent(w, inner);
            w.Append("reserved ").AppendJoin(", ", m.ReservedNames.Select(Quote)).Append(";\n");
        }
        Indent(w, depth);
        w.Append("}\n");
    }

    private static string Range(int start, int end) =>
        end >= MaxField ? $"{start} to max" : start == end ? start.ToString(CultureInfo.InvariantCulture) : $"{start} to {end}";

    private static void Extends(StringBuilder w, List<ProtoField> extensions, int depth, string syntax, Dictionary<string, ProtoMessage>? nested)
    {
        foreach (var g in extensions.GroupBy(x => x.Extendee ?? ""))
        {
            if (depth == 0) w.Append('\n');
            Indent(w, depth);
            w.Append("extend ").Append(g.Key).Append(" {\n");
            var inline = new HashSet<string>(StringComparer.Ordinal);
            foreach (var f in g) Field(w, f, depth + 1, syntax, nested ?? [], inline, inOneof: false);
            Indent(w, depth);
            w.Append("}\n");
        }
    }

    /// <summary>Editions write no singular labels: presence and required are features.</summary>
    private static string Label(ProtoField f, string syntax) => f.Label switch
    {
        3 => "repeated ",
        _ when syntax == "editions" => "",
        2 => "required ",
        _ => f.Proto3Optional || syntax != "proto3" ? "optional " : "",
    };

    private static void Field(StringBuilder w, ProtoField f, int depth, string syntax, Dictionary<string, ProtoMessage> nested, HashSet<string> inline, bool inOneof)
    {
        var local = f.TypeName is { } tn ? tn[(tn.LastIndexOf('.') + 1)..] : "";
        if (f.Type == 10 && syntax != "editions" && nested.TryGetValue(local, out var groupType))
        {
            inline.Add(local);
            Message(w, groupType, depth, syntax, inOneof ? CopyWithoutLabel(f) : f);
            return;
        }
        Indent(w, depth);
        if (f.Type == 11 && f.Label == 3 && nested.TryGetValue(local, out var entry) && entry.MapEntry && entry.Fields.Count == 2)
        {
            inline.Add(local);
            var key = entry.Fields.First(x => x.Number == 1);
            var value = entry.Fields.First(x => x.Number == 2);
            w.Append("map<").Append(TypeOf(key)).Append(", ").Append(TypeOf(value)).Append("> ");
        }
        else w.Append(inOneof ? "" : Label(f, syntax)).Append(TypeOf(f)).Append(' ');
        w.Append(f.Name).Append(" = ").Append(f.Number).Append(FieldOptions(f, syntax)).Append(";\n");
    }

    private static ProtoField CopyWithoutLabel(ProtoField f)
    {
        var copy = new ProtoField { Name = f.Name, Number = f.Number, Label = 0, Type = f.Type, TypeName = f.TypeName, JsonName = f.JsonName };
        copy.Options.AddRange(f.Options);
        return copy;
    }

    private static string TypeOf(ProtoField f) => f.Type is 11 or 14 or 10 ? f.TypeName ?? "bytes" : TypeNames[f.Type];

    private static string FieldOptions(ProtoField f, string syntax)
    {
        var parts = new List<string>();
        if (f.DefaultValue != null) parts.Add("default = " + DefaultText(f));
        if (f.JsonName != null && f.JsonName != JsonName(f.Name)) parts.Add("json_name = " + Quote(f.JsonName));
        parts.AddRange(f.Options.Select(o => $"{o.Name} = {o.Value}"));
        return parts.Count == 0 ? "" : " [" + string.Join(", ", parts) + "]";
    }

    private static string DefaultText(ProtoField f) => f.Type switch
    {
        9 => Quote(f.DefaultValue!),
        // Bytes defaults are stored C-escaped.
        12 => "\"" + f.DefaultValue + "\"",
        _ => f.DefaultValue!,
    };

    /// <summary>protoc's default json_name: underscores dropped, the letter after each upper-cased.</summary>
    public static string JsonName(string name)
    {
        var sb = new StringBuilder(name.Length);
        bool upper = false;
        foreach (var c in name)
        {
            if (c == '_') { upper = true; continue; }
            sb.Append(upper ? char.ToUpperInvariant(c) : c);
            upper = false;
        }
        return sb.ToString();
    }

    private static void Enum(StringBuilder w, ProtoEnum e, int depth)
    {
        Indent(w, depth);
        w.Append(Visibility(e.Visibility)).Append("enum ").Append(e.Name).Append(" {\n");
        foreach (var o in e.Options) { Indent(w, depth + 1); w.Append("option ").Append(o.Name).Append(" = ").Append(o.Value).Append(";\n"); }
        foreach (var (name, number, options) in e.Values)
        {
            Indent(w, depth + 1);
            w.Append(name).Append(" = ").Append(number);
            if (options.Count > 0) w.Append(" [").AppendJoin(", ", options.Select(o => $"{o.Name} = {o.Value}")).Append(']');
            w.Append(";\n");
        }
        if (e.ReservedRanges.Count > 0)
        {
            Indent(w, depth + 1);
            w.Append("reserved ").AppendJoin(", ", e.ReservedRanges.Select(r => r.End == int.MaxValue ? $"{r.Start} to max" : r.Start == r.End ? $"{r.Start}" : $"{r.Start} to {r.End}")).Append(";\n");
        }
        if (e.ReservedNames.Count > 0)
        {
            Indent(w, depth + 1);
            w.Append("reserved ").AppendJoin(", ", e.ReservedNames.Select(Quote)).Append(";\n");
        }
        Indent(w, depth);
        w.Append("}\n");
    }

    private static void Service(StringBuilder w, ProtoService s)
    {
        w.Append("service ").Append(s.Name).Append(" {\n");
        foreach (var o in s.Options) w.Append("  option ").Append(o.Name).Append(" = ").Append(o.Value).Append(";\n");
        foreach (var m in s.Methods)
        {
            w.Append("  rpc ").Append(m.Name).Append('(').Append(m.ClientStreaming ? "stream " : "").Append(m.Input).Append(") returns (")
                .Append(m.ServerStreaming ? "stream " : "").Append(m.Output).Append(')');
            if (m.Options.Count == 0) w.Append(";\n");
            else
            {
                w.Append(" {\n");
                foreach (var o in m.Options) w.Append("    option ").Append(o.Name).Append(" = ").Append(o.Value).Append(";\n");
                w.Append("  }\n");
            }
        }
        w.Append("}\n");
    }

    /// <summary>A double-quoted .proto string literal (C escapes; bytes above 0x7E as octal UTF-8).</summary>
    public static string Quote(string s)
    {
        var sb = new StringBuilder(s.Length + 2).Append('"');
        foreach (var b in Encoding.UTF8.GetBytes(s))
            sb.Append(b switch
            {
                (byte)'"' => "\\\"", (byte)'\\' => "\\\\", (byte)'\n' => "\\n", (byte)'\r' => "\\r", (byte)'\t' => "\\t", (byte)'\'' => "\\'",
                < 0x20 or > 0x7E => "\\" + Convert.ToString(b, 8).PadLeft(3, '0'),
                _ => ((char)b).ToString(),
            });
        return sb.Append('"').ToString();
    }
}
