using System.Globalization;
using System.Text;

namespace Corvus.Core.Protobuf;

/// <summary>A known option as .proto text writes it (value already quoted or named); unknown (custom) options are only counted.</summary>
public sealed record ProtoOption(string Name, string Value);

public sealed class ProtoField
{
    public string Name { get; set; } = "";
    public int Number { get; set; }
    /// <summary>1 optional, 2 required, 3 repeated.</summary>
    public int Label { get; set; } = 1;
    /// <summary>FieldDescriptorProto.Type: 1 double ... 18 sint64; 10 group, 11 message, 14 enum.</summary>
    public int Type { get; set; }
    public string? TypeName { get; set; }
    public string? Extendee { get; set; }
    public string? DefaultValue { get; set; }
    public int? OneofIndex { get; set; }
    public string? JsonName { get; set; }
    public bool Proto3Optional { get; set; }
    public List<ProtoOption> Options { get; } = [];
}

public sealed class ProtoMessage
{
    public string Name { get; set; } = "";
    public List<ProtoField> Fields { get; } = [];
    public List<ProtoField> Extensions { get; } = [];
    public List<ProtoMessage> Nested { get; } = [];
    public List<ProtoEnum> Enums { get; } = [];
    public List<(int Start, int End)> ExtensionRanges { get; } = [];
    public List<string> Oneofs { get; } = [];
    /// <summary>End exclusive, as stored.</summary>
    public List<(int Start, int End)> ReservedRanges { get; } = [];
    public List<string> ReservedNames { get; } = [];
    public List<ProtoOption> Options { get; } = [];
    public bool MapEntry { get; set; }
    /// <summary>Editions 2024 symbol visibility: 1 local, 2 export.</summary>
    public int Visibility { get; set; }
}

public sealed class ProtoEnum
{
    public string Name { get; set; } = "";
    public List<(string Name, int Number, List<ProtoOption> Options)> Values { get; } = [];
    /// <summary>End inclusive, as stored.</summary>
    public List<(int Start, int End)> ReservedRanges { get; } = [];
    public List<string> ReservedNames { get; } = [];
    public List<ProtoOption> Options { get; } = [];
    public int Visibility { get; set; }
}

public sealed record ProtoMethod(string Name, string Input, string Output, bool ClientStreaming, bool ServerStreaming, IReadOnlyList<ProtoOption> Options);

public sealed class ProtoService
{
    public string Name { get; set; } = "";
    public List<ProtoMethod> Methods { get; } = [];
    public List<ProtoOption> Options { get; } = [];
}

/// <summary>A FileDescriptorProto from its wire format; custom options are counted in <see cref="UnknownOptions"/>.</summary>
public sealed class ProtoFile
{
    public string Name { get; set; } = "";
    public string? Package { get; set; }
    /// <summary>"proto2" when the descriptor leaves it empty, "proto3", or "editions".</summary>
    public string Syntax { get; set; } = "proto2";
    public int? Edition { get; set; }
    public List<string> Dependencies { get; } = [];
    public List<int> PublicDependencies { get; } = [];
    public List<int> WeakDependencies { get; } = [];
    /// <summary>Editions 2024 "import option" files.</summary>
    public List<string> OptionDependencies { get; } = [];
    public List<ProtoMessage> Messages { get; } = [];
    public List<ProtoEnum> Enums { get; } = [];
    public List<ProtoService> Services { get; } = [];
    public List<ProtoField> Extensions { get; } = [];
    public List<ProtoOption> Options { get; } = [];
    public int UnknownOptions { get; set; }
    /// <summary>Bytes of the descriptor read (the blob may continue with other data).</summary>
    public int Length { get; set; }

    /// <summary>Reads a descriptor from the start of <paramref name="data"/>, ending at the first out-of-order field; null when none.</summary>
    public static ProtoFile? Read(ReadOnlySpan<byte> data)
    {
        var r = new WireReader(data);
        var file = new ProtoFile();
        int last = 0, fields = 0;
        bool syntaxSet = false;
        while (!r.End)
        {
            int start = r.Position;
            if (!r.Tag(out int field, out int wire) || field < last || (field == last && !RepeatedTop(field))) { r.Position = start; break; }
            bool ok = (field, wire) switch
            {
                (1, 2) => r.String(out var name) && SetName(file, name),
                (2, 2) => r.String(out var package) && Identifier(package, dotted: true) && Set(() => file.Package = package),
                (3, 2) => r.String(out var dependency) && dependency.EndsWith(".proto", StringComparison.Ordinal) && Add(file.Dependencies, dependency),
                (4, 2) => r.Message(out var m) && ReadMessage(m, file, out var message, 0) && Add(file.Messages, message),
                (5, 2) => r.Message(out var e) && ReadEnum(e, file, out var en) && Add(file.Enums, en),
                (6, 2) => r.Message(out var s) && ReadService(s, file, out var service) && Add(file.Services, service),
                (7, 2) => r.Message(out var x) && ReadField(x, file, out var ext) && Add(file.Extensions, ext),
                (8, 2) => r.Message(out var o) && ReadOptions(o, file, file.Options, FileOptions),
                (9, 2) => r.Message(out _), // source_code_info
                (10, 0) => r.Varint(out var pub) && Add(file.PublicDependencies, (int)pub),
                (10, 2) => r.Packed(file.PublicDependencies),
                (11, 0) => r.Varint(out var weak) && Add(file.WeakDependencies, (int)weak),
                (11, 2) => r.Packed(file.WeakDependencies),
                (12, 2) => r.String(out var syntax) && syntax is "proto2" or "proto3" or "editions" && Set(() => { file.Syntax = syntax; syntaxSet = true; }),
                (14, 0) => r.Varint(out var edition) && Set(() => file.Edition = (int)edition),
                (15, 2) => r.String(out var optionDependency) && optionDependency.EndsWith(".proto", StringComparison.Ordinal) && Add(file.OptionDependencies, optionDependency),
                _ => false,
            };
            if (!ok || (fields == 0 && field != 1)) { r.Position = start; break; }
            last = field;
            fields++;
        }
        if (fields < 2 || file.Name.Length == 0) return null;
        if (!syntaxSet && file.Edition != null) file.Syntax = "editions";
        file.Length = r.Position;
        return file;
    }

    private static bool RepeatedTop(int field) => field is 3 or 4 or 5 or 6 or 7 or 10 or 11 or 15;

    private static bool SetName(ProtoFile file, string name)
    {
        if (!name.EndsWith(".proto", StringComparison.Ordinal) || name.Length < 7 || name.Any(c => c < 0x21 || c > 0x7E || c is '"' or '\\')) return false;
        file.Name = name;
        return true;
    }

    private static bool Set(Action a) { a(); return true; }
    private static bool Add<T>(List<T> list, T item) { list.Add(item); return true; }

    /// <summary>An identifier, or a dotted name; type references may start with a dot.</summary>
    internal static bool Identifier(string s, bool dotted)
    {
        if (s.Length == 0 || s.Length > 4096) return false;
        foreach (var c in s)
            if (!(char.IsAsciiLetterOrDigit(c) || c == '_' || (dotted && c == '.'))) return false;
        return !char.IsAsciiDigit(s[0]) || dotted;
    }

    private static bool ReadMessage(ReadOnlySpan<byte> data, ProtoFile file, out ProtoMessage message, int depth)
    {
        message = new ProtoMessage();
        if (depth > 64) return false;
        var m = message;
        var r = new WireReader(data);
        while (!r.End)
        {
            if (!r.Tag(out int field, out int wire)) return false;
            bool ok = (field, wire) switch
            {
                (1, 2) => r.String(out var name) && Identifier(name, false) && Set(() => m.Name = name),
                (2, 2) => r.Message(out var f) && ReadField(f, file, out var pf) && Add(m.Fields, pf),
                (6, 2) => r.Message(out var x) && ReadField(x, file, out var ext) && Add(m.Extensions, ext),
                (3, 2) => r.Message(out var n) && ReadMessage(n, file, out var nested, depth + 1) && Add(m.Nested, nested),
                (4, 2) => r.Message(out var e) && ReadEnum(e, file, out var en) && Add(m.Enums, en),
                (5, 2) => r.Message(out var range) && Range(range, out var er) && Add(m.ExtensionRanges, er),
                (8, 2) => r.Message(out var oneof) && ReadOneof(oneof, out var oneofName) && Add(m.Oneofs, oneofName),
                (7, 2) => r.Message(out var o) && ReadOptions(o, file, m.Options, MessageOptions) && Set(() => m.MapEntry = m.Options.Any(p => p.Name == "map_entry" && p.Value == "true")),
                (9, 2) => r.Message(out var rr) && Range(rr, out var reserved) && Add(m.ReservedRanges, reserved),
                (10, 2) => r.String(out var rn) && Add(m.ReservedNames, rn),
                (11, 0) => r.Varint(out var visibility) && Set(() => m.Visibility = (int)visibility),
                _ => r.Skip(wire),
            };
            if (!ok) return false;
        }
        m.Options.RemoveAll(o => o.Name == "map_entry");
        return m.Name.Length > 0;
    }

    private static bool ReadOneof(ReadOnlySpan<byte> data, out string name)
    {
        name = "";
        var r = new WireReader(data);
        while (!r.End)
        {
            if (!r.Tag(out int field, out int wire)) return false;
            if (field == 1 && wire == 2) { if (!r.String(out name)) return false; }
            else if (!r.Skip(wire)) return false;
        }
        return Identifier(name, false);
    }

    private static bool Range(ReadOnlySpan<byte> data, out (int Start, int End) range)
    {
        range = default;
        var r = new WireReader(data);
        while (!r.End)
        {
            if (!r.Tag(out int field, out int wire)) return false;
            if (wire == 0 && field is 1 or 2 && r.Varint(out var v)) { if (field == 1) range.Start = (int)v; else range.End = (int)v; }
            else if (!r.Skip(wire)) return false;
        }
        return true;
    }

    private static bool ReadField(ReadOnlySpan<byte> data, ProtoFile file, out ProtoField field)
    {
        field = new ProtoField();
        var f = field;
        var r = new WireReader(data);
        while (!r.End)
        {
            if (!r.Tag(out int number, out int wire)) return false;
            bool ok = (number, wire) switch
            {
                (1, 2) => r.String(out var name) && Identifier(name, false) && Set(() => f.Name = name),
                (3, 0) => r.Varint(out var n) && Set(() => f.Number = (int)n),
                (4, 0) => r.Varint(out var label) && label is >= 1 and <= 3 && Set(() => f.Label = (int)label),
                (5, 0) => r.Varint(out var type) && type is >= 1 and <= 18 && Set(() => f.Type = (int)type),
                (6, 2) => r.String(out var typeName) && Identifier(typeName, true) && Set(() => f.TypeName = typeName),
                (2, 2) => r.String(out var extendee) && Identifier(extendee, true) && Set(() => f.Extendee = extendee),
                (7, 2) => r.String(out var def) && Set(() => f.DefaultValue = def),
                (9, 0) => r.Varint(out var oneof) && Set(() => f.OneofIndex = (int)oneof),
                (10, 2) => r.String(out var json) && Set(() => f.JsonName = json),
                (8, 2) => r.Message(out var o) && ReadOptions(o, file, f.Options, FieldOptions),
                (17, 0) => r.Varint(out var p3) && Set(() => f.Proto3Optional = p3 != 0),
                _ => r.Skip(wire),
            };
            if (!ok) return false;
        }
        // Unresolved descriptors may leave the type out.
        if (f.Type == 0 && f.TypeName != null) f.Type = 11;
        return f.Name.Length > 0 && f.Number > 0 && f.Type != 0;
    }

    private static bool ReadEnum(ReadOnlySpan<byte> data, ProtoFile file, out ProtoEnum en)
    {
        en = new ProtoEnum();
        var e = en;
        var r = new WireReader(data);
        while (!r.End)
        {
            if (!r.Tag(out int number, out int wire)) return false;
            bool ok = (number, wire) switch
            {
                (1, 2) => r.String(out var name) && Identifier(name, false) && Set(() => e.Name = name),
                (2, 2) => r.Message(out var v) && ReadEnumValue(v, file, e),
                (3, 2) => r.Message(out var o) && ReadOptions(o, file, e.Options, EnumOptions),
                (4, 2) => r.Message(out var rr) && Range(rr, out var range) && Add(e.ReservedRanges, range),
                (5, 2) => r.String(out var rn) && Add(e.ReservedNames, rn),
                (6, 0) => r.Varint(out var visibility) && Set(() => e.Visibility = (int)visibility),
                _ => r.Skip(wire),
            };
            if (!ok) return false;
        }
        return e.Name.Length > 0;
    }

    private static bool ReadEnumValue(ReadOnlySpan<byte> data, ProtoFile file, ProtoEnum e)
    {
        string name = "";
        int value = 0;
        var options = new List<ProtoOption>();
        var r = new WireReader(data);
        while (!r.End)
        {
            if (!r.Tag(out int number, out int wire)) return false;
            bool ok = (number, wire) switch
            {
                (1, 2) => r.String(out name) && Identifier(name, false),
                (2, 0) => r.Varint(out var v) && Set(() => value = (int)v),
                (3, 2) => r.Message(out var o) && ReadOptions(o, file, options, EnumValueOptions),
                _ => r.Skip(wire),
            };
            if (!ok) return false;
        }
        if (name.Length == 0) return false;
        e.Values.Add((name, value, options));
        return true;
    }

    private static bool ReadService(ReadOnlySpan<byte> data, ProtoFile file, out ProtoService service)
    {
        service = new ProtoService();
        var s = service;
        var r = new WireReader(data);
        while (!r.End)
        {
            if (!r.Tag(out int number, out int wire)) return false;
            bool ok = (number, wire) switch
            {
                (1, 2) => r.String(out var name) && Identifier(name, false) && Set(() => s.Name = name),
                (2, 2) => r.Message(out var m) && ReadMethod(m, file, out var method) && Add(s.Methods, method),
                (3, 2) => r.Message(out var o) && ReadOptions(o, file, s.Options, ServiceOptions),
                _ => r.Skip(wire),
            };
            if (!ok) return false;
        }
        return s.Name.Length > 0;
    }

    private static bool ReadMethod(ReadOnlySpan<byte> data, ProtoFile file, out ProtoMethod method)
    {
        method = null!;
        string name = "", input = "", output = "";
        bool client = false, server = false;
        var options = new List<ProtoOption>();
        var r = new WireReader(data);
        while (!r.End)
        {
            if (!r.Tag(out int number, out int wire)) return false;
            bool ok = (number, wire) switch
            {
                (1, 2) => r.String(out name) && Identifier(name, false),
                (2, 2) => r.String(out input) && Identifier(input, true),
                (3, 2) => r.String(out output) && Identifier(output, true),
                (4, 2) => r.Message(out var o) && ReadOptions(o, file, options, MethodOptions),
                (5, 0) => r.Varint(out var c) && Set(() => client = c != 0),
                (6, 0) => r.Varint(out var sv) && Set(() => server = sv != 0),
                _ => r.Skip(wire),
            };
            if (!ok) return false;
        }
        if (name.Length == 0 || input.Length == 0 || output.Length == 0) return false;
        method = new ProtoMethod(name, input, output, client, server, options);
        return true;
    }

    private enum OptionKind { String, Bool, Enum, Int, Message, Features }

    /// <summary>An option field: its name, how its value is written, enum names by number, and a message value's fields.</summary>
    private sealed record OptionSpec(string Name, OptionKind Kind, IReadOnlyDictionary<int, string>? Values = null, Dictionary<int, OptionSpec>? Fields = null);

    private static Dictionary<int, string> Names(params string[] names) => names.Select((n, i) => (n, i)).Where(x => x.n.Length > 0).ToDictionary(x => x.i, x => x.n);

    private static readonly Dictionary<int, string> Editions = new()
    {
        [0] = "EDITION_UNKNOWN", [900] = "EDITION_LEGACY", [998] = "EDITION_PROTO2", [999] = "EDITION_PROTO3", [1000] = "EDITION_2023", [1001] = "EDITION_2024",
        [1] = "EDITION_1_TEST_ONLY", [2] = "EDITION_2_TEST_ONLY", [99997] = "EDITION_99997_TEST_ONLY", [99998] = "EDITION_99998_TEST_ONLY",
        [99999] = "EDITION_99999_TEST_ONLY", [int.MaxValue] = "EDITION_MAX",
    };

    /// <summary>FeatureSet (editions): written as features.name = VALUE options.</summary>
    private static readonly Dictionary<int, OptionSpec> FeatureSet = new()
    {
        [1] = new("field_presence", OptionKind.Enum, Names("FIELD_PRESENCE_UNKNOWN", "EXPLICIT", "IMPLICIT", "LEGACY_REQUIRED")),
        [2] = new("enum_type", OptionKind.Enum, Names("ENUM_TYPE_UNKNOWN", "OPEN", "CLOSED")),
        [3] = new("repeated_field_encoding", OptionKind.Enum, Names("REPEATED_FIELD_ENCODING_UNKNOWN", "PACKED", "EXPANDED")),
        [4] = new("utf8_validation", OptionKind.Enum, Names("UTF8_VALIDATION_UNKNOWN", "", "VERIFY", "NONE")),
        [5] = new("message_encoding", OptionKind.Enum, Names("MESSAGE_ENCODING_UNKNOWN", "LENGTH_PREFIXED", "DELIMITED")),
        [6] = new("json_format", OptionKind.Enum, Names("JSON_FORMAT_UNKNOWN", "ALLOW", "LEGACY_BEST_EFFORT")),
        [7] = new("enforce_naming_style", OptionKind.Enum, Names("ENFORCE_NAMING_STYLE_UNKNOWN", "STYLE2024", "STYLE_LEGACY")),
        [8] = new("default_symbol_visibility", OptionKind.Enum, Names("DEFAULT_SYMBOL_VISIBILITY_UNKNOWN", "EXPORT_ALL", "EXPORT_TOP_LEVEL", "LOCAL_ALL", "STRICT")),
    };

    private static OptionSpec Features => new("features", OptionKind.Features, Fields: FeatureSet);

    private static readonly Dictionary<int, OptionSpec> FileOptions = new()
    {
        [1] = new("java_package", OptionKind.String), [8] = new("java_outer_classname", OptionKind.String), [10] = new("java_multiple_files", OptionKind.Bool),
        [20] = new("java_generate_equals_and_hash", OptionKind.Bool), [27] = new("java_string_check_utf8", OptionKind.Bool),
        [9] = new("optimize_for", OptionKind.Enum, Names("", "SPEED", "CODE_SIZE", "LITE_RUNTIME")), [11] = new("go_package", OptionKind.String),
        [16] = new("cc_generic_services", OptionKind.Bool), [17] = new("java_generic_services", OptionKind.Bool), [18] = new("py_generic_services", OptionKind.Bool),
        [42] = new("php_generic_services", OptionKind.Bool), [23] = new("deprecated", OptionKind.Bool), [31] = new("cc_enable_arenas", OptionKind.Bool),
        [36] = new("objc_class_prefix", OptionKind.String), [37] = new("csharp_namespace", OptionKind.String), [39] = new("swift_prefix", OptionKind.String),
        [40] = new("php_class_prefix", OptionKind.String), [41] = new("php_namespace", OptionKind.String), [44] = new("php_metadata_namespace", OptionKind.String),
        [45] = new("ruby_package", OptionKind.String), [50] = Features,
    };

    private static readonly Dictionary<int, OptionSpec> MessageOptions = new()
    {
        [1] = new("message_set_wire_format", OptionKind.Bool), [2] = new("no_standard_descriptor_accessor", OptionKind.Bool),
        [3] = new("deprecated", OptionKind.Bool), [7] = new("map_entry", OptionKind.Bool), [11] = new("deprecated_legacy_json_field_conflicts", OptionKind.Bool),
        [12] = Features,
    };

    private static readonly Dictionary<int, OptionSpec> FieldOptions = new()
    {
        [1] = new("ctype", OptionKind.Enum, Names("STRING", "CORD", "STRING_PIECE")), [2] = new("packed", OptionKind.Bool),
        [6] = new("jstype", OptionKind.Enum, Names("JS_NORMAL", "JS_STRING", "JS_NUMBER")), [5] = new("lazy", OptionKind.Bool),
        [15] = new("unverified_lazy", OptionKind.Bool), [3] = new("deprecated", OptionKind.Bool), [10] = new("weak", OptionKind.Bool),
        [16] = new("debug_redact", OptionKind.Bool), [17] = new("retention", OptionKind.Enum, Names("RETENTION_UNKNOWN", "RETENTION_RUNTIME", "RETENTION_SOURCE")),
        [19] = new("targets", OptionKind.Enum, Names("TARGET_TYPE_UNKNOWN", "TARGET_TYPE_FILE", "TARGET_TYPE_EXTENSION_RANGE", "TARGET_TYPE_MESSAGE",
            "TARGET_TYPE_FIELD", "TARGET_TYPE_ONEOF", "TARGET_TYPE_ENUM", "TARGET_TYPE_ENUM_ENTRY", "TARGET_TYPE_SERVICE", "TARGET_TYPE_METHOD")),
        [20] = new("edition_defaults", OptionKind.Message, Fields: new() { [3] = new("edition", OptionKind.Enum, Editions), [2] = new("value", OptionKind.String) }),
        [21] = Features,
        [22] = new("feature_support", OptionKind.Message, Fields: new()
        {
            [1] = new("edition_introduced", OptionKind.Enum, Editions), [2] = new("edition_deprecated", OptionKind.Enum, Editions),
            [3] = new("deprecation_warning", OptionKind.String), [4] = new("edition_removed", OptionKind.Enum, Editions), [5] = new("removal_error", OptionKind.String),
        }),
    };

    private static readonly Dictionary<int, OptionSpec> EnumOptions = new()
    {
        [2] = new("allow_alias", OptionKind.Bool), [3] = new("deprecated", OptionKind.Bool), [6] = new("deprecated_legacy_json_field_conflicts", OptionKind.Bool), [7] = Features,
    };

    private static readonly Dictionary<int, OptionSpec> EnumValueOptions = new()
    {
        [1] = new("deprecated", OptionKind.Bool), [2] = Features, [3] = new("debug_redact", OptionKind.Bool),
        [4] = new("feature_support", OptionKind.Message, Fields: FieldOptions[22].Fields),
    };

    private static readonly Dictionary<int, OptionSpec> ServiceOptions = new() { [33] = new("deprecated", OptionKind.Bool), [34] = Features };

    private static readonly Dictionary<int, OptionSpec> MethodOptions = new()
    {
        [33] = new("deprecated", OptionKind.Bool), [34] = new("idempotency_level", OptionKind.Enum, Names("IDEMPOTENCY_UNKNOWN", "NO_SIDE_EFFECTS", "IDEMPOTENT")),
        [35] = Features,
    };

    /// <summary>One option value as .proto writes it, or null when the wire type does not fit.</summary>
    private static string? OptionValue(ref WireReader r, int wire, OptionSpec spec, ProtoFile file)
    {
        switch (spec.Kind)
        {
            case OptionKind.String when wire == 2:
                return r.String(out var s) ? ProtoText.Quote(s) : null;
            case OptionKind.Bool or OptionKind.Enum or OptionKind.Int when wire == 0:
                if (!r.Varint(out var v)) return null;
                return spec.Kind == OptionKind.Bool ? (v != 0 ? "true" : "false")
                    : spec.Values?.GetValueOrDefault((int)v) ?? ((long)v).ToString(CultureInfo.InvariantCulture);
            case OptionKind.Message when wire == 2:
            {
                if (!r.Message(out var bytes)) return null;
                var parts = new List<string>();
                var inner = new WireReader(bytes);
                while (!inner.End)
                {
                    if (!inner.Tag(out int n, out int w)) return null;
                    if (spec.Fields!.TryGetValue(n, out var f) && OptionValue(ref inner, w, f, file) is { } value) parts.Add($"{f.Name}: {value}");
                    else if (!inner.Skip(w)) return null;
                }
                return "{ " + string.Join(" ", parts) + " }";
            }
            default:
                return null;
        }
    }

    private static bool ReadOptions(ReadOnlySpan<byte> data, ProtoFile file, List<ProtoOption> options, Dictionary<int, OptionSpec> known)
    {
        var r = new WireReader(data);
        while (!r.End)
        {
            if (!r.Tag(out int number, out int wire)) return false;
            if (known.TryGetValue(number, out var spec) && spec.Kind == OptionKind.Features && wire == 2)
            {
                if (!r.Message(out var bytes)) return false;
                var inner = new WireReader(bytes);
                while (!inner.End)
                {
                    if (!inner.Tag(out int n, out int w)) return false;
                    if (FeatureSet.TryGetValue(n, out var f) && OptionValue(ref inner, w, f, file) is { } value) options.Add(new("features." + f.Name, value));
                    // Language features (pb.cpp, pb.java) are extensions.
                    else if (inner.Skip(w)) file.UnknownOptions++;
                    else return false;
                }
                continue;
            }
            int start = r.Position;
            if (spec != null && OptionValue(ref r, wire, spec, file) is { } text)
            {
                options.Add(new(spec.Name, text));
                continue;
            }
            r.Position = start;
            if (!r.Skip(wire)) return false;
            if (number != 999) file.UnknownOptions++; // uninterpreted_option
        }
        return true;
    }
}

/// <summary>A bounds-checked protobuf wire-format reader; every read returns false instead of running past the end.</summary>
internal ref struct WireReader(ReadOnlySpan<byte> data)
{
    private readonly ReadOnlySpan<byte> _data = data;
    public int Position;

    public readonly bool End => Position >= _data.Length;

    public bool Varint(out ulong value)
    {
        value = 0;
        for (int shift = 0; shift < 64; shift += 7)
        {
            if (Position >= _data.Length) return false;
            byte b = _data[Position++];
            value |= (ulong)(b & 0x7F) << shift;
            if ((b & 0x80) == 0) return true;
        }
        return false;
    }

    public bool Tag(out int field, out int wire)
    {
        field = wire = 0;
        if (!Varint(out var tag) || tag > uint.MaxValue) return false;
        field = (int)(tag >> 3);
        wire = (int)(tag & 7);
        return field > 0 && wire is 0 or 1 or 2 or 5;
    }

    public bool Message(out ReadOnlySpan<byte> bytes)
    {
        bytes = default;
        if (!Varint(out var length) || length > (ulong)(_data.Length - Position)) return false;
        bytes = _data.Slice(Position, (int)length);
        Position += (int)length;
        return true;
    }

    public bool String(out string value)
    {
        value = "";
        if (!Message(out var bytes)) return false;
        try { value = Strict.GetString(bytes); }
        catch (DecoderFallbackException) { return false; }
        return true;
    }

    public bool Packed(List<int> into)
    {
        if (!Message(out var bytes)) return false;
        var inner = new WireReader(bytes);
        while (!inner.End)
        {
            if (!inner.Varint(out var v)) return false;
            into.Add((int)v);
        }
        return true;
    }

    public bool Skip(int wire)
    {
        switch (wire)
        {
            case 0: return Varint(out _);
            case 1: if (_data.Length - Position < 8) return false; Position += 8; return true;
            case 2: return Message(out _);
            case 5: if (_data.Length - Position < 4) return false; Position += 4; return true;
            default: return false;
        }
    }

    private static readonly UTF8Encoding Strict = new(false, true);
}
