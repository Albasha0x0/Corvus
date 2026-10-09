using System.Text;
using System.Text.RegularExpressions;

namespace NetDecompilerMcp.Services;

/// <summary>
/// A C/C++ project that provides a host function table for the "hostapi" binding style: the struct, the header that
/// defines it, the class / method handle types (FindClass / GetMethod return types), and where the helper functions the
/// generated code calls are defined (file and namespace). Helpers the project does not define are absent from
/// <see cref="Helpers"/>. <see cref="Members"/> lists every member of the table, so optional ones
/// (<see cref="HostApiDetector.OptionalMembers"/>) are used only when present.
/// </summary>
public sealed record HostApiProject(
    string Root,
    string TableName,
    string TableHeader,
    string ClassHandle,
    string MethodHandle,
    IReadOnlyDictionary<string, (string File, string? Namespace)> Helpers,
    IReadOnlySet<string> Members)
{
    public bool Has(string member) => Members.Contains(member);
}

/// <summary>
/// Finds a host function table in a project's headers (*.h, *.hh, *.hpp, *.hxx; build-output folders skipped; at most
/// 20,000 files of up to 2 MB). A table is a struct or class whose members include all of FindClass, GetMethod,
/// FieldOffset, StaticFieldOffset, GetStaticFieldData and Invoke, declared as function pointers or as methods. Names of
/// files and of the struct do not matter. Comments and string literals are ignored. Helpers are found by their
/// definitions: a function named ReadField, WriteField, ReadPtr, CallValue, GetMethodExact or GetMethodInHierarchy whose
/// first parameter is a const pointer to the table.
/// </summary>
public static class HostApiDetector
{
    public static readonly IReadOnlyList<string> RequiredMembers = ["FindClass", "GetMethod", "FieldOffset", "StaticFieldOffset", "GetStaticFieldData", "Invoke"];
    public static readonly IReadOnlyList<string> HelperNames = ["ReadField", "WriteField", "ReadPtr", "CallValue", "GetMethodExact", "GetMethodInHierarchy"];

    /// <summary>
    /// Table members used when present: EmbeddedStructOffset(klass, field) — a field's offset in the unboxed data of a
    /// value type; GetValueTypeSize(klass) — the unboxed size of a value type.
    /// </summary>
    public static readonly IReadOnlyList<string> OptionalMembers = ["EmbeddedStructOffset", "GetValueTypeSize"];

    private const int MaxFiles = 20_000;
    private const long MaxFileBytes = 2 * 1024 * 1024;
    private static readonly string[] HeaderExtensions = [".h", ".hh", ".hpp", ".hxx"];
    private static readonly HashSet<string> SkippedFolders = new(StringComparer.OrdinalIgnoreCase)
    {
        ".git", ".vs", ".vscode", ".idea", "bin", "obj", "build", "out", "node_modules", "packages",
    };

    private static readonly Regex StructStart = new(@"\b(typedef\s+)?(?:struct|class)\s+(\w+)?\s*(?::[^{;]*)?\{", RegexOptions.CultureInvariant);
    private static readonly Regex FunctionPointer = new(@"\(\s*\*\s*(\w+)\s*\)\s*\(", RegexOptions.CultureInvariant);
    private static readonly Regex Method = new(@"^(?<ret>[\w:\s\*&<>,]*?[\w\*&>])\s*\b(?<name>\w+)\s*\(", RegexOptions.CultureInvariant);
    private static readonly Regex NamespaceOpen = new(@"\bnamespace\s+([\w:]+)\s*$", RegexOptions.CultureInvariant);

    /// <summary>The project's host table, or null when no header in <paramref name="root"/> defines one.</summary>
    public static HostApiProject? Detect(string root, CancellationToken ct)
    {
        var headers = Headers(root).ToList();
        var texts = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        string Text(string file)
        {
            if (!texts.TryGetValue(file, out var t)) texts[file] = t = StripCommentsAndStrings(File.ReadAllText(file));
            return t;
        }

        foreach (var file in headers)
        {
            ct.ThrowIfCancellationRequested();
            var text = Text(file);
            foreach (var (name, members) in Structs(text))
            {
                if (!RequiredMembers.All(members.ContainsKey)) continue;
                var helpers = new Dictionary<string, (string, string?)>(StringComparer.Ordinal);
                foreach (var helper in HelperNames)
                {
                    var definition = new Regex($@"(?<=[\w>\*&\s])\b{helper}\s*\(\s*const\s+{Regex.Escape(name)}\s*\*", RegexOptions.CultureInvariant);
                    foreach (var candidate in headers)
                    {
                        var m = definition.Match(Text(candidate));
                        if (!m.Success) continue;
                        helpers[helper] = (candidate, NamespaceAt(Text(candidate), m.Index));
                        break;
                    }
                }
                return new HostApiProject(Path.GetFullPath(root), name, file, Handle(members["FindClass"], "HClass"), Handle(members["GetMethod"], "HMethod"), helpers,
                    members.Keys.ToHashSet(StringComparer.Ordinal));
            }
        }
        return null;
    }

    /// <summary>
    /// A project that calls a runtime's own exports rather than a host table: "il2cpp" when a header names Il2Cpp's
    /// class lookup (il2cpp_class_from_name, or class_from_name as a function pointer type or variable in an il2cpp
    /// namespace: typedef il2cpp_*_t, using fn_* = ..., inline / extern pointers), "mono" for mono_class_from_name; with
    /// the header that does. Null when neither is found.
    /// </summary>
    public static (string Style, string Header)? DetectRuntime(string root, CancellationToken ct)
    {
        foreach (var file in Headers(root))
        {
            ct.ThrowIfCancellationRequested();
            var text = StripCommentsAndStrings(File.ReadAllText(file));
            if (Il2CppLookup.IsMatch(text) || (Il2CppNamespace.IsMatch(text) && Il2CppPointer.IsMatch(text))) return ("il2cpp", file);
            if (MonoLookup.IsMatch(text)) return ("mono", file);
        }
        return null;
    }

    private static readonly Regex Il2CppLookup = new(@"\bil2cpp_class_from_name\w*",RegexOptions.CultureInvariant);
    private static readonly Regex Il2CppNamespace = new(@"\bnamespace\s+il2cpp\b", RegexOptions.CultureInvariant);
    private static readonly Regex Il2CppPointer = new(@"\b(?:using\s+fn_class_from_name\s*=|class_from_name\s*=\s*nullptr|extern\s+\w+\s+class_from_name\s*;)", RegexOptions.CultureInvariant);
    private static readonly Regex MonoLookup = new(@"\bmono_class_from_name\w*",RegexOptions.CultureInvariant);

    private static string Handle(string returnType, string fallback)
    {
        var t = Regex.Replace(returnType, @"\b(?:virtual|static|inline|extern|const)\b", "").Trim();
        return t.Length == 0 ? fallback : Regex.Replace(t, @"\s+", " ");
    }

    private static IEnumerable<string> Headers(string root)
    {
        if (!Directory.Exists(root)) throw new Core.ToolError($"Project directory not found: {root}");
        int count = 0;
        var pending = new Stack<string>([root]);
        var found = new List<string>();
        while (pending.Count > 0 && count < MaxFiles)
        {
            var dir = pending.Pop();
            IEnumerable<string> files, dirs;
            try { files = Directory.EnumerateFiles(dir); dirs = Directory.EnumerateDirectories(dir); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { continue; }
            foreach (var f in files)
            {
                if (!HeaderExtensions.Contains(Path.GetExtension(f), StringComparer.OrdinalIgnoreCase)) continue;
                try { if (new FileInfo(f).Length > MaxFileBytes) continue; } catch (IOException) { continue; }
                found.Add(f);
                if (++count >= MaxFiles) break;
            }
            foreach (var d in dirs)
            {
                var name = Path.GetFileName(d);
                if (!SkippedFolders.Contains(name) && !name.StartsWith("cmake-build", StringComparison.OrdinalIgnoreCase)) pending.Push(d);
            }
        }
        return found.OrderBy(f => f, StringComparer.OrdinalIgnoreCase); // deterministic choice when several match
    }

    /// <summary>Structs / classes in <paramref name="text"/>: the name (the typedef alias when there is one) and members by name -> return type.</summary>
    private static IEnumerable<(string Name, Dictionary<string, string> Members)> Structs(string text)
    {
        foreach (Match m in StructStart.Matches(text))
        {
            int open = m.Index + m.Length - 1;
            int close = MatchingBrace(text, open);
            if (close < 0) continue;
            var name = m.Groups[2].Success ? m.Groups[2].Value : null;
            if (m.Groups[1].Success && Regex.Match(text[(close + 1)..], @"^\s*(\w+)\s*;") is { Success: true } alias)
                name = alias.Groups[1].Value;
            if (name == null) continue;

            var members = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var declaration in TopLevel(text, open + 1, close).Split(';'))
            {
                var d = declaration.Trim();
                if (FunctionPointer.Match(d) is { Success: true } fp)
                    members.TryAdd(fp.Groups[1].Value, d[..fp.Index]);
                else if (Method.Match(d) is { Success: true } method)
                    members.TryAdd(method.Groups["name"].Value, method.Groups["ret"].Value);
            }
            yield return (name, members);
        }
    }

    /// <summary>The text between <paramref name="start"/> and <paramref name="end"/> without nested brace blocks (replaced by ';').</summary>
    private static string TopLevel(string text, int start, int end)
    {
        var sb = new StringBuilder();
        int depth = 0;
        for (int i = start; i < end; i++)
        {
            char c = text[i];
            if (c == '{') { if (depth++ == 0) sb.Append(';'); continue; }
            if (c == '}') { depth--; continue; }
            if (depth == 0) sb.Append(c);
        }
        return sb.ToString();
    }

    private static int MatchingBrace(string text, int open)
    {
        int depth = 0;
        for (int i = open; i < text.Length; i++)
        {
            if (text[i] == '{') depth++;
            else if (text[i] == '}' && --depth == 0) return i;
        }
        return -1;
    }

    /// <summary>The C++ namespace enclosing <paramref name="position"/> ("a::b"), or null in the global namespace.</summary>
    private static string? NamespaceAt(string text, int position)
    {
        var stack = new Stack<string?>();
        for (int i = 0; i < position && i < text.Length; i++)
        {
            if (text[i] == '{')
            {
                var before = text[Math.Max(0, i - 200)..i];
                stack.Push(NamespaceOpen.Match(before) is { Success: true } ns ? ns.Groups[1].Value : null);
            }
            else if (text[i] == '}' && stack.Count > 0) stack.Pop();
        }
        var names = stack.Reverse().Where(n => n != null).ToList();
        return names.Count == 0 ? null : string.Join("::", names);
    }

    /// <summary>Comments, string and character literals replaced by spaces (newlines kept), so offsets stay the same.</summary>
    internal static string StripCommentsAndStrings(string source)
    {
        var sb = new StringBuilder(source.Length);
        for (int i = 0; i < source.Length; i++)
        {
            char c = source[i];
            char next = i + 1 < source.Length ? source[i + 1] : '\0';
            if (c == '/' && next == '/')
            {
                while (i < source.Length && source[i] != '\n') { sb.Append(' '); i++; }
                if (i < source.Length) sb.Append('\n');
            }
            else if (c == '/' && next == '*')
            {
                sb.Append("  ");
                i += 2;
                while (i < source.Length && !(source[i] == '*' && i + 1 < source.Length && source[i + 1] == '/')) { sb.Append(source[i] == '\n' ? '\n' : ' '); i++; }
                if (i < source.Length) { sb.Append("  "); i++; }
            }
            else if (c is '"' or '\'')
            {
                char quote = c;
                sb.Append(' ');
                for (i++; i < source.Length && source[i] != quote && source[i] != '\n'; i++)
                {
                    if (source[i] == '\\' && i + 1 < source.Length) { sb.Append(' '); i++; }
                    sb.Append(' ');
                }
                if (i < source.Length) sb.Append(source[i] == '\n' ? '\n' : ' ');
            }
            else sb.Append(c);
        }
        return sb.ToString();
    }
}
