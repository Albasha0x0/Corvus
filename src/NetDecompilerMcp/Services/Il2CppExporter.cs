using System.Text;
using System.Text.Json;
using dnlib.DotNet;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Services;

/// <summary>
/// Exports Il2Cpp dummy-DLL metadata for native tools: an IDA Python script and a Ghidra script that create and name
/// every function, give it its C prototype and comment it with the managed signature, a C header with struct layouts
/// (<see cref="Il2CppLayout"/>; imported by the IDA script before the prototypes), and an Il2CppDumper-style script.json
/// whose Signature is the C prototype.
/// </summary>
public sealed class Il2CppExporter(Il2CppService il2cpp)
{
    public sealed record ExportResult(List<string> Files, int Methods, int Structs);

    private sealed record MethodEntry(ulong Rva, string Name, string Signature, string Prototype);

    public ExportResult Export(IReadOnlyList<LoadedAssembly> scope, string outputDirectory, string formats, string baseName, CancellationToken ct, bool overwrite = false)
    {
        var wanted = formats.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Select(f => f.ToLowerInvariant()).ToHashSet();
        if (wanted.Contains("all")) wanted = ["ida", "ghidra", "header", "json"];
        foreach (var f in wanted.Where(f => f is not ("ida" or "ghidra" or "header" or "json")))
            throw new ToolError(ErrorCode.InvalidArgument, $"Unknown format '{f}'. Use ida, ghidra, header, json or all.");
        // A rooted or relative path in baseName would put the files outside outputDirectory.
        if (string.IsNullOrWhiteSpace(baseName) || baseName.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 || baseName is "." or ".." || baseName.Length > 100)
            throw new ToolError(ErrorCode.InvalidArgument, "baseName must be a plain file name (no directories), at most 100 characters.",
                "Pass a name like 'il2cpp' and choose the folder with outputDirectory.");

        var layout = new Il2CppLayout();
        LayOut(layout, scope, ct);
        var methods = CollectMethods(scope, layout, ct);
        if (methods.Count == 0)
            throw new ToolError(ErrorCode.Unsupported, "No Il2Cpp [Address] attributes in the selected assemblies. This needs Il2CppDumper/Cpp2IL dummy DLLs.");
        var dir = SafeFile.FullPath(outputDirectory);
        Directory.CreateDirectory(dir);
        string Write(string name, string content) => SafeFile.WriteUnderRoot(dir, name, System.Text.Encoding.UTF8.GetBytes(content), overwrite);
        var planned = new[] { (".h", wanted.Overlaps(["header", "ida", "ghidra"])), ("_ida.py", wanted.Contains("ida")),
            ("_ghidra.py", wanted.Contains("ghidra")), ("_script.json", wanted.Contains("json")) };
        // Refused before writing anything, so a conflict leaves no partial set.
        if (!overwrite && planned.Where(p => p.Item2).Select(p => Path.Combine(dir, baseName + p.Item1)).FirstOrDefault(Path.Exists) is { } existing)
            throw new ToolError(ErrorCode.Conflict, $"{existing} exists: pass overwrite=true to replace it.");
        var files = new List<string>();

        string? headerPath = null;
        if (wanted.Contains("header") || wanted.Contains("ida") || wanted.Contains("ghidra"))
        {
            headerPath = Write(baseName + ".h", Header(layout));
            files.Add(headerPath);
        }
        if (wanted.Contains("ida"))
            files.Add(Write(baseName + "_ida.py", IdaScript(methods, Path.GetFileName(headerPath!))));
        if (wanted.Contains("ghidra"))
            files.Add(Write(baseName + "_ghidra.py", GhidraScript(methods)));
        if (wanted.Contains("json"))
            files.Add(Write(baseName + "_script.json", JsonSerializer.Serialize(new
            {
                ScriptMethod = methods.Select(m => new { Address = m.Rva, m.Name, Signature = m.Prototype, ManagedSignature = m.Signature }),
            }, new JsonSerializerOptions { WriteIndented = true })));
        return new ExportResult(files, methods.Count, layout.Structs.Count);
    }

    private List<MethodEntry> CollectMethods(IReadOnlyList<LoadedAssembly> scope, Il2CppLayout layout, CancellationToken ct)
    {
        var entries = new List<MethodEntry>();
        var used = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var e in scope.SelectMany(il2cpp.GetIndex).Where(e => e.Rva != null).OrderBy(e => e.Rva))
        {
            ct.ThrowIfCancellationRequested();
            var name = $"{e.Method.DeclaringType.FullName.Replace('/', '.')}$${e.Method.Name}";
            // Overloads and shared generic bodies would collide: keep names unique (IDA/Ghidra reject duplicates).
            if (used.TryGetValue(name, out int n)) { used[name] = n + 1; name = $"{name}_{n + 1}"; }
            else used[name] = 0;
            entries.Add(new MethodEntry(e.Rva!.Value, name, $"{Format.Method(e.Method)}  [{e.Assembly.Id} {Format.Token(e.Method)}]",
                Prototype(layout, e.Method, name)));
        }
        return entries;
    }

    private static string PyString(string s) => "\"" + s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\n", " ") + "\"";

    private static string IdaScript(List<MethodEntry> methods, string headerFile)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# IDA Python script generated by net-decompiler from Il2Cpp dummy DLLs.");
        sb.AppendLine("# File > Script file... (IDA 7.4+). Imports the struct layouts from the header next to this script, creates");
        sb.AppendLine("# functions, names them Namespace.Type$$Method, applies their C prototypes and comments the managed signatures.");
        sb.AppendLine("import os");
        sb.AppendLine("import idaapi");
        sb.AppendLine("import idc");
        sb.AppendLine("import ida_funcs");
        sb.AppendLine();
        sb.AppendLine("METHODS = [");
        foreach (var m in methods)
            sb.AppendLine($"    (0x{m.Rva:X}, {PyString(m.Name)}, {PyString(m.Signature)}, {PyString(m.Prototype)}),");
        sb.AppendLine("]");
        sb.AppendLine($"HEADER = {PyString(headerFile)}");
        sb.AppendLine("""

            def apply():
                base = idaapi.get_imagebase()
                header = os.path.join(os.path.dirname(os.path.abspath(__file__)), HEADER)
                errors = 0
                if os.path.exists(header):
                    with open(header) as f:
                        errors = idc.parse_decls(f.read(), idc.PT_SILENT)
                named = typed = 0
                for rva, name, signature, prototype in METHODS:
                    ea = base + rva
                    if not ida_funcs.get_func(ea):
                        ida_funcs.add_func(ea)
                    if idc.set_name(ea, name, idc.SN_NOWARN | idc.SN_NOCHECK):
                        named += 1
                    if idc.SetType(ea, prototype):
                        typed += 1
                    idc.set_func_cmt(ea, signature, 0)
                print("net-decompiler: named %d and typed %d of %d functions; header import errors: %d" % (named, typed, len(METHODS), errors))

            apply()
            """);
        return sb.ToString();
    }

    private static string GhidraScript(List<MethodEntry> methods)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# Ghidra script generated by net-decompiler from Il2Cpp dummy DLLs (Jython or PyGhidra).");
        sb.AppendLine("# Creates functions, names them Namespace.Type$$Method and adds the managed signature as a plate comment.");
        sb.AppendLine("# Import the .h next to this script first (File > Parse C Source): the C prototypes are applied where their");
        sb.AppendLine("# types are known.");
        sb.AppendLine("# @category net-decompiler");
        sb.AppendLine("from ghidra.program.model.symbol import SourceType");
        sb.AppendLine("from ghidra.app.util.cparser.C import CParserUtils");
        sb.AppendLine("from ghidra.app.cmd.function import ApplyFunctionSignatureCmd");
        sb.AppendLine();
        sb.AppendLine("METHODS = [");
        foreach (var m in methods)
            sb.AppendLine($"    (0x{m.Rva:X}, {PyString(m.Name.Replace(' ', '_'))}, {PyString(m.Signature)}, {PyString(m.Prototype)}),");
        sb.AppendLine("]");
        sb.AppendLine("""

            def apply():
                base = currentProgram.getImageBase()
                functions = currentProgram.getFunctionManager()
                named = typed = 0
                for rva, name, signature, prototype in METHODS:
                    addr = base.add(rva)
                    f = functions.getFunctionAt(addr)
                    if f is None:
                        f = createFunction(addr, None)
                    if f is not None:
                        try:
                            f.setName(name, SourceType.USER_DEFINED)
                            named += 1
                        except Exception:
                            pass
                        try:
                            definition = CParserUtils.parseSignature(None, currentProgram, prototype, False)
                            if definition is not None and ApplyFunctionSignatureCmd(addr, definition, SourceType.USER_DEFINED).applyTo(currentProgram):
                                typed += 1
                        except Exception:
                            pass
                    setPlateComment(addr, signature)
                print("net-decompiler: named %d and typed %d of %d functions" % (named, typed, len(METHODS)))

            apply()
            """);
        return sb.ToString();
    }

    private const string Prelude = """
        /* Struct layouts generated by net-decompiler from Il2Cpp dummy DLLs (64-bit). Offsets are the dumped ones; the */
        /* fields of generic instances, which the dumpers give offset 0, are laid out as Il2Cpp lays them out ("computed"). */
        /* Classes: absolute object offsets (klass and monitor header first). Value types: field-relative offsets. */
        /* Static fields: offsets in the class's static data (X_StaticFields). Packed: every gap is an explicit pad. */
        typedef signed char nd_i8;
        typedef unsigned char nd_u8;
        typedef short nd_i16;
        typedef unsigned short nd_u16;
        typedef int nd_i32;
        typedef unsigned int nd_u32;
        typedef long long nd_i64;
        typedef unsigned long long nd_u64;
        typedef void* nd_ptr;
        #pragma pack(push, 1)

        """;

    /// <summary>Every type of the scope with fields, and the static fields of each, laid out (generic instances follow from use).</summary>
    internal static void LayOut(Il2CppLayout layout, IReadOnlyList<LoadedAssembly> scope, CancellationToken ct)
    {
        foreach (var t in scope.SelectMany(a => a.Module.GetTypes()))
        {
            ct.ThrowIfCancellationRequested();
            if (t.IsEnum || t.IsInterface) continue;
            if (t.Fields.Any(f => !f.IsStatic && !f.IsLiteral) || !t.IsValueType) layout.Of(t);
            layout.StaticsOf(t);
        }
    }

    internal static string Header(Il2CppLayout layout)
    {
        var sb = new StringBuilder(Prelude);
        foreach (var s in layout.Structs)
        {
            var members = new HashSet<string>(StringComparer.Ordinal);
            sb.AppendLine($"/* {s.Title} */");
            sb.AppendLine($"struct {s.CName} {{");
            ulong position = 0;
            if (!s.IsValueType && !s.Statics)
            {
                sb.AppendLine("    nd_ptr klass;  /* 0x0 */");
                sb.AppendLine("    nd_ptr monitor;  /* 0x8 */");
                members.Add("klass");
                members.Add("monitor");
                position = Il2CppLayout.ObjectHeader;
            }
            int pad = 0;
            foreach (var m in s.Members)
            {
                if (m.Offset > position) sb.AppendLine($"    nd_u8 _pad{pad++}[0x{m.Offset - position:X}];");
                // A derived class may redeclare a base field's name: C members must be unique.
                var name = Il2CppLayout.Identifier(m.Name);
                if (!members.Add(name))
                {
                    name = $"{name}_{Il2CppLayout.Identifier(Format.StripArity(m.Owner))}";
                    for (int i = 2; !members.Add(name); i++) name = $"{Il2CppLayout.Identifier(m.Name)}_{i}";
                }
                sb.AppendLine($"    {m.CType} {name}{(m.Count > 0 ? $"[0x{m.Count:X}]" : "")};  /* 0x{m.Offset:X} {m.Managed}{(m.Computed ? " (computed)" : "")} */");
                position = m.Offset + m.Size;
            }
            if (s.Members.Count == 0) sb.AppendLine("    nd_u8 _empty;");
            else if (s.IsValueType && s.Size > position) sb.AppendLine($"    nd_u8 _tail[0x{s.Size - position:X}];");
            sb.AppendLine("};");
            sb.AppendLine();
        }
        sb.AppendLine("#pragma pack(pop)");
        return sb.ToString();
    }

    /// <summary>
    /// The C prototype of a method's native code: this (a pointer to its struct, or nd_ptr), the parameters and the
    /// trailing MethodInfo pointer every Il2Cpp method takes; value types by value, references as pointers.
    /// </summary>
    internal static string Prototype(Il2CppLayout layout, MethodDef method, string name)
    {
        var parameters = new List<string>();
        var used = new HashSet<string>(StringComparer.Ordinal) { "method" };
        if (!method.IsStatic)
        {
            var owner = layout.Of(method.DeclaringType);
            parameters.Add($"{(owner == null ? "nd_ptr" : $"struct {owner.CName}*")} __this");
        }
        int index = 0;
        foreach (var p in method.Parameters.Where(p => p.IsNormalMethodParameter))
        {
            var pname = Il2CppLayout.Identifier(string.IsNullOrEmpty(p.Name) ? $"a{index}" : p.Name);
            while (!used.Add(pname)) pname += "_";
            parameters.Add($"{layout.TypeOf(p.Type).Name} {pname}");
            index++;
        }
        parameters.Add("nd_ptr method");
        var ret = method.ReturnType.ElementType == ElementType.Void ? "void" : layout.TypeOf(method.ReturnType).Name;
        return $"{ret} {Il2CppLayout.Identifier(name)}({string.Join(", ", parameters)});";
    }
}
