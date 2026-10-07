using System.Text;
using dnlib.DotNet;
using NetDecompilerMcp.Core;
using static NetDecompilerMcp.Services.MetadataUtil;

namespace NetDecompilerMcp.Services;

/// <summary>
/// Generates C++ binding code for a managed type in the style of ModHost's plugin API (shared/abi.h HostApi,
/// plugin/mem.h, plugin/il2cpp_util.h): a struct that resolves the class, field offsets, static field data and methods
/// once in Init, plus typed accessors and invoke wrappers. Names come from the real Mono metadata, so the namespace and
/// class strings are exactly what mono_class_from_name sees.
/// </summary>
public sealed class CppBindingGenerator
{
    private const string CompilerGenerated = "System.Runtime.CompilerServices.CompilerGeneratedAttribute";

    /// <summary>C++ keywords and the names the generated wrappers use themselves.</summary>
    private static readonly HashSet<string> CppReserved = new(StringComparer.Ordinal)
    {
        "h", "obj", "a", "value", "alignas", "alignof", "and", "asm", "auto", "bool", "break", "case", "catch", "char", "class", "const",
        "constexpr", "const_cast", "continue", "decltype", "default", "delete", "do", "double", "dynamic_cast", "else", "enum", "explicit",
        "export", "extern", "false", "float", "for", "friend", "goto", "if", "inline", "int", "long", "mutable", "namespace", "new",
        "noexcept", "not", "nullptr", "operator", "or", "private", "protected", "public", "register", "reinterpret_cast", "return",
        "short", "signed", "sizeof", "static", "static_assert", "static_cast", "struct", "switch", "template", "this", "throw", "true",
        "try", "typedef", "typeid", "typename", "union", "unsigned", "using", "virtual", "void", "volatile", "while", "xor", "concept",
        "requires", "co_await", "co_return", "co_yield", "char8_t", "char16_t", "char32_t", "wchar_t",
    };

    public string Generate(LoadedAssembly asm, TypeDef type, IReadOnlyCollection<string>? only, bool includeInherited)
    {
        if (type.HasGenericParameters)
            throw new ToolError($"{type.FullName} is generic: bind the generic definition with host->MakeGeneric and resolve members on the instantiation.");
        var top = TopLevel(type);
        var structName = Identifier(Format.StripArity(type.Name)) + "Binding";
        bool Wanted(string name) => only == null || only.Count == 0 || only.Contains(name, StringComparer.Ordinal);

        var fields = type.Fields.Where(f => !f.IsLiteral && !IsGenerated(f, f.Name) && Wanted(f.Name)).ToList();
        var properties = type.Properties.Where(p => p.GetMethod != null && !IsGenerated(p, p.Name) && Wanted(p.Name)).ToList();
        var methods = type.Methods.Where(m => !m.IsConstructor && !IsAccessor(m) && !IsGenerated(m, m.Name) && Wanted(m.Name)).ToList();
        var inherited = includeInherited
            ? BaseChain(type).SelectMany(b => b.Properties.Where(p => p.GetMethod is { IsStatic: false, IsPrivate: false } && !p.Name.String.Contains('.') && !IsGenerated(p, p.Name) && Wanted(p.Name))).ToList()
            : [];
        if (only is { Count: > 0 })
        {
            var known = fields.Select(f => f.Name.String).Concat(properties.Select(p => p.Name.String)).Concat(methods.Select(m => m.Name.String))
                .Concat(inherited.Select(p => p.Name.String)).ToHashSet(StringComparer.Ordinal);
            var unknown = only.Where(n => !known.Contains(n)).ToList();
            if (unknown.Count > 0)
                throw new ToolError($"{type.FullName} has no bindable member(s): {string.Join(", ", unknown)}.");
        }

        var names = new HashSet<string>(StringComparer.Ordinal);
        string Unique(string n)
        {
            var name = n;
            for (int i = 2; !names.Add(name); i++) name = $"{n}{i}";
            return name;
        }

        var decls = new StringBuilder();
        var resolve = new StringBuilder();
        var checks = new List<string> { "klass" };
        var accessors = new StringBuilder();

        // ---- fields
        bool anyStatic = fields.Any(f => f.IsStatic);
        if (anyStatic) decls.AppendLine("    void* m_static = nullptr;          // static field data block");
        if (anyStatic) resolve.AppendLine("        m_static = h->GetStaticFieldData(klass);");
        foreach (var f in fields)
        {
            var off = Unique($"m_{Camel(f.Name)}{(f.IsStatic ? "StaticOff" : "Off")}");
            var (cpp, isPointer, isStruct) = CppType(f.FieldType);
            decls.AppendLine($"    int32_t {off} = -1;{Pad(off)}// {(f.IsStatic ? "static " : "")}{Format.Type(f.FieldType)} {f.Name}");
            resolve.AppendLine($"        {off} = h->{(f.IsStatic ? "StaticFieldOffset" : "FieldOffset")}(klass, \"{f.Name}\");");
            checks.Add($"{off} >= 0");
            var accessor = Pascal(f.Name);
            if (f.IsStatic)
            {
                checks.Add("m_static");
                if (isStruct)
                    accessors.AppendLine($"    void* {accessor}Addr() const {{ return m_static && {off} >= 0 ? static_cast<char*>(m_static) + {off} : nullptr; }}");
                else if (isPointer)
                    accessors.AppendLine($"    void* {accessor}(const HostApi* h) const {{ return ReadPtr(h, m_static, {off}); }}");
                else
                {
                    accessors.AppendLine($"    {cpp} {accessor}(const HostApi* h) const {{ return ReadField<{cpp}>(h, m_static, {off}); }}");
                    accessors.AppendLine($"    bool Set{accessor}(const HostApi* h, {cpp} value) const {{ return WriteField<{cpp}>(h, m_static, {off}, value); }}");
                }
            }
            else if (isStruct)
                accessors.AppendLine($"    void* {accessor}Addr(void* obj) const {{ return obj && {off} >= 0 ? static_cast<char*>(obj) + {off} : nullptr; }}  // embedded {Format.Type(f.FieldType)}");
            else if (isPointer)
                accessors.AppendLine($"    void* {accessor}(const HostApi* h, const void* obj) const {{ return ReadPtr(h, obj, {off}); }}");
            else
            {
                accessors.AppendLine($"    {cpp} {accessor}(const HostApi* h, const void* obj) const {{ return ReadField<{cpp}>(h, obj, {off}); }}");
                accessors.AppendLine($"    bool Set{accessor}(const HostApi* h, void* obj, {cpp} value) const {{ return WriteField<{cpp}>(h, obj, {off}, value); }}");
            }
        }

        // ---- property getters (invoked: call inside BeginMono/EndMono)
        foreach (var (p, viaHierarchy) in properties.Select(p => (p, false)).Concat(inherited.Select(p => (p, true))))
        {
            var getter = p.GetMethod!;
            var m = Unique($"m_get{Pascal(p.Name)}");
            decls.AppendLine($"    HMethod {m} = nullptr;{Pad(m)}// {Format.Property(p)}");
            resolve.AppendLine(viaHierarchy || getter.DeclaringType != type
                ? $"        {m} = GetMethodInHierarchy(h, klass, \"{getter.Name}\", 0);"
                : $"        {m} = h->GetMethod(klass, \"{getter.Name}\", 0);");
            checks.Add(m);
            var (cpp, isPointer, isStruct) = CppType(getter.ReturnType);
            var instance = getter.IsStatic ? "nullptr" : "obj";
            var param = getter.IsStatic ? "const HostApi* h" : "const HostApi* h, void* obj";
            if (isPointer)
                accessors.AppendLine($"    void* {Pascal(p.Name)}({param}) const {{ return h->Invoke({m}, {instance}, nullptr, 0); }}  // needs Mono scope");
            else if (!isStruct)
                accessors.AppendLine($"    {cpp} {Pascal(p.Name)}({param}) const {{ return CallValue<{cpp}>(h, {m}, {instance}); }}  // needs Mono scope");
        }

        // ---- methods (overloads with the same argument count are resolved by exact signature)
        var overloaded = methods.GroupBy(x => (x.Name.String, ParamCount(x))).Where(g => g.Count() > 1).Select(g => g.Key).ToHashSet();
        var wrapperSignatures = new HashSet<string>(StringComparer.Ordinal);
        foreach (var method in methods)
        {
            var m = Unique($"m_{Camel(method.Name)}");
            int argc = ParamCount(method);
            decls.AppendLine($"    HMethod {m} = nullptr;{Pad(m)}// {Format.Method(method)}");
            resolve.AppendLine(overloaded.Contains((method.Name.String, argc))
                ? $"        {m} = GetMethodExact(h, klass, \"{method.Name}\", \"{MonoParams(method)}\");"
                : $"        {m} = h->GetMethod(klass, \"{method.Name}\", {argc});");
            checks.Add(m);

            var parameters = new List<string> { "const HostApi* h" };
            if (!method.IsStatic) parameters.Add("void* obj");
            var args = new List<string>();
            foreach (var p in method.Parameters.Where(x => x.IsNormalMethodParameter))
            {
                var (cpp, isPointer, isStruct) = CppType(p.Type);
                var name = Identifier(p.Name);
                if (CppReserved.Contains(name)) name += "_";
                if (p.Type is ByRefSig || isStruct) { parameters.Add($"void* {name}"); args.Add(name); }        // pointer to the value / ref
                else if (isPointer) { parameters.Add($"void* {name}"); args.Add(name); }                      // object reference
                else { parameters.Add($"{cpp} {name}"); args.Add($"&{name}"); }                              // value types by pointer
            }
            var argArray = args.Count == 0 ? "nullptr" : "a";
            var setup = args.Count == 0 ? "" : $"void* a[{args.Count}] = {{ {string.Join(", ", args)} }}; ";
            var (retCpp, retPointer, retStruct) = CppType(method.ReturnType);
            var returnNote = method.ReturnType.ElementType == ElementType.Void ? "" : retPointer ? "  // returns the object" : $"  // boxed {Format.Type(method.ReturnType)}: Unbox<{(retStruct ? "T" : retCpp)}>(h, result)";
            // Overloads that differ only by managed reference types map to the same C++ parameter list: number them.
            var wrapper = Pascal(method.Name);
            string Key(string n) => n + "(" + string.Join(",", parameters.Select(p => p[..p.LastIndexOf(' ')])) + ")";
            for (int i = 2; !wrapperSignatures.Add(Key(wrapper)); i++) wrapper = Pascal(method.Name) + i;
            accessors.AppendLine($"    void* {wrapper}({string.Join(", ", parameters)}) const {{ {setup}return h->Invoke({m}, {(method.IsStatic ? "nullptr" : "obj")}, {argArray}, {args.Count}); }}{returnNote}");
        }

        var ns = top.Namespace.String;
        var className = type.DeclaringType == null ? type.Name.String : NestedName(type);
        var sb = new StringBuilder();
        sb.AppendLine($"// Generated by net-decompiler from {asm.Id} ({asm.AssemblyName}.dll): {type.FullName}  [{Format.Token(type)}]");
        sb.AppendLine("// Resolve(host) once in Init() (it runs inside the host's Mono scope); check Resolved() before use.");
        sb.AppendLine("// Field reads/writes use SafeRead/SafeWrite (no Mono attach needed). Invokes and getters must run on the Host main");
        sb.AppendLine("// thread inside h->BeginMono() / h->EndMono(). Value-type arguments are passed by pointer; objects as their pointer.");
        if (type.DeclaringType != null)
            sb.AppendLine($"// NOTE: nested type. mono_class_from_name may not find \"{className}\" directly; if FindClass fails, resolve it from the outer class.");
        sb.AppendLine("#pragma once");
        sb.AppendLine("#include \"../shared/abi.h\"");
        sb.AppendLine("#include \"mem.h\"");
        sb.AppendLine("#include \"il2cpp_util.h\"");
        sb.AppendLine();
        sb.AppendLine("namespace plugin {");
        sb.AppendLine();
        sb.AppendLine($"struct {structName} {{");
        sb.AppendLine("    HClass klass = nullptr;");
        sb.Append(decls);
        sb.AppendLine();
        sb.AppendLine("    bool Resolve(const HostApi* h) {");
        sb.AppendLine($"        klass = h->FindClass(\"{asm.AssemblyName}\", \"{ns}\", \"{className}\");");
        sb.AppendLine("        if (!klass) return false;");
        sb.Append(resolve);
        sb.AppendLine("        return Resolved();");
        sb.AppendLine("    }");
        sb.AppendLine();
        sb.AppendLine($"    bool Resolved() const {{ return {string.Join(" && ", checks)}; }}");
        if (accessors.Length > 0)
        {
            sb.AppendLine();
            sb.Append(accessors);
        }
        sb.AppendLine("};");
        sb.AppendLine();
        sb.AppendLine("} // namespace plugin");
        return sb.ToString();
    }

    private static IEnumerable<TypeDef> BaseChain(TypeDef t)
    {
        for (var b = BaseTypeDef(t); b != null && b.FullName != "System.Object" && b.FullName != "UnityEngine.Object"; b = BaseTypeDef(b))
            yield return b;
    }

    private static string NestedName(TypeDef t)
    {
        var parts = new List<string>();
        for (var c = t; c != null; c = c.DeclaringType) parts.Insert(0, c.Name);
        return string.Join("/", parts);
    }

    private static bool IsGenerated(IHasCustomAttribute m, string name) =>
        name.StartsWith('<') || m.CustomAttributes.IsDefined(CompilerGenerated);

    /// <summary>C++ type of a managed field/return; IsPointer for references, IsStruct for embedded value types.</summary>
    private static (string Cpp, bool IsPointer, bool IsStruct) CppType(TypeSig sig)
    {
        switch (sig.ElementType)
        {
            case ElementType.Boolean: return ("bool", false, false);
            case ElementType.U1: return ("uint8_t", false, false);
            case ElementType.I1: return ("int8_t", false, false);
            case ElementType.Char: return ("char16_t", false, false);
            case ElementType.I2: return ("int16_t", false, false);
            case ElementType.U2: return ("uint16_t", false, false);
            case ElementType.I4: return ("int32_t", false, false);
            case ElementType.U4: return ("uint32_t", false, false);
            case ElementType.I8: return ("int64_t", false, false);
            case ElementType.U8: return ("uint64_t", false, false);
            case ElementType.R4: return ("float", false, false);
            case ElementType.R8: return ("double", false, false);
            case ElementType.I: return ("intptr_t", false, false);
            case ElementType.U: return ("uintptr_t", false, false);
            case ElementType.Void: return ("void", false, false);
        }
        if (sig is ValueTypeSig vt)
        {
            var td = Try(() => vt.TypeDefOrRef.ResolveTypeDef());
            if (td?.IsEnum == true && td.GetEnumUnderlyingType() is { } underlying)
                return CppType(underlying);
            return ("void*", false, true);
        }
        return ("void*", true, false); // classes, strings, arrays, interfaces, delegates, generic class instances
    }

    /// <summary>Mono short parameter names for GetMethodExact, e.g. "String,Color" or "Int32&,Boolean".</summary>
    private static string MonoParams(MethodDef m) =>
        string.Join(",", m.MethodSig.Params.Select(MonoName));

    private static string MonoName(TypeSig sig) => sig switch
    {
        ByRefSig r => MonoName(r.Next) + "&",
        SZArraySig a => MonoName(a.Next) + "[]",
        GenericInstSig g => Format.StripArity(g.GenericType.TypeDefOrRef.Name) + "`" + g.GenericArguments.Count,
        _ => sig.ToTypeDefOrRef()?.Name.String ?? sig.TypeName,
    };

    /// <summary>Accessor name for a member: "m_health" / "_health" / "health" -> "Health".</summary>
    private static string Pascal(string name)
    {
        var bare = name.StartsWith("m_", StringComparison.Ordinal) ? name[2..] : name.TrimStart('_');
        var id = bare.Length == 0 ? "Value" : Identifier(bare);
        return char.ToUpperInvariant(id[0]) + id[1..];
    }

    private static string Camel(string name)
    {
        var p = Pascal(name);
        return char.ToLowerInvariant(p[0]) + p[1..];
    }

    private static string Identifier(string name)
    {
        var s = new string(name.Select(c => char.IsLetterOrDigit(c) || c == '_' ? c : '_').ToArray());
        return s.Length == 0 || char.IsDigit(s[0]) ? "_" + s : s;
    }

    private static string Pad(string name) => new(' ', Math.Max(1, 28 - name.Length));
}
