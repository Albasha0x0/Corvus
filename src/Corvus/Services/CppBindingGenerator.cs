using System.Text;
using dnlib.DotNet;
using Corvus.Core;
using static Corvus.Core.MetadataUtil;

namespace Corvus.Services;

/// <summary>
/// Generates C++ binding code for a managed type: a struct that resolves the class, field offsets, static field data and
/// methods once, plus typed accessors and invoke wrappers. Names come from the real metadata, so the namespace and class
/// strings are exactly what mono_class_from_name sees. Two output styles:
/// <list type="bullet">
/// <item>"mono" (default): the standard Mono embedding API (mono_class_from_name, mono_field_get_offset,
/// mono_runtime_invoke, ...) through a function table filled from the runtime's exports. Self-contained.</item>
/// <item>"hostapi": for plugin frameworks whose host passes a HostApi table (FindClass / FieldOffset / GetMethod /
/// Invoke, with shared/abi.h, mem.h and il2cpp_util.h helpers).</item>
/// <item>"il2cpp": the Il2Cpp runtime's exports (il2cpp_class_from_name, il2cpp_field_get_offset,
/// il2cpp_runtime_invoke, ...), plus the native code pointer of each method and typed direct calls. Self-contained.</item>
/// </list>
/// </summary>
public sealed partial class CppBindingGenerator
{
    public static readonly IReadOnlyList<string> Styles = ["mono", "hostapi", "il2cpp"];

    private const string CompilerGenerated = "System.Runtime.CompilerServices.CompilerGeneratedAttribute";

    /// <summary>C++ keywords and the names the generated wrappers use themselves.</summary>
    private static readonly HashSet<string> CppReserved = new(StringComparer.Ordinal)
    {
        "h", "api", "obj", "a", "value", "exception", "alignas", "alignof", "and", "asm", "auto", "bool", "break", "case", "catch", "char",
        "class", "const", "constexpr", "const_cast", "continue", "decltype", "default", "delete", "do", "double", "dynamic_cast", "else",
        "enum", "explicit", "export", "extern", "false", "float", "for", "friend", "goto", "if", "inline", "int", "long", "mutable",
        "namespace", "new", "noexcept", "not", "nullptr", "operator", "or", "private", "protected", "public", "register",
        "reinterpret_cast", "return", "short", "signed", "sizeof", "static", "static_assert", "static_cast", "struct", "switch",
        "template", "this", "throw", "true", "try", "typedef", "typeid", "typename", "union", "unsigned", "using", "virtual", "void",
        "volatile", "while", "xor", "concept", "requires", "co_await", "co_return", "co_yield", "char8_t", "char16_t", "char32_t", "wchar_t",
    };

    /// <summary>The members to bind, chosen once and rendered by either style.</summary>
    private sealed record Selection(
        List<FieldDef> Fields,
        List<(PropertyDef Property, bool ViaHierarchy)> Getters,
        List<MethodDef> Methods,
        HashSet<(string Name, int Argc)> Overloaded);

    /// <summary>
    /// The chosen style and why, plus for "hostapi" the detected project (null when none was found) and where the header
    /// will be written (include paths are relative to its folder; default: the project root).
    /// </summary>
    public sealed record BindingTarget(string Style, string Reason, HostApiProject? Project = null, string? HeaderPath = null);

    public static string NormalizeStyle(string style)
    {
        var s = style.Trim().ToLowerInvariant();
        return Styles.Contains(s) ? s : throw new ToolError(ErrorCode.InvalidArgument, $"Unknown style '{style}': use {string.Join(" or ", Styles)}.");
    }

    /// <summary>
    /// Chooses the style: an explicit <paramref name="style"/>; else "hostapi" when the project directory
    /// (<paramref name="projectDir"/>, or the server's --binding-project) has a host table; else the runtime API the
    /// project calls (Il2Cpp or Mono exports: <see cref="HostApiDetector.DetectRuntime"/>); else "il2cpp" for an Il2Cpp
    /// dummy assembly (<paramref name="il2cppAssembly"/>); else the server's --binding-style; else "mono". The project is
    /// scanned whenever a directory is known, so an explicit "hostapi" still gets computed include paths.
    /// </summary>
    public static BindingTarget ChooseStyle(string? style, string? projectDir, string? headerPath, ServerOptions? options, CancellationToken ct,
        bool il2cppAssembly = false)
    {
        var dir = projectDir ?? options?.BindingProject;
        var dirLabel = projectDir != null ? "projectDir" : "--binding-project";
        var project = dir != null ? HostApiDetector.Detect(dir, ct) : null;
        var header = headerPath == null ? null : Path.GetFullPath(Path.Combine(dir ?? Directory.GetCurrentDirectory(), headerPath));
        var members = string.Join(", ", HostApiDetector.RequiredMembers);

        if (style != null)
        {
            var s = NormalizeStyle(style);
            return new BindingTarget(s, $"style={s} requested", s == "hostapi" ? project : null, header);
        }
        if (project != null)
            return new BindingTarget("hostapi",
                $"{dirLabel} has a host table: {project.TableName} in {Relative(project.Root, project.TableHeader)} (members {members})", project, header);
        var why = dir != null ? $"no struct with {members} in {Path.GetFullPath(dir)}" : "no projectDir";
        if (dir != null && HostApiDetector.DetectRuntime(dir, ct) is { } runtime)
            return new BindingTarget(runtime.Style, $"{dirLabel} calls the {(runtime.Style == "il2cpp" ? "Il2Cpp" : "Mono")} runtime API ({Relative(Path.GetFullPath(dir), runtime.Header)}); {why}", null, header);
        if (il2cppAssembly)
            return new BindingTarget("il2cpp", $"Il2Cpp dummy assembly ([Address] attributes); {why}", null, header);
        if (options?.BindingStyle is { } serverDefault)
            return new BindingTarget(serverDefault, $"server default --binding-style {serverDefault}; {why}", null, header);
        return new BindingTarget("mono", $"self-contained default; {why}", null, header);
    }

    public string Generate(LoadedAssembly asm, TypeDef type, IReadOnlyCollection<string>? only, bool includeInherited, string style = "mono") =>
        Generate(asm, type, only, includeInherited, new BindingTarget(NormalizeStyle(style), $"style={NormalizeStyle(style)} requested"));

    public string Generate(LoadedAssembly asm, TypeDef type, IReadOnlyCollection<string>? only, bool includeInherited, BindingTarget target)
    {
        var selection = Select(type, only, includeInherited);
        string code;
        _template = type.HasGenericParameters;
        try
        {
            code = target.Style switch
            {
                "mono" => RenderMono(asm, type, selection),
                "il2cpp" => RenderIl2Cpp(asm, type, selection),
                _ => RenderHostApi(asm, type, selection, target),
            };
        }
        finally
        {
            _template = false;
        }
        // Template parameter names must not be names the code itself uses (an accessor "T1", a parameter "_").
        // Only the binding itself: the shared helpers before it have their own template parameters.
        var own = code.LastIndexOf("#endif // NETDECOMP_", StringComparison.Ordinal) is var end and >= 0 ? code[end..] : code;
        var used = string.Join("\n", own.Split('\n').Select(l => l.Contains("//", StringComparison.Ordinal) ? l[..l.IndexOf("//", StringComparison.Ordinal)] : l));
        var names = TemplateParameters(type);
        for (int i = 0; i < names.Count; i++)
            while (System.Text.RegularExpressions.Regex.IsMatch(used, $@"(?<![\w$]){System.Text.RegularExpressions.Regex.Escape(names[i])}(?![\w$])") || names.Take(i).Contains(names[i]))
                names[i] += "_";
        for (int i = names.Count - 1; i >= 0; i--) code = code.Replace(TypeParameter(i), names[i]);
        return $"// Style {target.Style}: {target.Reason}.{Environment.NewLine}" + code;
    }

    private static string Relative(string fromFolder, string file) => Path.GetRelativePath(fromFolder, file).Replace('\\', '/');

    private static Selection Select(TypeDef type, IReadOnlyCollection<string>? only, bool includeInherited)
    {
        bool Wanted(string name) => only == null || only.Count == 0 || only.Contains(name, StringComparer.Ordinal);

        bool Named(string name) => only is { Count: > 0 } && only.Contains(name, StringComparer.Ordinal);

        var fields = type.Fields.Where(f => !f.IsLiteral && !IsGenerated(f, f.Name) && Wanted(f.Name)).ToList();
        var properties = type.Properties.Where(p => p.GetMethod != null && !IsGenerated(p, p.Name) && Wanted(p.Name)).ToList();
        var methods = type.Methods.Where(m => !m.IsConstructor && !IsAccessor(m) && !IsGenerated(m, m.Name) && Wanted(m.Name)).ToList();

        // Base-class members: all public/protected getters with includeInherited, and any base member named in 'only'
        // (e.g. a singleton's static Instance declared on a generic base). The nearest declaration of a name wins.
        var own = fields.Select(f => f.Name.String).Concat(properties.Select(p => p.Name.String)).Concat(methods.Select(m => m.Name.String))
            .ToHashSet(StringComparer.Ordinal);
        var inherited = new List<PropertyDef>();
        foreach (var b in BaseChain(type))
        {
            foreach (var p in b.Properties)
                if (p.GetMethod is { IsPrivate: false } && !p.Name.String.Contains('.') && !IsGenerated(p, p.Name)
                    && ((includeInherited && Wanted(p.Name)) || Named(p.Name)) && own.Add(p.Name))
                    inherited.Add(p);
            foreach (var f in b.Fields)
                if (Named(f.Name) && !f.IsLiteral && !f.IsStatic && own.Add(f.Name)) // offsets resolve through the parent chain
                    fields.Add(f);
            foreach (var m in b.Methods)
                if (Named(m.Name) && !m.IsConstructor && !IsAccessor(m) && !m.IsPrivate && !own.Contains(m.Name))
                    methods.Add(m);
            foreach (var m in b.Methods.Where(m => Named(m.Name))) own.Add(m.Name);
        }
        if (only is { Count: > 0 })
        {
            var unknown = only.Where(n => !own.Contains(n)).ToList();
            if (unknown.Count > 0)
            {
                var staticBaseFields = unknown.Where(n => BaseChain(type).Any(b => b.Fields.Any(f => f.Name == n && f.IsStatic && !f.IsLiteral))).ToList();
                throw new ToolError(ErrorCode.InvalidArgument, $"{type.FullName} has no bindable member(s): {string.Join(", ", unknown)}." +
                    (staticBaseFields.Count > 0 ? $" Static fields of a base class ({string.Join(", ", staticBaseFields)}) live in that class's static data: generate a binding for the base class." : ""));
            }
        }
        var overloaded = methods.GroupBy(x => (x.Name.String, ParamCount(x))).Where(g => g.Count() > 1).Select(g => g.Key).ToHashSet();
        return new Selection(fields, [.. properties.Select(p => (p, false)), .. inherited.Select(p => (p, true))], methods, overloaded);
    }

    /// <summary>
    /// The function table and helpers every "mono" binding uses, guarded so several generated headers can be included
    /// in one translation unit.
    /// </summary>
    private const string MonoPreamble = """
        #include <cstdint>
        #include <cstring>
        #include <type_traits>

        #ifndef NETDECOMP_MONOBIND
        #define NETDECOMP_MONOBIND
        // Shared by every net-decompiler binding of style "mono": Mono embedding API entry points and helpers.
        namespace monobind {

        struct MonoDomain; struct MonoImage; struct MonoClass; struct MonoClassField; struct MonoMethod;
        struct MonoVTable; struct MonoObject;

        // Fill with Load(lookup), where lookup(name) returns that export of the Mono runtime: GetProcAddress on
        // mono-2.0-bdwgc.dll / mono-2.0-sgen.dll / mono.dll, dlsym on libmonobdwgc-2.0.so / libmonosgen-2.0.so /
        // libmono-2.0.so, or the function itself when linked.
        struct MonoApi {
            MonoDomain* (*get_root_domain)() = nullptr;
            MonoImage* (*image_loaded)(const char* assemblyName) = nullptr;
            MonoClass* (*class_from_name)(MonoImage* image, const char* ns, const char* name) = nullptr;
            MonoClass* (*class_get_nested_types)(MonoClass* klass, void** iter) = nullptr;
            const char* (*class_get_name)(MonoClass* klass) = nullptr;
            MonoClass* (*class_get_parent)(MonoClass* klass) = nullptr;
            MonoClassField* (*class_get_field_from_name)(MonoClass* klass, const char* name) = nullptr;
            uint32_t (*field_get_offset)(MonoClassField* field) = nullptr;
            MonoVTable* (*class_vtable)(MonoDomain* domain, MonoClass* klass) = nullptr;
            void* (*vtable_get_static_field_data)(MonoVTable* vtable) = nullptr;
            MonoMethod* (*class_get_method_from_name)(MonoClass* klass, const char* name, int paramCount) = nullptr;
            MonoMethod* (*class_get_methods)(MonoClass* klass, void** iter) = nullptr;
            uint32_t (*method_get_token)(MonoMethod* method) = nullptr;
            MonoObject* (*runtime_invoke)(MonoMethod* method, void* obj, void** params, MonoObject** exc) = nullptr;
            void* (*object_unbox)(MonoObject* obj) = nullptr;

            // True when every entry point was found.
            template <class Lookup> bool Load(Lookup&& lookup) {
                bool ok = true;
                auto get = [&](auto& fn, const char* name) {
                    fn = reinterpret_cast<std::remove_reference_t<decltype(fn)>>(lookup(name));
                    ok = ok && fn != nullptr;
                };
                get(get_root_domain, "mono_get_root_domain");
                get(image_loaded, "mono_image_loaded");
                get(class_from_name, "mono_class_from_name");
                get(class_get_nested_types, "mono_class_get_nested_types");
                get(class_get_name, "mono_class_get_name");
                get(class_get_parent, "mono_class_get_parent");
                get(class_get_field_from_name, "mono_class_get_field_from_name");
                get(field_get_offset, "mono_field_get_offset");
                get(class_vtable, "mono_class_vtable");
                get(vtable_get_static_field_data, "mono_vtable_get_static_field_data");
                get(class_get_method_from_name, "mono_class_get_method_from_name");
                get(class_get_methods, "mono_class_get_methods");
                get(method_get_token, "mono_method_get_token");
                get(runtime_invoke, "mono_runtime_invoke");
                get(object_unbox, "mono_object_unbox");
                return ok;
            }
        };

        inline MonoClass* FindClass(const MonoApi& api, const char* assembly, const char* ns, const char* name) {
            MonoImage* image = api.image_loaded(assembly);
            return image ? api.class_from_name(image, ns, name) : nullptr;
        }

        inline MonoClass* FindNested(const MonoApi& api, MonoClass* outer, const char* name) {
            if (!outer) return nullptr;
            void* iter = nullptr;
            while (MonoClass* nested = api.class_get_nested_types(outer, &iter))
                if (std::strcmp(api.class_get_name(nested), name) == 0) return nested;
            return nullptr;
        }

        // Instance fields: offset from the start of the object (header included). Static fields: offset in StaticData().
        inline int32_t FieldOffset(const MonoApi& api, MonoClass* klass, const char* name) {
            MonoClassField* field = api.class_get_field_from_name(klass, name);
            return field ? static_cast<int32_t>(api.field_get_offset(field)) : -1;
        }

        inline void* StaticData(const MonoApi& api, MonoClass* klass) {
            MonoVTable* vtable = api.class_vtable(api.get_root_domain(), klass);
            return vtable ? api.vtable_get_static_field_data(vtable) : nullptr;
        }

        inline MonoMethod* MethodByToken(const MonoApi& api, MonoClass* klass, uint32_t token) {
            void* iter = nullptr;
            while (MonoMethod* method = api.class_get_methods(klass, &iter))
                if (api.method_get_token(method) == token) return method;
            return nullptr;
        }

        inline MonoMethod* MethodInHierarchy(const MonoApi& api, MonoClass* klass, const char* name, int paramCount) {
            for (MonoClass* c = klass; c; c = api.class_get_parent(c))
                if (MonoMethod* method = api.class_get_method_from_name(c, name, paramCount)) return method;
            return nullptr;
        }

        template <class T> T Read(const void* base, int32_t offset) {
            T value{};
            if (base && offset >= 0) std::memcpy(&value, static_cast<const char*>(base) + offset, sizeof value);
            return value;
        }

        template <class T> bool Write(void* base, int32_t offset, T value) {
            if (!base || offset < 0) return false;
            std::memcpy(static_cast<char*>(base) + offset, &value, sizeof value);
            return true;
        }

        // Calls a method. A managed exception goes to *exception (when given) and the result is nullptr.
        inline MonoObject* Invoke(const MonoApi& api, MonoMethod* method, void* obj, void** args, MonoObject** exception = nullptr) {
            MonoObject* exc = nullptr;
            MonoObject* result = method ? api.runtime_invoke(method, obj, args, &exc) : nullptr;
            if (exception) *exception = exc;
            return exc ? nullptr : result;
        }

        // A value-type result, unboxed (T{} when the call failed or threw).
        template <class T> T CallValue(const MonoApi& api, MonoMethod* method, void* obj, void** args = nullptr) {
            T value{};
            if (MonoObject* boxed = Invoke(api, method, obj, args)) std::memcpy(&value, api.object_unbox(boxed), sizeof value);
            return value;
        }

        } // namespace monobind
        #endif // NETDECOMP_MONOBIND
        """;

    private static string RenderMono(LoadedAssembly asm, TypeDef type, Selection s)
    {
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

        // Fields are accessed in place; no Mono call needed.
        bool anyStatic = s.Fields.Any(f => f.IsStatic);
        if (anyStatic)
        {
            decls.AppendLine("    void* m_static = nullptr;          // static field data block");
            resolve.AppendLine("        m_static = StaticData(api, klass);");
            checks.Add("m_static");
        }
        var wrapperSignatures = new HashSet<string>(StringComparer.Ordinal);
        foreach (var f in s.Fields)
        {
            var off = Unique($"m_{Camel(f.Name)}{(f.IsStatic ? "StaticOff" : "Off")}");
            var (cpp, isPointer, isStruct) = CppType(f.FieldType);
            decls.AppendLine($"    int32_t {off} = -1;{Pad(off)}// {(f.IsStatic ? "static " : "")}{Format.Type(f.FieldType)} {f.Name}");
            resolve.AppendLine($"        {off} = FieldOffset(api, klass, \"{f.Name}\");");
            checks.Add($"{off} >= 0");
            var accessor = ReserveAccessor(wrapperSignatures, f.Name);
            var (target, objParam, constObjParam) = f.IsStatic ? ("m_static", "", "") : ("obj", "void* obj", "const void* obj");
            if (isStruct)
                accessors.AppendLine($"    void* {accessor}Addr({objParam}) const {{ return {target} && {off} >= 0 ? static_cast<char*>({target}) + {off} : nullptr; }}  // embedded {Format.Type(f.FieldType)}");
            else if (isPointer)
                accessors.AppendLine($"    MonoObject* {accessor}({constObjParam}) const {{ return Read<MonoObject*>({target}, {off}); }}");
            else
            {
                accessors.AppendLine($"    {cpp} {accessor}({constObjParam}) const {{ return Read<{cpp}>({target}, {off}); }}");
                accessors.AppendLine($"    bool Set{accessor}({Join(objParam, $"{cpp} value")}) const {{ return Write<{cpp}>({target}, {off}, value); }}");
            }
        }

        // Getters are invoked and require a thread attached to Mono. Their C++ signatures are taken before the method
        // wrappers': a static method of the same name and parameters is numbered.
        foreach (var (p, viaHierarchy) in s.Getters)
        {
            var getter = p.GetMethod!;
            var m = Unique($"m_get{Pascal(p.Name)}");
            decls.AppendLine($"    MonoMethod* {m} = nullptr;{Pad(m)}// {PropertyComment(type, p)}");
            resolve.AppendLine(viaHierarchy || getter.DeclaringType != type
                ? $"        {m} = MethodInHierarchy(api, klass, \"{getter.Name}\", 0);"
                : $"        {m} = api.class_get_method_from_name(klass, \"{getter.Name}\", 0);");
            checks.Add(m);
            var (cpp, isPointer, isStruct) = CppType(AsSeenFrom(type, getter, getter.ReturnType));
            var instance = getter.IsStatic ? "nullptr" : "obj";
            List<string> parameters = getter.IsStatic ? ["const MonoApi& api"] : ["const MonoApi& api", "void* obj"];
            var name = UniqueWrapper(wrapperSignatures, p.Name, parameters);
            var param = string.Join(", ", parameters);
            if (isPointer || isStruct)
                accessors.AppendLine($"    MonoObject* {name}({param}) const {{ return Invoke(api, {m}, {instance}, nullptr); }}{(isStruct ? $"  // boxed {Format.Type(getter.ReturnType)}" : "")}");
            else if (IsTypeParameter(cpp))
                accessors.AppendLine($"    {cpp} {name}({param}) const {{ return Result<{cpp}>(api, Invoke(api, {m}, {instance}, nullptr)); }}");
            else
                accessors.AppendLine($"    {cpp} {name}({param}) const {{ return CallValue<{cpp}>(api, {m}, {instance}); }}");
        }

        // Overloads with equal argument counts are distinguished by metadata token.
        foreach (var method in s.Methods)
        {
            var m = Unique($"m_{Camel(method.Name)}");
            int argc = ParamCount(method);
            bool byToken = s.Overloaded.Contains((method.Name.String, argc));
            decls.AppendLine($"    MonoMethod* {m} = nullptr;{Pad(m)}// {Format.Method(method)}");
            if (byToken && method.DeclaringType != type)
                throw new ToolError(ErrorCode.Unsupported, $"{Format.MemberLabel(method)} is overloaded on the base class {method.DeclaringType.FullName}: generate a binding for that class.");
            resolve.AppendLine(byToken
                ? $"        {m} = MethodByToken(api, klass, 0x{method.MDToken.Raw:X8});  // overloaded {method.Name}({MonoParams(method)})"
                : method.DeclaringType != type
                    ? $"        {m} = MethodInHierarchy(api, klass, \"{method.Name}\", {argc});  // declared on {method.DeclaringType.FullName}"
                    : $"        {m} = api.class_get_method_from_name(klass, \"{method.Name}\", {argc});");
            checks.Add(m);

            var (parameters, args) = WrapperParameters(method, "const MonoApi& api");
            var argArray = args.Count == 0 ? "nullptr" : "a";
            var setup = args.Count == 0 ? "" : $"void* a[{args.Count}] = {{ {string.Join(", ", args)} }}; ";
            var wrapper = UniqueWrapper(wrapperSignatures, method.Name, parameters);
            parameters.Add("MonoObject** exception = nullptr");
            accessors.AppendLine($"    MonoObject* {wrapper}({string.Join(", ", parameters)}) const {{ {setup}return Invoke(api, {m}, {(method.IsStatic ? "nullptr" : "obj")}, {argArray}, exception); }}{ReturnNote(method, "api.object_unbox(result)")}");
        }

        var sb = new StringBuilder();
        sb.AppendLine($"// Generated by net-decompiler from {asm.Id} ({asm.AssemblyName}.dll): {type.FullName}  [{Format.Token(type)}]");
        sb.AppendLine("// Standard Mono embedding API, no other headers needed. Fill a monobind::MonoApi once with Load(), then call");
        sb.AppendLine("// Resolve(api) on a thread attached to Mono (mono_thread_attach) and check Resolved(). Method calls and property");
        sb.AppendLine("// getters also need an attached thread; field reads and writes only need a live object pointer.");
        sb.AppendLine("// Value-type arguments are passed by value (by pointer for structs and ref parameters); objects as their pointer.");
        if (s.Overloaded.Count > 0)
            sb.AppendLine("// Overloaded methods are matched by metadata token: regenerate this header when the assembly changes.");
        if (type.IsValueType)
            sb.AppendLine("// Value type: instance offsets include the object header (two pointers); subtract it for unboxed data.");
        sb.AppendLine("#pragma once");
        sb.AppendLine(MonoPreamble);
        sb.AppendLine();
        sb.AppendLine("namespace monobind {");
        sb.AppendLine();
        StructHead(sb, type, "MonoClass*", "const MonoApi& api", MonoFindClass(asm, type), "MonoObject", decls);
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
        sb.AppendLine("} // namespace monobind");
        return sb.ToString();
    }

    /// <summary>FindClass for a top-level type; nested types are found through their enclosing classes.</summary>
    private static string MonoFindClass(LoadedAssembly asm, TypeDef type)
    {
        var chain = new List<TypeDef>();
        for (var c = type; c != null; c = c.DeclaringType) chain.Insert(0, c);
        var expr = $"FindClass(api, \"{asm.AssemblyName}\", \"{chain[0].Namespace}\", \"{chain[0].Name}\")";
        foreach (var nested in chain.Skip(1))
            expr = $"FindNested(api, {expr}, \"{nested.Name}\")";
        return expr;
    }

    private static string RenderHostApi(LoadedAssembly asm, TypeDef type, Selection s, BindingTarget target)
    {
        var project = target.Project;
        var table = project?.TableName ?? "HostApi";
        var hclass = project?.ClassHandle ?? "HClass";
        var hmethod = project?.MethodHandle ?? "HMethod";
        var h = $"const {table}* h";
        var used = new HashSet<string>(StringComparer.Ordinal); // helpers this binding calls

        var top = TopLevel(type);
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

        // value types: offsets into the unboxed data when the host offers them (see HostApiDetector.OptionalMembers)
        bool unboxedOffsets = type.IsValueType && project?.Has("EmbeddedStructOffset") == true;
        if (type.IsValueType && project?.Has("GetValueTypeSize") == true)
        {
            decls.AppendLine("    int32_t m_size = -1;               // unboxed size (compare with a hand-written mirror's sizeof)");
            resolve.AppendLine("        m_size = h->GetValueTypeSize(klass);");
            accessors.AppendLine("    int32_t Size() const { return m_size; }");
        }

        bool anyStatic = s.Fields.Any(f => f.IsStatic);
        if (anyStatic) decls.AppendLine("    void* m_static = nullptr;          // static field data block");
        if (anyStatic) resolve.AppendLine("        m_static = h->GetStaticFieldData(klass);");
        var wrapperSignatures = new HashSet<string>(StringComparer.Ordinal);
        foreach (var f in s.Fields)
        {
            var off = Unique($"m_{Camel(f.Name)}{(f.IsStatic ? "StaticOff" : "Off")}");
            var (cpp, isPointer, isStruct) = CppType(f.FieldType);
            decls.AppendLine($"    int32_t {off} = -1;{Pad(off)}// {(f.IsStatic ? "static " : "")}{Format.Type(f.FieldType)} {f.Name}");
            resolve.AppendLine($"        {off} = h->{(f.IsStatic ? "StaticFieldOffset" : unboxedOffsets ? "EmbeddedStructOffset" : "FieldOffset")}(klass, \"{f.Name}\");");
            checks.Add($"{off} >= 0");
            var accessor = ReserveAccessor(wrapperSignatures, f.Name);
            if (f.IsStatic)
            {
                checks.Add("m_static");
                if (isStruct)
                    accessors.AppendLine($"    void* {accessor}Addr() const {{ return m_static && {off} >= 0 ? static_cast<char*>(m_static) + {off} : nullptr; }}");
                else if (isPointer)
                {
                    used.Add("ReadPtr");
                    accessors.AppendLine($"    void* {accessor}({h}) const {{ return ReadPtr(h, m_static, {off}); }}");
                }
                else
                {
                    used.Add("ReadField"); used.Add("WriteField");
                    accessors.AppendLine($"    {cpp} {accessor}({h}) const {{ return ReadField<{cpp}>(h, m_static, {off}); }}");
                    accessors.AppendLine($"    bool Set{accessor}({h}, {cpp} value) const {{ return WriteField<{cpp}>(h, m_static, {off}, value); }}");
                }
            }
            else if (isStruct)
                accessors.AppendLine($"    void* {accessor}Addr(void* obj) const {{ return obj && {off} >= 0 ? static_cast<char*>(obj) + {off} : nullptr; }}  // embedded {Format.Type(f.FieldType)}");
            else if (isPointer)
            {
                used.Add("ReadPtr");
                accessors.AppendLine($"    void* {accessor}({h}, const void* obj) const {{ return ReadPtr(h, obj, {off}); }}");
            }
            else
            {
                used.Add("ReadField"); used.Add("WriteField");
                accessors.AppendLine($"    {cpp} {accessor}({h}, const void* obj) const {{ return ReadField<{cpp}>(h, obj, {off}); }}");
                accessors.AppendLine($"    bool Set{accessor}({h}, void* obj, {cpp} value) const {{ return WriteField<{cpp}>(h, obj, {off}, value); }}");
            }
        }

        // Getters are invoked and require the host's managed-call context. Their C++ signatures are taken before the
        // method wrappers': a static method of the same name and parameters is numbered.
        foreach (var (p, viaHierarchy) in s.Getters)
        {
            var getter = p.GetMethod!;
            var m = Unique($"m_get{Pascal(p.Name)}");
            decls.AppendLine($"    {hmethod} {m} = nullptr;{Pad(m)}// {PropertyComment(type, p)}");
            if (viaHierarchy || getter.DeclaringType != type) used.Add("GetMethodInHierarchy");
            resolve.AppendLine(viaHierarchy || getter.DeclaringType != type
                ? $"        {m} = GetMethodInHierarchy(h, klass, \"{getter.Name}\", 0);"
                : $"        {m} = h->GetMethod(klass, \"{getter.Name}\", 0);");
            checks.Add(m);
            var (cpp, isPointer, isStruct) = CppType(AsSeenFrom(type, getter, getter.ReturnType));
            var instance = getter.IsStatic ? "nullptr" : "obj";
            List<string> parameters = getter.IsStatic ? [h] : [h, "void* obj"];
            var param = string.Join(", ", parameters);
            if (isPointer || IsTypeParameter(cpp))
                accessors.AppendLine($"    void* {UniqueWrapper(wrapperSignatures, p.Name, parameters)}({param}) const {{ return h->Invoke({m}, {instance}, nullptr, 0); }}  // managed call{(isPointer ? "" : $"; a {cpp}: the object, or the boxed value")}");
            else if (!isStruct)
            {
                used.Add("CallValue");
                accessors.AppendLine($"    {cpp} {UniqueWrapper(wrapperSignatures, p.Name, parameters)}({param}) const {{ return CallValue<{cpp}>(h, {m}, {instance}); }}  // managed call");
            }
        }

        // Overloads with equal argument counts are resolved by exact signature.
        foreach (var method in s.Methods)
        {
            var m = Unique($"m_{Camel(method.Name)}");
            int argc = ParamCount(method);
            decls.AppendLine($"    {hmethod} {m} = nullptr;{Pad(m)}// {Format.Method(method)}");
            bool exact = s.Overloaded.Contains((method.Name.String, argc));
            if (exact && method.DeclaringType != type)
                throw new ToolError(ErrorCode.Unsupported, $"{Format.MemberLabel(method)} is overloaded on the base class {method.DeclaringType.FullName}: generate a binding for that class.");
            if (exact) used.Add("GetMethodExact");
            if (!exact && method.DeclaringType != type) used.Add("GetMethodInHierarchy");
            resolve.AppendLine(exact
                ? $"        {m} = GetMethodExact(h, klass, \"{method.Name}\", \"{MonoParams(method)}\");"
                : method.DeclaringType != type
                    ? $"        {m} = GetMethodInHierarchy(h, klass, \"{method.Name}\", {argc});  // declared on {method.DeclaringType.FullName}"
                    : $"        {m} = h->GetMethod(klass, \"{method.Name}\", {argc});");
            checks.Add(m);

            var (parameters, args) = WrapperParameters(method, h);
            var argArray = args.Count == 0 ? "nullptr" : "a";
            var setup = args.Count == 0 ? "" : $"void* a[{args.Count}] = {{ {string.Join(", ", args)} }}; ";
            var wrapper = UniqueWrapper(wrapperSignatures, method.Name, parameters);
            accessors.AppendLine($"    void* {wrapper}({string.Join(", ", parameters)}) const {{ {setup}return h->Invoke({m}, {(method.IsStatic ? "nullptr" : "obj")}, {argArray}, {args.Count}); }}{ReturnNote(method, "Unbox<T>(h, result)")}");
        }

        var includes = new List<string>();
        var missing = new List<string>();
        string? ns = null;
        if (project != null)
        {
            var headerFolder = Path.GetDirectoryName(target.HeaderPath ?? Path.Combine(project.Root, StructName(type) + ".h"))!;
            includes.Add(Relative(headerFolder, project.TableHeader));
            foreach (var helper in HostApiDetector.HelperNames.Where(used.Contains))
            {
                if (project.Helpers.TryGetValue(helper, out var where))
                {
                    var include = Relative(headerFolder, where.File);
                    if (!includes.Contains(include)) includes.Add(include);
                    ns ??= where.Namespace;
                }
                else missing.Add(helper);
            }
        }

        var managedNs = top.Namespace.String;
        var className = type.DeclaringType == null ? type.Name.String : NestedName(type);
        var sb = new StringBuilder();
        sb.AppendLine($"// Generated by net-decompiler from {asm.Id} ({asm.AssemblyName}.dll): {type.FullName}  [{Format.Token(type)}]");
        sb.AppendLine($"// For a host that passes a {table} function table. Call Resolve(h) once where the host allows managed lookups;");
        sb.AppendLine("// check Resolved() before use. Field accessors read and write through the project's ReadField / WriteField / ReadPtr;");
        sb.AppendLine("// getters and method wrappers call h->Invoke, so they need whatever managed-call context the host requires.");
        sb.AppendLine("// Value-type arguments are passed by pointer; objects as their pointer.");
        if (project == null && used.Count > 0)
            sb.AppendLine($"// Include the header that defines {table} and the helpers this code calls ({string.Join(", ", HostApiDetector.HelperNames.Where(used.Contains))}) before this one.");
        if (missing.Count > 0)
            sb.AppendLine($"// NOTE: not found in {project!.Root}: {string.Join(", ", missing)}. Define them (first parameter: const {table}*) or edit the calls below.");
        if (type.DeclaringType != null)
            sb.AppendLine($"// NOTE: nested type. mono_class_from_name may not find \"{className}\" directly; if FindClass fails, resolve it from the outer class.");
        if (unboxedOffsets)
            sb.AppendLine("// Value type: instance offsets are into the unboxed data (EmbeddedStructOffset): pass a pointer to the struct itself, or a boxed object + 2 pointers.");
        else if (type.IsValueType)
            sb.AppendLine("// Value type: instance offsets include the object header (two pointers); subtract it for unboxed data.");
        sb.AppendLine("#pragma once");
        if (type.HasGenericParameters) sb.AppendLine("#include <type_traits>");
        foreach (var include in includes) sb.AppendLine($"#include \"{include}\"");
        sb.AppendLine();
        if (ns != null)
        {
            sb.AppendLine($"namespace {ns} {{");
            sb.AppendLine();
        }
        StructHead(sb, type, hclass, h, $"h->FindClass(\"{asm.AssemblyName}\", \"{managedNs}\", \"{className}\")", null, decls);
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
        if (ns != null)
        {
            sb.AppendLine();
            sb.AppendLine($"}} // namespace {ns}");
        }
        return sb.ToString();
    }

    private static string StructName(TypeDef type) => BaseName(type) + "Binding";

    /// <summary>
    /// The type's name; a generic definition's with its arity and enclosing types (Action_1, Dictionary_2_Enumerator), as
    /// definitions that differ only by those share a name.
    /// </summary>
    private static string BaseName(TypeDef type)
    {
        if (!type.HasGenericParameters) return Identifier(Format.StripArity(type.Name));
        var name = Identifier(type.Name);
        for (var outer = type.DeclaringType; outer != null; outer = outer.DeclaringType) name = Identifier(outer.Name) + "_" + name;
        return name;
    }

    /// <summary>Wrapper parameters after the API parameter, and the matching entries of the argument array.</summary>
    private static (List<string> Parameters, List<string> Args) WrapperParameters(MethodDef method, string apiParameter)
    {
        var parameters = new List<string> { apiParameter };
        if (!method.IsStatic) parameters.Add("void* obj");
        var args = new List<string>();
        var names = ParameterNames(method);
        foreach (var (p, name) in method.Parameters.Where(x => x.IsNormalMethodParameter).Zip(names))
        {
            var (cpp, isPointer, isStruct) = CppType(p.Type);
            if (p.Type is ByRefSig || isStruct) { parameters.Add($"void* {name}"); args.Add(name); }        // pointer to the value / ref
            else if (isPointer) { parameters.Add($"void* {name}"); args.Add(name); }                      // object reference
            else if (IsTypeParameter(cpp)) { parameters.Add($"{cpp} {name}"); args.Add($"Arg({name})"); } // the object, or a pointer to the value
            else { parameters.Add($"{cpp} {name}"); args.Add($"&{name}"); }                              // value types by pointer
        }
        return (parameters, args);
    }

    /// <summary>Overloads that differ only by managed reference types map to the same C++ parameter list: number them.</summary>
    private static string UniqueWrapper(HashSet<string> signatures, string methodName, List<string> parameters)
    {
        var baseName = SafeName(Pascal(methodName));
        var types = parameters.Select(p => p[..p.LastIndexOf(' ')]).ToList();
        // A type parameter can be instantiated as any type: it collides with every type in its position.
        bool Collides(string key)
        {
            if (key == AnySignature) return true;
            var other = key.Split('\u0001');
            return other.Length == types.Count && other.Zip(types).All(t => t.First == t.Second || IsTypeParameter(t.First) || IsTypeParameter(t.Second));
        }
        var wrapper = baseName;
        for (int i = 2; signatures.Where(s => s.StartsWith(wrapper + "(", StringComparison.Ordinal)).Any(s => Collides(s[(wrapper.Length + 1)..])); i++)
            wrapper = baseName + i;
        signatures.Add(wrapper + "(" + string.Join('\u0001', types));
        return wrapper;
    }

    private const string AnySignature = "\u0002";

    /// <summary>
    /// A field accessor's name (and Set + name): taken whatever the parameters, so a getter or wrapper of the same name
    /// (a property over the field "_instance") is numbered.
    /// </summary>
    private static string ReserveAccessor(HashSet<string> signatures, string fieldName)
    {
        var baseName = SafeName(Pascal(fieldName));
        var name = baseName;
        for (int i = 2; signatures.Any(s => s.StartsWith(name + "(", StringComparison.Ordinal) || s.StartsWith("Set" + name + "(", StringComparison.Ordinal)); i++)
            name = baseName + i;
        signatures.Add(name + "(" + AnySignature);
        signatures.Add("Set" + name + "(" + AnySignature);
        return name;
    }

    /// <summary>The C++ names of a method's parameters: identifiers, not keywords, unique (transformed metadata repeats names).</summary>
    private static List<string> ParameterNames(MethodDef method)
    {
        var names = new List<string>();
        foreach (var p in method.Parameters.Where(x => x.IsNormalMethodParameter))
        {
            var name = Identifier(p.Name);
            if (CppReserved.Contains(name)) name += "_";
            for (int i = 2; names.Contains(name); i++) name = $"{Identifier(p.Name)}{i}";
            names.Add(name);
        }
        return names;
    }

    private static string ReturnNote(MethodDef method, string unbox)
    {
        if (method.ReturnType.ElementType == ElementType.Void) return "";
        var (retCpp, retPointer, retStruct) = CppType(method.ReturnType);
        return retPointer ? "  // returns the object" : $"  // boxed {Format.Type(method.ReturnType)}: {unbox.Replace("<T>", $"<{(retStruct ? "T" : retCpp)}>")}";
    }

    /// <summary>Accessor and wrapper names must not collide with the struct's own Resolve / Resolved.</summary>
    private static string SafeName(string name) => HelperNames.Contains(name) ? name + "_" : name;

    /// <summary>Names of the struct's own members and of the helpers its code calls, which an accessor or wrapper would hide.</summary>
    private static readonly HashSet<string> HelperNames = new(StringComparer.Ordinal)
    {
        "Resolve", "Resolved", "Definition", "Arg", "Result", "Invoke", "CallValue", "Read", "Write", "ReadStatic", "WriteStatic", "ReadField",
        "WriteField", "ReadPtr", "FindClass", "FindNested", "FieldOffset", "StaticData", "MethodByToken", "MethodInHierarchy", "MethodPointer",
        "GetMethodExact", "GetMethodInHierarchy", "Unbox",
    };

    private static string Join(string a, string b) => a.Length == 0 ? b : $"{a}, {b}";

    /// <summary>The property's declaration; for an inherited one also what its type parameter is here and where it is declared.</summary>
    private static string PropertyComment(TypeDef type, PropertyDef p)
    {
        var getter = p.GetMethod!;
        var seen = AsSeenFrom(type, getter, getter.ReturnType);
        var notes = new List<string>();
        if (!ReferenceEquals(seen, getter.ReturnType)) notes.Add($"{Format.Type(getter.ReturnType)} = {Format.Type(seen)}");
        if (p.DeclaringType != type) notes.Add($"declared on {p.DeclaringType.FullName}");
        return Format.Property(p) + (notes.Count > 0 ? $"  [{string.Join(", ", notes)}]" : "");
    }

    /// <summary>
    /// Substitutes a generic base's type parameter with the argument supplied by <paramref name="type"/>'s base chain
    /// (Base&lt;T&gt;.Instance on "class C : Base&lt;C&gt;" is a C). Other types are returned unchanged.
    /// </summary>
    private static TypeSig AsSeenFrom(TypeDef type, IMemberDef member, TypeSig sig)
    {
        if (sig is not GenericVar { Number: var n } || member.DeclaringType == type) return sig;
        IList<TypeSig>? args = null;
        for (var t = type; t != null && t != member.DeclaringType; )
        {
            var baseSig = t.BaseType?.ToTypeSig();
            var next = BaseTypeDef(t);
            if (baseSig is GenericInstSig inst)
            {
                // the base's arguments, themselves possibly parameters of t (resolved with the previous level's arguments)
                args = inst.GenericArguments.Select(a => a is GenericVar { Number: var k } && args != null && k < args.Count ? args[(int)k] : a).ToList();
            }
            else args = null;
            t = next;
        }
        return args != null && n < args.Count && args[(int)n] is not GenericVar ? args[(int)n] : sig;
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
        if (sig is GenericVar v && _template) return (TypeParameter((int)v.Number), false, false);
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
        // The dumpers write type arguments as classes whatever they are: the definition tells a value type.
        if (sig is TypeDefOrRefSig tr && Try(() => tr.TypeDefOrRef.ResolveTypeDef()) is { IsValueType: true } td)
        {
            if (td.IsEnum && td.GetEnumUnderlyingType() is { } underlying) return CppType(underlying);
            if (td.Namespace == "System" && Primitive(td.Name) is { } primitive) return (primitive, false, false);
            return ("void*", false, true);
        }
        if (sig is ValueTypeSig) return ("void*", false, true);
        if (sig is GenericInstSig gi && (gi.GenericType is ValueTypeSig || Try(() => gi.GenericType.TypeDefOrRef.ResolveTypeDef())?.IsValueType == true))
            return ("void*", false, true);
        return ("void*", true, false); // classes, strings, arrays, interfaces, delegates, generic class instances
    }

    private static string? Primitive(string name) => name switch
    {
        "Boolean" => "bool", "Byte" => "uint8_t", "SByte" => "int8_t", "Char" => "char16_t", "Int16" => "int16_t", "UInt16" => "uint16_t",
        "Int32" => "int32_t", "UInt32" => "uint32_t", "Int64" => "int64_t", "UInt64" => "uint64_t", "Single" => "float", "Double" => "double",
        "IntPtr" => "intptr_t", "UIntPtr" => "uintptr_t",
        _ => null,
    };

    /// <summary>Mono short parameter names, e.g. "String,Color" or "Int32&amp;,Boolean" (GetMethodExact; comments).</summary>
    private static string MonoParams(MethodDef m) =>
        string.Join(",", m.MethodSig.Params.Select(MonoName));

    private static string MonoName(TypeSig sig) => sig switch
    {
        ByRefSig r => MonoName(r.Next) + "&",
        SZArraySig a => MonoName(a.Next) + "[]",
        GenericInstSig g => Format.StripArity(g.GenericType.TypeDefOrRef.Name) + "`" + g.GenericArguments.Count,
        _ => sig.ToTypeDefOrRef()?.Name.String ?? sig.TypeName,
    };

    /// <summary>Accessor name for a member: "m_count" / "_count" / "count" -> "Count".</summary>
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
