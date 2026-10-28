using System.Text;
using dnlib.DotNet;
using Corvus.Core;
using static Corvus.Core.MetadataUtil;

namespace Corvus.Services;

public sealed partial class CppBindingGenerator
{
    /// <summary>Function table and helpers of every "aot" binding, include-guarded and in aotbind to avoid project clashes.</summary>
    private const string AotPreamble = """
        #include <cstddef>
        #include <cstdint>
        #include <cstring>
        #include <type_traits>

        #ifndef AOTBIND_SHARED
        #define AOTBIND_SHARED
        // Shared by every binding of style "aot": runtime entry points and helpers.
        namespace aotbind {

        struct Il2CppDomain; struct Il2CppAssembly; struct Il2CppImage; struct Il2CppClass; struct FieldInfo; struct MethodInfo;
        struct Il2CppObject;

        // Fill with Load(lookup), where lookup(name) returns that export of the runtime: GetProcAddress on
        // GameAssembly.dll, dlsym on libil2cpp.so, or the function itself when linked.
        struct AotApi {
            Il2CppDomain* (*domain_get)() = nullptr;
            const Il2CppAssembly** (*domain_get_assemblies)(const Il2CppDomain* domain, size_t* size) = nullptr;
            const Il2CppImage* (*assembly_get_image)(const Il2CppAssembly* assembly) = nullptr;
            const char* (*image_get_name)(const Il2CppImage* image) = nullptr;
            Il2CppClass* (*class_from_name)(const Il2CppImage* image, const char* ns, const char* name) = nullptr;
            Il2CppClass* (*class_get_nested_types)(Il2CppClass* klass, void** iter) = nullptr;
            const char* (*class_get_name)(Il2CppClass* klass) = nullptr;
            Il2CppClass* (*class_get_parent)(Il2CppClass* klass) = nullptr;
            FieldInfo* (*class_get_field_from_name)(Il2CppClass* klass, const char* name) = nullptr;
            size_t (*field_get_offset)(FieldInfo* field) = nullptr;
            void (*field_static_get_value)(FieldInfo* field, void* value) = nullptr;
            void (*field_static_set_value)(FieldInfo* field, void* value) = nullptr;
            const MethodInfo* (*class_get_method_from_name)(Il2CppClass* klass, const char* name, int argsCount) = nullptr;
            const MethodInfo* (*class_get_methods)(Il2CppClass* klass, void** iter) = nullptr;
            uint32_t (*method_get_token)(const MethodInfo* method) = nullptr;
            Il2CppObject* (*runtime_invoke)(const MethodInfo* method, void* obj, void** params, Il2CppObject** exc) = nullptr;
            void* (*object_unbox)(Il2CppObject* obj) = nullptr;

            // True when every entry point was found.
            template <class Lookup> bool Load(Lookup&& lookup) {
                bool ok = true;
                auto get = [&](auto& fn, const char* name) {
                    fn = reinterpret_cast<std::remove_reference_t<decltype(fn)>>(lookup(name));
                    ok = ok && fn != nullptr;
                };
                get(domain_get, "il2cpp_domain_get");
                get(domain_get_assemblies, "il2cpp_domain_get_assemblies");
                get(assembly_get_image, "il2cpp_assembly_get_image");
                get(image_get_name, "il2cpp_image_get_name");
                get(class_from_name, "il2cpp_class_from_name");
                get(class_get_nested_types, "il2cpp_class_get_nested_types");
                get(class_get_name, "il2cpp_class_get_name");
                get(class_get_parent, "il2cpp_class_get_parent");
                get(class_get_field_from_name, "il2cpp_class_get_field_from_name");
                get(field_get_offset, "il2cpp_field_get_offset");
                get(field_static_get_value, "il2cpp_field_static_get_value");
                get(field_static_set_value, "il2cpp_field_static_set_value");
                get(class_get_method_from_name, "il2cpp_class_get_method_from_name");
                get(class_get_methods, "il2cpp_class_get_methods");
                get(method_get_token, "il2cpp_method_get_token");
                get(runtime_invoke, "il2cpp_runtime_invoke");
                get(object_unbox, "il2cpp_object_unbox");
                return ok;
            }
        };

        // The image is matched by name with or without ".dll".
        inline Il2CppClass* FindClass(const AotApi& api, const char* assembly, const char* ns, const char* name) {
            size_t count = 0;
            const Il2CppAssembly** assemblies = api.domain_get_assemblies(api.domain_get(), &count);
            size_t length = std::strlen(assembly);
            for (size_t i = 0; i < count; i++) {
                const Il2CppImage* image = api.assembly_get_image(assemblies[i]);
                const char* imageName = image ? api.image_get_name(image) : nullptr;
                if (!imageName || std::strncmp(imageName, assembly, length) != 0) continue;
                if (imageName[length] != '\0' && std::strcmp(imageName + length, ".dll") != 0) continue;
                return api.class_from_name(image, ns, name);
            }
            return nullptr;
        }

        inline Il2CppClass* FindNested(const AotApi& api, Il2CppClass* outer, const char* name) {
            if (!outer) return nullptr;
            void* iter = nullptr;
            while (Il2CppClass* nested = api.class_get_nested_types(outer, &iter))
                if (std::strcmp(api.class_get_name(nested), name) == 0) return nested;
            return nullptr;
        }

        // Instance fields: offset from the start of the object (header included).
        inline int32_t FieldOffset(const AotApi& api, Il2CppClass* klass, const char* name) {
            FieldInfo* field = api.class_get_field_from_name(klass, name);
            return field ? static_cast<int32_t>(api.field_get_offset(field)) : -1;
        }

        inline const MethodInfo* MethodByToken(const AotApi& api, Il2CppClass* klass, uint32_t token) {
            void* iter = nullptr;
            while (const MethodInfo* method = api.class_get_methods(klass, &iter))
                if (api.method_get_token(method) == token) return method;
            return nullptr;
        }

        inline const MethodInfo* MethodInHierarchy(const AotApi& api, Il2CppClass* klass, const char* name, int paramCount) {
            for (Il2CppClass* c = klass; c; c = api.class_get_parent(c))
                if (const MethodInfo* method = api.class_get_method_from_name(c, name, paramCount)) return method;
            return nullptr;
        }

        // The method's native code: the first member of the runtime's MethodInfo.
        inline void* MethodPointer(const MethodInfo* method) {
            return method ? *reinterpret_cast<void* const*>(method) : nullptr;
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

        template <class T> T ReadStatic(const AotApi& api, FieldInfo* field) {
            T value{};
            if (field) api.field_static_get_value(field, &value);
            return value;
        }

        template <class T> bool WriteStatic(const AotApi& api, FieldInfo* field, T value) {
            if (!field) return false;
            api.field_static_set_value(field, &value);
            return true;
        }

        // Calls a method. A managed exception goes to *exception (when given) and the result is nullptr.
        inline Il2CppObject* Invoke(const AotApi& api, const MethodInfo* method, void* obj, void** args, Il2CppObject** exception = nullptr) {
            Il2CppObject* exc = nullptr;
            Il2CppObject* result = method ? api.runtime_invoke(method, obj, args, &exc) : nullptr;
            if (exception) *exception = exc;
            return exc ? nullptr : result;
        }

        // A value-type result, unboxed (T{} when the call failed or threw).
        template <class T> T CallValue(const AotApi& api, const MethodInfo* method, void* obj, void** args = nullptr) {
            T value{};
            if (Il2CppObject* boxed = Invoke(api, method, obj, args)) std::memcpy(&value, api.object_unbox(boxed), sizeof value);
            return value;
        }

        } // namespace aotbind
        #endif // AOTBIND_SHARED
        """;

    private static string RenderAot(LoadedAssembly asm, TypeDef type, Selection s)
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

        var wrapperSignatures = new HashSet<string>(StringComparer.Ordinal);
        foreach (var f in s.Fields)
        {
            var (cpp, isPointer, isStruct) = CppType(f.FieldType);
            var accessor = ReserveAccessor(wrapperSignatures, f.Name);
            if (f.IsStatic)
            {
                // Static fields are read and written through the runtime (it runs the class initializer first).
                var field = Unique($"m_{Camel(f.Name)}Field");
                decls.AppendLine($"    FieldInfo* {field} = nullptr;{Pad(field)}// static {CText.Line(Format.Type(f.FieldType))} {CText.Line(f.Name)}");
                resolve.AppendLine($"        {field} = api.class_get_field_from_name(klass, {CText.Quote(f.Name)});");
                checks.Add(field);
                if (isStruct)
                    accessors.AppendLine($"    bool {accessor}(const AotApi& api, void* value) const {{ if (!{field}) return false; api.field_static_get_value({field}, value); return true; }}  // copies the {CText.Line(Format.Type(f.FieldType))} into value");
                else
                {
                    var t = isPointer ? "Il2CppObject*" : cpp;
                    accessors.AppendLine($"    {t} {accessor}(const AotApi& api) const {{ return ReadStatic<{t}>(api, {field}); }}");
                    accessors.AppendLine($"    bool Set{accessor}(const AotApi& api, {t} value) const {{ return WriteStatic<{t}>(api, {field}, value); }}");
                }
                continue;
            }
            var off = Unique($"m_{Camel(f.Name)}Off");
            decls.AppendLine($"    int32_t {off} = -1;{Pad(off)}// {CText.Line(Format.Type(f.FieldType))} {CText.Line(f.Name)}");
            resolve.AppendLine($"        {off} = FieldOffset(api, klass, {CText.Quote(f.Name)});");
            checks.Add($"{off} >= 0");
            if (isStruct)
                accessors.AppendLine($"    void* {accessor}Addr(void* obj) const {{ return obj && {off} >= 0 ? static_cast<char*>(obj) + {off} : nullptr; }}  // embedded {CText.Line(Format.Type(f.FieldType))}");
            else if (isPointer)
                accessors.AppendLine($"    Il2CppObject* {accessor}(const void* obj) const {{ return Read<Il2CppObject*>(obj, {off}); }}");
            else
            {
                accessors.AppendLine($"    {cpp} {accessor}(const void* obj) const {{ return Read<{cpp}>(obj, {off}); }}");
                accessors.AppendLine($"    bool Set{accessor}({Join("void* obj", $"{cpp} value")}) const {{ return Write<{cpp}>(obj, {off}, value); }}");
            }
        }

        // Getters are invoked and need a thread attached to the runtime (il2cpp_thread_attach). Their signatures are
        // reserved before method wrappers, so a same-named method is the one numbered.
        foreach (var (p, viaHierarchy) in s.Getters)
        {
            var getter = p.GetMethod!;
            var m = Unique($"m_get{Pascal(p.Name)}");
            decls.AppendLine($"    const MethodInfo* {m} = nullptr;{Pad(m)}// {CText.Line(PropertyComment(type, p))}{Address(getter)}");
            resolve.AppendLine(viaHierarchy || getter.DeclaringType != type
                ? $"        {m} = MethodInHierarchy(api, klass, {CText.Quote(getter.Name)}, 0);"
                : $"        {m} = api.class_get_method_from_name(klass, {CText.Quote(getter.Name)}, 0);");
            checks.Add(m);
            var (cpp, isPointer, isStruct) = CppType(AsSeenFrom(type, getter, getter.ReturnType));
            var instance = getter.IsStatic ? "nullptr" : "obj";
            List<string> parameters = getter.IsStatic ? ["const AotApi& api"] : ["const AotApi& api", "void* obj"];
            var name = UniqueWrapper(wrapperSignatures, p.Name, parameters);
            var param = string.Join(", ", parameters);
            if (isPointer || isStruct)
                accessors.AppendLine($"    Il2CppObject* {name}({param}) const {{ return Invoke(api, {m}, {instance}, nullptr); }}{(isStruct ? $"  // boxed {CText.Line(Format.Type(getter.ReturnType))}" : "")}");
            else if (IsTypeParameter(cpp))
                accessors.AppendLine($"    {cpp} {name}({param}) const {{ return Result<{cpp}>(api, Invoke(api, {m}, {instance}, nullptr)); }}");
            else
                accessors.AppendLine($"    {cpp} {name}({param}) const {{ return CallValue<{cpp}>(api, {m}, {instance}); }}");
        }

        // Overloads with equal argument counts are matched by the recorded metadata token.
        foreach (var method in s.Methods)
        {
            var m = Unique($"m_{Camel(method.Name)}");
            int argc = ParamCount(method);
            bool byToken = s.Overloaded.Contains((method.Name.String, argc));
            decls.AppendLine($"    const MethodInfo* {m} = nullptr;{Pad(m)}// {CText.Line(Format.Method(method))}{Address(method)}");
            if (byToken && method.DeclaringType != type)
                throw new ToolError(ErrorCode.Unsupported, $"{Format.MemberLabel(method)} is overloaded on the base class {method.DeclaringType.FullName}: generate a binding for that class.");
            resolve.AppendLine(byToken
                ? $"        {m} = MethodByToken(api, klass, 0x{MetadataToken(method):X8});  // overloaded {CText.Line(method.Name)}({CText.Line(MonoParams(method))})"
                : method.DeclaringType != type
                    ? $"        {m} = MethodInHierarchy(api, klass, {CText.Quote(method.Name)}, {argc});  // declared on {CText.Line(method.DeclaringType.FullName)}"
                    : $"        {m} = api.class_get_method_from_name(klass, {CText.Quote(method.Name)}, {argc});");
            checks.Add(m);

            var (parameters, args) = WrapperParameters(method, "const AotApi& api");
            var argArray = args.Count == 0 ? "nullptr" : "a";
            var setup = args.Count == 0 ? "" : $"void* a[{args.Count}] = {{ {string.Join(", ", args)} }}; ";
            var wrapper = UniqueWrapper(wrapperSignatures, method.Name, parameters);
            parameters.Add("Il2CppObject** exception = nullptr");
            accessors.AppendLine($"    Il2CppObject* {wrapper}({string.Join(", ", parameters)}) const {{ {setup}return Invoke(api, {m}, {(method.IsStatic ? "nullptr" : "obj")}, {argArray}, exception); }}{ReturnNote(method, "api.object_unbox(result)")}");
            accessors.AppendLine($"    void* {Unique(wrapper + "Pointer")}() const {{ return MethodPointer({m}); }}  // native code, e.g. to hook");
            if (DirectCall(method, m) is { } direct) accessors.AppendLine($"    {direct.Replace("$NAME", Unique("Call" + wrapper))}");
        }

        var sb = new StringBuilder();
        sb.AppendLine($"// Generated from {CText.Line(asm.Id)} ({CText.Line(asm.AssemblyName)}.dll): {CText.Line(type.FullName)}  [{Format.Token(type)}]");
        sb.AppendLine("// AOT runtime API, no other headers needed. Fill an aotbind::AotApi once with Load(), then call");
        sb.AppendLine("// Resolve(api) on a thread attached to the runtime (il2cpp_thread_attach) and check Resolved(). Invoke wrappers and");
        sb.AppendLine("// property getters also need an attached thread; field reads and writes only need a live object pointer.");
        sb.AppendLine("// Invoke wrappers take value types by value (by pointer for structs and ref parameters) and objects as their pointer.");
        sb.AppendLine("// XPointer() is the method's native code; CallX calls it directly (no exception handling: a managed exception");
        sb.AppendLine("// thrown there unwinds through the caller), with the MethodInfo as the last argument as the compiled code expects.");
        if (s.Overloaded.Count > 0)
            sb.AppendLine("// Overloaded methods are matched by metadata token: regenerate this header for each new build.");
        if (type.IsValueType)
            sb.AppendLine("// Value type: instance offsets include the object header (two pointers); subtract it for unboxed data.");
        sb.AppendLine("#pragma once");
        sb.AppendLine(AotPreamble);
        sb.AppendLine();
        sb.AppendLine("namespace aotbind {");
        sb.AppendLine();
        if (type.HasGenericParameters && LayoutTemplate(type) is { } layout) sb.Append(layout).AppendLine();
        StructHead(sb, type, "Il2CppClass*", "const AotApi& api", AotFindClass(asm, type), "Il2CppObject", decls);
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
        sb.AppendLine("} // namespace aotbind");
        return sb.ToString();
    }

    private static string AotFindClass(LoadedAssembly asm, TypeDef type)
    {
        var chain = new List<TypeDef>();
        for (var c = type; c != null; c = c.DeclaringType) chain.Insert(0, c);
        var expr = $"FindClass(api, {CText.Quote(asm.AssemblyName)}, {CText.Quote(chain[0].Namespace)}, {CText.Quote(chain[0].Name)})";
        foreach (var nested in chain.Skip(1))
            expr = $"FindNested(api, {expr}, {CText.Quote(nested.Name)})";
        return expr;
    }

    /// <summary>The method's metadata token: the [Token] attribute, else the assembly's own.</summary>
    private static uint MetadataToken(MethodDef method) =>
        AotMetadataService.GetAttributes(method).FirstOrDefault(a => a.Name == "TokenAttribute") is { } token &&
        token.Values.TryGetValue("Token", out var value) && AotMetadataService.ParseNumber(value) is { } parsed
            ? (uint)parsed
            : method.MDToken.Raw;

    /// <summary>"  [RVA 0x...]" when the dummy records the method's native code address.</summary>
    private static string Address(MethodDef method) =>
        AotMetadataService.GetAttributes(method).FirstOrDefault(a => a.Name == "AddressAttribute") is { } address &&
        address.Values.TryGetValue("RVA", out var rva) && rva != "-1"
            ? $"  [RVA {CText.Line(rva)}]"
            : "";

    /// <summary>A typed direct call of the native code ("$NAME" placeholder); null when a parameter or result is a struct.</summary>
    private static string? DirectCall(MethodDef method, string field)
    {
        string? Native(TypeSig sig)
        {
            if (sig is ByRefSig) return "void*";
            var (cpp, isPointer, isStruct) = CppType(sig);
            return isStruct ? null : isPointer ? "void*" : cpp;
        }
        var ret = method.ReturnType.ElementType == ElementType.Void ? "void" : Native(method.ReturnType);
        if (ret == null) return null;
        var types = new List<string>();
        var parameters = new List<string>();
        var args = new List<string>();
        if (!method.IsStatic)
        {
            types.Add("void*");
            parameters.Add("void* obj");
            args.Add("obj");
        }
        foreach (var (p, name) in method.Parameters.Where(x => x.IsNormalMethodParameter).Zip(ParameterNames(method)))
        {
            if (Native(p.Type) is not { } t) return null;
            types.Add(t);
            parameters.Add($"{t} {name}");
            args.Add(name);
        }
        types.Add("const MethodInfo*");
        args.Add(field);
        var fn = $"{ret} (*)({string.Join(", ", types)})";
        var call = $"reinterpret_cast<{fn}>(MethodPointer({field}))({string.Join(", ", args)})";
        return $"{ret} $NAME({string.Join(", ", parameters)}) const {{ {(ret == "void" ? "" : "return ")}{call}; }}";
    }
}
