namespace Corvus.Native.Calls;

/// <summary>
/// The JNI function tables: JNIEnv (JNINativeInterface) and JavaVM (JNIInvokeInterface) slots by index, with signatures
/// for the common functions. A call through [[env] + slot * pointer size] names the slot.
/// </summary>
internal static class JniInterface
{
    public enum Table : byte { Env, Vm }

    private static readonly string[] Types = ["Object", "Boolean", "Byte", "Char", "Short", "Int", "Long", "Float", "Double", "Void"];
    private static readonly string[] Primitives = ["Boolean", "Byte", "Char", "Short", "Int", "Long", "Float", "Double"];

    private static readonly string[] EnvNames = BuildEnv();
    private static readonly string[] VmNames = ["reserved0", "reserved1", "reserved2", "DestroyJavaVM", "AttachCurrentThread", "DetachCurrentThread", "GetEnv", "AttachCurrentThreadAsDaemon"];

    private static string[] BuildEnv()
    {
        var n = new List<string> { "reserved0", "reserved1", "reserved2", "reserved3", "GetVersion", "DefineClass", "FindClass", "FromReflectedMethod",
            "FromReflectedField", "ToReflectedMethod", "GetSuperclass", "IsAssignableFrom", "ToReflectedField", "Throw", "ThrowNew", "ExceptionOccurred",
            "ExceptionDescribe", "ExceptionClear", "FatalError", "PushLocalFrame", "PopLocalFrame", "NewGlobalRef", "DeleteGlobalRef", "DeleteLocalRef",
            "IsSameObject", "NewLocalRef", "EnsureLocalCapacity", "AllocObject", "NewObject", "NewObjectV", "NewObjectA", "GetObjectClass", "IsInstanceOf",
            "GetMethodID" };
        foreach (var t in Types) n.AddRange([$"Call{t}Method", $"Call{t}MethodV", $"Call{t}MethodA"]);
        foreach (var t in Types) n.AddRange([$"CallNonvirtual{t}Method", $"CallNonvirtual{t}MethodV", $"CallNonvirtual{t}MethodA"]);
        n.Add("GetFieldID");
        foreach (var t in Types[..9]) n.Add($"Get{t}Field");
        foreach (var t in Types[..9]) n.Add($"Set{t}Field");
        n.Add("GetStaticMethodID");
        foreach (var t in Types) n.AddRange([$"CallStatic{t}Method", $"CallStatic{t}MethodV", $"CallStatic{t}MethodA"]);
        n.Add("GetStaticFieldID");
        foreach (var t in Types[..9]) n.Add($"GetStatic{t}Field");
        foreach (var t in Types[..9]) n.Add($"SetStatic{t}Field");
        n.AddRange(["NewString", "GetStringLength", "GetStringChars", "ReleaseStringChars", "NewStringUTF", "GetStringUTFLength", "GetStringUTFChars",
            "ReleaseStringUTFChars", "GetArrayLength", "NewObjectArray", "GetObjectArrayElement", "SetObjectArrayElement"]);
        foreach (var p in Primitives) n.Add($"New{p}Array");
        foreach (var p in Primitives) n.Add($"Get{p}ArrayElements");
        foreach (var p in Primitives) n.Add($"Release{p}ArrayElements");
        foreach (var p in Primitives) n.Add($"Get{p}ArrayRegion");
        foreach (var p in Primitives) n.Add($"Set{p}ArrayRegion");
        n.AddRange(["RegisterNatives", "UnregisterNatives", "MonitorEnter", "MonitorExit", "GetJavaVM", "GetStringRegion", "GetStringUTFRegion",
            "GetPrimitiveArrayCritical", "ReleasePrimitiveArrayCritical", "GetStringCritical", "ReleaseStringCritical", "NewWeakGlobalRef",
            "DeleteWeakGlobalRef", "ExceptionCheck", "NewDirectByteBuffer", "GetDirectBufferAddress", "GetDirectBufferCapacity", "GetObjectRefType", "GetModule"]);
        return [.. n];
    }

    /// <summary>"JNIEnv::FindClass" for slot 6 of the JNIEnv table; null past the table or for a reserved slot.</summary>
    public static string? Name(Table table, int slot)
    {
        var names = table == Table.Env ? EnvNames : VmNames;
        if (slot < 0 || slot >= names.Length || names[slot].StartsWith("reserved", StringComparison.Ordinal)) return null;
        return (table == Table.Env ? "JNIEnv::" : "JavaVM::") + names[slot];
    }

    private static readonly Dictionary<string, ApiSignature> Signatures = BuildSignatures();

    public static ApiSignature? Signature(string name) => Signatures.GetValueOrDefault(name);

    private static Dictionary<string, ApiSignature> BuildSignatures()
    {
        var s = new Dictionary<string, ApiSignature>(StringComparer.Ordinal);
        static ApiParam P(string name, ApiParamType type = ApiParamType.Pointer) => new(name, type);
        void Env(string name, params ApiParam[] rest) => s["JNIEnv::" + name] = new ApiSignature("JNIEnv::" + name, [P("env"), .. rest], false, true);
        void Vm(string name, params ApiParam[] rest) => s["JavaVM::" + name] = new ApiSignature("JavaVM::" + name, [P("vm"), .. rest], false, true);

        foreach (var name in new[] { "GetVersion", "ExceptionOccurred", "ExceptionDescribe", "ExceptionClear", "ExceptionCheck" }) Env(name);
        Env("DefineClass", P("name", ApiParamType.AnsiString), P("loader"), P("buf"), P("bufLen", ApiParamType.Int));
        Env("FindClass", P("name", ApiParamType.AnsiString));
        Env("ThrowNew", P("clazz"), P("message", ApiParamType.AnsiString));
        Env("FatalError", P("msg", ApiParamType.AnsiString));
        foreach (var name in new[] { "GetMethodID", "GetStaticMethodID", "GetFieldID", "GetStaticFieldID" })
            Env(name, P("clazz"), P("name", ApiParamType.AnsiString), P("sig", ApiParamType.AnsiString));
        foreach (var name in new[] { "NewGlobalRef", "DeleteGlobalRef", "DeleteLocalRef", "NewLocalRef", "GetObjectClass", "GetSuperclass", "Throw",
                     "GetArrayLength", "GetStringLength", "GetStringUTFLength", "MonitorEnter", "MonitorExit", "NewWeakGlobalRef", "DeleteWeakGlobalRef",
                     "GetDirectBufferAddress", "GetDirectBufferCapacity", "GetObjectRefType", "AllocObject", "UnregisterNatives" })
            Env(name, P(name.Contains("Array") ? "array" : name.Contains("String") ? "string" : name.Contains("Buffer") ? "buf" : "obj"));
        Env("IsInstanceOf", P("obj"), P("clazz"));
        Env("IsSameObject", P("ref1"), P("ref2"));
        Env("NewStringUTF", P("bytes", ApiParamType.AnsiString));
        Env("GetStringUTFChars", P("string"), P("isCopy"));
        Env("ReleaseStringUTFChars", P("string"), P("utf", ApiParamType.AnsiString));
        Env("GetStringChars", P("string"), P("isCopy"));
        Env("ReleaseStringChars", P("string"), P("chars"));
        Env("RegisterNatives", P("clazz"), P("methods"), P("nMethods", ApiParamType.Int));
        Env("GetJavaVM", P("vm"));
        Env("PushLocalFrame", P("capacity", ApiParamType.Int));
        Env("PopLocalFrame", P("result"));
        Env("EnsureLocalCapacity", P("capacity", ApiParamType.Int));
        Env("NewObjectArray", P("length", ApiParamType.Int), P("elementClass"), P("initialElement"));
        Env("GetObjectArrayElement", P("array"), P("index", ApiParamType.Int));
        Env("SetObjectArrayElement", P("array"), P("index", ApiParamType.Int), P("value"));
        Env("NewDirectByteBuffer", P("address"), P("capacity", ApiParamType.Int64));
        foreach (var p in Primitives)
        {
            Env($"New{p}Array", P("length", ApiParamType.Int));
            Env($"Get{p}ArrayElements", P("array"), P("isCopy"));
            Env($"Release{p}ArrayElements", P("array"), P("elems"), P("mode", ApiParamType.Int));
            Env($"Get{p}ArrayRegion", P("array"), P("start", ApiParamType.Int), P("len", ApiParamType.Int), P("buf"));
            Env($"Set{p}ArrayRegion", P("array"), P("start", ApiParamType.Int), P("len", ApiParamType.Int), P("buf"));
        }
        foreach (var t in Types)
        {
            foreach (var suffix in new[] { "", "V", "A" })
            {
                // the method's own arguments follow (varargs, a va_list or a jvalue array)
                Env($"Call{t}Method{suffix}", P("obj"), P("methodID"));
                Env($"CallStatic{t}Method{suffix}", P("clazz"), P("methodID"));
                Env($"CallNonvirtual{t}Method{suffix}", P("obj"), P("clazz"), P("methodID"));
            }
            if (t == "Void") continue;
            var value = t switch { "Float" => ApiParamType.Float, "Double" => ApiParamType.Double, "Long" => ApiParamType.Int64, "Object" => ApiParamType.Pointer, _ => ApiParamType.Int };
            Env($"Get{t}Field", P("obj"), P("fieldID"));
            Env($"Set{t}Field", P("obj"), P("fieldID"), P("value", value));
            Env($"GetStatic{t}Field", P("clazz"), P("fieldID"));
            Env($"SetStatic{t}Field", P("clazz"), P("fieldID"), P("value", value));
        }
        foreach (var suffix in new[] { "", "V", "A" }) Env("NewObject" + suffix, P("clazz"), P("methodID"));

        Vm("DestroyJavaVM");
        Vm("DetachCurrentThread");
        Vm("GetEnv", P("penv"), P("version", ApiParamType.Hex));
        Vm("AttachCurrentThread", P("penv"), P("args"));
        Vm("AttachCurrentThreadAsDaemon", P("penv"), P("args"));
        return s;
    }

    /// <summary>
    /// The table a function's first parameter points to: JNIEnv for a native method (Java_* export), JavaVM for
    /// JNI_OnLoad / JNI_OnUnload; null otherwise.
    /// </summary>
    public static Table? FirstParameter(string? function) => function switch
    {
        null => null,
        "JNI_OnLoad" or "JNI_OnUnload" => Table.Vm,
        _ when function.StartsWith("Java_", StringComparison.Ordinal) => Table.Env,
        _ => null,
    };
}
