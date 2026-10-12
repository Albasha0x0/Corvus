namespace Corvus.Mcp;

// Contract rows of the android family (Core/Toolsets.cs); the tables and their rules are in ToolEffects.cs and ParameterDomains.cs.

public static partial class ToolEffects
{
    private static Dictionary<string, Effects> AndroidTools() => new(StringComparer.Ordinal)
    {
        // Android packages (read natively; nothing executed)
        ["get_android_manifest"] = Reads(),
        ["list_android_resources"] = Reads(),
        ["get_android_resource"] = Changes(destructive: true, idempotent: true), // savePath; overwrite=true replaces a file
        ["list_dex_classes"] = Reads(),
        ["get_dex_class"] = Reads(),
        ["disassemble_dex"] = Reads(),
        ["map_java_dotnet"] = Reads(),
        ["decompile_java"] = Reads(longRunning: true, openWorld: true), // runs the JADX server (java -jar); its first call loads the package
        ["search_dex"] = Reads(longRunning: true), // the first call builds the package's code index
        ["find_dex_references"] = Reads(longRunning: true),
        ["list_jni_bindings"] = Reads(longRunning: true), // indexes the DEX code, and a library's code when a table's class needs it

        // Android devices through adb (open-world: they reach a device); install and uninstall need --allow-device-changes
        ["list_android_devices"] = Reads(openWorld: true),
        ["get_android_device_info"] = Reads(openWorld: true),
        ["list_android_packages"] = Reads(openWorld: true),
        ["get_android_package_info"] = Reads(openWorld: true),
        ["read_android_log"] = Reads(openWorld: true),
        ["pull_android_package"] = Changes(destructive: false, idempotent: true, longRunning: true, openWorld: true), // writes into a new or empty directory
        ["pull_android_file"] = Changes(destructive: true, idempotent: true, longRunning: true, openWorld: true), // overwrite=true replaces a file
        ["install_android_package"] = Changes(destructive: true, idempotent: false, longRunning: true, openWorld: true), // replaces an installed app
        ["uninstall_android_package"] = Changes(destructive: true, idempotent: true, openWorld: true),
    };
}

public static partial class ParameterDomains
{
    private static Dictionary<string, IReadOnlyDictionary<string, Domain>> AndroidTools() => new(StringComparer.Ordinal)
    {
        ["disassemble_dex"] = new Dictionary<string, Domain> { ["format"] = Of(["smali", "annotated"]) },
        ["decompile_java"] = new Dictionary<string, Domain> { ["engine"] = Of(["jadx"]) },
        ["read_android_log"] = new Dictionary<string, Domain> { ["priority"] = Of(["V", "D", "I", "W", "E", "F"], "verbose", "debug", "info", "warn", "warning", "error", "fatal") },
        ["search_dex"] = new Dictionary<string, Domain> { ["kind"] = Of(["string", "type", "method", "field", "const", "opcode"], "class") },
        ["list_jni_bindings"] = new Dictionary<string, Domain> { ["kind"] = Of(["static_export", "registered", "unresolved", "export_only"]) },
        ["find_dex_references"] = new Dictionary<string, Domain> { ["direction"] = Of(["to", "from"]), ["kind"] = Of(["auto", "class", "method", "field", "string"]) },
    };
}
