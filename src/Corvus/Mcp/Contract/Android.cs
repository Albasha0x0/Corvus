using L = Corvus.Mcp.LatencyClass;
using O = Corvus.Mcp.OutputClass;

namespace Corvus.Mcp;

// Contract rows of the android family (Core/Toolsets.cs); the tables and their rules are in ToolEffects.cs, ParameterDomains.cs and ToolContract.cs.

public static partial class ToolEffects
{
    private static Dictionary<string, Effects> AndroidTools() => new(StringComparer.Ordinal)
    {
        // Android packages (read natively; nothing executed)
        ["get_android_manifest"] = Reads(),
        ["list_android_resources"] = Reads(),
        ["get_android_resource"] = Changes(destructive: true, idempotent: true), // outputPath; overwrite=true replaces a file
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
        ["read_android_log"] = new Dictionary<string, Domain>
        {
            ["priority"] = Of(["V", "D", "I", "W", "E", "F"], "verbose", "debug", "info", "warn", "warning", "error", "fatal"),
            ["buffer"] = Of(["main", "system", "crash", "events", "radio", "all", "default"]),
        },
        ["search_dex"] = new Dictionary<string, Domain> { ["kind"] = Of(["string", "type", "method", "field", "const", "opcode"], "class") },
        ["list_jni_bindings"] = new Dictionary<string, Domain> { ["kind"] = Of(["static_export", "registered", "unresolved", "export_only"]) },
        ["find_dex_references"] = new Dictionary<string, Domain> { ["direction"] = Of(["to", "from"]), ["kind"] = Of(["auto", "class", "method", "field", "string"]) },
    };
}

public sealed partial record ToolContract
{
    private static Dictionary<string, ToolContract> AndroidTools() => new(StringComparer.Ordinal)
    {
        ["get_android_manifest"] = Row(O.Report, L.Instant),
        ["list_android_resources"] = Row(O.List, L.Instant, sort: "resource id, configuration"),
        ["get_android_resource"] = Row(O.Bytes, L.Instant, noDryRun: "writes only with outputPath; overwrite=false refuses an existing file"),
        ["list_dex_classes"] = Row(O.List, L.Instant, sort: "class descriptor"),
        ["get_dex_class"] = Row(O.Code, L.Instant),
        ["disassemble_dex"] = Row(O.Code, L.Instant),
        ["decompile_java"] = Row(O.Code, L.Long),
        ["search_dex"] = Row(O.List, L.Interactive, sort: "code order"),
        ["find_dex_references"] = Row(O.List, L.Interactive, sort: "source, offset"),
        ["map_java_dotnet"] = Row(O.List, L.Interactive, sort: "discovery order"),
        ["list_jni_bindings"] = Row(O.List, L.Interactive, sort: "library, export order"),
        ["list_android_devices"] = Row(O.Report, L.Interactive),
        ["get_android_device_info"] = Row(O.Report, L.Interactive),
        ["list_android_packages"] = Row(O.List, L.Interactive, sort: "package name"),
        ["get_android_package_info"] = Row(O.Report, L.Interactive),
        ["pull_android_package"] = Row(O.Edit, L.Long, noDryRun: "writes only into a new or empty directory"),
        ["pull_android_file"] = Row(O.Edit, L.Long, noDryRun: "writes only to the path it is given; overwrite=false refuses an existing file"),
        ["read_android_log"] = Row(O.Report, L.Interactive),
        ["install_android_package"] = Row(O.Edit, L.Long, noDryRun: "N14: gated by --allow-device-changes"),
        ["uninstall_android_package"] = Row(O.Edit, L.Long, noDryRun: "N14: gated by --allow-device-changes"),
    };
}
