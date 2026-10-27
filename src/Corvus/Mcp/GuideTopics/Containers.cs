namespace Corvus.Mcp;

public static partial class Guide
{
    private const string ContainersTopic = """
        Files, containers and wrapped apps (nothing is executed).
        - summarize_file: identity, signature, markers, wrapping, features, strings and entry points in one call; its views field lists the views that apply.
        - Details: survey_features, extract_strings, extract_embedded.
        - Wrapped apps (single-file .exe, Costura, .nupkg, Xamarin / MAUI .apk): list_assemblies path= lists the assemblies inside.
        - search_container finds types and members inside by name (kind=file: inner paths); unpack_container extracts and loads them.
        - list_assemblies and unpack_container flag ReadyToRun and merged assemblies.
        - list_assemblies path= lists and unpack_container writes the files of Electron .asar (with integrity verdicts), WebGL .data, Qt .rcc, Flash SWF, and HAR / mitmproxy captures.
        - Unsafe archive entry names are listed, never extracted; captured requests are never fetched or replayed.
        - Electron: summarize_file gives versions, fuses and webPreferences; search_container kind=electron lists preload scripts, IPC channels and process sinks.
        - search_container kind=endpoint lists endpoints in app code or a capture (capture= joins the two); kind=request lists a capture's requests (header and cookie values only with values=true).
        - search_container kind=packet takes a Wireshark display filter over a pcap; CORVUS_TSHARK adds TShark fields.
        - search_container kind=dart lists a Flutter app's Dart URIs and identifiers.
        - unpack_container on a pcap reassembles TCP and writes HTTP responses and tls.json; keyLog (SSLKEYLOGFILE) decrypts TLS and QUIC.
        - summarize_file views for single formats: qlog, certificate, evtx, procmon, registry (table= a key path), pri, protobuf, flutter, wasm, assets.
        - summarize_file view=script peels PowerShell, batch, VBScript and JavaScript transformation layers without running them.
        - summarize_file view=package reviews an npm, PyPI, VS Code or browser extension package before install.
        - analyze_js: bundler signatures and source maps; view=position maps a minified line:column to the original.
        - Blazor WebAssembly (_framework/*.wasm): unpack_container converts the files to loadable PEs; save_assembly to a .wasm path writes Webcil back.
        - Other .wasm files load as native images: disassemble gives WAT, decompile_native a lifted view, find_xrefs and native_call_tree the calls.
        - Serialized asset files (.assets, levelN, bundles): summarize_build first; summarize_file view=assets lists script objects and fields (script= one class).
        - extract_strings on asset files or a build folder classifies their string fields and config text (URLs, IPs, encoded values).
        - Android packages (.apk, .aab, split sets): get_android_manifest, list_android_resources, get_android_resource.
        - DEX code: list_dex_classes, get_dex_class, disassemble_dex (smali; .class files: javap listing), search_dex, find_dex_references.
        - mapping=<R8 mapping.txt> on the DEX tools restores original names.
        - decompile_java needs CORVUS_JAVA_DECOMPILER (JADX); engine=vineflower needs CORVUS_JAVA_DECOMPILER2.
        - list_jni_bindings pairs native methods with Java_ exports and RegisterNatives tables; export_project on a package writes a Gradle project.
        - map_java_dotnet links a Java wrapper class or method to its .NET counterpart and back (then decompile_member).
        - Devices through adb: list_android_devices, get_android_device_info, list_android_packages, get_android_package_info, read_android_log, pull_android_package, pull_android_file.
        - install_android_package and uninstall_android_package need --allow-device-changes.
        """;
}
