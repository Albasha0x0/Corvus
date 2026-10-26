namespace Corvus.Mcp;

public static partial class Guide
{
    private const string ContainersTopic = """
        Files, containers and wrapped apps (nothing is executed).
        summarize_file reports signature, markers, container wrapping, features, typed strings and entry points of a file in one call;
        survey_features, extract_strings and extract_embedded give the details.
        summarize_file views: overview (default: identity, hashes, signature, assemblies, highlights, entry points, typed value counts);
        managed (detail.file and detail.assemblies: identity, signature, markers, wrapping, features, values, entry points; the first
        assembly in full, the others in brief); native (detail.image for ELF / Mach-O, detail.packers, detail.nativeAot, detail.triage
        for a loaded image: entry points, top functions and strings, import groups); android (manifest, runtimes, ABIs, DEX, signature);
        electron (versions, fuses, archive integrity, webPreferences); go (toolchain, modules, build settings); all (every view).
        The record's views lists the views that apply to the file.
        An app wrapped in a container (single-file .exe, Costura, .nupkg, Xamarin/MAUI .apk): list_assemblies with path shows the
        assemblies inside, search_container finds types/members in them by name (kind=file: inner file names and paths), and
        unpack_container extracts and loads them.
        list_assemblies and unpack_container flag ReadyToRun and merged (ILMerge/ILRepack) assemblies.
        Electron .asar archives: list_assemblies with path lists every entry (filter / offset / limit page them) with its integrity
        verdict (ok, hash_mismatch, block_mismatch, no_integrity, unpacked_missing) and the header hash against the one the app
        declares (good, bad, absent); unsafe names are listed, never extracted; unpack_container writes every file, .unpacked ones too.
        Unity WebGL Build/<name>.data (also .gz, .br): list_assemblies with path lists its files with their roles (Il2Cpp metadata
        and version, serialized files, bundles), the Unity version and the .wasm / .framework.js beside it; unpack_container extracts them.
        Qt resource collections (.rcc, or compiled into a Qt 5 / 6 program): list_assemblies with path lists each file with its
        locale and storage; unpack_container writes them expanded.
        Flash SWF files: list_assemblies with path lists the ActionScript 3 blocks (.abc, with a .classes.txt outline), actions,
        images, sounds and binary data, named by SymbolClass; unpack_container writes them.
        Traffic captures (HAR, mitmproxy flow files): list_assemblies with path lists each response (method, status, MIME type, URL)
        as host/path (the query folded into a short hash); unpack_container writes the bodies, decoded from base64 and their
        Content-Encoding (gzip, deflate, br, zstd). Nothing is fetched or replayed.
        summarize_file on an Electron executable or its .asar adds Electron / Chromium / Node versions, fuses, archive integrity,
        the package.json main entry and webPreferences values (nodeIntegration, contextIsolation, sandbox...) with file:line:column.
        search_container kind=electron lists preload scripts, contextBridge keys, IPC channels, child_process / shell sinks and
        native add-ons with file:line:column; kind=endpoint lists a capture's request templates, or the endpoints an APK, .NET or iOS
        app's code names (Retrofit, OkHttp, HttpClient, Refit, gRPC, URL strings) by method, and capture= joins the two (code,
        capture, code+capture), or compares two captures (added, removed, changed, same); kind=request lists a HAR, mitmproxy or
        .saz capture's requests in order: header and cookie names (values=true shows values), body, GraphQL operations, status,
        time, SSE / NDJSON message shapes and WebSocket messages; kind=packet takes a
        Wireshark display filter (ip.addr==10.0.0.1 and tcp.port==443, dns.qry.name contains "api", tls.sni==x, not udp) and lists a
        pcap / pcapng capture's matching frames, streamed at any size, with the fields it names (also h2c, QUIC Initial,
        SMB2 and Kerberos names in-process, JA3 / JA4; other fields through TShark when CORVUS_TSHARK finds it). unpack_container on
        a pcap reassembles TCP and writes HTTP/1.x, HTTP/2 and HTTP/3 (QUIC) responses as files, other streams under streams/, and
        tls.json (version, cipher, JA3 / JA4 / JA4S); keyLog (SSLKEYLOGFILE) or the pcapng's secrets blocks decrypt TLS 1.2 / 1.3 and
        QUIC; summarize_file view=qlog reads QUIC event logs; view=certificate reads PEM, DER, PKCS #7 and PKCS #12
        files (fingerprints, SPKI pins, chains); view=evtx pages a Windows event log's events, recovered ones too;
        view=procmon pages a Process Monitor log's events; view=registry reads a
        registry hive file (table= a key path) with its deleted keys; view=pri pages a package resource index's
        names and candidates (table= part of a name); kind=dart lists a Flutter app's Dart
        package: / dart: URIs and identifiers (summarize_file view=flutter gives its packages).
        summarize_file view=protobuf rebuilds embedded protobuf descriptors as .proto files.
        summarize_file view=script reads PowerShell, batch, VBScript and JavaScript with their transformation layers peeled to plain
        text, never run (each layer with its decoding chain; offset pages the text); view=package reviews an npm, PyPI, VS Code or
        browser extension package before installing: install scripts, entry points, permissions, findings noteworthy or worth reviewing.
        analyze_js on a .js file: bundler signatures and its source map; view=position maps a minified line:column to the original source.
        Blazor WebAssembly (_framework/*.wasm, Webcil): load_assembly does not read these yet; unpack_container on the _framework folder converts them to PEs that load; save_assembly to a .wasm path writes Webcil back.
        Any other .wasm loads as a native image: disassemble gives a function's WAT (as wasm2wat), decompile_native a lifted view,
        find_xrefs / native_call_tree its calls (call_indirect by type), globals and data; summarize_file view=wasm validates it
        and joins its imports to the JS glue beside it (Emscripten, wasm-bindgen, Go) by name.
        Unity builds: unity_overview first; summarize_file view=unity on a .assets, levelN or bundle file lists MonoBehaviour assets with
        their script fields (script= one class), laid out from the type tree, the Managed assemblies or loaded Il2Cpp metadata;
        extract_strings on the same files, a build folder or its package classifies their string fields and config TextAssets (URLs, IPs, encoded values),
        reading an Il2Cpp build's metadata for the layouts when no load did.
        Android packages (.apk, .aab, split sets), read natively: get_android_manifest (components, exported state, permissions, deep links),
        list_android_resources and get_android_resource (decoded XML, @type/name values). DEX code: list_dex_classes, get_dex_class (exact
        method ids), disassemble_dex (smali of one method or class; a jar of .class files or a .class: the javap -c -p listing), decompile_java
        (Java through JADX when CORVUS_JAVA_DECOMPILER is set; class files also through Vineflower, engine=vineflower with CORVUS_JAVA_DECOMPILER2; kept on disk by input hash), search_dex (strings, types, members, constants, opcodes), find_dex_references (callers, field readers / writers, callees); mapping=<R8 mapping.txt> on the DEX tools names classes and members by their originals (kept per package). JNI: list_jni_bindings pairs native methods with Java_ exports and RegisterNatives tables. export_project with a package path writes a Gradle project. Xamarin / MAUI and Unity Mono (AndroidJavaObject calls by name): map_java_dotnet links a Java wrapper
        class or method to its .NET type or method (then decompile_member) and back.
        Devices through adb: list_android_devices, get_android_device_info, list_android_packages, get_android_package_info, read_android_log,
        pull_android_package (then the tools above on the APKs), pull_android_file; install_android_package and uninstall_android_package
        only with --allow-device-changes.
        """;
}
