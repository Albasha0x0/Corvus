# Guide: containers

<!-- Generated from src/Corvus/Mcp/Guide.cs; run the tests with CORVUS_UPDATE_DOCS=1 to update. -->

Files, containers and wrapped apps (nothing is executed).
summarize_file reports signature, markers, container wrapping, features, typed strings and entry points of a file in one call;
survey_features, extract_strings and extract_embedded give the details.
An app wrapped in a container (single-file .exe, Costura, .nupkg, Xamarin/MAUI .apk): list_assemblies with path shows the
assemblies inside, search_container finds types/members in them by name, and unpack_container extracts and loads them.
list_assemblies and unpack_container flag ReadyToRun and merged (ILMerge/ILRepack) assemblies.
Electron .asar archives: list_assemblies with path lists every entry (filter / offset / limit page them) with its integrity
verdict (ok, hash_mismatch, block_mismatch, no_integrity, unpacked_missing) and the header hash against the one the app
declares (good, bad, absent); unsafe names are listed, never extracted; unpack_container writes every file, .unpacked ones too.
Blazor WebAssembly (_framework/*.wasm, Webcil): load_assembly does not read these yet; unpack_container on the _framework folder converts them to PEs that load; save_assembly to a .wasm path writes Webcil back.
Unity builds: unity_overview first.
Android packages (.apk, .aab, split sets), read natively: get_android_manifest (components, exported state, permissions, deep links),
list_android_resources and get_android_resource (decoded XML, @type/name values). DEX code: list_dex_classes, get_dex_class (exact
method ids), disassemble_dex (smali of one method or class), decompile_java
(Java through JADX when CORVUS_JAVA_DECOMPILER is set), search_dex (strings, types, members, constants, opcodes), find_dex_references (callers, field readers / writers, callees). JNI: list_jni_bindings pairs native methods with Java_ exports and RegisterNatives tables. export_project with a package path writes a Gradle project. Xamarin / MAUI and Unity Mono (AndroidJavaObject calls by name): map_java_dotnet links a Java wrapper
class or method to its .NET type or method (then decompile_member) and back.
Devices through adb: list_android_devices, get_android_device_info, list_android_packages, get_android_package_info, read_android_log,
pull_android_package (then the tools above on the APKs), pull_android_file; install_android_package and uninstall_android_package
only with --allow-device-changes.
