# Guide: il2cpp

<!-- Generated from src/Corvus/Mcp/Guide.cs; run the tests with CORVUS_UPDATE_DOCS=1 to update. -->

Il2Cpp games.
Il2CppDumper and Cpp2IL are not needed: load_assembly the game folder or its global-metadata.dat (GameAssembly.dll beside it; a memory
dump of it works too), or a mobile build: an .apk/.xapk/.aab (libil2cpp.so; slice= picks the ABI), an .ipa or .app (UnityFramework),
macOS .app or Linux GameAssembly.so. The built-in reader (metadata v24-39) makes dummy assemblies plus the script and literal data, cached
per user. Unreadable metadata is an error with a reason; items it could not read are listed by reason in the load report.
Encrypted or transformed metadata is not decrypted: dump the decrypted copy from the running game's memory and load that.
global-metadata.dat with no binary beside it still loads: images, types, nesting, methods with parameter names, fields,
properties, events, tokens and searchable string literals; signature types show as TypeInBinary, with no addresses.
Dummy DLLs have empty bodies: get_il2cpp_info (RVAs, field offsets; slot=N for the method implementing a vtable slot),
find_method_by_address (native address -> method), export_il2cpp_symbols (IDA/Ghidra scripts + C struct header).
With Il2CppDumper's script.json next to a DummyDll folder, functions are bounded by the next function start, generic
instantiations are named both ways (get_il2cpp_info 'List`1<int>::Add'), and type metadata / MethodInfo slots resolve.
With stringliteral.json and GameAssembly.dll too, search_strings finds the literals and the methods whose native code loads them.
generate_cpp_binding emits C++ binding code for a Mono or Il2Cpp type: style=mono uses the Mono embedding API; il2cpp the Il2Cpp
runtime exports plus each method's native code pointer and a typed direct call; hostapi a function table the host passes (FindClass,
GetMethod, FieldOffset, StaticFieldOffset, GetStaticFieldData, Invoke). projectDir is scanned for such a table and helpers.
Native view: load the dummy DLLs and GameAssembly.dll, then apply_il2cpp_names (C# names in every native tool and in IDA).
Unity: unity_overview (folder or exe) reports engine version, Mono or Il2Cpp, whether the metadata is readable or encrypted,
markers and the next calls; nextSteps dump_from_memory means the metadata or Assembly-CSharp.dll is encrypted on disk.
