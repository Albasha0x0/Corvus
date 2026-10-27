# Guide: aot

<!-- Generated from src/Corvus/Mcp/Guide.cs; run the tests with CORVUS_UPDATE_DOCS=1 to update. -->

Managed code compiled ahead of time to native code, with global-metadata.dat.
- Load: load_assembly the app folder or its global-metadata.dat, with GameAssembly.dll or a memory dump of it beside it.
- Mobile builds load too: .apk/.xapk/.aab (libil2cpp.so; slice= picks the ABI), .ipa or .app (UnityFramework); Linux: GameAssembly.so.
- The built-in reader (metadata v24-39) writes dummy assemblies, cached per user; the load report lists unread items by reason.
- Encrypted or transformed metadata is not decrypted: save the decrypted copy from the running process and load that.
- global-metadata.dat alone loads types, methods, fields and string literals, without addresses.
- Dummy assemblies have empty bodies: get_method_addresses gives RVAs and field offsets (slot=N: the method in a vtable slot).
- find_method_by_address maps a native address to its method; export_method_symbols writes IDA / Ghidra scripts and a C header.
- script.json beside a dummy assembly folder bounds functions, names generic instantiations and resolves metadata slots.
- stringliteral.json with GameAssembly.dll: search_strings finds the literals and the methods that load them.
- generate_cpp_binding writes C++ binding code for a type: style=mono (embedding API), aot (runtime exports, direct calls) or hostapi (a host function table; projectDir is scanned for one).
- Native view: load the dummy assemblies and GameAssembly.dll, then apply_metadata_names names the output of every native tool and IDA.
- summarize_build (folder or exe): runtime version, Mono or AOT, metadata readable or encrypted, next calls.
- nextSteps dump_from_memory means the metadata or assemblies are encrypted on disk.
