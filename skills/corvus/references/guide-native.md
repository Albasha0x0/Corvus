# Guide: native

<!-- Generated from src/Corvus/Mcp/Guide.cs; run the tests with CORVUS_UPDATE_DOCS=1 to update. -->

Native files: PE without .NET metadata, ELF, Mach-O; x86, x64, ARM64, 32-bit ARM / Thumb.
- load_assembly the file, or pass its path as image.
- The first code tool call waits for the code index (seconds; minutes for a very large image); progress reports the phase.
- Overview: get_pe_info (view=code: code statistics, late-bound imports), list_exports, list_resources, get_resource, survey_features.
- list_imports: includeDynamic=true adds GetProcAddress imports; bind=true shows each binding.
- Functions: list_functions, list_globals, disassemble, inspect_instruction, get_cfg, analyze_native_function, get_exception_info.
- References: find_xrefs ('kernel32!CreateFileW' lists every call site), native_call_tree, find_call_paths to='native:<image>!<function>'.
- Indirect calls: resolve_call_targets, find_virtual_calls (crossCheck=true compares with IDA or Ghidra).
- Values: get_call_arguments, trace_native_values (engine=ida|ghidra uses the decompiler's IR).
- emulate_native runs a decoder or hash in an emulator, never natively; engine=speakeasy runs a whole PE with Windows APIs modelled.
- Search: search_native_strings, search_bytes (?? wildcards; memory=engine for loaded bytes), search_instructions, trace_native_feature, find_similar_functions.
- Data: read_bytes (type= reads values), convert_number, resolve_address, list_cpp_classes, get_native_type (at=0x48 names a field; read=true adds values).
- decompile_native needs IDA or Ghidra (functions=[...] decompiles several; callersOf= the callers); search_decompiled runs a regex over pseudocode (cursor= continues).
- Addresses: hex VA (0x180001000) or RVA (0x1000), rva:/va:/off: prefixes, export names, module!import, sub_<rva>, function names.
- A name on several addresses is an ambiguous error listing them.
- Symbols: a matching local PDB or DWARF is read with the code index; load_pdb loads one by path or downloads it (download=true); search_pdb_symbols lists its symbols.
- Names from load_pdb and apply_metadata_names are saved per file SHA-256; list_native_edits shows the layers, clear=true removes one.
- NativeAOT images name themselves from their metadata; get_nativeaot_info shows version, types, methods and strings.
- Node-API add-ons (.node) name callbacks after the JavaScript names they register (js_<name>); descriptors built at run time are not read.
- Cross-image: load the DLLs an image imports (or loadProviders=true) and call tools follow imports, forwarders and thunks.
- Engines: list_functions, disassemble, inspect_instruction, search_instructions, get_cfg, find_xrefs and native_call_tree take engine=auto|ours|ida|ghidra.
- auto (default) uses an engine that has analyzed the image, else the built-in index; --engine or CORVUS_ENGINE sets the default; results name the engine.
- 32-bit ARM: an odd address is Thumb code one byte lower; list_functions flags A32 functions "arm".
- Name priority: user > pdb > nativeaot > metadata > objc > swift > dart > napi > ida > ghidra > discovered.
- decompile_native pushes names, patches, prototypes and types into the engine's database; --prewarm ida|ghidra|auto analyzes images as they load.
- server_status shows each engine session; code indexes are saved by file SHA-256 (--index-cache off disables it).
- An IDA database beside the input (x.i64) made from the same bytes seeds the engine database; a copy is used.
- Other instruction sets (MIPS, PowerPC, RISC-V, ...): format tools answer; code tools need IDA or Ghidra, else refuse with unsupported (details.reason instructions-not-decoded).
- Editing and engine edits: the edits topic. Build to build: the builds topic.
