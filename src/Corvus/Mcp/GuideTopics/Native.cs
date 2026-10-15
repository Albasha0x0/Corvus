namespace Corvus.Mcp;

public static partial class Guide
{
    private const string NativeTopic = """
        Native files (PE .exe/.dll/.sys without .NET metadata, ELF, Mach-O; x86, x64, ARM64 and 32-bit ARM / Thumb): load_assembly the file, or pass its path as image.
        The first code tool call on an image waits for its code index (seconds; minutes for a very large image); progress reports the phase.
        Overview: get_pe_info (headers, mitigations, PDB, version, rich header, signature, anything malformed; capability groups;
        view=code: code statistics, late-bound imports, modules loaded by name), list_imports
        (includeDynamic=true adds GetProcAddress imports; bind=true shows each binding), list_exports (MSVC names demangled),
        list_resources / get_resource, survey_features.
        Code: list_functions, list_globals (named data with types), disassemble, inspect_instruction (operands, registers, flags, flow; mid-instruction and data
        addresses classified), get_cfg, find_xrefs (every call site of an import: 'kernel32!CreateFileW'; struct
        members through IDA: Type::member), native_call_tree, find_call_paths to='native:<image>!<function>' (ranked call chains
        from roots, from='native:...' or managed callers through P/Invoke), get_call_arguments (recovered arguments as data),
        trace_native_values (where a value comes from or goes, across callers, callees and globals;
        engine=ida|ghidra slices each function in the decompiler's IR), resolve_call_targets
        (targets of indirect calls with their basis; scope=image lists the unresolved ones), analyze_native_function (one
        function in sections: identity, signature, frame, callers, callees, data, flow; params and pseudocode on request),
        trace_native_feature (strings, names, imports, exports and classes matching a text, to ranked functions and hubs),
        find_similar_functions (look-alikes of a function ranked with evidence, also across loaded images; duplicates and near-duplicate clusters), search_native_strings, search_bytes (?? and nibble wildcards, bit masks; memory=engine for loaded bytes), search_instructions (mnemonic / operand regexes, operand values), read_bytes (type= reads values), convert_number, resolve_address, list_cpp_classes (RTTI classes, bases,
        vftables), get_native_type (a type's layout from the PDB, RTTI, Il2Cpp or the engine by name, id or typed address; at=0x48 names a field;
        read=true adds the field values at an address), get_exception_info (MSVC try / catch, SEH scopes, funclets), find_virtual_calls (obj->vfunc() sites resolved
        through RTTI; crossCheck=true compares with IDA or Ghidra), decompile_native (C pseudocode through IDA or Ghidra when installed;
        functions=[...] decompiles several in one request, each with its own deadline; callersOf= the callers of one), search_decompiled (a regex over many functions' pseudocode; cursor= continues); emulate_native (Ghidra p-code emulation of a decoder, hash or computed constant: args,
        registers, memory and stubs= for calls; nothing runs natively).
        Addresses: hex VA (0x180001000) or RVA (0x1000), rva:/va:/off: prefixes, export names, module!import, sub_<rva>, function names
        (a name on several addresses is an ambiguous error listing them).
        Symbols: a matching local PDB is read with the code index (DWARF for ELF and Mach-O: its own sections, a .debug/.dbg file by
        build-id or .gnu_debuglink, a dSYM); load_pdb loads one by path or downloads it (download=true: symbol server, debuginfod);
        search_pdb_symbols lists its symbols; resolve_address adds DWARF source lines and inlined functions. Names from load_pdb and apply_il2cpp_names are saved per file SHA-256 and reapplied
        when the same file loads again; list_native_edits shows the layers, clear=true on either tool removes one.
        NativeAOT images name themselves from their metadata when the code index builds (methods, vtable slots, MethodTables,
        frozen strings); get_nativeaot_info shows the version, recovery stages, types, methods and strings.
        Node-API add-ons (.node) name their callbacks after the JavaScript names they register (napi layer: js_<name>,
        js_get_ / js_set_ for accessors, js_Class_member), from constant napi_create_function / napi_define_properties /
        napi_define_class / napi_module_register arguments; descriptors built at run time (node-addon-api, napi-rs) are not read.
        Cross-image: load the DLLs an image imports (or load_assembly loadProviders=true) and the call tools follow imports,
        forwarders and thunks into them.
        Engines: list_functions, disassemble, search_instructions, get_cfg, find_xrefs and native_call_tree take engine=auto|ours|ida|ghidra. auto
        (default) uses the first engine (IDA, then Ghidra) that has analyzed the image's bytes, open or saved in the analysis cache,
        else the built-in index (tools that need an engine, such as decompile_native: the first installed); ida / ghidra start that engine; --engine / CORVUS_ENGINE sets the server default. Every result has an
        "Engine: ours|ida|ghidra (why)" line. 32-bit ARM: an odd address is Thumb code one byte
        lower; list_functions flags A32 functions "arm". inspect_instruction takes auto|ours|ida|ghidra (auto: the built-in decoder for x86 / x64 / ARM).
        Name priority: user > pdb > nativeaot > il2cpp > objc > swift > napi > ida > ghidra > discovered; our names win in engine output. decompile_native pushes
        names, patches, Il2Cpp prototypes, RTTI and PDB types into the engine's database; --prewarm ida|ghidra|auto analyzes images
        as they load; server_status shows each engine session (opening stage and seconds, busy request, analysis complete or partial,
        database, worker). Code indexes are saved on disk by file SHA-256 (--index-cache off disables it).
        An IDA database left beside the input (x.i64 or x.dll.i64) that IDA made from the same bytes starts the image's engine
        database the first time: a copy is used, the file itself is never changed; server_status names the database.
        Other instruction sets (MIPS, PowerPC, RISC-V, s390x, ...): format tools answer (get_pe_info, list_imports, list_exports, list_functions
        from declared starts, resolve_address, read_bytes, search_bytes, search_native_strings, get_exception_info); code tools (disassemble,
        inspect_instruction, search_instructions, get_cfg, find_xrefs, native_call_tree, find_virtual_calls, get_call_arguments, trace_native_values,
        resolve_call_targets, find_similar_functions) go through IDA or Ghidra, else refuse with unsupported (details.reason instructions-not-decoded,
        details.arch the file's machine name); reports mark their code facts "not decoded" with coverage partial.
        Editing and engine type edits: the edits topic. Build-to-build: the builds topic.
        """;
}
