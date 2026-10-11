namespace NetDecompilerMcp.Mcp;

/// <summary>
/// The server's guidance: a core sent as the MCP instructions, and topics served by the guide prompt and the
/// netdecomp://guide/{topic} resource. Clients cut instructions at 2,048 characters, so the core names an entry tool
/// for every area and the rules; the details live in the topics.
/// </summary>
public static class Guide
{
    /// <summary>Claude Code's default cut for server instructions and each tool description.</summary>
    public const int ClientLimit = 2_048;

    public const string Core = """
        Reverse engineering of .NET assemblies and native PE files (x86/x64). Reads bytes only; nothing is executed.
        Start: load_assembly(path) takes a file or a folder (.NET or native .exe/.dll/.sys); results name an id (app.dll, app.dll#2) that later calls take as assembly or image. Unknown file: summarize_file. Wrapped apps (single-file, .apk, .nupkg, Costura): list_assemblies path=..., unpack_container. Unity: unity_overview. Il2Cpp: load the game folder or global-metadata.dat.
        .NET: find with search_symbols, search_strings, search_constants, search_il; outline with get_type_info; read with decompile_member (one method, cheapest), decompile_type, get_il; follow with find_references, find_callees, get_call_tree, find_call_paths, find_overrides, get_type_hierarchy.
        Native: get_pe_info, list_imports, list_exports, list_functions, find_xrefs ('kernel32!CreateFileW'), disassemble, native_call_tree, decompile_native (IDA or Ghidra; server_status says which).
        Edit in memory, dryRun=true first: rename_symbol, stub_method, patch_method_csharp, patch_method_il, simplify_methods (folds string decoders); native rename_native, patch_bytes, patch_asm. Review list_edits / diff_edits, undo_edit; save_assembly / save_native write a new file.
        New build: load both, then update_to_new_build (dryRun) or compare_assemblies / compare_native_images.
        Rules: an error reads "Error (<code>)" with a Next: line; follow it. limit_exceeded returns an id: read_result pages it. Long text: pass the footer's offset=N. Lists also return structured items/offset/total. Symbols: Ns.Type::Method(int), short names, or tokens (0x06000123).
        More: the guide prompt or netdecomp://guide/{topic} (dotnet, native, il2cpp, containers, edits, builds, dumps, errors); server_status for version, engines, limits, toolsets and a stale-server check.
        """;

    /// <summary>Topic name to text, in the order they are listed.</summary>
    public static readonly IReadOnlyDictionary<string, string> Topics = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["dotnet"] = """
            .NET assemblies.
            Load: load_assembly takes a file or a whole folder (an application folder, a Unity *_Data/Managed folder, an Il2CppDumper
            DummyDll folder). Load related assemblies too: cross-references and inherited members only see what is loaded or resolvable;
            add_search_directory adds a folder for reference resolution. Method bodies are indexed in the background after loading; files
            that change on disk are reloaded automatically (notices appear as "[workspace] ..." lines at the top of a tool result).
            reload_assembly re-reads a file, unload_assembly drops it (both discard unsaved edits); list_assemblies lists what is loaded.
            Discover: search_symbols, search_strings, search_constants, search_il, list_namespaces, list_types, get_type_info (cheap
            outline), get_assembly_info, resolve_symbol (what a name resolves to), get_attributes, decompile_assembly_attributes.
            Read: decompile_member (one method) is faster and smaller than decompile_type; get_il for raw IL.
            Navigate: find_references (who uses X, incl. calls through base/interface methods), find_callees, get_call_tree (multi-level
            callers/callees), find_call_paths (how execution reaches a method), find_overrides, get_type_hierarchy.
            P/Invokes: find_callees / get_call_tree follow them into loaded native code ('native: kernel32.dll!CreateFileW -> ...'); the
            .NET call tools take native exports as symbols ('kernel32.dll!CreateFileW', 'native:<image>!<name|#ord|addr>').
            verify_native_imports checks [DllImport]s against the real DLL exports (verified, contradicted, unresolved, dynamic_only,
            not_checked, each with a reason).
            Resources: list_resources, get_resource (managed and Win32 resources; savePath writes one to a file).
            ReadyToRun: get_r2r_code shows a method's precompiled native code (calls named as managed methods); find_r2r_method maps a
            native address back to its method. Mixed-mode C++/CLI assemblies load as .NET plus a native view.
            Export: export_project writes a buildable C# project into an empty directory.
            Malformed metadata is named with stream / table / row / token / file offset in get_assembly_info.
            """,
        ["il2cpp"] = """
            Il2Cpp games.
            No external dumper is needed: load_assembly the game folder or its global-metadata.dat (GameAssembly.dll beside it; a memory
            dump of it works too), or a mobile build: an .apk/.xapk/.aab (libil2cpp.so; slice= picks the ABI), an .ipa or .app (UnityFramework),
            macOS .app or Linux GameAssembly.so. The built-in reader (metadata v24-39) makes dummy assemblies plus the script and literal data, cached
            per user. Unreadable metadata is an error with a reason; items it could not read are listed by reason in the load report.
            Dummy DLLs have empty bodies: get_il2cpp_info (RVAs, field offsets; slot=N for the method implementing a vtable slot),
            find_method_by_address (native address -> method), export_il2cpp_symbols (IDA/Ghidra scripts + C struct header).
            With Il2CppDumper's script.json next to a DummyDll folder, functions are bounded by the next function start, generic
            instantiations are named both ways (get_il2cpp_info 'List`1<int>::Add'), and type metadata / MethodInfo slots resolve.
            With stringliteral.json and GameAssembly.dll too, search_strings finds the literals and the methods whose native code loads them.
            generate_cpp_binding emits C++ binding code for a Mono or Il2Cpp type (style mono, il2cpp or hostapi).
            Native view: load the dummy DLLs and GameAssembly.dll, then apply_il2cpp_names (C# names in every native tool and in IDA).
            Unity: unity_overview (folder or exe) reports engine version, Mono or Il2Cpp, whether the metadata is readable or encrypted,
            markers and the next calls; nextSteps dump_from_memory means the metadata or Assembly-CSharp.dll is encrypted on disk.
            """,
        ["containers"] = """
            Files, containers and wrapped apps (nothing is executed).
            summarize_file reports signature, markers, container wrapping, features, typed strings and entry points of a file in one call;
            survey_features, extract_strings and extract_embedded give the details.
            An app wrapped in a container (single-file .exe, Costura, .nupkg, Xamarin/MAUI .apk): list_assemblies with path shows the
            assemblies inside, search_container finds types/members in them by name, and unpack_container extracts and loads them.
            list_assemblies and unpack_container flag ReadyToRun and merged (ILMerge/ILRepack) assemblies.
            Unity builds: unity_overview first.
            Android packages (.apk, .aab, split sets), read natively: get_android_manifest (components, exported state, permissions, deep links),
            list_android_resources and get_android_resource (decoded XML, @type/name values). DEX code: list_dex_classes, get_dex_class (exact
            method ids), disassemble_dex (smali of one method or class), decompile_java
            (Java through JADX when NDM_JAVA_DECOMPILER is set), search_dex (strings, types, members, constants, opcodes), find_dex_references (callers, field readers / writers, callees). Xamarin / MAUI: map_java_dotnet links a Java wrapper
            class or method to its .NET type or method (then decompile_member) and back.
            Devices through adb: list_android_devices, get_android_device_info, list_android_packages, get_android_package_info, read_android_log,
            pull_android_package (then the tools above on the APKs), pull_android_file; install_android_package and uninstall_android_package
            only with --allow-device-changes.
            """,
        ["edits"] = """
            Editing and saving (in memory until saved; dryRun=true previews).
            .NET: rename_symbol, rename_namespace, stub_method (always return X), patch_method_csharp (C# body; lambdas, async, LINQ),
            add_members_csharp, add_types_csharp, patch_method_il (prepend hooks, IL that C# cannot express).
            simplify_methods cleans transformed code. fold: calls that compute a string from constant inputs (string decoders; char,
            array, StringBuilder, Encoding and Base64 helpers) run in a safe IL interpreter and become the literal; calls outside the
            safe subset (I/O, reflection, exceptions, instance objects, native code, mutable statics) are kept and reported. cfg: constant
            branches and switches fold (constant propagation through locals, readonly statics and calls with constant arguments), dead
            stores, empty try/finally, dead handlers and unreachable code go, and flattened control flow becomes sequential code; a
            dispatcher whose state differs between runs is kept (flattened-shape). inline: forwarders and static delegate fields (call
            proxies) call their real target when the field's initializer always sets the same one (else delegate-target). Every body is
            stack-verified or left unchanged, with a reason code (docs/simplify.md). decompile_member simplified=true previews it.
            Review: list_edits, diff_edits; undo_edit, revert_edits. Carry edits: export_edits writes a script, apply_edits replays it
            (tied to its build: another build needs targetBuild=other; dryRun=true first). Unsaved edits and patches are journaled; a
            file whose last session ended without saving gets a [workspace] notice naming the journal to replay.
            save_assembly writes a new file (never overwrites the original without overwrite=true; keeps a .bak; untouched parts are
            written byte-for-byte, anything that cannot be is listed; strict=true refuses such a save).
            Native: rename_native and comment_native (kept per file hash), patch_bytes / patch_asm (relocation-correct under ASLR; a
            patch larger than its site: extend=true moves it into a code cave or a new section; unsafe sites are refused with a reason),
            list_native_edits, undo_native_edit, save_native to a new file (checksum recomputed, an invalidated signature reported).
            export_native_annotations writes IDA / Ghidra scripts; export_native_patches writes IDAPython, IDA .dif, IPS or JSON.
            Engine edits (IDA or Ghidra): set_native_type (prototypes), set_native_local (decompiler locals), get_native_frame and
            set_native_stack_var (stack frames), declare_native_types and list_native_types (C declarations kept per image),
            define_native (code, functions, data items, undefined bytes), set_native_operand (operand display: number base,
            offset, stack variable, enum member, struct offset);
            ida_python runs IDAPython in the image's IDA worker, off unless --ida-scripting; export_engine_database writes the IDA
            database as an .i64 for the GUI.
            Notes: record_note anchors a finding, question, hypothesis or todo to '<image>@<address>', '<assembly>:<symbol>', a file or
            a dump; notes persist per user by file SHA-256 / module MVID. update_note changes one in part (expectedRevision; a conflict
            returns the current note); list_notes filters by status, kind, anchor, tag and text. decompile_member and decompile_native
            start with a "// notes: N open" line when the target has open notes.
            Sessions: save_session writes the loaded files (path, SHA-256), edits, patches, names, comments and notes to one JSON file;
            load_session restores it (dryRun first), finding moved files by SHA-256 under searchRoots; targetBuild=other carries the
            work to the build now at the recorded path.
            """,
        ["builds"] = """
            New builds: load both (the second gets an id like app.dll#2).
            .NET: compare_assemblies, then find_counterpart carries renamed types/members and changed offsets forward; export_edits +
            apply_edits re-applies a patch set to the new build.
            Native: update_to_new_build (dryRun=true first) carries names, comments, PDB / Il2Cpp layers, patches, code patterns, notes and
            the Il2Cpp method mapping in one call, with a reason code for everything that did not carry. The single steps:
            compare_native_images, diff_function (what changed in one function: aligned instructions, or pseudocode with view=pseudocode),
            map_address_between_builds, migrate_native_names, migrate_native_patches, make_code_pattern
            (anchor=xrefs: a signature at every referencing instruction) / search_code_pattern.
            """,
        ["native"] = """
            Native files (PE .exe/.dll/.sys without .NET metadata, ELF, Mach-O; x86, x64 and ARM64): load_assembly the file, or pass its path as image.
            Overview: get_pe_info (headers, mitigations, PDB, version, rich header, signature, anything malformed; capability groups;
            code statistics once the index is built), list_imports
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
            trace_native_feature (strings, names, imports, exports and classes matching a text, to ranked functions and hubs), search_native_strings, search_bytes (?? wildcards), search_instructions (mnemonic / operand regexes, operand values), read_bytes (type= reads values), convert_number, resolve_address, list_cpp_classes (RTTI classes, bases,
            vftables), get_native_type (a type's layout from the PDB, RTTI, Il2Cpp or the engine by name, id or typed address; at=0x48 names a field;
            read=true adds the field values at an address), get_exception_info (MSVC try / catch, SEH scopes, funclets), find_virtual_calls (obj->vfunc() sites resolved
            through RTTI; crossCheck=true compares with IDA or Ghidra), decompile_native (C pseudocode through IDA or Ghidra when installed;
            functions=[...] decompiles several in one request, each with its own deadline).
            Addresses: hex VA or RVA, rva:/va:/off: prefixes, export names, module!import, sub_<rva>.
            Symbols: a matching local PDB is read with the code index; load_pdb loads one by path or downloads it (download=true);
            search_pdb_symbols lists its symbols. Names from load_pdb and apply_il2cpp_names are saved per file SHA-256 and reapplied
            when the same file loads again; list_native_edits shows the layers, clear=true on either tool removes one.
            NativeAOT images name themselves from their metadata when the code index builds (methods, vtable slots, MethodTables,
            frozen strings); get_nativeaot_info shows the version, recovery stages, types, methods and strings.
            Cross-image: load the DLLs an image imports (or load_assembly loadProviders=true) and the call tools follow imports,
            forwarders and thunks into them.
            Engines: list_functions, disassemble, search_instructions, get_cfg, find_xrefs and native_call_tree take engine=auto|ours|ida|ghidra. auto
            (default) uses an engine's analysis once it has finished in this session (IDA's before Ghidra's), else the built-in index,
            and never starts an engine; every result has an "Engine: ours|ida|ghidra (why)" line. ARM (Thumb) images work through IDA,
            else Ghidra (NDM_GHIDRA_DIR and a JDK). inspect_instruction takes auto|ours|ida|ghidra (auto: the built-in decoder for x86 / x64 / ARM64).
            Name priority: user > pdb > nativeaot > il2cpp > ida > ghidra > discovered; our names win in engine output. decompile_native pushes
            names, patches, Il2Cpp prototypes, RTTI and PDB types into the engine's database; --prewarm ida|ghidra|auto analyzes images
            as they load; get_engine_status shows each engine session of an image (opening stage, analysis complete or partial, language,
            database, worker). Code indexes are saved on disk by file SHA-256 (--index-cache off disables it).
            Editing and engine type edits: the edits topic. Build-to-build: the builds topic.
            """,
        ["dumps"] = """
            Crash dumps and live processes.
            open_minidump (user-mode .dmp: exception, faulting module+function and instruction, modules and whether the binaries exist
            locally, threads), dump_stack (x64 unwind data, x86 frame pointers; scanned frames marked heuristic), read_dump_memory.
            Load the crashed binaries first so frames get your names, PDB and Il2Cpp names; pass imageDirectories when they are not at
            their recorded paths. .NET dumps: the runtime's DAC (found locally: dacPath, the same runtime installed here, symbol stores;
            downloadDac=true fetches it, never under NDM_OFFLINE=1; always signature-checked) decodes the managed exception and its
            inner chain, and gives managed frames a token, IL offset and the loaded assembly of that build (load the app's assemblies
            first; decompile_member assembly=<id> member=<token>). Mono frames stay identified only. With heap memory in the dump:
            dump_heap (stats per type, or objects by type) and dump_object (fields, strings, arrays; the exception's address works).
            No dump, only text (Player.log, error.log, Report.wer, event text, an exception's ToString, a debugger stack):
            symbolize_stack_text names each frame in the loaded build; check buildCheck before trusting a name (mismatch: another build).
            A folder of dumps: bucket_minidumps groups them by signature; open the largest bucket's representative.
            inspect_process does the same for a running local process (Windows), read-only: modules, regions, threads and stacks. It
            opens only query and read handles, writes and suspends nothing, and closes every handle before returning. Pick the target
            by pid or name (a shared name is refused with the candidate pids).
            """,
        ["errors"] = """
            Errors, paging and limits.
            Errors start with "Error (<code>)" (not_found, ambiguous, invalid_argument, unsupported, not_loaded, limit_exceeded, timeout,
            provider_unavailable, ...) and usually a "Next:" line with the call that can succeed. After the text, errors repeat as JSON
            ("error (json): {code, retryable, message, next, partial, details}"); partial holds what was found before a time limit or
            cancellation. An argument name the tool does not declare is invalid_argument with the closest declared names.
            A result too large to send comes back as limit_exceeded with an id: read_result pages through it. Long text is paged:
            follow the footer's offset=N. List, search and info tools also return structured content (items, offset, total, truncated);
            to page on, pass offset = offset + the items received. Tools marked [Long-running ...] can take more than 10 s.
            Symbols: 'Ns.Type', 'Ns.Outer+Inner', 'Ns.Type::Method', 'Ns.Type::Method(int, string)', 'Ns.Type::.ctor', short names, or
            tokens like '0x06000123'. The assembly parameter is optional unless a name is ambiguous; errors list candidates.
            server_status: version and commit, program path, install kind, client, limits, engines, toolsets, and the tools or modes that
            cannot work here with the fix; expectedCatalogDigest detects a stale server (`NetDecompilerMcp doctor` checks too) and
            expectedExecutable a client that started another copy than the one it was registered with.
            Toolsets: every tool is registered by default. --toolsets (or NDM_TOOLSETS) narrows the catalog for small-context clients:
            all, core (without engine edits, dumps and live processes), or names such as core,dumps; tools of other families are not listed.
            Resources: netdecomp://assemblies, netdecomp://assembly/{id}/info, netdecomp://assembly/{id}/type/{Ns.Type},
            netdecomp://assembly/{id}/il/{symbol}, netdecomp://guide/{topic}.
            """,
    };

    /// <summary>The topic's text, or null for an unknown topic (case-insensitive).</summary>
    public static string? Topic(string? name) =>
        name is null ? null : Topics.FirstOrDefault(t => t.Key.Equals(name.Trim(), StringComparison.OrdinalIgnoreCase)).Value;

    public static string TopicList => string.Join(", ", Topics.Keys);
}
