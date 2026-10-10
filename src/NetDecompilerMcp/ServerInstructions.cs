namespace NetDecompilerMcp;

internal static class ServerInstructions
{
    public const string Text = """
        Headless .NET decompiler (ILSpy engine + dnlib + Roslyn) and native PE analyzer. No GUI, no dnSpy needed.

        Workflow:
        1. load_assembly with a file or a whole folder (e.g. an application folder, a Unity *_Data/Managed folder, or an Il2CppDumper DummyDll folder).
           Load related assemblies too: cross-references and inherited members only see what is loaded or resolvable.
           Method bodies are indexed in the background after loading; files that change on disk are reloaded automatically
           (notices appear as "[workspace] ..." lines at the top of a tool result).
           Il2Cpp games need no external dumper: load_assembly the game folder or its global-metadata.dat (GameAssembly.dll beside
           it; a memory dump of it works too). The built-in reader (metadata v24-31) makes dummy assemblies plus the script and
           literal data, cached per user, and the Il2Cpp tools work as with an Il2CppDumper DummyDll folder. Unreadable metadata is
           an error with a reason; items it could not read are listed by reason in the load report.
           An app that ships wrapped in a container (single-file .exe, Costura, .nupkg, Xamarin/MAUI .apk): list_assemblies with path shows the
           assemblies inside, search_container finds types/members in them by name, and unpack_container extracts and loads them.
           list_assemblies and unpack_container flag ReadyToRun and merged (ILMerge/ILRepack) assemblies; get_r2r_code shows a ReadyToRun
           method's precompiled native code (calls named as managed methods) and find_r2r_method maps a native address back to its method.
           summarize_file reports signature, markers, container wrapping, features, typed strings and entry points of a file in one call;
           survey_features, extract_strings and extract_embedded give the details. Nothing is executed.
           For a Unity game start with unity_overview (folder or exe): engine version, Mono or Il2Cpp, whether the Il2Cpp
           metadata is readable or encrypted, anti-cheat / obfuscator / packer markers and the next calls with their arguments;
           nextSteps dump_from_memory means the metadata or Assembly-CSharp.dll is encrypted on disk.
        2. Discover: search_symbols, search_strings, search_constants, search_il, list_namespaces, list_types, get_type_info (cheap outline).
        3. Read code: decompile_member (one method) is faster and smaller than decompile_type; get_il for raw IL.
        4. Navigate: find_references (who uses X, incl. calls through base/interface methods), find_callees, get_call_tree
           (multi-level callers/callees), find_call_paths (how execution reaches a method), find_overrides, get_type_hierarchy, get_attributes.
        5. New versions: load both builds (the second gets an id like Name#2), then compare_assemblies and find_counterpart to carry
           renamed types/members and changed offsets forward; export_edits + apply_edits re-applies a patch set to the new build
           (scripts are tied to their build: apply_edits refuses another build unless targetBuild=other; dryRun=true first).
        6. Il2Cpp dummy DLLs have empty bodies: get_il2cpp_info (RVAs, field offsets; slot=N for the method implementing a vtable slot),
           find_method_by_address (native address -> method), export_il2cpp_symbols (IDA/Ghidra scripts + C struct header).
           With Il2CppDumper's script.json next to the DummyDll folder, functions are bounded by the next function start, generic
           instantiations are named both ways (get_il2cpp_info 'List`1<int>::Add'; overloads told apart by the C signature, or
           reported as ambiguous), and type metadata / MethodInfo slots resolve.
           With stringliteral.json and GameAssembly.dll too, search_strings finds the game's literals and the methods whose native code loads them. generate_cpp_binding emits C++ binding code for a Mono type
           (standard Mono embedding API, or a host function table detected in projectDir with the include paths computed).
        7. Patch in memory (dryRun=true previews): rename_symbol, rename_namespace, stub_method, patch_method_csharp (C# body; lambdas,
           async, LINQ supported), add_members_csharp, add_types_csharp, patch_method_il, simplify_methods (transformed code: folds
           string-decoder calls to literals, removes dead branches, normalizes switch dispatchers, inlines forwarders;
           decompile_member simplified=true previews it).
           Review with list_edits / diff_edits, undo with undo_edit / revert_edits, then save_assembly (never overwrites the original
           without overwrite=true; keeps a .bak; what no edit touched is written byte-for-byte, and anything that cannot be is
           listed with a reason; strict=true refuses such a save instead).

        8. Native PE files (.exe/.dll/.sys without .NET metadata; x86 and x64): load_assembly with the file path (or pass the path as image
           to any native tool). get_pe_info (headers, mitigations, PDB, version, rich header, signature, anything malformed), list_imports,
           list_exports (MSVC names demangled), list_resources / get_resource (Win32 resources), list_functions, disassemble, get_cfg,
           find_xrefs (incl. every call site of an import: 'kernel32!CreateFileW'), native_call_tree, search_native_strings, search_bytes
           (?? wildcards), read_bytes, resolve_address, list_cpp_classes (RTTI classes, bases, vftables), get_exception_info (MSVC try / catch
           types, SEH scopes, funclets and their parent function), decompile_native (C pseudocode
           through IDA when installed; server_status says whether it is). Addresses: hex VA or RVA, rva:/va:/off: prefixes, export names,
           module!import, sub_<rva>. The code index is built in the background after loading; a matching local PDB is read then and
           names functions and data (load_pdb loads one by path, or downloads it with download=true; search_pdb_symbols lists its symbols
           with signatures). verify_native_imports checks a .NET
           assembly's [DllImport]s against the real DLL exports: verified, contradicted (DLL found, export missing or the binding
           disagrees), unresolved, dynamic_only (the assembly loads the library itself or sets a DllImportResolver) or not_checked,
           each with a reason; a missing static import does not rule out run-time loading. Malformed metadata is named with
           stream / table / row / token / file offset there and in get_assembly_info.
           Calls: disassemble and find_xrefs show recovered call arguments (CreateFileW(L"a.ini", GENERIC_READ, ...)); get_call_arguments
           gives them as data. Late-bound imports (GetProcAddress) appear in get_pe_info, list_imports includeDynamic=true, find_xrefs
           ('module!name') and native_call_tree as [dynamic]. survey_features also takes a native image.
           Cross-image: load the DLLs an image imports (by path, or load_assembly loadProviders=true) and native_call_tree, find_xrefs,
           disassemble and resolve_address follow imports, forwarders and thunks into them; list_imports bind=true shows each binding.
           find_callees / get_call_tree follow P/Invokes into native code ('native: kernel32.dll!CreateFileW -> KernelBase.dll!CreateFileW
           at VA [image]'); the .NET call tools take native exports as symbols ('kernel32.dll!CreateFileW', 'native:<image>!<name|#ord|addr>').
           Mixed-mode C++/CLI assemblies load as .NET plus a native view (id = file name). ReadyToRun: get_r2r_code, find_r2r_method.
           Il2Cpp games: load the dummy DLLs and GameAssembly.dll, then apply_il2cpp_names (C# names in every native tool and in IDA).
           Edits: rename_native / comment_native (kept per file hash), patch_bytes / patch_asm (dryRun first), list_native_edits,
           undo_native_edit, save_native to a new file; export_native_annotations writes IDA / Ghidra scripts. Patches stay correct
           under ASLR: relocation entries the new bytes no longer use are neutralized and new absolute addresses get an entry; when
           the page has no free slot the error is no_relocation_slot (write it RIP-relative, or force=true for a preferred-base-only patch).
           A patch larger than its site: patch_asm / patch_bytes extend=true put a relocation stub in a code cave (the site jumps to
           it; it runs the new code, plus the displaced instructions with stubMode=before|after, and returns after the site); unsafe
           sites are refused with a reason code (branch_target_in_site, unwind_data, no_space, ...). dryRun shows the stub first.
           New builds: load both (the second gets an id like game.dll#2); compare_native_images matches functions (unique-only, ambiguous
           ones listed), map_address_between_builds carries an address over, migrate_native_names (dryRun first) copies your names;
           make_code_pattern / search_code_pattern give byte patterns that survive rebuilds. export_native_patches writes your patches
           as an IDAPython script, IDA .dif, IPS or JSON; migrate_native_patches (dryRun first) carries them to a new build, reapplying
           each only where the new build's original bytes still match and refusing the rest with a reason.
           IDA: ARM64 / ARM images get list_functions, disassemble, get_cfg, find_xrefs and native_call_tree through IDA when it is
           installed (marked "(via IDA)"). Name priority: user > pdb > il2cpp > ida (library functions IDA recognized, flagged
           `library`) > discovered. decompile_native applies patches and undo inside the IDA database (no re-analysis) and pushes
           Il2Cpp prototypes and MSVC RTTI class types (pseudocode shows Class *this, this->__vftable->...). With a PDB (beside the
           image or via load_pdb) it first loads the PDB's structs, enums, typedefs and prototypes into the database, once per PDB,
           through IDA's PDB loader or else the server's own PDB type reader; the first output line names the type source. --ida-prewarm or
           NDM_IDA_PREWARM=1 analyzes images in IDA in the background as they load (server_status shows the progress).
        9. Crash dumps (user-mode .dmp): open_minidump (exception, faulting module+function and instruction, modules and whether the
           binaries exist locally, threads), dump_stack (x64 unwind data, x86 frame pointers; scanned frames marked heuristic),
           read_dump_memory. Load the crashed binaries first so frames get your names, PDB and Il2Cpp names; pass imageDirectories
           when they are not at their recorded paths. Managed frames are only identified (use SOS for them).
           inspect_process does the same for a running local process (Windows), read-only: modules, regions, threads and stacks.
           It opens only query and read handles, writes and suspends nothing, and closes every handle before returning. Pick the
           target by pid or name (a shared name is refused with the candidate pids); running threads' registers are a snapshot.
           Native code indexes are saved on disk by file SHA-256: reopening the same bytes loads the index in seconds
           (server_status shows the cache; --index-cache off disables it).

        Errors start with "Error (<code>)" (not_found, ambiguous, invalid_argument, unsupported, not_loaded, limit_exceeded, timeout,
        provider_unavailable, ...) and usually a "Next:" line with the call that can succeed. A result too large to send comes back as
        limit_exceeded with an id: read_result pages through it. server_status reports version, limits and available engines.
        After the text, errors repeat as JSON ("error (json): {code, retryable, message, next, partial, details}"); partial holds what
        was found before a time limit or cancellation. An argument name the tool does not declare is invalid_argument with the
        closest declared names (details.suggestions); it is never ignored. List, search and info tools also return structured content (items, offset,
        total, truncated) beside the readable text; to page on, pass offset = offset + the items received. Tools marked
        [Long-running ...] can take more than 10 s (server_status lists them). Pass expectedCatalogDigest to server_status to detect
        a stale server; `NetDecompilerMcp doctor` compares the installed server with this build.

        Symbols: 'Ns.Type', 'Ns.Outer+Inner', 'Ns.Type::Method', 'Ns.Type::Method(int, string)', 'Ns.Type::.ctor', short names,
        or tokens like '0x06000123'. The assembly parameter is optional unless a name is ambiguous; errors list candidates.
        Long output is paged: follow the footer's offset=N.
        Resources: netdecomp://assemblies, netdecomp://assembly/{id}/info, netdecomp://assembly/{id}/type/{Ns.Type}, netdecomp://assembly/{id}/il/{symbol}.
        """;
}
