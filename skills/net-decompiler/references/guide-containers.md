# Guide: containers

<!-- Generated from src/NetDecompilerMcp/Mcp/Guide.cs; run the tests with NDM_UPDATE_DOCS=1 to update. -->

Files, containers and wrapped apps (nothing is executed).
summarize_file reports signature, markers, container wrapping, features, typed strings and entry points of a file in one call;
survey_features, extract_strings and extract_embedded give the details.
An app wrapped in a container (single-file .exe, Costura, .nupkg, Xamarin/MAUI .apk): list_assemblies with path shows the
assemblies inside, search_container finds types/members in them by name, and unpack_container extracts and loads them.
list_assemblies and unpack_container flag ReadyToRun and merged (ILMerge/ILRepack) assemblies.
Unity builds: unity_overview first.
Android packages (.apk, .aab, split sets), read natively: get_android_manifest (components, exported state, permissions, deep links),
list_android_resources and get_android_resource (decoded XML, @type/name values). DEX code: list_dex_classes, get_dex_class (exact
method ids), disassemble_dex (smali of one method or class), search_dex (strings, types, members, constants, opcodes), find_dex_references (callers, field readers / writers, callees).
