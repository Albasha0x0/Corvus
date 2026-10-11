# Guide: containers

<!-- Generated from src/NetDecompilerMcp/Mcp/Guide.cs; run the tests with NDM_UPDATE_DOCS=1 to update. -->

Files, containers and wrapped apps (nothing is executed).
summarize_file reports signature, markers, container wrapping, features, typed strings and entry points of a file in one call;
survey_features, extract_strings and extract_embedded give the details.
An app wrapped in a container (single-file .exe, Costura, .nupkg, Xamarin/MAUI .apk): list_assemblies with path shows the
assemblies inside, search_container finds types/members in them by name, and unpack_container extracts and loads them.
list_assemblies and unpack_container flag ReadyToRun and merged (ILMerge/ILRepack) assemblies.
Unity builds: unity_overview first.
