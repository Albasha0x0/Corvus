# Contributing

## Build and test

Requires the .NET 10 SDK. Warnings are errors and the recommended analyzers run on every build.

```powershell
dotnet build
dotnet test                         # quick set: everything not marked [Trait("Speed", "Slow")]; keep it near 30 s
$env:CORVUS_ALL_TESTS=1; dotnet test   # everything (or dotnet test -p:CORVUS_ALL_TESTS=1)
```

Run the quick set while iterating and the full set before a pull request. Tests that need real-world data (application
folders, Il2Cpp games, external tools) read their locations from `CORVUS_*` environment variables and are skipped when
those are unset; the README's "Build, test, publish" section lists them. Real libraries in tests come from
`<PackageDownload>` items in the test project, never from paths on one machine. A new external tool used by tests is
found through an environment variable with a neutral name.

## Adding or changing a tool

A tool is a method with `[McpServerTool]` in `src/Corvus/Tools`. Its `[Description]` texts become the MCP
tool description: keep them accurate, tight and under 2,048 characters (clients cut longer ones). Then:

1. `src/Corvus/Mcp/ToolEffects.cs`: add the tool's effects (read-only, destructive, idempotent, open-world,
   long-running). Annotations come only from this table.
2. `src/Corvus/Mcp/ParameterDomains.cs`: add the value set of every closed string parameter; an `engine`
   parameter always needs one.
3. `src/Corvus/Core/Toolsets.cs`: put the tool in exactly one family.
4. `src/Corvus/Mcp/Guide.cs`: name the tool in the core or in a topic, so the guide covers it.
5. `README.md`: add it to a tool table and update the tool count.
6. Tests: the tool's own tests, and a case in `McpProtocolTests.ToolCases` so it is called over stdio.

The guard tests (catalog audit and size ceiling, layering, README sync, parameter domains, contract sweep, guide
coverage, toolsets) fail when one of these steps is missing. The catalog size ceiling in `CatalogAuditTests` is
raised only deliberately, with the new figure recorded there.

`docs/simplify.md`, `docs/errors.md`, `docs/saving.md`, `docs/tools.md`, the client table of `docs/installation.md`
and `skills/net-decompiler` are generated from the code (`SimplifyManifest`, the error codes, `SaveManifest`, the tool
catalog, the client catalog, the guide) and checked by tests: after changing their sources, run the tests once with
`CORVUS_UPDATE_DOCS=1` and commit the regenerated files. The testing policy is `docs/testing.md`.

## Style

- Plain compiler and engineering vocabulary in identifiers, comments, commit messages and docs.
- Comments only where the code cannot speak for itself: the reason for a decision, an invariant, a workaround and its
  cause, units and limits. One line preferred; say a thing once.
- No machine-specific paths and no product or game names in the tool itself.

## Commits and pull requests

- One commit per logical change, with its tests; the quick set is green at every commit.
- Commit messages are short and mechanical: `area: what changed` (e.g. `find_xrefs: struct member targets through IDA`).
- A pull request describes what changed and how it was tested, and keeps the README and docs in sync.

## Releasing

Write the version's section at the top of `docs/release-notes.md` ("Changes in behaviour" first), then run
`./release.ps1 -Version X.Y.Z` on a clean `main`: it bumps the version, regenerates the generated docs, runs the full
suite, commits and tags. `-Push` also pushes, waits for the release workflow, checks that every archive and
`SHA256SUMS` is attached and matches, sets the release body from the notes and prints the manual checklist;
`-VerifyOnly` does the checks for a release already pushed.

## Reporting problems

Bugs and feature requests: the issue forms. Security problems: privately, as described in [SECURITY.md](SECURITY.md).
