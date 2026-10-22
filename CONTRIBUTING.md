# Contributing

## Build and test

Requires the .NET 10 SDK, feature band 10.0.4xx (pinned in `global.json`, so the test fixtures and their recorded samples build the same everywhere). Warnings are errors and the recommended analyzers run on every build.

```powershell
dotnet build
dotnet test                         # quick set: everything not marked [Trait("Speed", "Slow")]; keep it near 30 s
$env:CORVUS_ALL_TESTS=1; dotnet test   # everything (or dotnet test -p:CORVUS_ALL_TESTS=1)
./test.ps1                           # before each commit and push: the quick tests of the families you changed
./test.ps1 -All                      # the whole quick set
./test.ps1 -Full -Background         # the full set on HEAD, in a worktree of its own (-Status shows it); the pre-push
                                     #   hook starts it on every push to main: git config core.hooksPath .githooks
./test.ps1 -Affected                 # the slow tests of the families you changed, in the foreground
./test.ps1 -Full -IfChanged          # everything, skipped when it already passed on this exact tree
./test.ps1 -Stamp                    # records the last full run's passes when its recording step failed (same tree only)
```

Run the quick set while iterating and the full set before a pull request. Tests that need real-world data (application
folders, Il2Cpp games, external tools) read their locations from `CORVUS_*` environment variables and are skipped when
those are unset; the [test data variables](docs/testing.md#test-data-variables) table lists them. Real libraries in tests come from
`<PackageDownload>` items in the test project, never from paths on one machine. A new external tool used by tests is
found through an environment variable with a neutral name.

## Adding or changing a tool

A tool is a method with `[McpServerTool]` in `src/Corvus/Tools`. Its `[Description]` texts become the MCP
tool description: keep them accurate, tight and under 2,048 characters (clients cut longer ones). Then:

1. `src/Corvus/Mcp/Contract` (one file per family, e.g. `src/Corvus/Mcp/Contract/Native.cs`): add the tool's
   effects (read-only, destructive, idempotent, open-world, long-running), from which its annotations come; the
   value set of every closed string parameter (an `engine` parameter always needs one); and its contract row (output
   and latency class, lean and core profiles, dryRun policy, list sort key).
2. `tests/Corvus.Tests/ContractSweepData` (same layout): list every parameter naming a file the tool writes.
3. `src/Corvus/Core/Toolsets.cs`: put the tool in exactly one family.
4. `src/Corvus/Mcp/Guide.cs`: name the tool in the core or in a topic, so the guide covers it.
5. `README.md`: add it to a tool table and update the tool count.
6. Tests: the tool's own tests, and a case in `McpProtocolTests.ToolCases` so it is called over stdio.

The guard tests (catalog audit and size ceiling, layering, README sync, parameter domains, contract sweep, guide
coverage, toolsets) fail when one of these steps is missing. The catalog size ceiling in `CatalogAuditTests` is
raised only deliberately, with the new figure recorded there.

`docs/simplify.md`, `docs/errors.md`, `docs/saving.md`, `docs/tools.md`, the client table of `docs/installation.md`
and `skills/corvus` are generated from the code (`SimplifyManifest`, the error codes, `SaveManifest`, the tool
catalog, the client catalog, the guide) and checked by tests: after changing their sources, run the tests once with
`CORVUS_UPDATE_DOCS=1` and commit the regenerated files. The testing policy is `docs/testing.md`.

## Style

- Plain compiler and engineering vocabulary in identifiers, comments, commit messages and docs.
- Comments only where the code cannot speak for itself: the reason for a decision, an invariant, a workaround and its
  cause, units and limits. One line preferred; say a thing once.
- No machine-specific paths and no product or game names in the tool itself.

## Commits and pull requests

- One commit per logical change, with its tests; the quick set is green at every commit.
- Commit messages: a subject `type(scope): imperative summary` of at most 72 characters, lower case after the colon
  and no final period (e.g. `fix(live): keep deferred stop points in code an entry point writes`); types `feat`,
  `fix`, `perf`, `test`, `docs`, `refactor`, `ci`, `chore`; scopes `live`, `dumps`, `il2cpp`, `engines`, `native`,
  `dotnet`, `edits`, `containers`, `mobile`, `web`, `catalog`, `session`, `tests`, `release`. A body wrapped at 72
  columns says what happened before, why it was wrong and what the code does now, then a `Verified:` paragraph naming
  the tests run; issue references go in `Fixes #N` / `Refs #N` / `Upstream:` trailers. The commit-msg hook
  (`.githooks/commit-msg`, enabled with the pre-push hook) rejects a subject or line width that does not follow this.
- A pull request describes what changed and how it was tested, and keeps the README and docs in sync.

## Releasing

Write the version's section at the top of `docs/release-notes.md` (Highlights, then Breaking changes, Changes and
Fixes), then run `./release.ps1 -Version X.Y.Z` on a clean `main`: it bumps the version, regenerates the generated docs,
runs the full suite, commits and tags. `-Push` also pushes, waits for the release workflow, checks that every asset (archives, MCP
bundles, the `CorvusRE` NuGet tool package) and `SHA256SUMS` is attached and matches, sets the release body from the
notes and prints the manual checklist, which also lists the channels that wait for a public repository (nuget.org,
MCP Registry, winget, Scoop, Homebrew, plugin marketplace); `-VerifyOnly` does the checks for a release already
pushed. The workflow makes the bundles with `./release.ps1 -Bundle`.

## Reporting problems

Bugs and feature requests: the issue forms. Security problems: privately, as described in [SECURITY.md](SECURITY.md).

## Layout

```
src/Corvus/
  Core/      workspace (loading, locking, reference resolution), symbol resolver, formatting, paging
  Services/  decompiler, search, references, fast IL reader, call graph, assembly comparer, Il2Cpp (+ IDA/Ghidra/C
             export, Il2CppDumper script.json / stringliteral.json reader, string literals and native code references, metadata ↔ native navigation), C++ binding generator, resources, assembly report, edits and edit history, IL assembler,
             C# patcher (module merger, access fixer), background indexing, file watching
    Analysis/  bounds-checked PE parsing, byte-level helpers (identification, bounded decompression, carving, safe
               output paths), container formats, unpacking
  Tools/     thin MCP tool classes: resolve input, call a service, format text
  Mcp/       resources, prompts, completion
tests/
  TestFixture/            sample assembly covering every feature (inheritance, async, resources, stand-in Il2Cpp attributes)
  TestFixture.Consumer/   second assembly that uses the first (cross-assembly and virtual-dispatch references)
  Corvus.Tests/ service, patching, concurrency, protocol and real-assembly tests
samples/Notes/            v1 and v2 of the guides' sample program (docs/guides, docs/showcase), built by the test project
docs/                     user and contributor documentation; index in docs/README.md
```

To add a tool, put the logic in a service, then add a `[McpServerTool]` method in `Tools/` that wraps it in
`ToolSupport.Read`, `Write` or `Edit` and returns text. Throw `ToolError` for anything the agent should read and
act on. `McpProtocolTests.ToolCases` must get an entry, or the coverage test fails.
