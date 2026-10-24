# Contributing

## Build and test

Requires the .NET 10 SDK, feature band 10.0.4xx (pinned in `global.json` so fixtures and recorded samples build the
same everywhere). Warnings are errors; the recommended analyzers run on every build.

```powershell
dotnet build
dotnet test                            # quick set: everything not marked [Trait("Speed", "Slow")]; keep it near 30 s
$env:CORVUS_ALL_TESTS=1; dotnet test   # everything (or dotnet test -p:CORVUS_ALL_TESTS=1)
./test.ps1                             # before each commit and push: quick tests of the families you changed
./test.ps1 -All                        # the whole quick set
./test.ps1 -Affected                   # quick set plus the slow tests of the families you changed, in the foreground
./test.ps1 -Full -Background           # full set on HEAD in a worktree of its own (-Status shows it); the pre-push
                                       #   hook starts it on every push to main: git config core.hooksPath .githooks
./test.ps1 -Full -IfChanged            # everything, skipped when it already passed on this exact tree
./test.ps1 -Stamp                      # records the last full run's passes when its recording step failed (same tree only)
```

Run the quick set while iterating and the full set before a pull request. Tests that need real-world data
(application folders, Il2Cpp builds, external tools) read their locations from `CORVUS_*` variables and skip when they
are unset; see the [test data variables](docs/testing.md#test-data-variables). Real libraries come from
`<PackageDownload>` items in the test project, never from paths on one machine. A new external tool is found through a
variable with a neutral name. The full testing policy is `docs/testing.md`.

## Adding or changing a tool

A tool is a `[McpServerTool]` method in `src/Corvus/Tools` that wraps a service call in `ToolSupport.Read`, `Write` or
`Edit` and returns text; put the logic in a service. Throw `ToolError` for anything the agent should read and act on.
Its `[Description]` texts become the MCP tool description: keep them accurate and tight (a tool description is at most
600 bytes, a parameter description 160; `CatalogAuditTests`). Then:

1. `src/Corvus/Mcp/Contract` (one file per family, e.g. `src/Corvus/Mcp/Contract/Native.cs`): the tool's effects
   (read-only, destructive, idempotent, open-world, long-running), from which its annotations come; the value set of
   every closed string parameter (an `engine` parameter always needs one); its contract row (output and latency class,
   lean and core profiles, dryRun policy, list sort key).
2. `tests/Corvus.Tests/ContractSweepData` (same layout): every parameter naming a file the tool writes.
3. `src/Corvus/Core/Toolsets.cs`: the tool in exactly one family.
4. `src/Corvus/Mcp/Guide.cs`: the tool named in the core or a topic.
5. `docs/features.md`: a tool table row; update the tool count there and in `README.md`.
6. Tests: the tool's own, and a case in `McpProtocolTests.ToolCases` so it is called over stdio.

The guard tests (catalog audit and size ceiling, layering, README sync, parameter domains, contract sweep, guide
coverage, toolsets) fail when a step is missing. The catalog size ceiling in `CatalogAuditTests` is raised only
deliberately, with the new figure recorded there.

`docs/simplify.md`, `docs/errors.md`, `docs/limitations.md`, `docs/migration-reasons.md`, `docs/saving.md`,
`docs/tools.md`, `docs/schemas`, the client table of `docs/installation.md` and `skills/corvus` are generated from the
code (`SimplifyManifest`, the error codes, `SaveManifest`, the tool catalog, the client catalog, the guide, among
others) and checked by tests: after changing their sources, run the tests once with `CORVUS_UPDATE_DOCS=1` and commit
the regenerated files.

## Style

- Plain compiler and engineering vocabulary in identifiers, comments, commit messages and docs.
- Comments only where the code cannot speak for itself: the reason for a decision, an invariant, a workaround and its
  cause, units and limits. One line preferred; say a thing once.
- No machine-specific paths and no product names in the tool itself.

## Commits and pull requests

- One commit per logical change, with its tests; the quick set is green at every commit.
- Subject: `type(scope): imperative summary`, at most 72 characters, lower case after the colon, no final period
  (e.g. `fix(live): keep deferred stop points in code an entry point writes`).
  - Types: `feat`, `fix`, `perf`, `test`, `docs`, `refactor`, `ci`, `chore`.
  - Scopes: `live`, `dumps`, `il2cpp`, `engines`, `native`, `dotnet`, `edits`, `containers`, `mobile`, `web`,
    `catalog`, `session`, `tests`, `release`.
- Body wrapped at 72 columns: what happened before, why it was wrong, what the code does now; then a `Verified:`
  paragraph naming the tests run. Issue references go in `Fixes #N` / `Refs #N` / `Upstream:` trailers.
- The commit-msg hook (`.githooks/commit-msg`, enabled with the pre-push hook) rejects a subject or line width that
  does not follow this.
- A pull request describes what changed and how it was tested, and keeps the README and docs in sync.

## Releasing

1. Write the version's section at the top of `docs/release-notes.md` (Highlights, then Breaking changes, Changes and
   Fixes).
2. On a clean `main`, run `./release.ps1 -Version X.Y.Z`. It requires a recorded full pass on this commit or an
   ancestor at most 50 commits back (`-MaxBehind`) with no later background failure (`-SkipTests` overrides), bumps
   the version, regenerates the generated docs with a quick run, commits and tags.
3. `-Push` also pushes, waits for the release workflow, checks that every asset (archives, MCP bundles, the
   `CorvusRE` NuGet tool package) and `SHA256SUMS` is attached and matches, sets the release body from the notes,
   checks the update from the previous release in WSL, and prints the manual checklist (install checks, nuget.org and
   MCP Registry listings, winget, Scoop, Homebrew, plugin marketplace). `-VerifyOnly` runs the checks for a release
   already pushed. The workflow makes the bundles with `./release.ps1 -Bundle`.

## Reporting problems

Bugs and feature requests: the issue forms. Security problems: privately, as described in [SECURITY.md](SECURITY.md).

## Layout

```
src/Corvus/
  Core/      workspace (loading, locking, reference resolution), symbol resolver, formatting, paging, file formats
  Services/  one folder per tool family (decompiler, search, references, call graph, edits, Il2Cpp, simplify, ...);
             Analysis/ holds bounds-checked PE parsing, byte-level helpers, container formats and unpacking
  Native/    native image readers (PE, ELF, Mach-O, DWARF, PDB), code analysis, diff, dumps, live sessions,
             engine providers (IDA, Ghidra)
  Tools/     thin MCP tool classes per family: resolve input, call a service, format text
  Mcp/       catalog, tool contract, guide, resources, prompts, completion
  Setup/     install and client setup commands, the command line
  Relay/     corvus relay: the development reload relay over a watched publish folder
tests/
  TestFixture/            sample assembly covering every feature (inheritance, async, resources, stand-in Il2Cpp attributes)
  TestFixture.Consumer/   second assembly that uses the first (cross-assembly and virtual-dispatch references)
  TestFixture.FakeTools/  stand-in external tools
  Corvus.Tests/           one folder per tool family (docs/testing.md#layout)
  agents/                 real-client checks and the token benchmark
samples/Notes/            v1 and v2 of the guides' sample program (docs/guides, docs/showcase), built by the test project
docs/                     user and contributor documentation; index in docs/README.md
```
