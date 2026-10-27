# Contributing

## Build and test

- Requires the .NET 10 SDK, feature band 10.0.4xx, pinned in `global.json` so fixtures and recorded samples build the
  same everywhere.
- Warnings are errors; the recommended analyzers run on every build.

```powershell
dotnet build
dotnet test                            # quick set: every test not marked [Trait("Speed", "Slow")]; keep it near 30 s
$env:CORVUS_ALL_TESTS=1; dotnet test   # everything (or dotnet test -p:CORVUS_ALL_TESTS=1)
./test.ps1                             # before each commit and push: quick tests of the changed families
./test.ps1 -All                        # the whole quick set
./test.ps1 -Affected                   # quick set plus the slow tests of the changed families
./test.ps1 -Full -Background           # full set on HEAD in its own worktree; -Status shows it
./test.ps1 -Full -IfChanged            # everything, skipped when it already passed on this tree
./test.ps1 -Stamp                      # records the last full run's passes when its recording step failed
```

- Enable the hooks once: `git config core.hooksPath .githooks`. The pre-push hook starts `./test.ps1 -Full -Background`.
- Run the full set before a pull request.
- Tests that need real-world data read `CORVUS_*` variables and skip when unset: [test data variables](docs/testing.md#test-data-variables).
- Real libraries come from `<PackageDownload>` items, never machine paths.
- A new external tool is found through a variable with a neutral name.
- Testing policy: [docs/testing.md](docs/testing.md).

## Adding or changing a tool

A tool is a `[McpServerTool]` method in `src/Corvus/Tools` that wraps a service call in `ToolSupport.Read`, `Write` or
`Edit`; the logic lives in a service.

- Throw `ToolError` for anything the agent should act on.
- `[Description]` texts become the MCP descriptions: at most 600 bytes per tool, 160 per parameter (`CatalogAuditTests`).

Then:

1. `src/Corvus/Mcp/Contract` (one file per family): effects (read-only, destructive, idempotent, open-world,
   long-running), the value set of each closed string parameter (`engine` always needs one) and the contract row
   (output and latency class, lean and core profiles, dryRun policy, list sort key).
2. `tests/Corvus.Tests/ContractSweepData`: every parameter naming a file the tool writes.
3. `src/Corvus/Core/Toolsets.cs`: the tool in exactly one family.
4. `src/Corvus/Mcp/Guide.cs`: the tool named in the core or a topic.
5. `docs/features.md`: a tool table row and the tool count; the count also in `README.md` and `README.*.md`.
6. Tests: the tool's own, and a case in `McpProtocolTests.ToolCases`.

- Guard tests (catalog audit, layering, README sync, parameter domains, contract sweep, guide coverage, toolsets) fail
  when a step is missing.
- The catalog size ceiling in `CatalogAuditTests` is raised only deliberately, with the new figure recorded there.
- Agent skills for this work: `.agents/skills` (`corvus-tool-checklist`, `corvus-catalog-audit`,
  `corvus-release-notes`). For Claude Code, link `.claude/skills` to that folder. `MaintainerSkillTests` checks them.

## Generated docs

- Generated and checked by tests: `docs/simplify.md`, `docs/errors.md`, `docs/limitations.md`,
  `docs/migration-reasons.md`, `docs/saving.md`, `docs/tools.md`, `docs/schemas`, the client table of
  `docs/installation.md`, `skills/corvus`.
- After changing their sources, run the tests once with `CORVUS_UPDATE_DOCS=1` and commit the result.

## Style

- Plain compiler and engineering vocabulary in identifiers, comments, commit messages and docs.
- Comments only for what the code cannot say: a reason, an invariant, a workaround and its cause, units and limits.
- No machine-specific paths; no product names in the tool itself.

## Commits and pull requests

- One commit per logical change, with its tests; the quick set is green at every commit.
- Subject: `type(scope): imperative summary`, at most 72 characters, lower case after the colon, no final period.
  Example: `fix(live): keep deferred stop points in code an entry point writes`.
  - Types: `feat`, `fix`, `perf`, `test`, `docs`, `refactor`, `ci`, `chore`.
  - Scopes: `live`, `dumps`, `aot`, `engines`, `native`, `dotnet`, `edits`, `containers`, `mobile`, `web`,
    `catalog`, `session`, `tests`, `release`.
- Body wrapped at 72 columns: before, why it was wrong, what the code does now; then `Verified:` with the tests run.
- Trailers: `Fixes #N`, `Refs #N`, `Upstream:`.
- The commit-msg hook (`.githooks/commit-msg`) rejects a subject or line width that breaks these rules.
- A pull request states what changed and how it was tested, and keeps `README.md`, its translations and the docs in
  sync (`TranslatedReadmeTests`).

## Releasing

1. Write the version's section at the top of `docs/release-notes.md`: Highlights, Breaking changes, Changes, Fixes.
2. On a clean `main`: `./release.ps1 -Version X.Y.Z`.
   - Requires a recorded full pass on this commit or an ancestor at most 50 commits back (`-MaxBehind`), with no later
     background failure (`-SkipTests` overrides).
   - Bumps the version, regenerates the generated docs, commits and tags.
3. `-Push` also pushes, waits for the release workflow, verifies every asset against `SHA256SUMS`, sets the release
   body, checks the update from the previous release in WSL and prints the manual checklist.
   - `-VerifyOnly` runs the checks for a release already pushed.
   - The workflow builds the MCP bundles with `./release.ps1 -Bundle`.

## Reporting problems

- Bugs and feature requests: the issue forms.
- Security problems: privately, see [SECURITY.md](SECURITY.md).

## Layout

```
src/Corvus/
  Core/      workspace, symbol resolver, formatting, paging, file formats
  Services/  one folder per tool family; Analysis/ holds PE parsing, containers and unpacking
  Native/    native image readers (PE, ELF, Mach-O, DWARF, PDB), code analysis, diff, dumps, live sessions, engines
  Tools/     MCP tool classes per family: resolve input, call a service, format text
  Mcp/       catalog, tool contract, guide, resources, prompts, completion
  Setup/     install and client setup commands, the command line
  Relay/     corvus relay: reloads a watched publish folder during development
tests/
  TestFixture/            sample assembly covering every feature
  TestFixture.Consumer/   second assembly that references the first
  TestFixture.FakeTools/  stand-in external tools
  Corvus.Tests/           one folder per tool family (docs/testing.md#layout)
  agents/                 real-client checks and the token benchmark
samples/Notes/            v1 and v2 of the guides' sample program, built by the test project
docs/                     user and contributor documentation; index in docs/README.md
```
