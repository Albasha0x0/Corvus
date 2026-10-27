# Contributing

## Build and test

- Requires the .NET 10 SDK, feature band 10.0.4xx (`global.json`). Warnings are errors.

```powershell
dotnet build
dotnet test                            # quick set: tests not marked [Trait("Speed", "Slow")]
$env:CORVUS_ALL_TESTS=1; dotnet test   # everything
./test.ps1                             # quick tests of the changed families
./test.ps1 -All                        # the whole quick set
./test.ps1 -Full                       # full set
```

- Run `./test.ps1` before each commit and pull request.
- Enable the hooks once: `git config core.hooksPath .githooks`. The pre-push hook starts `./test.ps1 -Full -Background`.
- Real libraries come from `<PackageDownload>` items, never machine paths.

## Add a tool

A tool is a `[McpServerTool]` method in `src/Corvus/Tools` that wraps a service call in `ToolSupport.Read`, `Write` or `Edit`.
Throw `ToolError` for anything the agent should act on. `[Description]` text is the MCP description: at most 600 bytes per tool and 160 per parameter.

1. `src/Corvus/Mcp/Contract`: one file per family with the effects, the value set of each closed string parameter and the contract row.
2. `tests/Corvus.Tests/ContractSweepData`: every parameter naming a file the tool writes.
3. `src/Corvus/Core/Toolsets.cs`: the tool in exactly one family.
4. `src/Corvus/Mcp/Guide.cs`: the tool named in the core or a topic.
5. `docs/features.md`: a tool table row and the tool count; the count also in `README.md` and `README.*.md`.
6. Tests: the tool's own, and a case in `McpProtocolTests.ToolCases`.

Guard tests (catalog audit, layering, README sync, parameter domains, contract sweep, guide coverage, toolsets) fail when a step is missing.
Raise the catalog size ceiling in `CatalogAuditTests` only on purpose, with the new figure recorded there.

## Generated docs

- Checked by tests: `docs/simplify.md`, `docs/errors.md`, `docs/limitations.md`, `docs/migration-reasons.md`, `docs/saving.md`, `docs/tools.md`, `docs/schemas`, the client table of `docs/installation.md`, `skills/corvus`.
- After changing their sources, run the tests once with `CORVUS_UPDATE_DOCS=1` and commit the result.

## Commits and pull requests

- One commit per logical change, with its tests; the quick set is green at every commit.
- Subject: `type(scope): imperative summary`, at most 72 characters, lower case, no final period. Example: `fix(live): keep deferred stop points in code an entry point writes`.
- Types: `feat`, `fix`, `perf`, `test`, `docs`, `refactor`, `ci`, `chore`.
- Scopes: `live`, `dumps`, `aot`, `engines`, `native`, `dotnet`, `edits`, `containers`, `mobile`, `web`, `catalog`, `session`, `tests`, `release`.
- Body wrapped at 72 columns: what happened before, why it was wrong, what the code does now; then `Verified:` with the tests run.
- Trailers: `Fixes #N`, `Refs #N`, `Upstream:`. The commit-msg hook (`.githooks/commit-msg`) rejects a subject or width that breaks these rules.
- A pull request states what changed and how it was tested, and keeps `README.md`, its translations and the docs in sync (`TranslatedReadmeTests`).

## Reporting problems

- Bugs and feature requests: the issue forms.
- Security problems: privately, see [SECURITY.md](SECURITY.md).

## Layout

```
src/Corvus/
  Core/      workspace, symbol resolver, formatting, paging, file formats
  Services/  one folder per tool family; Analysis/ holds PE parsing, containers and unpacking
  Native/    native image readers, code analysis, diff, dumps, live sessions, engines
  Tools/     MCP tool classes per family
  Mcp/       catalog, tool contract, guide, resources, prompts, completion
  Setup/     install and client setup commands, the command line
  Relay/     corvus relay: reloads a watched publish folder during development
tests/       TestFixture, TestFixture.Consumer, TestFixture.FakeTools, Corvus.Tests
samples/     Notes: v1 and v2 of the guides' sample program
docs/        user and contributor documentation; index in docs/README.md
```
