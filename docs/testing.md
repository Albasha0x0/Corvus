# Testing policy

## Two sets

- **Quick set** (`dotnet test`): every test not marked `[Trait("Speed", "Slow")]`. It runs while iterating and must stay
  near 30 seconds, so a quick test uses the small fixtures in `tests/TestFixture` and builds nothing external. The
  quick set is green at every commit.
- **Full set** (`CORVUS_ALL_TESTS=1 dotnet test`, or `dotnet test -p:CORVUS_ALL_TESTS=1`): adds real-library builds, whole-server
  runs over stdio, sweeps, fuzzing and the large runtime packs. It runs before pushing.

CI (`.github/workflows/ci.yml`) runs the quick set as a smoke lane; the release workflow builds the release archives.
The full set and the real-application runs are done locally.

## Test data

- Real libraries come from `<PackageDownload>` items in the test project, read through `RealPackages.Lib`; tests never
  read paths of one machine.
- Data that cannot be redistributed (application folders, Il2Cpp games, external tools) is found through `CORVUS_*`
  environment variables (README, "Build, test, publish"), and a test without its data is skipped.
- A new external tool used by tests is wired through an environment variable with a neutral name, with its command-line
  options kept in one table.

## Guard tests

These fail when a change misses one of its follow-up steps (CONTRIBUTING.md lists them):

- catalog audit and size ceiling, toolsets, parameter domains, contract sweep and tool effects;
- layering (which namespaces may use which);
- README sync (tool tables, tool and prompt counts) and docs facts (clients, release targets, commands, environment
  variables, release-notes version, links, command-line examples);
- guide coverage (every tool is named in the guide; the guide, skill and docs name only registered tools);
- community files (SECURITY.md, CONTRIBUTING.md, issue forms);
- leaks: once every test has run, child processes of the test process still running, or files left in the run's own
  temporary folder (TMP, TEMP and TMPDIR point there for the tests and the servers they start), fail the run with
  their names. A folder a test class keeps for the whole run is registered with `LeakGuard.DeleteAtEnd`.

## Generated documents

`docs/errors.md`, `docs/simplify.md`, `docs/saving.md`, `docs/tools.md`, the client table of `docs/installation.md`
and the skill in `skills/corvus` are generated from the code and compared by tests. After changing their
sources, regenerate them and commit the result:

```sh
CORVUS_UPDATE_DOCS=1 dotnet test
```

## Guides and showcases

`docs/guides` and `docs/showcase` run on the sample in `samples/Notes`, which the test project builds. Each
`<!-- check: ... -->` comment marks the fenced block after it: `setup` commands must succeed, a `batch` runs its steps
in one session, a `run` starts the sample, and the `output` block that follows must equal what they print, with
repository paths made relative and each SHA-256 and GUID replaced by a label (`<sha256-1>`). The quick set checks the
blocks' shape; the full set runs them (`SampleDocsTests`), and `CORVUS_UPDATE_DOCS=1` with the full set rewrites the
output blocks.

## Command-line tests

The command line is tested in process: `ToolCli.RunAsync` with string writers and a server over in-memory streams, so
these tests cost one server start each and need no published program.
