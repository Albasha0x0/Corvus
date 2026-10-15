# Testing policy

## Two sets

- **Quick set** (`dotnet test`): every test not marked `[Trait("Speed", "Slow")]`. It runs while iterating and stays under
  50 seconds on an idle machine (a ceiling against creep: about 30 s of parallel work and the timing and process-wide
  tests that run alone after it), so a quick test uses the small fixtures in `tests/TestFixture` and builds nothing external. The
  quick set is green at every commit.
- **Full set** (`CORVUS_ALL_TESTS=1 dotnet test`, or `dotnet test -p:CORVUS_ALL_TESTS=1`): adds real-library builds, whole-server
  runs over stdio, sweeps, fuzzing and the large runtime packs. A push needs the quick set; the full set then runs off
  the critical path, `./test.ps1 -Full -Background`, on the pushed commit in a worktree of its own (`-Status` shows
  the result), and a failure is fixed in the next commit. A background run is exhaustive and reuses family passes
  (`-Sampled` runs the routine quarter of the sweeps without reuse). `./test.ps1 -Affected` runs the quick set plus the slow
  tests of the families changed since `origin/main` in the foreground (shared code such as `Core`, `Mcp` or test
  `Support` runs everything). Releases gate on the full set: a routine `./test.ps1 -Full` sweeps an evenly spread
  quarter of the real images; `-Exhaustive` (gates and releases, `CORVUS_SWEEP=exhaustive`) takes them all. `./test.ps1 -Full` records the clean tree it
  passed on (in `.git`), and `-IfChanged` and `release.ps1` skip a second full run on that tree. Each full run on a
  clean tree also records which test families passed, under a key of the family's own folders, all shared code, the
  repository files its tests read, the SDK, the OS build and the `CORVUS_*` settings (`test-reuse.psm1`).
  `./test.ps1 -Full -Reuse` then runs only the families whose key changed, plus the contract tests and the classes
  known to be flaky under load. `release.ps1` runs the suite through `test.ps1` before the version bump, so every
  release run records its passes: patch releases gate on the reusing run; minor releases (`x.y.0`) run the whole
  exhaustive suite. With `CORVUS_SECOND_GHIDRA_DIR` set (another Ghidra, such as the oldest supported one), it then runs
  the `Engines` tests again with that Ghidra. After publishing, it installs the previous release with `install.sh` in WSL
  under a throwaway home and checks that `corvus update` reaches the new one.

CI (`.github/workflows/ci.yml`) runs the quick set as a smoke lane; the release workflow builds the release archives.
The full set and the real-application runs are done locally.

## Layout

`tests/Corvus.Tests` has one folder per tool family, so a change's tests are found by folder: `Dotnet`, `DotnetEdits`,
`NativeAnalysis`, `NativeFormats`, `Engines` (IDA and Ghidra), `NativeEdits`, `Builds`, `Containers`, `Mobile`, `Dumps`,
`Il2Cpp`, `NativeAot`, `Session` (workspace, notes, server, setup), `Contract` (catalog, ratchets, protocol, sweeps of the
output contract) and `Support` (builders, fixtures and shared harnesses). Namespaces do not follow the folders.
Long engine classes are split into nested classes (by engine and topic) because xUnit runs one class's tests in sequence.

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
- community files (SECURITY.md names every call that starts a process or reaches the network; CONTRIBUTING.md, issue
  forms; no machine path in a tracked file);
- ratchets: each list in `tests/Corvus.Tests/Ratchets` may only shrink, and every entry states a `# permanent:` reason;
- format fuzzing: every format reader (found by reflection) has a quick fuzz test marked `[FuzzEntry]`, or a reviewed
  entry in `Ratchets/format-fuzz.txt`;
- protocol matrix: every MCP protocol version the SDK speaks is negotiated and answered;
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
