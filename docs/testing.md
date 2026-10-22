# Testing policy

## Two sets

- **Quick set** (`dotnet test`): every test not marked `[Trait("Speed", "Slow")]`. It runs while iterating and stays under
  50 seconds on an idle machine (a ceiling against creep: about 30 s of parallel work and the timing and process-wide
  tests that run alone after it), so a quick test uses the small fixtures in `tests/TestFixture` and builds nothing external.
  Before each commit, `./test.ps1` runs the quick tests of the families the change touches (since `origin/main`,
  uncommitted files included; by the coverage map where it knows a file), plus the contract tests; shared code runs
  the whole quick set, and `./test.ps1 -All` runs it anyway.
- **Full set** (`CORVUS_ALL_TESTS=1 dotnet test`, or `dotnet test -p:CORVUS_ALL_TESTS=1`): adds real-library builds, whole-server
  runs over stdio, sweeps, fuzzing and the large runtime packs. A push needs the commit gate above; the full set then runs off
  the critical path: the pre-push hook (`.githooks/pre-push`, enabled per clone with `git config core.hooksPath
  .githooks`) starts `./test.ps1 -Full -Background` on the commit pushed to main, in a worktree of its own (`-Status`
  shows the result; the worktree goes under `CORVUS_BACKGROUND_DIR`, else the temp folder, so it can sit where the
  antivirus does not quarantine the script fixtures; it is kept between runs, so each run checks out its commit there and
  builds incrementally), and a failure is fixed in the next commit. A push while a run is going is queued: when the run
  ends, one run starts on the newest commit, at the strongest strength asked meanwhile. A whole-suite run, background or not, holds an exclusive machine lock while it runs when `CORVUS_HEAVY_LOCK` names a lock script
  (called as `heavy <name> -OwnerPid <pid>`, which waits for the lock, and `release <name>`), so other load on the machine waits for it. A background run runs at below-normal priority (its test
  hosts and engine workers inherit it) and reuses family passes; it is routine strength, a quarter of the sweeps
  without the `Tier=Release` tests (`-Exhaustive`: release strength; `-Whole`: release strength without reuse). `./test.ps1 -Affected` runs the quick set plus the slow
  tests of the families changed since `origin/main` in the foreground (shared code such as `Core`, `Mcp` or test
  `Support` runs everything). Releases gate on the full set: a routine `./test.ps1 -Full` sweeps an evenly spread
  quarter of the real images and leaves out the tests marked `[Trait("Tier", "Release")]` (measurements, accuracy
  oracles against IDA, the largest inputs); `-Exhaustive` (gates and releases, `CORVUS_SWEEP=exhaustive`) takes
  every image and those tests. A `-Filter` given on the command line keeps them. `./test.ps1 -Full` records the clean tree it
  passed on (in `.git`), and `-IfChanged` and `release.ps1` skip a second full run on that tree. A run keeps its results
  until the next one: if recording them fails, `./test.ps1 -Stamp` records them without a rerun, on the same tree only. Each full run on a
  clean tree also records which test families passed, under a key of the family's own folders, all shared code, the
  repository files its tests read, the SDK, the OS build and the `CORVUS_*` settings (`test-reuse.psm1`).
  `./test.ps1 -Full -Reuse` then runs only the families whose key changed, plus the contract tests and the classes
  known to be flaky under load; its stamp is marked `reused`. `./test.ps1 -CoverageMap` (weekly; one instrumented run
  per family) records which source files each family's tests run, and for a week the keys follow it: a shared file
  keys only the families that ran it, and a file no family ran keeps the folder rules. The slow test classes of the last full run (30 s or more)
  get a coverage run of their own and a key of their own: a change reruns such a class only when a source file it ran,
  a file of its test folder or a setting changed, so a reader change reruns the comparisons against that reader alone. `release.ps1` runs the suite through `test.ps1` before
  the version bump, so every release run records its passes: patch releases take a reused pass; minor releases (`x.y.0`)
  want a whole exhaustive pass, or a reused one when only documentation changed since the last whole pass. With
  `CORVUS_SECOND_GHIDRA_DIR` set (another Ghidra, such as the oldest supported one), every whole-suite full run (and
  `./test.ps1 -SecondGhidra`) runs the `Engines` tests again with that Ghidra (the IDA-only tests skip: `CORVUS_TEST_ENGINE=ghidra`), keyed like a family
  with that Ghidra in the settings: unchanged inputs skip it, and a retry runs only the tests that failed. After
  publishing, `release.ps1` installs the previous release with `install.sh` in WSL under a throwaway home and checks
  that `corvus update` reaches the new one.
- **Failures, hangs and quarantine.** A failure fails the run; nothing is retried to green. A full run reruns each
  failed test once (25 at most) only to label it, "failed" or "failed, passed on rerun (suspected flaky)", printed and
  kept in `.git/corvus-last-run-labels.txt`; the run stays failed. A test that runs past its hang limit (2 minutes in a
  quick run, 30 minutes in a full run) ends the run with a dump of the test host, kept with the test sequence in
  `.git/corvus-hang-<time>`. `tests/Corvus.Tests/Ratchets/quarantine.txt` lists quarantined tests, one
  `Class.Method | owner | issue | yyyy-MM-dd` line each, the date by which the test is fixed or removed: a quarantined
  test still runs and its failure is reported, but it alone does not fail a run that completed; past its date the
  entry no longer applies, and `QuarantineListTests` fails until it is removed.
- **Releases.** `release.ps1` runs no suite in the foreground: it ships when the newest background pass is on the
  release commit or an ancestor, stops on a known background failure (`-SkipTests` overrides), names the families not
  yet verified on the current inputs, and runs the quick set after the version bump. A failure found later goes into a
  patch release. For release-strength passes, start `./test.ps1 -Full -Background -Exhaustive` (or `-Whole`).
- **Run times.** Every run but a coverage run records its test times from its TRX results in
  `.git/corvus-test-history.jsonl` (the last 30 runs of each mode: commit gate, push, full, perf and filtered runs; a
  test that passed in under a second is kept in its class's total) and rewrites `.git/corvus-time-report.md`: each
  mode's latest run against its target (the commit gate under 2 minutes with its build, a push's background run under
  15 minutes, a whole run under 30 minutes) with the tests that keep a missed target out of reach, and per mode the wall
  and summed time, the tests running in each 5-minute bucket, the critical path, the 20 slowest classes and tests with
  their median and 90th percentile, regressions (over 5 s and 1.5 times the median in each of the last two runs), heavy
  lock and permit waits, and the failed tests. A run prints one line from it; `./test.ps1 -Status` shows each mode's
  latest run against its target. The tests start the longest classes first, by their median time in the history's runs
  of the same mode (`Support/CollectionOrder.cs`).
- **Machine-wide permits.** A test class that runs IDA (`[IdaFact]`), Ghidra (`[GhidraFact]`) or another heavy
  resource (`[Permit("live")]`, `[Permit("reference-tool")]`) waits for a permit before it starts and holds it until its
  last test ends (`Support/MachinePermits.cs`: IDA 2, Ghidra 2, live 2, reference tools 4). Every test process on the
  machine takes the same permits, so lanes' runs and the background run together never exceed them. The wait stays out
  of the tests' times, and the time report lists it per resource.
- **Shared engine analyses.** IDA and Ghidra tests on the System32 sample start from a copy of one saved analysis per
  engine, engine install and server build (`Support/EngineSeed.cs`, kept under `corvus-test-data/engine-seed` in the
  temporary folder), instead of analysing it again in every empty cache: about half the time of those classes. Tests
  that measure or check a cold open keep an empty cache.
- **Timing budgets.** A test that times its work against a budget also asserts the mechanism that makes the work fast:
  a cache hit, a process not started, one worker request. It carries `[Trait("Perf", "Timing")]`, and its budget goes
  through `PerfBudget.Check`. Gating runs record the time in the test output. The perf run (`./test.ps1 -Perf`,
  nightly after a full run: `CORVUS_PERF=1`, filter `Perf=Timing`, one test at a time) enforces the budgets. It runs
  alone on the machine: it holds the heavy lock and every test permit. A test over its budget runs up to 4 more times
  and counts as over only when most of the 5 samples are. The run fails only on a test that was also over in the
  perf run before (`.git/corvus-perf-verdicts.json`), so a single slow run is reported but does not fail the run;
  `-Status` shows the last verdict.

CI (`.github/workflows/ci.yml`) runs the quick set as a smoke lane; the release workflow builds the release archives.
The full set and the real-application runs are done locally. To run the Live family (slow tests included) on macOS
and Windows ARM64, start ci.yml by hand with its `live` input: `gh workflow run ci.yml --ref <branch> -f live=true`.
The manual job installs 64-bit Python and the tested Frida release on macos-latest, windows-11-arm, ubuntu-latest and
windows-latest, and uploads one TRX per machine (`live-results-<os>`).

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
  the measured lists (`coverage.txt`, `duplicate-lines.txt`; `CountRatchet`) hold one value
  per key that moves one way only, and `CORVUS_UPDATE_RATCHETS=1` records a tighter value;
- dead code and copies: unused or never-read private members (IDE0051, IDE0052) are build errors; the full set counts
  the significant lines (no blanks, comments, lone braces or usings) of `src/` that lie in a copied block of 8 or more,
  per file pair, against `Ratchets/duplicate-lines.txt` (`DuplicateCodeTests`);
- coverage floor: `./test.ps1 -Full -Coverage` collects line coverage of the server (coverlet, `corvus` only) over the
  whole suite and checks each source area (`src/Corvus/<folder>`, a level deeper under `Native`, `Services` and
  `Tools`) and the total against `Ratchets/coverage.txt`, floors set one point below the run that recorded them;
- format fuzzing: every format reader (found by reflection) has a quick fuzz test marked `[FuzzEntry]`, or a reviewed
  entry in `Ratchets/format-fuzz.txt`;
- protocol matrix: every MCP protocol version the SDK speaks is negotiated and answered;
- real-data speed: a test that reads real-world data (a real-data attribute, or a `CORVUS_*` data variable in its code)
  carries `Speed=Slow` on the method or class, so setting the variable never slows the quick set (`RealDataSpeedTests`);
- leaks: once every test has run, child processes of the test process still running, or files left in the run's own
  temporary folder (TMP, TEMP and TMPDIR point there for the tests and the servers they start), fail the run with
  their names. A folder a test class keeps for the whole run is registered with `LeakGuard.DeleteAtEnd`.

## Mutation testing, client checks and the token benchmark

These run on demand (gates and releases), never in the quick or full set by default, and skip with the reason when
their tool is missing:

- **Mutation testing** (`./test.ps1 -Mutation [-Target sqlite,pe]`): Stryker.NET (`CORVUS_STRYKER`, else
  `dotnet-stryker` on PATH) mutates the files of the targets in `tests/mutation.json` (the core readers: SQLite,
  pcap, PE, ELF, Mach-O, the ARM decoders; the file holds every Stryker option) in one run, with the tests that read
  them. Stryker compiles the whole project once per run (about an hour here, whatever is mutated), so targets share a
  run. Surviving mutants (survived or not covered) per target are checked against `Ratchets/mutation-survivors.txt`
  (`MutationTests`), and the score per target is printed.
- **Installer listings against reference tools** (`InstallerComparisonTests`): with `CORVUS_INSTALLERS` naming a
  folder of real installers in `nsis`, `inno`, `msi` and `burn` subfolders, each installer's files (name and size)
  are compared with a reference tool's listing: `CORVUS_ARCHIVE_LISTER` (7-Zip), `CORVUS_SETUP_LISTER` (innounp),
  `CORVUS_MSI_LISTER` (lessmsi), `CORVUS_BUNDLE_EXTRACTOR` (the WiX `wix` tool). A format whose tool is unset is
  skipped; each installer must match at least 99% of the reference rows.
- **Capture HTTP objects against Wireshark** (`CaptureObjectsTSharkTests`): with `CORVUS_TSHARK` set, synthetic
  captures (Content-Length, chunked, gzip / deflate / brotli, pipelining, resent segments, ranges, bodies ending at
  close, request bodies) must export exactly the files `tshark --export-objects http` exports, by SHA-256. With
  `CORVUS_CAPTURES` naming a folder of captures (key logs beside them as `<name>*.keys`), every object TShark exports
  must be among ours; TShark's `object<frame>` files from frames that start no HTTP message are counted apart.
- **Package review on real packages** (`PackageDatasetTests`): `CORVUS_PACKAGES_BAD` names a folder of known-bad npm,
  PyPI and VS Code packages and `CORVUS_PACKAGES_GOOD` one of ordinary packages, each grouped in subfolders; prints the
  noteworthy share per subfolder and checks both against floors. `CORVUS_PACKAGES_REPORT` names a file for one line
  per package with its findings.
- **Real-client checks** (`tests/agents/run-tasks.ps1`, or the full set with `CORVUS_CLIENT_CHECKS=1`): each installed
  agent client (Claude Code, Codex, Gemini CLI; `CORVUS_CLIENT_CLAUDE`, `CORVUS_CLIENT_CODEX`,
  `CORVUS_CLIENT_GEMINI` name other executables) gets one known-answer question about the Notes sample through this
  build's server, graded by the facts in `tests/agents/tasks.json`. Every client option lives in
  `tests/agents/clients.json`. A client that is not installed or not signed in is skipped.
- **Token benchmark** (`run-tasks.ps1 -Set bench -Server corvus,reference -Runs 3`): ten known-answer tasks, per
  client and server: correctness, tools called, input tokens (with the cached part), output tokens, cost and wall time,
  in `results.jsonl`. `CORVUS_REFERENCE_SERVER` holds the server to compare against (JSON
  `{"command": ..., "args": [...]}`); `CORVUS_AGENT_SERVER` replaces this build.

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
