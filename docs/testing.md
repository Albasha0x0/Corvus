# Testing policy

## Two sets

| Command | Runs |
|---|---|
| `dotnet test` | Quick set: every test not marked `[Trait("Speed", "Slow")]`. |
| `CORVUS_ALL_TESTS=1 dotnet test` (or `-p:CORVUS_ALL_TESTS=1`) | Full set: adds real-library builds, whole-server stdio runs, sweeps, fuzzing and the large runtime packs. |
| `./test.ps1` | Commit gate: quick tests of the families changed since `origin/main` (uncommitted and untracked files included; by the coverage map where it knows a file), plus the contract tests. Shared code runs the whole quick set. |
| `./test.ps1 -All` | The whole quick set. |
| `./test.ps1 -Affected` | Quick set plus the slow tests of the changed families, in the foreground; shared code (`Core`, `Mcp`, test `Support`) runs everything. |
| `./test.ps1 -Full` | Full set, routine strength: an evenly spread quarter of the real-image sweeps, without `[Trait("Tier", "Release")]` tests (measurements, IDA accuracy oracles, the largest inputs). Names the engines whose tests skip (set `CORVUS_GHIDRA_DIR`, `CORVUS_IDA_DIR`). |
| `./test.ps1 -Full -Exhaustive` | Release strength (`CORVUS_SWEEP=exhaustive`): every sweep input and the `Tier=Release` tests. |
| `./test.ps1 -Full -IfChanged` | Skips when a full run already passed on this clean tree (`release.ps1` uses the same stamp). |
| `./test.ps1 -Full -Reuse` | Only the families whose input key changed, plus the contract tests and the classes flaky under load; its stamp is marked `reused`. |
| `./test.ps1 -Full -Background [-Commit <sha>]` | `-Full -Reuse` on the committed HEAD (or `<sha>`) in a worktree of its own; returns at once. `-Exhaustive`: release strength with reuse; `-Whole`: release strength without reuse. |
| `./test.ps1 -Status` | The last background run and the offload, host tier, nightly and perf state. |
| `./test.ps1 -Wait` | Returns when the background run and any run queued behind it end; exit 0 on a pass. Wait on this, not on `-Status`. |
| `./test.ps1 -Stamp` | Records the last full run's passes when its recording step failed (same tree only). |
| `./test.ps1 -Filter <expr>` | Any `dotnet test` filter; a filter given on the command line keeps the `Tier=Release` tests. |
| `./test.ps1 -CoverageMap` | One instrumented run per family recording the source files its tests run. |
| `./test.ps1 -SecondGhidra` | The `Engines` tests on `CORVUS_SECOND_GHIDRA_DIR`. |
| `./test.ps1 -Perf` | The timing budgets, enforced, alone on the machine. |
| `./test.ps1 -Mutation [-Target sqlite,pe]`, `-Full -Coverage` | See [Mutation testing](#mutation-testing-client-checks-and-the-token-benchmark) and [Guard tests](#guard-tests). |
| `./test.ps1 -RemoteRun -Group <group> -Shard <i>/<n>` | One shard of an offload group, as CI runs it. |
| `./test.ps1 -Remote -Filter <filter> -Repeat <n>` | A filter `n` times on the test host. |
| `./test.ps1 -HostTier` | The host tier's classes on the test host. |

- **Quick set.** Run while iterating. It stays under 50 s on an idle machine (about 30 s of parallel work, then the
  timing and process-wide tests that run alone), so a quick test uses the small fixtures in `tests/TestFixture` and
  builds nothing external.
- **Background run after a push.** The pre-push hook (`.githooks/pre-push`; enable per clone with
  `git config core.hooksPath .githooks`) starts `./test.ps1 -Full -Background -Commit <sha>` for a push to main; other
  branches start nothing. A failure is fixed in the next commit.
  - The worktree lives under `CORVUS_BACKGROUND_DIR` (default: the temp folder; pick a folder the antivirus does not
    scan, as it quarantines script fixtures). It is kept between runs and builds incrementally.
  - A push while a run is going is queued: when the run ends, one run starts on the newest queued commit at the
    strongest strength asked.
  - Every 10 s a sampler records how late the run woke, how long a normal-priority helper takes to create a small file
    in the permit folder and the temp folder, that volume's disk queue and idle time, free memory and pages/s
    (`.git/corvus-background.log.io`). `-Status` names each window where a file took over 1 s or the run woke over 1 s
    late, so CPU starvation is told apart from a slow disk.
  - A whole run refreshes a coverage map older than 6 days.
- **Variables.** On Windows, full, background, perf, remote and host-tier runs take `CORVUS_*` and `GHIDRA_INSTALL_DIR`
  user variables a shell started earlier lacks.
- **Priority and locks.** Every run except `-Perf` runs below normal priority (nice 10 on Linux and macOS; builds,
  test hosts and engine workers inherit it); `CORVUS_TEST_PRIORITY=normal` keeps normal priority. A whole-suite run
  without reuse (nightly, release gate) holds an exclusive machine lock when `CORVUS_HEAVY_LOCK` names a lock script
  (called as `heavy <name> -OwnerPid <pid>`, which waits for the lock, and `release <name>`); a push run (`-Reuse`)
  takes none and relies on the machine-wide permits.
- **Stamps and reuse** (`test-reuse.psm1`). A full run on a clean tree records the tree it passed on (in `.git`) and
  each test family that passed, under a key of: the family's own folders, all shared code, the repository files its
  tests read, the SDK, the OS build, the `CORVUS_*` settings with the state of each path they name (a file's size and
  write time, a folder's files to three levels down, the IDA install IDA's own configuration names) and each external
  tool found on PATH or in a default folder. A tool installed or updated in place therefore reruns everything.
  - A run that reuses nothing checks the selection: a family failing under the key of a recorded pass is a selection
    miss, logged in `.git/corvus-selection-misses.txt` and shown by `-Status`.
  - For a week after `-CoverageMap`, keys follow the map: a shared file keys only the families that ran it; a file no
    family ran keeps the folder rules. Slow classes of the last full run (30 s or more) get their own coverage run and
    key, so a change reruns such a class only when a source file it ran, a file of its test folder or a setting changed.
  - A run keeps its results until the next one; if recording fails, `-Stamp` records them without a rerun.
- **Second Ghidra.** With `CORVUS_SECOND_GHIDRA_DIR` set (such as the oldest supported Ghidra), every whole-suite full
  run and `-SecondGhidra` rerun the `Engines` tests on it (`CORVUS_TEST_ENGINE=ghidra`: IDA-only tests skip), keyed
  like a family with that Ghidra in the settings: unchanged inputs skip it; a retry runs only the failed tests.
- **Failures, hangs and quarantine.** A failure fails the run; nothing is retried to green.
  - A full run reruns each failed test once (25 at most) only to label it "failed" or "failed, passed on rerun
    (suspected flaky)"; labels are printed and kept in `.git/corvus-last-run-labels.txt`. Each failure's first message
    lines are printed; the run's and rerun's results are kept in `.git/corvus-failed-runs` (newest 10 runs).
  - A test past its hang limit (2 min in a quick run, 30 min in a full run) ends the run with a dump of the test host
    (mini in a quick run, full in a full run), kept with the test sequence in `.git/corvus-hang-<time>`. Dumps over
    100 MB are kept in the newest three hang folders only.
  - `tests/Corvus.Tests/Ratchets/quarantine.txt` lists quarantined tests, one `Class.Method | owner | issue |
    yyyy-MM-dd` line each (the date by which it is fixed or removed). A quarantined test still runs and is reported,
    but its failure alone does not fail a completed run. Past its date the entry no longer applies and
    `QuarantineListTests` fails until it is removed.
- **Releases.** `release.ps1` runs no suite in the foreground. It ships when a full pass (background, nightly or
  `./test.ps1 -Full`, each recorded in `.git/corvus-full-passes.txt`) is on the release commit or an ancestor at most
  `-MaxBehind` (50) commits back; it stops on a background failure after that pass on its history (`-SkipTests`
  overrides), names the families not yet verified on the current inputs, and runs the quick set after the version
  bump. A failure found later goes into a patch release. By policy, patch releases take a reused pass and minor
  releases (`x.y.0`) a whole pass (`./test.ps1 -Full -Background -Whole`; `-Exhaustive` for a reused release-strength
  pass); `release.ps1` does not check the strength. It writes a summary of the pass it relied on to
  `release/tests.json` in the release commit (`-Summary <file>` previews it), which the release attaches as
  `corvus-tests.json` ([installation.md](installation.md#install-script)). After publishing, `release.ps1` installs the previous release with
  `install.sh` in WSL under a throwaway home and checks that `corvus update` reaches the new one.
- **Offloaded classes** (`test-remote.psm1`). Every push to main also runs three groups of heavy classes on
  GitHub-hosted runners (the `offload` job of `ci.yml`; skipped for documentation-only commits):
  - `sweep`: engine-free sweeps, matrices and reference comparisons (the patterns in `test-remote.psm1`);
  - `ghidra`: classes that use only Ghidra (the release pinned in `Support/remote-tools-assets.json`, on a pinned JDK);
    a class using both engines goes here and keeps its IDA tests local (trait `Engine=ida` or `Engine=ghidra` on each
    engine fact), the two halves joined per test;
  - `live`: the live family (Frida 17.24.3).

  Tests that need real data never go to GitHub. Groups are dealt to Windows shards longest first by the seconds each
  class took in earlier offload runs (`Support/offload-seconds.json`; `Save-OffloadSeconds` rebuilds it from the jobs'
  `offload.trx` artifacts), with the cross-platform classes also on Linux as a check. A routine whole-suite run on a
  commit that has that job (the push run, or `-Full` on a commit on `origin/main`) leaves those classes out, waits
  for the GitHub run with `gh` and joins its TRX results; family passes and the tree stamp need both halves. A class
  reruns here, and its local result counts, when there it failed a test on any platform, skipped a test that ran here
  in the last whole run (a class using both engines: skipped on both sides), took under 20% of its local time (when
  that was 30 s or more), or has no results (a run that does not appear within 2 minutes, a failed or cancelled job).
  `-Status` shows one `github` line; it and the time report name each class that failed there with its result here.
  `CORVUS_TEST_OFFLOAD=0` runs everything here.
- **Test host.** `./test-remote-setup.ps1 -Target user@host` prepares a Windows machine over OpenSSH:
  - the PowerShell 7, MinGit, Python, JDK and Ghidra releases pinned with their SHA-256 in
    `Support/remote-tools-assets.json` (under `~/corvus-test-host/tools`), the reference tools the real-data classes
    compare against (wabt, baksmali, jadx-headless-mcp, Vineflower, the Hermes CLI releases, TShark by an
    administrative extract of the Wireshark installer) with their variables set, the Frida release the server pins, a
    clone of the repository, the .NET SDK `global.json` names with the x64 and x86 runtimes (checked against
    Microsoft's release metadata) and the Visual C++ build tools (bootstrapper signature checked);
  - each step keeps what is there, so a rerun fills gaps; `-Check` changes nothing and names what is missing;
  - the .NET Framework 4.8 Developer Pack and a Microsoft Defender exclusion for the host folder (Defender quarantines
    some benign script fixtures) are only named, with the command that adds them;
  - the host needs OpenSSH Server, an administrator account and this machine's key authorized; its engine and live
    permits are its own.

  With `CORVUS_TEST_REMOTE=user@host` answering over ssh, a whole-suite run sends its offloaded classes there instead
  of GitHub: one `dotnet test` run at a time, below normal priority, in a worktree of the host's clone, TRX copied back
  by scp and joined as above. A release-strength run (`-Exhaustive`, `-Whole`, nightly) sends them at that strength;
  without a host it runs them here, since GitHub runs routine strength. A commit origin lacks (a push run starts before
  its push lands) goes as a git bundle (`-Status` says so); only if that fails do the classes run here. A run that
  finds another on the host waits and reports how long (`-Remote` prints it live; the offload note, the tier record and
  `-Status` name it). Live classes the host left without a full result take the push's GitHub live results where
  those prove them; a class that failed on the host still reruns here.

  The test host also takes:
  - the host group, which never goes to GitHub: the Program Files sweep, the timed and working-set classes (they need
    an otherwise idle machine), and the real-data classes whose variables the host has set, dealt between here and
    the host longest first. Copy real data with `./test-remote-setup.ps1 -Target user@host -Data` (the folders and
    files the real-data variables name, links followed, into `~/corvus-data`, variables set to the copies; a copy
    whose name and size match is kept; a copy leaving under 10 GB free is refused; `-Check` names what is missing).
    Variables naming a program the tests run (the tool table in `test-remote.psm1`) are not copied. A class whose
    variable the host lacks stays here and is named;
  - about half the classes with IDA facts, dealt longest first, when the host has its own licensed IDA Pro 9 or newer
    (`-IdaDirectory <folder there>` sets `CORVUS_IDA_DIR` there; setup never installs IDA). They run whole there,
    Ghidra facts included; IDA classes in files with real-data facts stay here. In turn about half the Ghidra-only
    classes stay here.

  A push run leaves the host group's classes no host takes, and those a host left without a failure, to the nightly
  whole run; their families record no pass and `-Status` names them. `./test.ps1 -Remote -Filter <filter> -Repeat <n>`
  sends the working tree as is (uncommitted changes included, as a git bundle; nothing is pushed), builds once there,
  runs the filter `n` times, prints each exit code and copies failed runs' TRX files to `TestResults/remote`.
- **Run times** (`test-time.psm1`). Every run but a coverage run records its TRX times in
  `.git/corvus-test-history.jsonl` (last 30 runs per mode: commit gate, push, full, perf, filter; a test that passed
  in under a second counts only in its class total) and rewrites `.git/corvus-time-report.md`:
  - each mode's latest run against its target: commit gate with build under 2 min, push run under 15 min, whole run
    under 30 min, with the tests keeping a missed target out of reach;
  - per mode: wall and summed time, tests running per bucket (1 minute; 5 minutes for runs of 15 min or more), the
    critical path, the 20 slowest classes and tests with median and 90th percentile, regressions (over 5 s and 1.5
    times the median in each of the last two runs), heavy lock and permit waits, and the failed tests.

  A run prints one line from it; `-Status` shows each mode's latest run against its target. Classes start longest
  first by their median time in the same mode (`Support/CollectionOrder.cs`).
- **Machine-wide permits** (`Support/MachinePermits.cs`). A class using IDA (`[IdaFact]`), Ghidra (`[GhidraFact]`) or
  another heavy resource (`[Permit("live")]`, `[Permit("reference-tool")]`) waits for a permit before it starts and
  holds it until its last test ends: IDA 2, Ghidra 2, live 2, reference tools 4; a machine with 64 GB or more adds
  one IDA, one Ghidra and two reference-tool permits. Every test process on the machine shares them. The wait is left
  out of test times and listed per resource in the time report.
- **Tests in a process of their own.** A test that measures the whole process (heap growth, retained memory, working
  set) or sets a process variable reruns its body in a child process (`Support/ChildTest.cs`), so it runs beside the
  parallel classes. Sweeps, fuzzers and timed tests run in parallel too; budgets hold only in the perf run. Still run
  alone after the parallel classes: deadline and cancellation timings (parallel classes starve the thread pool), tests
  that rebuild `samples/`, and the relay's real-server run.
- **Shared engine analyses.** IDA and Ghidra tests on the System32 sample start from a copy of one saved analysis per
  engine, engine install and server build (`Support/EngineSeed.cs`, under `corvus-test-data/engine-seed` in the temp
  folder): about half the time of those classes. Tests that measure or check a cold open keep an empty cache.
- **Timing budgets.** A test timing its work against a budget also asserts the mechanism that makes it fast (a cache
  hit, a process not started, one worker request). It carries `[Trait("Perf", "Timing")]` and reports each measurement
  through `PerfBudget.Time`, `AtMost` or `AtLeast` as `perf: <name> <value> <unit> (budget <= <limit> <unit>)`.
  Gating runs only record the line. The perf run (`./test.ps1 -Perf`; nightly after a full run; `CORVUS_PERF=1`,
  filter `Perf=Timing`, one test at a time) enforces budgets:
  - it holds the heavy lock and every test permit. When processes outside the run use over 25% of the CPU in more
    than a tenth of its 10 s samples, the run is partial: it names that load, records no verdict and exits 3;
  - a test over budget runs up to 4 more times and counts as over only when most of the 5 samples are;
  - each measurement is compared with `tests/Corvus.Tests/Ratchets/perf-baseline.txt` (one baseline per name and OS;
    a new name needs a line). A value past 1.5 times its baseline (below baseline / 1.5 for a rate) reruns its tests 4
    times, and it regresses when the median of each sample's worst value is past it;
  - the run fails only on an over-budget test or regressed measurement that was also so in the previous perf run
    (`.git/corvus-perf-verdicts.json`); `-Status` shows the last verdict. Baselines start at the budgets and change
    only by a commit that tightens them.
- **Host tier.** The stable families in `test-remote.psm1`: Accuracy, Builds, Containers, DotnetEdits, Dumps, Il2Cpp,
  Mobile, NativeAot, NativeEdits, NativeFormats, Support and Web. A push run leaves their classes out (here and on the
  test host) and runs only their smoke tests (trait `Smoke=push`: one or two fast tests per family; Accuracy has
  none); it records no pass for these families.
  - `./host-tier.ps1 -Register [-At 02:00]` adds an opt-in Windows scheduled task for the current user (`-Unregister`
    removes it) running `./test.ps1 -HostTier` on HEAD in its own worktree. It builds here only for the family keys,
    sends the tier's classes to `CORVUS_TEST_REMOTE` (as a bundle when origin lacks the commit), and records a pass for
    each family whose classes all ran there and passed with a full result: no test skipped that ran in the last whole
    run here (`.git/corvus-last-whole.trx`, kept by every run without `-Reuse`), no class far shorter there.
  - A class whose inputs are this machine's own, whose file has live real data, or whose real-data or engine variables
    the host lacks stays unsent and is named; its family records no pass. A family with a class that failed there
    returns to push runs, which run it whole (`-Status` names it) until a tier run passes it with a full result.
  - No idle condition (it costs this machine only the build); a missed night runs when the machine is on again; a
    pass stays valid until its family's inputs change. Logs: `.git/corvus-host-tier.log` (test output in `.log.run`),
    host results in `.git/corvus-host-tier.trx`; `-Status` shows what the last run recorded, what failed, the classes
    without a full result and those kept here.
- **Nightly run.** `./nightly.ps1 -Register [-At 02:00]` adds an opt-in Windows scheduled task for the current user
  (`-Unregister` removes it). Each night, once the machine has been idle 10 minutes, it starts a full run of HEAD in
  the background worktree (`-Strength`, `whole` by default, which holds the heavy lock; while another run is going,
  the request is queued and runs on the newest queued commit), waits for that run only, and logs its result with the commit tested and the
  commit asked for. Then it runs `./test.ps1 -Perf` in its own worktree (`corvus-perf-worktree`) on the tested commit,
  unless another full run holds or waits for the heavy lock. The night's run compares 3 engine seeds with a cold
  analysis (`CORVUS_SEED_VALIDATE=3`, left out of reuse keys so a push run's pass still counts). Logs:
  `.git/corvus-nightly.log` (test output in `.log.run`); `-Status` shows the last step.

CI (`.github/workflows/ci.yml`) runs the quick set as a smoke lane plus the offload job; `release.yml` builds the
release archives; `codeql.yml` and `scorecard.yml` scan the code and the repository weekly and on each push, and
Dependabot proposes weekly package and action updates. Every workflow is read-only by default and pins actions by
commit SHA (`ReleaseProvenanceTests`). The shipped projects (`src/Corvus`, `src/Corvus.Clr32`) restore from committed
`packages.lock.json` files: a local restore rewrites them after a package change (commit them with it), and on CI
runners (`CI=true`) every restore is locked, so a package version or hash the lock file does not name fails the
build (`LockFileTests`). The full set and real-application runs are local. To run the Live family (slow tests included) on
macOS and Windows ARM64, start ci.yml by hand: `gh workflow run ci.yml --ref <branch> -f live=true`. That job installs
64-bit Python and the tested Frida release on macos-latest, windows-11-arm, ubuntu-latest and windows-latest and
uploads one TRX per machine (`live-results-<os>`).

## Layout

`tests/Corvus.Tests` has one folder per tool family, so a change's tests are found by folder: `Dotnet`, `DotnetEdits`,
`NativeAnalysis`, `NativeFormats`, `Engines` (IDA and Ghidra), `NativeEdits`, `Builds`, `Containers`, `Mobile`, `Dumps`,
`Live`, `Il2Cpp`, `NativeAot`, `Web`, `Accuracy`, `Session` (workspace, notes, server, setup), `Contract` (catalog,
ratchets, protocol, output-contract sweeps) and `Support` (builders, fixtures, shared harnesses). Namespaces do not
follow folders. Long engine classes are split into nested classes (by engine and topic), since xUnit runs one class's
tests in sequence.

## Test data

- Real libraries come from `<PackageDownload>` items in the test project, read through `RealPackages.Lib`; tests never
  read paths of one machine.
- Data that cannot be redistributed (application folders, Il2Cpp builds, external tools) is found through `CORVUS_*`
  variables (below); a test without its data is skipped.
- A new external tool is wired through a variable with a neutral name, its command-line options kept in one table.

### Test data variables

Every `CORVUS_*` variable the tests and test scripts read, except the server's own ([configuration](configuration.md)).
`TestDataVariablesTests` fails on a variable read but not listed, a listed one no longer read, or a "Read by" cell that
differs from its readers. `CORVUS_UPDATE_DOCS=1` rewrites the "Read by" cells and adds missing variables as rows to
describe.

| Variable | What it names | Read by |
|---|---|---|
| `CORVUS_ACCURACY_DIR` | A research folder (images.json and the reference scores) for the function discovery dump; results go under its results/ours. | AccuracyTests |
| `CORVUS_ACCURACY_IDS` | Comma-separated image ids of images.json to dump (default all). | AccuracyTests |
| `CORVUS_AGENT_SERVER` | The server the agent task runner starts instead of this repository's build. | tests/agents/run-tasks.ps1 |
| `CORVUS_ALL_TESTS` | `1` runs the full set: real-library builds, whole-server sweeps and the downloads the quick set leaves out. | FormatFuzz, FridaEnvironmentTests, test-remote.psm1, test-reuse.psm1, test.ps1 |
| `CORVUS_ANDROID_PACKAGE` | A real Android package (.apk, .aab or split set). | AndroidRealTests, DalvikDisassemblerTests, OutputBudgetTests |
| `CORVUS_ARCHIVE_LISTER` | The 7-Zip command line the NSIS listings are compared with. | InstallerComparisonTests |
| `CORVUS_ASSEMBLY_DIR` | A folder of real .NET assemblies. | CppBindingTests, RealAssemblyTests, SerialTimingTests |
| `CORVUS_BACKGROUND_DIR` | The folder background runs and the nightly perf run keep their worktrees in (default: the temp folder). | host-tier.ps1, nightly.ps1, test-reuse.psm1, test.ps1 |
| `CORVUS_BUNDLE_EXTRACTOR` | The WiX command line whose `burn extract` the WiX Burn listings are compared with. | InstallerComparisonTests |
| `CORVUS_BUNDLE_PAIRS` | A folder of folders, each holding two builds of one JavaScript bundle as old.* and new.*. | JsBundleFilesTests, JsDiffTests |
| `CORVUS_CALLPATH_TARGET` | A method to search call paths to (default: picked from the assemblies). | SerialTimingTests |
| `CORVUS_CAPTURES` | A folder of network captures (key logs beside them as `<name>*.keys`) whose HTTP objects are compared with TShark's. | CaptureObjectsTSharkTests |
| `CORVUS_CDB` | The cdb debugger the minidump stacks are compared with (default: the Windows SDK's). | MinidumpRealTests |
| `CORVUS_CLAUDE` | The claude command line that validates the plugin manifests (default: claude on PATH). | PluginManifestTests |
| `CORVUS_CLIENT_CHECKS` | `1` runs the real-client checks: each installed agent client answers a known question through this build (model calls cost tokens). | ClientCheckTests, tests/agents/run-tasks.ps1 |
| `CORVUS_COMPARE_ASSEMBLY` | The assembly compared between the two builds below. | ComparerTests |
| `CORVUS_COMPARE_EXPECT` | Known type moves between the two builds, `Old.Name=>New.Name;...` (optional). | ComparerTests |
| `CORVUS_COMPARE_NEW_DIR` | The newer of two builds of one application (a folder). | ComparerTests, FolderCompareTests, RealAssemblyTests |
| `CORVUS_COMPARE_OLD_DIR` | The older of the two builds. | ComparerTests, FolderCompareTests, RealAssemblyTests |
| `CORVUS_COVERAGE_REPORT` | The coverlet report of a full run, checked against the coverage floors (`./test.ps1 -Full -Coverage` sets it). | CoverageFloorTests, test.ps1 |
| `CORVUS_DEBUG_ARGS` | `1` prints the call sites whose arguments were not recovered in the system DLL recovery run. | CallArgumentTests |
| `CORVUS_DIFF_PAIRS` | Build pairs matched per source (default 6). | NativeDiffRealTests |
| `CORVUS_ELECTRON_APPS` | A folder of installed Electron apps; every .asar below it (six levels) is read. | ElectronGraphTests, ElectronTests, JsEndpointsTests, NodeApiTests |
| `CORVUS_ELF_CORES` | A folder of Linux or Android ELF core files, with the program's libraries beside them. | ElfCoreTests |
| `CORVUS_EXPORT_LIST` | A file listing assemblies whose exported projects must build; errors go to `<list>.report.txt`. | ExportBuildTests |
| `CORVUS_EXPORT_REAL` | `1` exports real libraries to projects and builds them. | ExportBuildTests |
| `CORVUS_FIRMWARE_IMAGES` | A folder of firmware images whose filesystems are compared file by file with the reference extractors. | FirmwareComparisonTests |
| `CORVUS_FIXTURE_HERMESC` | A folder with one subfolder per Hermes compiler release, for rebuilding the Hermes fixtures. | tests/Corvus.Tests/Web/HermesFixtures/build.ps1 |
| `CORVUS_FIXTURE_LLVM` | A folder holding ld.lld, llvm-objcopy and llvm-nm, for rebuilding the CFI, instruction-set and string form fixtures. | tests/Corvus.Tests/Dumps/CfiFixtures/build.ps1, tests/Corvus.Tests/Engines/IsaFixtures/build.ps1, tests/Corvus.Tests/NativeAnalysis/StringFormFixtures/build.ps1 |
| `CORVUS_FIXTURE_POWERSHELL_LAYERS` | The folder of the PowerShell transformation module the script fixtures are generated with; nothing runs the output. | tests/Corvus.Tests/Web/ScriptFixtures/generate.ps1 |
| `CORVUS_FIXTURE_PYTHONS` | The Python interpreters (separated by the path separator) that compile the Python fixtures. | tests/Corvus.Tests/Containers/PythonFixtures/build.ps1 |
| `CORVUS_FIXTURE_RUSTC` | The rustc that builds the CFI, instruction-set and string form fixtures (default: rustc on PATH). | tests/Corvus.Tests/Dumps/CfiFixtures/build.ps1, tests/Corvus.Tests/Engines/IsaFixtures/build.ps1, tests/Corvus.Tests/NativeAnalysis/StringFormFixtures/build.ps1 |
| `CORVUS_FIXTURE_SWIFT` | The swiftc that builds the Swift string form fixtures (default: swiftc on PATH). | tests/Corvus.Tests/NativeAnalysis/StringFormFixtures/build.ps1 |
| `CORVUS_FIXTURE_SWIFT_STATIC_SDK` | The musl-1.2.5.sdk folder of the Swift Static Linux SDK, for the Linux Swift string form fixtures. | tests/Corvus.Tests/NativeAnalysis/StringFormFixtures/build.ps1 |
| `CORVUS_FORMAT_FUZZ_ITERATIONS` | Mutated inputs per ELF and Mach-O fuzz test (default 300). | ElfFileTests, MachOFileTests |
| `CORVUS_FS_REFERENCE` | The program that runs the firmware reference script as root: sh on Linux, wsl.exe on Windows. | FirmwareComparisonTests |
| `CORVUS_FUZZ_CASES` | Mutated inputs per container and inspection fixture (defaults 40 and 30). | InspectionTests, UnpackTests |
| `CORVUS_FUZZ_COUNT` | Seeds of the simplify and save fuzz tests (defaults 40 and 60). | SaveFidelityTests, SimplifyFuzzTests |
| `CORVUS_FUZZ_SEED` | One simplify fuzz seed to run, or `random` for a fresh one. | SimplifyFuzzTests |
| `CORVUS_GO_SAMPLES` | A folder of Go programs (ELF, PE, Mach-O) whose function tables are read; none is run. | GoRealTests |
| `CORVUS_HBC_DIR` | A folder of Hermes bytecode bundles, read and compared with hbcdump. | HermesTests |
| `CORVUS_HEAVY_LOCK` | A script that takes and reports a machine-wide lock (`heavy <name> -OwnerPid <pid>`), held by whole-suite runs. | nightly.ps1, test-reuse.psm1 |
| `CORVUS_HOSTAPI_PROJECT_DIR` | The root of a C/C++ project with a host function table, for `generate_cpp_binding style=hostapi`. | CppBindingTests |
| `CORVUS_IDA_ORACLE_FILES` | Images (separated by `;`) whose functions are compared with IDA's (default: a fixed set of system DLLs). | NativeCodeOracleTests |
| `CORVUS_IL2CPP_BUILD` | An Il2Cpp build folder or its global-metadata.dat. | Il2CppRawTests, ImportedNamesTests, LiveCompiledNamesRealTests, OutputBudgetTests, SessionFileTests, UnityAssetStringsTests |
| `CORVUS_IL2CPP_BUILD_DUMP` | Reference output for `CORVUS_IL2CPP_BUILD` (dummy assemblies, script.json, stringliteral.json), compared with the built-in reader. | Il2CppRawTests |
| `CORVUS_IL2CPP_DUMMY_DIR` | A folder of dummy assemblies with `[Address]` attributes. | Il2CppExportTests, RealAssemblyTests |
| `CORVUS_IL2CPP_GENERICS_BUILD` | A Windows Il2Cpp build whose code registration is filled at run time. | Il2CppRawTests |
| `CORVUS_IL2CPP_MOBILE` | A folder of Android packages of Il2Cpp builds. | Il2CppMobileTests, NativeIdaFormatsTests |
| `CORVUS_IL2CPP_STRINGS_DIR` | A folder of dummy assemblies with stringliteral.json and script.json (and optionally GameAssembly.dll) beside it. | DumpRealDataTests, Il2CppNavigationTests, Il2CppStringTests |
| `CORVUS_INSTALLERS` | A folder of installers (NSIS, Inno Setup, MSI, WiX Burn) compared by file name and size with the reference listers. | InstallerComparisonTests |
| `CORVUS_JAVA_JARS` | A folder of jars (searched three levels deep) disassembled and compared with javap. | JvmClassTests |
| `CORVUS_LARGE_NATIVE_IMAGE` | A native image of 100 MB or more, for speed measurements. | SimilarFunctionsRealTests |
| `CORVUS_LIVE_SOAK_MINUTES` | Minutes the observed program runs in the long session test (default 2). | LiveLongSessionRealTests |
| `CORVUS_LLVM_BIN` | An LLVM bin folder (clang, llvm-dwp, llvm-readobj, ...) that builds the DWARF and format fixtures and checks their output. | Arm64FormatCodeTests, DwarfDebugMapTests, DwarfObjectTests, DwarfOracleTests, DwarfSplitTests, DwarfVariablesTests, ElfFileTests, FormatWriterTests, ItaniumDemangleTests, MachOFileTests, NativeFixtures |
| `CORVUS_MOBILE_APPS` | A folder of app packages (.apk, .ipa), searched two levels deep. | AppGraphTests, MobileRulesTests |
| `CORVUS_MSI_LISTER` | The lessmsi command line the MSI listings are compared with. | InstallerComparisonTests |
| `CORVUS_NATIVEAOT_SAMPLES` | `1` builds the NativeAOT sample for several frameworks and options and checks the recovered names against its PDB (Windows, with the C++ build tools). | LiveCompiledNamesRealTests, NativeAotSampleTests |
| `CORVUS_NATIVE_ADAPTER_SAMPLE` | Images per folder the adapter consistency test reads (default 60; 0 for all). | NativeAdapterConsistencyTests |
| `CORVUS_NATIVE_LARGE_IMAGE` | One large image whose code index is measured for time, memory and completeness. | NativeCodeSweepTests |
| `CORVUS_NATIVE_STDIO_SAMPLE` | Images per folder of the stdio sweep (default 25). | NativeStdioSweepTests |
| `CORVUS_NATIVE_STRESS_SECONDS` | Seconds the native concurrency test runs (default 30). | NativeConcurrencyTests |
| `CORVUS_NATIVE_SWEEP_LIMIT` | Images of the code index sweep (default 400 in an exhaustive run, a quarter of it in a routine one). | NativeCodeSweepTests |
| `CORVUS_NATIVE_TOOL_FUZZ_DUMP` | A folder that receives the failing inputs of the native tool fuzz test. | NativeToolFuzzTests |
| `CORVUS_NATIVE_TOOL_FUZZ_ITERATIONS` | Iterations of the native tool fuzz test (default 2,500). | NativeToolFuzzTests |
| `CORVUS_NATIVE_TOOL_FUZZ_SEED` | The base seed of the native tool fuzz test. | NativeToolFuzzTests |
| `CORVUS_NATIVE_TOOL_SWEEP_IDA` | Images of the native tool sweep also read through IDA (default 2). | NativeToolSweepTests |
| `CORVUS_NATIVE_TOOL_SWEEP_LIMIT` | Images of the native tool sweep (default 120 in an exhaustive run, a quarter of it in a routine one). | NativeToolSweepTests |
| `CORVUS_NATIVE_TOOL_SWEEP_PF_LIMIT` | Images from the program folders in the native tool sweep (default 120 in an exhaustive run, a quarter of it in a routine one). | NativeToolSweepTests |
| `CORVUS_NETWORK_TESTS` | `1` runs the tests that download from Microsoft's symbol server (runtime DACs, PDBs). | ElfCoreHeapRealTests, ManagedDumpRealTests, PdbOracleTests |
| `CORVUS_PACKAGES_BAD` | A folder of known-bad packages (npm, PyPI, editor extensions) in subfolders; the noteworthy share is checked against floors. | PackageDatasetTests |
| `CORVUS_PACKAGES_GOOD` | A folder of ordinary packages, grouped the same way. | PackageDatasetTests |
| `CORVUS_PACKAGES_REPORT` | A file for one line per package (folder, file, review, findings). | PackageDatasetTests |
| `CORVUS_PDB_SAMPLE` | `image path\|function\|function...`: a real image shipped with its PDB, whose named functions are typed through IDA. | PdbIdaTypesTests |
| `CORVUS_PDFJS` | A folder of extracted pdfjs-dist packages, measured for data flow. | JsFlowTests |
| `CORVUS_PE_FUZZ_DUMP` | A folder that receives the PE fuzz inputs over their time or memory bound. | NativePeFuzzTests |
| `CORVUS_PE_FUZZ_ITERATIONS` | Iterations of the PE fuzz test (default 20,000). | NativePeFuzzTests |
| `CORVUS_PE_FUZZ_SEED` | The base seed of the PE fuzz test. | NativePeFuzzTests |
| `CORVUS_PE_FUZZ_TIME_BOUND_MS` | CPU time bound per PE fuzz input, in milliseconds (default 10,000); an input also fails after 60 s of wall time. | NativePeFuzzTests |
| `CORVUS_PE_SWEEP_LIMIT` | Images of the PE sweep (default all). | NativePeSweepTests |
| `CORVUS_PE_SWEEP_REPORT` | A file for the PE sweep report. | NativePeSweepTests |
| `CORVUS_PERF_FACTOR` | How far over its baseline the simplify sweep may run before it fails (default 5 times). | SimplifySweepTests |
| `CORVUS_PIPELINE_BUDGET_MINUTES` | A pipeline round trip part's total time (default 90 in an exhaustive run, else 45). | PipelineRoundTripTests |
| `CORVUS_PIPELINE_KEEP` | Set to keep the pipeline round trip's work files. | PipelineRoundTripTests |
| `CORVUS_PIPELINE_ONLY` | A substring of the pipeline option names to run. | PipelineRoundTripTests |
| `CORVUS_PIPELINE_PARALLEL` | Pipeline round trips run at once per part (default 1). | PipelineRoundTripTests |
| `CORVUS_PIPELINE_PROFILES` | A folder of bundled .crproj profiles (default: Build/Profiles next to the tool). | PipelineRoundTripTests |
| `CORVUS_PIPELINE_RECHECK` | `1` runs the pipeline options that are skipped with a reason, to see whether they still fail. | PipelineRoundTripTests |
| `CORVUS_PIPELINE_REPORT` | A file for the pipeline report (each part writes its own, its number before the extension). | PipelineRoundTripTests |
| `CORVUS_PIPELINE_SAMPLE` | A substring of the pipeline sample names to run. | PipelineRoundTripTests |
| `CORVUS_PIPELINE_SAMPLES` | A folder of the pipeline tool's sample projects (one Program.cs each), round-tripped beside PipelineSamples/*.cs. | PipelineRoundTripTests |
| `CORVUS_PIPELINE_SEED` | One pipeline seed to run. | PipelineRoundTripTests |
| `CORVUS_PIPELINE_SEEDS` | Pipeline seeds per option (default 3 in an exhaustive run, else one of the three by day). | PipelineRoundTripTests |
| `CORVUS_PIPELINE_TOOL` | The executable of the transformation pipeline tool, which reads a .crproj project. | PipelineRoundTripTests, test-remote.psm1 |
| `CORVUS_R2R_COMPOSITE_DIR` | A composite ReadyToRun app: the output of a self-contained `dotnet publish` with composite ReadyToRun. | ReadyToRunTests |
| `CORVUS_REFERENCE_SERVER` | The server the agent task runner compares against (`{"command": ..., "args": [...]}`). | tests/agents/run-tasks.ps1 |
| `CORVUS_RELEASE_WSL` | The WSL distribution release.ps1 checks the update from the previous release in (default Ubuntu). | release.ps1 |
| `CORVUS_SECOND_GHIDRA_DIR` | A second Ghidra installation; `./test.ps1 -SecondGhidra` runs the engine tests on it. | test.ps1 |
| `CORVUS_SERVER_EXE` | A published server to time for the catalog latency figure (default: the test build through dotnet). | CatalogTimingTests |
| `CORVUS_SETUP_LISTER` | The innounp command line the Inno Setup listings are compared with. | InstallerComparisonTests |
| `CORVUS_SNAPSHOT_RUNS` | Repetitions of the .NET snapshot run (such as 30). | LiveDotnetRealTests |
| `CORVUS_STRYKER` | The Stryker.NET executable for `./test.ps1 -Mutation` (default: dotnet-stryker on PATH). | test.ps1 |
| `CORVUS_STUB_APPS` | `;`-separated `assembly path\|member token\|method token\|type token` entries: applications with missing references, whose first resolutions build stubs. | StubAppsRealDataTests |
| `CORVUS_SWEEP` | `exhaustive` sweeps every input of the real-image sweeps (`./test.ps1 -Full -Exhaustive` sets it); `full` runs the whole simplify sweep. | SimplifySweepTests, SweepScope, test-remote.psm1, test-reuse.psm1, test.ps1 |
| `CORVUS_TEST_OFFLOAD` | `0` keeps the offloaded classes in the local run. | test-remote.psm1 |
| `CORVUS_TEST_PRIORITY` | `normal` keeps a test run at normal priority. | test-reuse.psm1 |
| `CORVUS_TEST_YARA_X` | The folder fetch-yara-x.ps1 fills with the YARA-X builds the tests use. | YaraTestTools, tests/Corvus.Tests/Support/fetch-yara-x.ps1 |
| `CORVUS_UNITY_BUILDS` | `;`-separated Unity build folders and packages (player folders, .app, .apk, WebGL builds), overviewed and their MonoBehaviour assets read by view=unity. | UnityFieldTests, UnityOverviewTests |
| `CORVUS_UPDATE_DOCS` | `1` rewrites the generated documents instead of failing on a difference. | DocsTests, ErrorContractTests, MigrationReasonTests, ProtocolSampleTests, SampleDocsTests, SaveFidelityTests, SchemaDocsTests, SimplifyContractTests, SkillTests, release.ps1, test-reuse.psm1 |
| `CORVUS_UPDATE_RATCHETS` | `1` drops ratchet entries that now comply and writes a missing list from the current state. | CountRatchet, Ratchet |
| `CORVUS_VCALL_IMAGE` | A real C++ image for the virtual call acceptance run. | VirtualCallTests |
| `CORVUS_VCALL_SAMPLE` | Call sites of that image sampled (default 150). | VirtualCallTests |
| `CORVUS_WASM_DIR` | A folder of .wasm files, validated and converted to text, compared with WABT. | WasmTextTests, WasmValidationTests |
| `CORVUS_WEBPACK_APPS` | A folder of folders, each an app's extracted webpack output. | JsRuntimeTests |
| `CORVUS_WPF_APPS` | A folder of WPF programs (.exe, three levels deep) whose BAML must decompile to XAML that parses. | XamlEventsTests |
| `CORVUS_SEED_VALIDATE` | How many engine seeds to compare with a cold analysis of their input; the night's run sets `3`. | EngineSeedTests, nightly.ps1, test-reuse.psm1 |
| `CORVUS_TEST_REMOTE` | The test host (`user@host`) prepared by `test-remote-setup.ps1`; a whole-suite run sends its offloaded classes there when it answers over ssh. | host-tier.ps1, test-remote-setup.ps1, test-remote.psm1, test.ps1 |
| `CORVUS_TEST_SCP` | The scp program, or a `.ps1` script standing in for it; OpenSSH's own when unset. | test-remote-setup.ps1, test-remote.psm1 |
| `CORVUS_TEST_SSH` | The ssh program, or a `.ps1` script standing in for it; OpenSSH's own when unset. | test-remote-setup.ps1, test-remote.psm1 |
| `CORVUS_WINDOWS_APP_SDK` | A Microsoft.WindowsAppSDK package version whose XAML compiler builds the test app. | XbfCompilerTests |

### Variables the test scripts set

`test.ps1` and the test harness set these for their own runs; they are not inputs.

- `CORVUS_CHILD_TEST` (ChildTest): marks the process ChildTest starts to run one test's body alone.
- `CORVUS_MUTATION_REPORT` (MutationTests, test.ps1): the Stryker.NET report `./test.ps1 -Mutation` hands to MutationTests.
- `CORVUS_PERF` (PdbIdaTypesTests, PerfBudget, test.ps1): `1` in the perf run, the only run whose budgets fail tests.
- `CORVUS_PERMITS_HELD` (MachinePermits, test-reuse.psm1, test.ps1): `1` when the run holds the machine permits itself, so its tests take none.
- `CORVUS_PERMIT_LOG` (MachinePermits, test-reuse.psm1, test.ps1): the file tests append their permit waits to, for the run's time record.
- `CORVUS_TEST_ENGINE` (NativeIdaProviderTests, test.ps1): `ghidra` in the second-Ghidra pass, where the IDA-only tests skip.
- `CORVUS_TEST_GH` (test-remote.psm1): a stand-in for gh in the offload tests.
- `CORVUS_TEST_HISTORY` (CollectionOrder, test-reuse.psm1, test.ps1): the recorded class times, so the longest classes start first.
- `CORVUS_TEST_MODE` (CollectionOrder, test-reuse.psm1, test.ps1): the run's mode, which picks the recorded times that apply.
- `CORVUS_TEST_PUSH_RUN` (test-remote.psm1, test.ps1): `1` in the background run a push starts.

## Guard tests

These fail when a change misses a follow-up step (CONTRIBUTING.md lists them):

- catalog audit and size ceiling, toolsets, parameter domains, contract sweep and tool effects;
- layering (which namespaces may use which);
- README sync (tool tables, tool and prompt counts) and doc facts (clients, release targets, commands, environment
  variables, release-notes version, links, command-line examples);
- guide coverage (every tool is named in the guide; the guide, skill and docs name only registered tools);
- community files (SECURITY.md names every call that starts a process or reaches the network; CONTRIBUTING.md, issue
  forms; no machine path in a tracked file);
- ratchets: each list in `tests/Corvus.Tests/Ratchets` may only shrink, and every entry states a `# permanent:` reason;
  the measured lists (`coverage.txt`, `duplicate-lines.txt`; `CountRatchet`) hold one value per key that moves one way
  only, and `CORVUS_UPDATE_RATCHETS=1` records a tighter value;
- dead code and copies: unused or never-read private members (IDE0051, IDE0052) are build errors; the full set counts
  the significant lines of `src/` (no blanks, comments, lone braces or usings) in copied blocks of 8 or more, per file
  pair, against `Ratchets/duplicate-lines.txt` (`DuplicateCodeTests`);
- coverage floor: `./test.ps1 -Full -Coverage` collects line coverage of the server (coverlet, `corvus` only) over the
  whole suite and checks each source area (`src/Corvus/<folder>`, a level deeper under `Native`, `Services` and
  `Tools`) and the total against `Ratchets/coverage.txt`, floors one point below the recording run;
- format fuzzing: every format reader (found by reflection) has a quick fuzz test marked `[FuzzEntry]`, or a reviewed
  entry in `Ratchets/format-fuzz.txt`;
- protocol matrix: every MCP protocol version the SDK speaks is negotiated and answered;
- real-data speed: a test that reads real-world data (a real-data attribute, or a `CORVUS_*` data variable in its code)
  carries `Speed=Slow` on the method or class, so setting the variable never slows the quick set (`RealDataSpeedTests`);
- process environment: a class that sets a `CORVUS_*` variable of the test process runs in the `ProcessEnvironment`
  collection (alone), sets an external tool's variable in that tool's collection, or sets it in a body `ChildTest`
  reruns in a child process (`EnvironmentCollectionTests`);
- leaks: once every test has run, child processes of the test process still running, or files left in the run's own
  temporary folder (TMP, TEMP and TMPDIR point there for the tests and the servers they start), fail the run with
  their names. A folder a class keeps for the whole run is registered with `LeakGuard.DeleteAtEnd`.

## Mutation testing, client checks and the token benchmark

On demand (gates and releases), never in the quick or full set by default; each skips with the reason when its tool is
missing.

- **Mutation testing** (`./test.ps1 -Mutation [-Target sqlite,pe]`): Stryker.NET (`CORVUS_STRYKER`, else
  `dotnet-stryker` on PATH) mutates the targets in `tests/mutation.json` (the core readers: SQLite, pcap, PE, ELF,
  Mach-O, the ARM decoders; the file holds every Stryker option) in one run, with the tests that read them. Stryker
  compiles the whole project once per run (about an hour, whatever is mutated), so targets share a run. Surviving
  mutants (survived or not covered) per target are checked against `Ratchets/mutation-survivors.txt`
  (`MutationTests`); the score per target is printed.
- **Installer listings** (`InstallerComparisonTests`): with `CORVUS_INSTALLERS` naming a folder with `nsis`, `inno`,
  `msi` and `burn` subfolders, each installer's files (name and size) are compared with `CORVUS_ARCHIVE_LISTER`
  (7-Zip), `CORVUS_SETUP_LISTER` (innounp), `CORVUS_MSI_LISTER` (lessmsi) or `CORVUS_BUNDLE_EXTRACTOR` (the WiX `wix`
  tool). A format whose tool is unset is skipped; each installer must match at least 99% of the reference rows.
- **Dependencies against syft** (`DependencyListerComparisonTests`, `CORVUS_DEPENDENCY_LISTER`): an app with two NuGet
  packages, published as a framework-dependent single-file bundle and as a folder, must list in `view=dependencies`
  every NuGet package URL syft lists, and both packages on each. A built Android package must list every package URL
  syft lists for it, and every Maven URL it lists for the same bytes read as a Java archive.
- **Advisories against osv-scanner** (`OsvAdvisoriesTests`, `CORVUS_OSV_SCANNER`, offline databases downloaded): an
  app with an old Newtonsoft.Json and NLog, published with a lock file, must report in `view=dependencies` the same
  advisories osv-scanner reports for that packages.lock.json.
- **Compiled XAML** (`XbfCompilerTests`, `CORVUS_WINDOWS_APP_SDK` naming a Microsoft.WindowsAppSDK version): a WinUI
  app (application, window, a page of resources, styles, templates, visual states, conditional XAML) is built; each
  `.xbf` read with `view=xbf` must be complete, declare the source's elements in order and resolve every event handler
  the source names.
- **Il2Cpp capabilities against capa** (`Il2CppCapaTests`, `CORVUS_CAPA` naming standalone capa 10.0.0): the freeze
  file for a built x64 Il2Cpp binary whose functions call methods named as `File.WriteAllText`, `RegistryKey.GetValue`
  and `HttpClient.GetAsync` must load in capa and match "write file in .NET", "query or enumerate registry value" and
  "send HTTP request" at the calling functions. Rerun for each capa release: the freeze format changes between them.
- **Behaviour labels against capa** (`NativeCapaTests`, `CORVUS_CAPA` naming standalone capa 10.0.0): a built x64
  program whose functions call `CreateProcessA`, `RegSetValueExA` and `ExitProcess` must get "create process on
  Windows", "set registry value" and "terminate process" at those functions, read from capa's result document
  through the worker host. capa itself only reads the program.
- **Whole-program emulation against speakeasy** (`ProgramEmulationRealTests`, `CORVUS_EMULATOR` naming speakeasy
  2.0.0b9): a small x86 program allocates a page, decodes a fixed text into it, writes it to a file and exits;
  `emulate_native engine=speakeasy` must list its five kernel32 calls in order, save the file with the text and hold
  the text at the allocation in its region set. A second build calls a function no emulator models and must stop by
  that function's name.
- **Capture HTTP objects against Wireshark** (`CaptureObjectsTSharkTests`, `CORVUS_TSHARK`): synthetic captures
  (Content-Length, chunked, gzip / deflate / brotli, pipelining, resent segments, ranges, bodies ending at close,
  request bodies) must export exactly the files `tshark --export-objects http` exports, by SHA-256. With
  `CORVUS_CAPTURES` (key logs beside them as `<name>*.keys`), every object TShark exports must be among ours; TShark's
  `object<frame>` files from frames that start no HTTP message are counted apart.
- **Package review on real packages** (`PackageDatasetTests`): `CORVUS_PACKAGES_BAD` (known-bad npm, PyPI and VS Code
  packages) and `CORVUS_PACKAGES_GOOD` (ordinary ones), each grouped in subfolders; prints the noteworthy share per
  subfolder and checks both against floors. `CORVUS_PACKAGES_REPORT` names a file for one line per package.
- **Repeated snapshots of a .NET program** (`LiveDotnetRealTests`, full set, `CORVUS_SNAPSHOT_RUNS` such as 30): each
  run starts the readers program on a new server, snapshots it while it reads, and checks that it finishes every open
  and exits with code 0, per architecture (Windows x64 and x86, Linux x64).
- **Real-client checks** (`tests/agents/run-tasks.ps1`, or the full set with `CORVUS_CLIENT_CHECKS=1`): each installed
  agent client (Claude Code, Codex, Gemini CLI; `CORVUS_CLIENT_CLAUDE`, `CORVUS_CLIENT_CODEX`, `CORVUS_CLIENT_GEMINI`
  name other executables) gets one known-answer question about the Notes sample through this build's server, graded
  by the facts in `tests/agents/tasks.json`. Client options live in `tests/agents/clients.json`. A client that is not
  installed or not signed in is skipped.
- **Token benchmark** (`run-tasks.ps1 -Set bench -Server corvus,reference -Runs 3`): ten known-answer tasks per client
  and server; records correctness, tools called, input tokens (with the cached part), output tokens, cost and wall
  time in `results.jsonl`. `CORVUS_REFERENCE_SERVER` is the server to compare against (JSON
  `{"command": ..., "args": [...]}`); `CORVUS_AGENT_SERVER` replaces this build.

## Generated documents

Generated from the code and compared by tests: `docs/errors.md`, `docs/limitations.md`, `docs/migration-reasons.md`,
`docs/simplify.md`, `docs/saving.md`, `docs/tools.md`, `docs/schemas`, the client table of `docs/installation.md`, the
skill in `skills/corvus`, the protocol samples and the "Read by" cells above. After changing their sources, regenerate
and commit:

```sh
CORVUS_UPDATE_DOCS=1 dotnet test
```

## Guides and showcases

`docs/guides` and `docs/showcase` run on `samples/Notes`, which the test project builds. Each `<!-- check: ... -->`
comment marks the fenced block after it: `setup` commands must succeed, a `batch` runs its steps in one session, a
`run` starts the sample, and the following `output` block must equal what they print (repository paths made relative,
each SHA-256 and GUID replaced by a label such as `<sha256-1>`). The quick set checks block shape; the full set runs
them (`SampleDocsTests`); `CORVUS_UPDATE_DOCS=1` with the full set rewrites the output blocks.

## Command-line tests

The command line is tested in process (`ToolCli.RunAsync` with in-memory I/O and a server over in-memory streams):
one server start per test, no published program needed.
