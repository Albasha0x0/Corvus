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
  builds incrementally), and a failure is fixed in the next commit. Every 10 s of the run, a sampler records how late
  the run woke for the sample, the time a normal-priority helper takes to create a small file in the permit folder and
  in the temp folder, with that volume's disk queue and idle time, free memory and pages/s
  (`.git/corvus-background.log.io`); `-Status` names each window in which a file took over 1 s or the run woke over 1 s
  late, so a run starved of CPU is told apart from a slow disk. A push while a run is going is queued: when the run
  ends, one run starts on the newest commit, at the strongest strength asked meanwhile. `./test.ps1 -Wait` returns
  when the run and any run queued behind it end, prints the result and exits 0 on a pass, so a script or agent waits
  on it instead of polling `-Status`. A whole-suite run without reuse (the nightly run, a release gate) holds an exclusive machine lock while it runs when `CORVUS_HEAVY_LOCK` names a lock script
  (called as `heavy <name> -OwnerPid <pid>`, which waits for the lock, and `release <name>`), so other load on the machine waits for it; a push run (`-Reuse`) takes none and relies on the machine-wide permits. Every test run except `-Perf`, in the
  foreground or the background, runs at below-normal priority (nice 10 on Linux and macOS; its builds, test hosts and
  engine workers inherit it), so the desktop stays responsive; `CORVUS_TEST_PRIORITY=normal` keeps normal priority. A
  background run reuses family passes; it is routine strength, a quarter of the sweeps
  without the `Tier=Release` tests (`-Exhaustive`: release strength; `-Whole`: release strength without reuse). `./test.ps1 -Affected` runs the quick set plus the slow
  tests of the families changed since `origin/main` in the foreground (shared code such as `Core`, `Mcp` or test
  `Support` runs everything). Releases gate on the full set: a routine `./test.ps1 -Full` sweeps an evenly spread
  quarter of the real images and leaves out the tests marked `[Trait("Tier", "Release")]` (measurements, accuracy
  oracles against IDA, the largest inputs); `-Exhaustive` (gates and releases, `CORVUS_SWEEP=exhaustive`) takes
  every image and those tests. A `-Filter` given on the command line keeps them. `./test.ps1 -Full` records the clean tree it
  passed on (in `.git`), and `-IfChanged` and `release.ps1` skip a second full run on that tree. A run keeps its results
  until the next one: if recording them fails, `./test.ps1 -Stamp` records them without a rerun, on the same tree only. Each full run on a
  clean tree also records which test families passed, under a key of the family's own folders, all shared code, the
  repository files its tests read, the SDK, the OS build and the `CORVUS_*` settings, with the state of each tool,
  engine install or data folder a setting names (a file's size and write time, a folder's files to three levels down;
  and the IDA install IDA's own configuration names) and of each external tool found on PATH or in a default folder,
  so a tool installed or updated in place reruns everything (`test-reuse.psm1`). A run that reuses nothing checks the selection: a family
  that fails under the key of a recorded pass is a selection miss, logged in `.git/corvus-selection-misses.txt` and shown
  by `-Status`.
  `./test.ps1 -Full -Reuse` then runs only the families whose key changed, plus the contract tests and the classes
  known to be flaky under load; its stamp is marked `reused`. `./test.ps1 -CoverageMap` (one instrumented run
  per family; a whole background run refreshes a map 6 days old) records which source files each family's tests run, and for a week the keys follow it: a shared file
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
  kept in `.git/corvus-last-run-labels.txt`; the run stays failed. Each failure's first message lines are printed with
  the labels, and the run's results and its rerun's are kept in `.git/corvus-failed-runs` (the newest 10 runs). A
  test that runs past its hang limit (2 minutes in a quick run, 30 minutes in a full run) ends the run with a dump of
  the test host, kept with the test sequence in
  `.git/corvus-hang-<time>`. `tests/Corvus.Tests/Ratchets/quarantine.txt` lists quarantined tests, one
  `Class.Method | owner | issue | yyyy-MM-dd` line each, the date by which the test is fixed or removed: a quarantined
  test still runs and its failure is reported, but it alone does not fail a run that completed; past its date the
  entry no longer applies, and `QuarantineListTests` fails until it is removed.
- **Releases.** `release.ps1` runs no suite in the foreground: it ships when a full pass (background, nightly or
  `./test.ps1 -Full`, each recorded in `.git/corvus-full-passes.txt`) is on the release commit or an ancestor at most
  `-MaxBehind` (50) commits back, stops on a background failure after that pass on its history (`-SkipTests` overrides), names the families not
  yet verified on the current inputs, and runs the quick set after the version bump. A failure found later goes into a
  patch release. For release-strength passes, start `./test.ps1 -Full -Background -Exhaustive` (or `-Whole`).
- **Offloaded classes.** Every push to main also runs three groups of heavy classes on GitHub-hosted runners: the
  engine-free sweeps, matrices and reference comparisons (the table in `test-remote.psm1`), the classes that use only
  Ghidra (the release pinned in `Support/remote-tools-assets.json`, on a pinned JDK), and the live family (Frida
  17.24.3). A class that uses both engines goes with the Ghidra group and keeps its IDA tests here (the trait
  `Engine=ida` or `Engine=ghidra` of each engine fact); the two halves join per test. Tests that need real data never
  go to GitHub. The groups are the `offload` job of `ci.yml`, dealt to Windows shards, with the cross-platform classes
  on Linux as a check (`./test.ps1 -RemoteRun -Group <group> -Shard <i>/<n>` runs one shard). A routine whole-suite run here on a
  commit that has that job (the background push run, or `-Full` on a commit on `origin/main`) leaves those classes out,
  waits for the run with `gh`, and joins its TRX results, so family passes and the tree stamp need both halves. A class
  runs once more here when it failed a test there on any platform, skipped a test there that ran here in the last whole
  run (for a class using both engines: skipped a test on both sides that ran here then), or has no results there (a run
  that does not appear within 2 minutes, a failed or cancelled job); its result here is the one that counts. `-Status`
  shows one `github` line, and it and the time report name each class that failed there with its result here;
  `CORVUS_TEST_OFFLOAD=0` runs everything here.
- **Test host.** Prepare a second machine for test runs: `./test-remote-setup.ps1 -Target user@host` sets up a Windows
  machine over OpenSSH with the PowerShell 7, MinGit, Python, JDK and Ghidra releases pinned with their SHA-256 in
  `Support/remote-tools-assets.json` (under `~/corvus-test-host/tools`), the reference tools the real-data classes
  compare against from the same table (wabt, baksmali, jadx-headless-mcp, Vineflower, the Hermes CLI releases and
  TShark, the last from the Wireshark installer package by an administrative extract, with their variables set), the
  Frida release the server pins, a clone of
  the repository, the .NET SDK `global.json` names with the x64 and x86 runtimes the tests start programs on (checked
  against Microsoft's release metadata), and the Visual C++ build tools (the bootstrapper's Microsoft signature is
  checked). A step keeps what is already there, so running it again fills only the gaps; `-Check` changes nothing and
  names what is missing. The host needs OpenSSH Server, an administrator account and this machine's key in its
  authorized keys; its engine and live permits are its own. With `CORVUS_TEST_REMOTE` naming such a host (`user@host`)
  and the host answering over ssh, a whole-suite run sends its offloaded classes there instead of waiting for GitHub:
  one `dotnet test` run, one at a time, at below-normal priority in a worktree of the host's clone, with the TRX results
  copied back by scp and joined as above. A test host also takes the host group, which never goes to GitHub: the
  Program Files sweep and the timed and working-set classes, which need a machine no other run loads, and the classes
  with real-data facts whose variables the host has set: copy the real data there with
  `./test-remote-setup.ps1 -Target user@host -Data` (the folders and files the real-data variables name here, links
  followed, into `~/corvus-data` with the variables set to the copies; a copy whose size and name still match is kept,
  and a copy that would leave under 10 GB free is refused; `-Check` names what is missing). Variables that name a
  program the tests run (the tool table in `test-remote.psm1`) are not copied. A class whose variable the host lacks,
  data or program, stays here, and the run names it. A host with its own licensed IDA Pro 9 or newer
  (`./test-remote-setup.ps1 -Target user@host -IdaDirectory <folder there>` sets `CORVUS_IDA_DIR` there; setup never
  installs IDA) also takes about half the classes with IDA facts, dealt longest first by their recorded times so the
  IDA tests run on both machines at once; it runs them whole, Ghidra facts included. IDA classes in files with
  real-data facts stay here. A push run leaves the host group's classes that no test host
  takes, and those a host left without a failure, to the nightly whole run: it records no family pass for their
  families, and `-Status` names them. A class that failed on the host still runs again here. Run a filter repeatedly on the host:
  `./test.ps1 -Remote -Filter <filter> -Repeat <n>` sends the working tree as it is (uncommitted changes included, as a
  git bundle; nothing is pushed), builds it there once and runs the filter `n` times, printing each run's exit code and
  copying the TRX files of failed runs to `TestResults/remote`.
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
- **Tests in a process of their own.** A test that measures the whole process (heap growth, retained memory, working
  set) or sets a variable of the process reruns its body in a process of its own (`Support/ChildTest.cs`), so it runs
  beside the parallel classes instead of alone after them. The sweeps, fuzzers and timed tests run in parallel too; a
  timing budget holds only in the perf run, which runs alone. What still runs alone after the parallel classes:
  deadline and cancellation timings (parallel classes starve the thread pool), tests that rebuild `samples/` and the
  relay's real-server run.
- **Shared engine analyses.** IDA and Ghidra tests on the System32 sample start from a copy of one saved analysis per
  engine, engine install and server build (`Support/EngineSeed.cs`, kept under `corvus-test-data/engine-seed` in the
  temporary folder), instead of analysing it again in every empty cache: about half the time of those classes. Tests
  that measure or check a cold open keep an empty cache.
- **Timing budgets.** A test that times its work against a budget also asserts the mechanism that makes the work fast:
  a cache hit, a process not started, one worker request. It carries `[Trait("Perf", "Timing")]` and reports each
  measurement through `PerfBudget.Time`, `AtMost` or `AtLeast` as one line, `perf: <name> <value> <unit> (budget <= <limit>
  <unit>)`. Gating runs only record the line. The perf run (`./test.ps1 -Perf`, nightly after a full run: `CORVUS_PERF=1`,
  filter `Perf=Timing`, one test at a time) enforces the budgets. It runs alone on the machine: it holds the heavy lock
  and every test permit. A test over its budget runs up to 4 more times and counts as over only when most of the 5
  samples are. Each measurement is also compared with `tests/Corvus.Tests/Ratchets/perf-baseline.txt`, one baseline per
  name and OS (a new measurement name needs a line there): a value past 1.5 times its baseline (below a rate's baseline
  divided by 1.5) runs its tests 4 more times, and the measurement regresses when the median of each sample's worst
  value is past it. The run fails only on a test over budget or a regressed measurement that was also so in the perf
  run before (`.git/corvus-perf-verdicts.json`), so a single slow run is reported but does not fail the run; `-Status`
  shows the last verdict. The baselines start at the budgets and change only by a commit that tightens them.
- **Host tier.** The host tier in `test-remote.psm1` names the stable families (test folders) whose tests change
  least: Accuracy, Builds, Containers, DotnetEdits, Dumps, Il2Cpp, Mobile, NativeAot, NativeEdits, NativeFormats,
  Support and Web.
- **Nightly run.** `./nightly.ps1 -Register [-At 02:00]` adds a Windows scheduled task for the current user (opt-in;
  `-Unregister` removes it). Each night, once the machine has been idle for 10 minutes, it starts a full run of HEAD in
  the background worktree (`-Strength`, whole by default, which holds the heavy lock), waits for it and any run queued
  behind it, then runs `./test.ps1 -Perf`, unless another full run holds or waits for the heavy lock by then. The
  night's run also compares 3 engine seeds with a cold analysis (`CORVUS_SEED_VALIDATE=3`, left out of the reuse
  keys so a push run's pass still counts). Each step goes to `.git/corvus-nightly.log`, the test output to
  `.git/corvus-nightly.log.run`, and `-Status` shows the last step.

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
  environment variables (the table below), and a test without its data is skipped.
- A new external tool used by tests is wired through an environment variable with a neutral name, with its command-line
  options kept in one table.

### Test data variables

Every `CORVUS_*` variable the tests and test scripts read, except the server's own (in [configuration](configuration.md)).
`TestDataVariablesTests` checks the list against the code: a variable read and not listed, a listed variable no longer
read, or a "Read by" cell that differs from the classes and scripts that read it fails the test. With
`CORVUS_UPDATE_DOCS=1` it rewrites the "Read by" cells and adds a missing variable as a row to describe.

| Variable | What it names | Read by |
|---|---|---|
| `CORVUS_ACCURACY_DIR` | A research folder (images.json and the reference scores) for the function discovery dump; results go under its results/ours. | AccuracyTests |
| `CORVUS_ACCURACY_IDS` | Comma-separated image ids of images.json to dump (default all). | AccuracyTests |
| `CORVUS_AGENT_SERVER` | The server the agent task runner starts instead of this repository's build. | tests/agents/run-tasks.ps1 |
| `CORVUS_ALL_TESTS` | `1` runs the full set: real-library builds, whole-server sweeps and the downloads the quick set leaves out. | FormatFuzz, FridaEnvironmentTests, test-remote.psm1, test-reuse.psm1, test.ps1 |
| `CORVUS_ANDROID_PACKAGE` | A real Android package (.apk, .aab or split set). | AndroidRealTests, DalvikDisassemblerTests, OutputBudgetTests |
| `CORVUS_ARCHIVE_LISTER` | The 7-Zip command line the NSIS listings are compared with. | InstallerComparisonTests |
| `CORVUS_ASSEMBLY_DIR` | A folder of real .NET assemblies. | CppBindingTests, RealAssemblyTests, SerialTimingTests |
| `CORVUS_BACKGROUND_DIR` | The folder background runs keep their worktree in (default: the temp folder). | test-reuse.psm1, test.ps1 |
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
| `CORVUS_FIXTURE_LLVM` | A folder holding ld.lld, llvm-objcopy and llvm-nm, for rebuilding the CFI and instruction-set fixtures. | tests/Corvus.Tests/Dumps/CfiFixtures/build.ps1, tests/Corvus.Tests/Engines/IsaFixtures/build.ps1 |
| `CORVUS_FIXTURE_POWERSHELL_LAYERS` | The folder of the PowerShell transformation module the script fixtures are generated with; nothing runs the output. | tests/Corvus.Tests/Web/ScriptFixtures/generate.ps1 |
| `CORVUS_FIXTURE_PYTHONS` | The Python interpreters (separated by the path separator) that compile the Python fixtures. | tests/Corvus.Tests/Containers/PythonFixtures/build.ps1 |
| `CORVUS_FIXTURE_RUSTC` | The rustc that builds the CFI and instruction-set fixtures (default: rustc on PATH). | tests/Corvus.Tests/Dumps/CfiFixtures/build.ps1, tests/Corvus.Tests/Engines/IsaFixtures/build.ps1 |
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
| `CORVUS_IL2CPP_DUMMY_DIR` | A DummyDll folder written by an Il2Cpp dumper. | Il2CppExportTests, RealAssemblyTests |
| `CORVUS_IL2CPP_GAME` | An Il2Cpp game folder or its global-metadata.dat. | Il2CppRawTests, ImportedNamesTests, LiveCompiledNamesRealTests, OutputBudgetTests, SessionFileTests |
| `CORVUS_IL2CPP_GAME_DUMP` | A dumper's output for `CORVUS_IL2CPP_GAME` (DummyDll folder, script.json, stringliteral.json), compared with the built-in reader. | Il2CppRawTests |
| `CORVUS_IL2CPP_GENERICS_GAME` | A Windows Il2Cpp game whose code registration is filled at run time. | Il2CppRawTests |
| `CORVUS_IL2CPP_MOBILE` | A folder of Android packages of Il2Cpp games. | Il2CppMobileTests, NativeIdaFormatsTests |
| `CORVUS_IL2CPP_STRINGS_DIR` | A DummyDll folder with stringliteral.json and script.json (and optionally GameAssembly.dll) beside it. | DumpRealDataTests, Il2CppNavigationTests, Il2CppStringTests |
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
| `CORVUS_PE_FUZZ_TIME_BOUND_MS` | Time bound per PE fuzz input, in milliseconds (default 10,000). | NativePeFuzzTests |
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
| `CORVUS_SWEEP` | `exhaustive` sweeps every input of the real-image sweeps (`./test.ps1 -Full -Exhaustive` sets it); `full` runs the whole simplify sweep. | SimplifySweepTests, SweepScope, test-reuse.psm1, test.ps1 |
| `CORVUS_TEST_OFFLOAD` | `0` keeps the offloaded classes in the local run. | test-remote.psm1 |
| `CORVUS_TEST_PRIORITY` | `normal` keeps a test run at normal priority. | test-reuse.psm1 |
| `CORVUS_TEST_YARA_X` | The folder fetch-yara-x.ps1 fills with the YARA-X builds the tests use. | YaraTestTools, tests/Corvus.Tests/Support/fetch-yara-x.ps1 |
| `CORVUS_UNITY_TITLES` | `;`-separated Unity game folders, overviewed beside the game libraries found on the machine. | UnityOverviewTests |
| `CORVUS_UPDATE_DOCS` | `1` rewrites the generated documents instead of failing on a difference. | DocsTests, ErrorContractTests, MigrationReasonTests, ProtocolSampleTests, SampleDocsTests, SaveFidelityTests, SchemaDocsTests, SimplifyContractTests, SkillTests, release.ps1, test-reuse.psm1 |
| `CORVUS_UPDATE_RATCHETS` | `1` drops ratchet entries that now comply and writes a missing list from the current state. | CountRatchet, Ratchet |
| `CORVUS_VCALL_IMAGE` | A real C++ image for the virtual call acceptance run. | VirtualCallTests |
| `CORVUS_VCALL_SAMPLE` | Call sites of that image sampled (default 150). | VirtualCallTests |
| `CORVUS_WASM_DIR` | A folder of .wasm files, validated and converted to text, compared with WABT. | WasmTextTests, WasmValidationTests |
| `CORVUS_WEBPACK_APPS` | A folder of folders, each an app's extracted webpack output. | JsRuntimeTests |
| `CORVUS_WPF_APPS` | A folder of WPF programs (.exe, three levels deep) whose BAML must decompile to XAML that parses. | XamlEventsTests |
| `CORVUS_SEED_VALIDATE` | How many engine seeds to compare with a cold analysis of their input; the night's run sets `3`. | EngineSeedTests, nightly.ps1, test-reuse.psm1 |
| `CORVUS_TEST_REMOTE` | The test host (`user@host`) prepared by `test-remote-setup.ps1`; a whole-suite run sends its offloaded classes there when it answers over ssh. | test-remote-setup.ps1, test-remote.psm1, test.ps1 |
| `CORVUS_TEST_SCP` | The scp program, or a `.ps1` script standing in for it; OpenSSH's own when unset. | test-remote-setup.ps1, test-remote.psm1 |
| `CORVUS_TEST_SSH` | The ssh program, or a `.ps1` script standing in for it; OpenSSH's own when unset. | test-remote-setup.ps1, test-remote.psm1 |

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
- process environment: a test class that sets a `CORVUS_*` variable of the test process runs in the
  `ProcessEnvironment` collection (nothing beside it), sets an external tool's variable in that tool's collection, or
  sets it in a body that `ChildTest` reruns in a process of its own (`EnvironmentCollectionTests`);
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
- **Dependencies against a reference SBOM tool** (`DependencyListerComparisonTests`): with `CORVUS_DEPENDENCY_LISTER`
  naming syft, an app with two NuGet packages is published as a framework-dependent single-file bundle and as a folder;
  `view=dependencies` must list every NuGet package URL the tool lists, and both packages on each. A built Android
  package must list every package URL the tool lists for it, and every Maven URL the tool lists for the same bytes read
  as a Java archive.
- **Advisories against osv-scanner** (`OsvAdvisoriesTests`): with `CORVUS_OSV_SCANNER` naming osv-scanner and its
  offline databases downloaded, an app with an old Newtonsoft.Json and NLog is published with a lock file; the
  advisories of `view=dependencies` must equal the ones osv-scanner reports for that packages.lock.json.
- **Capture HTTP objects against Wireshark** (`CaptureObjectsTSharkTests`): with `CORVUS_TSHARK` set, synthetic
  captures (Content-Length, chunked, gzip / deflate / brotli, pipelining, resent segments, ranges, bodies ending at
  close, request bodies) must export exactly the files `tshark --export-objects http` exports, by SHA-256. With
  `CORVUS_CAPTURES` naming a folder of captures (key logs beside them as `<name>*.keys`), every object TShark exports
  must be among ours; TShark's `object<frame>` files from frames that start no HTTP message are counted apart.
- **Package review on real packages** (`PackageDatasetTests`): `CORVUS_PACKAGES_BAD` names a folder of known-bad npm,
  PyPI and VS Code packages and `CORVUS_PACKAGES_GOOD` one of ordinary packages, each grouped in subfolders; prints the
  noteworthy share per subfolder and checks both against floors. `CORVUS_PACKAGES_REPORT` names a file for one line
  per package with its findings.
- **Repeated snapshots of a .NET program** (`LiveDotnetRealTests`, full set): `CORVUS_SNAPSHOT_RUNS` names a number of
  runs (such as 30); each run starts the readers program on a new server, snapshots it while it reads, and checks that
  it finishes every open and exits with code 0, per architecture (Windows x64 and x86, Linux x64).
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
