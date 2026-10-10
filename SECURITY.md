# Security policy

## Reporting a vulnerability

Report vulnerabilities privately through the repository's **Security** tab ("Report a vulnerability"). Do not open a
public issue for a security problem. Include the version (`NetDecompilerMcp version`), the operating system, the MCP
client, and the smallest input or tool call that shows the problem.

Before attaching anything, remove what you may not share: proprietary binaries, crash dumps (they hold process memory),
symbol files, paths and user names. A synthetic or public sample that reproduces the problem is preferred.

Fixes go into the next release; the release notes name the fixed problem once a release is available.

## Security boundary

The server analyzes files; it does not run them.

- **Inputs are read as bytes.** Loading, decompiling, disassembling and patching parse files in the server's own process.
  Nothing from an analyzed file is executed, with one exception below. Malformed files are reported as errors.
- **`simplify_methods`** evaluates string-decoder calls in a safe IL interpreter: a fixed instruction subset, no I/O,
  reflection, native code or mutable statics, an instruction budget, 16 MB of simulated memory and 5 s per method.
  Calls outside that subset are left in place and reported ([docs/simplify.md](docs/simplify.md)).
- **`inspect_process`** (opt-in toolset `live`) opens only query and read handles to a running process, writes and
  suspends nothing, and closes every handle before it returns.
- **External engines.** `decompile_native` and the IDA modes of other tools run IDA through idalib in a separate
  worker process. On Windows the worker runs in a Job Object that ends it with the server and caps its memory; on other
  systems it runs in its own process group, which is killed with the server. `ida_python` runs arbitrary Python in
  that worker and is off unless the server is started with `--ida-scripting`.
- **Network.** The server reaches the network only to download a .NET reference pack from nuget.org when analyzed code
  targets an uninstalled .NET version (`NDM_OFFLINE=1` turns this off), when `load_pdb` is called with
  `download=true`, and when `NetDecompilerMcp update` fetches a release from GitHub.
- **Files written.** Tools write only to paths given in the call (saved assemblies and images keep a `.bak` of an
  original they replace, and never overwrite without `overwrite=true`), plus per-user caches and annotation files.
  `NetDecompilerMcp install` writes only the client configuration files it lists, each with a `.netdecompiler.bak`
  copy of the previous version.

Problems inside this boundary, such as an input that makes the server execute code from it, write outside the
documented locations, or reach the network otherwise, are security issues. Crashes and hangs on malformed input are
bugs; report them as issues unless they lead to one of the above.
