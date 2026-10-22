# Corvus

**Reverse engineering for AI agents.** Corvus is an MCP server that lets your agent read, trace, compare and patch
compiled programs: .NET assemblies and native PE, ELF and Mach-O binaries. One self-contained binary, no runtime to
install, nothing uploaded; by default nothing it reads is executed.

[![Release](https://img.shields.io/github/v/release/Albasha0x0/Corvus?style=flat-square)](https://github.com/Albasha0x0/Corvus/releases)
[![CI](https://img.shields.io/github/actions/workflow/status/Albasha0x0/Corvus/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/Albasha0x0/Corvus/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/Albasha0x0/Corvus?style=flat-square)](https://github.com/Albasha0x0/Corvus/stargazers)

> [!NOTE]
> Corvus is under active development. Tools, parameters and output can change between releases; breaking changes are
> listed in the [release notes](docs/release-notes.md). Bug reports and feedback are welcome in
> [issues](https://github.com/Albasha0x0/Corvus/issues). If Corvus is useful to you, a star helps other people find it.

[Quick start](#quick-start) · [How it works](#how-it-works) · [What you can analyze](#what-you-can-analyze) ·
[Showcases](#showcases) · [Why Corvus](#why-corvus) · [Documentation](#documentation)

## Quick start

**Windows** (PowerShell):

```powershell
irm https://raw.githubusercontent.com/Albasha0x0/Corvus/main/install.ps1 | iex
```

**Linux / macOS:**

```sh
curl -fsSL https://raw.githubusercontent.com/Albasha0x0/Corvus/main/install.sh | sh
```

The installer verifies the download against the release's `SHA256SUMS` and registers Corvus with the MCP clients it
finds. As a plugin (server and skill; needs the .NET 10 SDK): `/plugin install corvus --marketplace Albasha0x0/Corvus`
in Claude Code, `codex plugin marketplace add Albasha0x0/Corvus` then `corvus` in `/plugins` in Codex
([installation](docs/installation.md#claude-code-and-codex-plugins)). Restart your client and ask:

> Load app.dll with Corvus and explain how it builds its export file. Cite the methods you read.

From a terminal: `corvus decompile_member --load app.dll member=Ns.Type::Method` ([command line](docs/cli.md)).

## How it works

Your agent calls Corvus over MCP. Corvus answers with bounded, structured results: every list pages, every error names
the next step, and long results are kept for `read_result`. The agent follows calls and references, explains the
behaviour, and can patch a copy and save it.

Native code is analyzed by Corvus's own engine (x86, x64, ARM32, ARM64), with IDA or Ghidra as optional decompilers
when installed. Their databases and output are kept, so the second question about a binary is fast.

## What you can analyze

| Target | What you get | Needs |
|---|---|---|
| .NET assemblies | C# decompilation, IL, references, call graphs, build comparison, C# and IL patching, saving | nothing |
| Unity and Il2Cpp games | metadata, addresses, string literals, IDA / Ghidra scripts, C++ bindings | nothing |
| Native binaries (PE, ELF, Mach-O) | functions, disassembly, CFG, cross-references, values, RTTI, PDB types, similar functions | nothing |
| Native pseudocode | decompilation, engine types, frames, scripting | IDA 9 (idalib) or Ghidra 12 |
| NativeAOT and ReadyToRun | method names, MethodTables, strings, precompiled code | nothing |
| Native patching | names, comments, byte and assembly patches, patched copies, carried to new builds | nothing |
| Containers | single-file bundles, NuGet, APK, ASAR, Unity WebGL, HAR captures, installers (MSI, NSIS, Inno Setup, WiX Burn), frozen Python programs, firmware images; CycloneDX SBOM, YARA-X matches | nothing |
| Android packages | manifest, resources, DEX, smali, Java (JADX), JNI bindings, devices over adb | JADX for Java, adb for devices |
| Crash dumps | Windows minidumps, Linux and macOS core dumps, .NET exceptions, stacks, heap; crash text | nothing |
| Running programs | sessions with stop points, call recording, code coverage, activity traces, snapshots and child processes on Windows, Linux and macOS | Frida 17.24.3 or newer 17.x; off by default |

Full list: [features](docs/features.md) and the [tool reference](docs/tools.md) (165 tools, 15 prompts).

## Showcases

- **[Decompile, rebuild, run](docs/showcase/round-trip.md):** an assembly exported as a C# project that builds with
  warnings as errors, runs with the same output, and is measured against the original.
- **[Inside a single-file app](docs/showcase/single-file.md):** a .NET single-file executable extracted without running
  it, its assemblies extracted byte for byte.
- **[Where SQLite makes its random numbers](docs/showcase/sqlite-random.md):** a crypto constant in a native SQLite
  build traced to `sqlite3_randomness` and its callers, recorded as an evidence bundle and re-verified.
- **[A Json.NET error traced to its code](docs/showcase/json-reference-loop.md):** "Self referencing loop detected"
  followed from the message to the deciding setting and every caller, with the evidence re-verified.

Each step in the showcases and [guides](docs/guides/1-first-session.md) is checked by a test.

## Why Corvus

- **Works with nothing installed.** Native analysis, .NET decompilation, containers and dumps are built in.
- **Fast.** Results come from saved indexes and engine databases; warm calls answer in milliseconds.
- **Sized for agents.** Every result fits a token budget per part, with paging and kept results.
- **Edits, not just reads.** Patch .NET and native code in memory, review the diff, save a verified copy, and carry
  names and patches to the next build.
- **Every platform.** Windows, Linux (glibc and musl) and macOS, x64 and arm64: win-x64, win-arm64, linux-x64,
  linux-arm64, linux-musl-x64, linux-musl-arm64, osx-x64 and osx-arm64.

Supported clients: Claude Code, Claude Desktop, Cursor, Windsurf, VS Code, VS Code Insiders, VSCodium, Cline, Roo Code,
Kilo Code, Visual Studio, Codex, Gemini CLI, Qwen Code, GitHub Copilot CLI, OpenCode, Crush, Zed, LM Studio,
Amazon Q, Kiro, Antigravity, Devin, Command Code, Grok Build, OMP and Pi. Any other client: `corvus config`.

## Documentation

[Installation](docs/installation.md) · [Configuration](docs/configuration.md) · [Features](docs/features.md) · [Tool reference](docs/tools.md) ·
[Command line](docs/cli.md) · [Errors](docs/errors.md) · [Troubleshooting](docs/troubleshooting.md) ·
[FAQ](docs/faq.md) · [Release notes](docs/release-notes.md) · [All pages](docs/README.md)

Guides: [first session](docs/guides/1-first-session.md) · [decode and patch](docs/guides/2-decode-and-patch.md) ·
[new build](docs/guides/3-new-build.md).

## Responsible use

Analyze software you own or are permitted to analyze. Decompiling, patching or redistributing third-party code can be
restricted by its license and by law where you live.

[Contributing](CONTRIBUTING.md) · [Security](SECURITY.md) · [MIT license](LICENSE)

## Star history

<a href="https://www.star-history.com/#Albasha0x0/Corvus&Date">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=Albasha0x0/Corvus&type=Date&theme=dark" />
    <img alt="Corvus star history" src="https://api.star-history.com/svg?repos=Albasha0x0/Corvus&type=Date" />
  </picture>
</a>
