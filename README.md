# Corvus

**English** · [简体中文](README.zh-CN.md) · [日本語](README.ja.md)

MCP server for reverse engineering and security analysis of compiled programs: .NET assemblies and native PE, ELF and
Mach-O binaries.

[![Release](https://img.shields.io/github/v/release/Albasha0x0/Corvus?style=flat-square)](https://github.com/Albasha0x0/Corvus/releases)
[![CI](https://img.shields.io/github/actions/workflow/status/Albasha0x0/Corvus/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/Albasha0x0/Corvus/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square)](LICENSE)

- One self-contained binary. Nothing is uploaded; nothing it reads is executed by default.
- Tools and output can change between releases; see the [release notes](docs/release-notes.md).

## Quick start

Windows (PowerShell):

```powershell
irm https://raw.githubusercontent.com/Albasha0x0/Corvus/main/install.ps1 | iex
```

Linux and macOS:

```sh
curl -fsSL https://raw.githubusercontent.com/Albasha0x0/Corvus/main/install.sh | sh
```

The installer verifies the download and registers Corvus with the MCP clients it finds. Restart the client and ask:

> Load app.dll with Corvus and explain how it builds its export file. Cite the methods you read.

- Plugin, container image and other clients: [installation](docs/installation.md).
- From a terminal: `corvus decompile_member --load app.dll member=Ns.Type::Method` ([command line](docs/cli.md)).
- Builds: win-x64, win-arm64, linux-x64, linux-arm64, linux-musl-x64, linux-musl-arm64, osx-x64, osx-arm64.

## How it works

- The agent calls Corvus over MCP; every result is bounded, every list pages, every error names the next step.
- Corvus's own engine reads native code (x86, x64, ARM32, ARM64); IDA or Ghidra, when installed, add pseudocode.
- Edits happen in memory; the agent reviews the diff and saves a patched copy.

## What it reads

| Input | Shows | Needs |
|---|---|---|
| .NET assemblies | C#, IL, references, call graphs, patches | nothing |
| Native PE, ELF, Mach-O | functions, disassembly, cross-references, types, patches | nothing |
| Native pseudocode | decompiled functions, engine types, scripts | IDA 9 or Ghidra 12 |
| NativeAOT, ReadyToRun, Il2Cpp | method names and addresses, strings | nothing |
| WebAssembly | modules, components, disassembly | nothing |
| Containers | single-file bundles, APK, IPA, installers, disk images, firmware | nothing |
| Documents and scripts | Office macros, PDF actions, deobfuscated scripts | nothing |
| Packages before install | npm, PyPI, RubyGems and extension packages | nothing |
| Network captures | pcap streams, HTTP objects, TLS with a key log | nothing |
| Android | manifest, resources, DEX, Java | JADX for Java, adb for devices |
| Crash dumps | minidumps, core dumps, stacks, .NET heap | nothing |
| Running programs | stop points, call recording, code coverage | Frida 17.24.3 or newer 17.x; off by default |

All 165 tools and 15 prompts: [features](docs/features.md), [tool reference](docs/tools.md).

Guides: [first session](docs/guides/1-first-session.md) · [decode and patch](docs/guides/2-decode-and-patch.md) ·
[new build](docs/guides/3-new-build.md).

## Documentation

[Installation](docs/installation.md) · [Configuration](docs/configuration.md) · [Features](docs/features.md) ·
[Tool reference](docs/tools.md) · [Command line](docs/cli.md) · [Errors](docs/errors.md) ·
[Troubleshooting](docs/troubleshooting.md) · [FAQ](docs/faq.md) · [Release notes](docs/release-notes.md) ·
[All pages](docs/README.md)

## Responsible use

Analyze only software you own or may analyze. Licenses and local law can restrict decompiling, patching and
redistribution.

[Contributing](CONTRIBUTING.md) · [Security](SECURITY.md) · [Apache-2.0 license](LICENSE)