# Check an installer before it is installed

Read what an installer would write, register and run, without running it.

Requires Corvus ([installation](../installation.md)) and a POSIX shell.

## Identify the installer

```sh
corvus summarize_file path=setup.msi
corvus get_pe_info image=setup.exe
```

- `summarize_file`: type, hashes, signature verdict, the installer format and the views that apply.
- `get_pe_info`: version resource, signature, sections, mitigations and header anomalies of an `.exe` stub.
- Authenticode digest and signature checks are exact; chain trust uses the machine's root store.

## Read an MSI package

```sh
corvus summarize_file path=setup.msi view=installer
```

- Product name, version, manufacturer, product and upgrade codes.
- Custom actions: kind (DLL, EXE, JScript, VBScript, nested install), source, target and when each runs.
- Registry values, services with their account and start type, and shortcuts.
- Findings: custom actions that run code, script text from inline, `Binary` or property sources, autostart keys and services.

## Extract the files

```sh
corvus unpack_container path=setup.exe extractOnly=true outputDirectory=out/setup
for f in $(find out/setup -type f); do corvus summarize_file path="$f"; done
```

- Reads `.msi`, `.msp`, `.mst`, `.cab`, WiX Burn, NSIS, Inno Setup, Squirrel and ClickOnce.
- Files land under their install paths; runnable files get a `.bin` suffix.
- `summarize_file` on each file gives its type, hashes, signature verdict and views.

## See what the programs call

```sh
corvus survey_features path=out/setup/app/app.exe.bin
corvus survey_features path=out/setup/app/app.exe.bin category=all
corvus list_imports image=out/setup/app/app.exe.bin
```

- Capabilities by category (network, execution, persistence, crypto) from API calls, imports and strings.
- `category=all` adds the evidence for each one.
- Features describe API use, not whether the code runs.
- With capa installed (`CORVUS_CAPA`), `category=capa` adds capa labels by function.

## Compare with the version installed now

```sh
corvus unpack_container path=setup-1.4.exe extractOnly=true outputDirectory=out/1.4
corvus unpack_container path=setup-1.5.exe extractOnly=true outputDirectory=out/1.5
corvus compare_folders oldPath=out/1.4 newPath=out/1.5
```

- Lists added, removed, modified and renamed files, with text diffs.

## Check packages from a registry

- npm, PyPI, VS Code and browser extension packages: `corvus summarize_file path=<package> view=package` ([package gate](package-gate.md)).
