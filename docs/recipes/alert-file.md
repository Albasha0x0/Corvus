# Look at a file an endpoint alert named

Read a file an endpoint alert reported, from a copy, without running it.

Requires Corvus ([installation](../installation.md)) and a copy of the file, here `sample.bin`.

- Every command below reads the file; none runs or changes it.
- `CORVUS_OFFLINE=1` refuses Corvus's own downloads; fetch a rule pack before setting it.

## Match the file to the alert

```sh
corvus summarize_file path=sample.bin
```

- SHA-256, SHA-1 and MD5 to compare with the alert, type, size, entropy and signature verdict.
- The views that apply, such as `native`, `managed`, `script`, `lnk` or `installer`.

## Read the headers

```sh
corvus get_pe_info image=sample.bin
corvus list_imports image=sample.bin
corvus list_imports image=sample.bin filter=Process
```

- `get_pe_info`: machine, subsystem, sections with entropy, mitigations, version resource, debug and PDB records, signature and anomalies; PE, ELF and Mach-O.
- `list_imports`: imported modules and functions; `filter=` keeps names that contain the text.

## See its capabilities

```sh
corvus survey_features path=sample.bin
corvus survey_features path=sample.bin category=all
```

- Capabilities by category (network, execution, persistence, crypto) from API calls, imports and strings.
- `category=all` adds the evidence for each one; features describe API use, not whether the code runs.
- With capa installed (`CORVUS_CAPA`), `category=capa` adds capa labels by function.

## Search its strings

```sh
corvus search_native_strings image=sample.bin query=http
corvus search_native_strings image=sample.bin query=pipe limit=50
corvus extract_strings path=sample.bin types=url,domain,ipv4,registry_key
```

- `search_native_strings`: strings of a native image; `regex=true` takes a pattern.
- `extract_strings`: typed values of a .NET assembly, with where they are used.

## Read scripts and shortcuts

```sh
corvus summarize_file path=sample.ps1 view=script
corvus summarize_file path=sample.lnk view=lnk
```

- `script`: PowerShell, batch, VBScript or JavaScript with obfuscation folded; nothing runs.
- `lnk`: the shortcut's target, arguments and noteworthy traits.

## Match rules

```sh
corvus rules fetch yara-forge-core
corvus search_container path="$PWD/sample.bin" query=pack:yara-forge-core kind=yara
```

- Corvus ships no rules; `rules fetch` checks the pack's SHA-256.
- Also takes a rule file, a folder or rule text as `query=`.

## Record the case

```sh
corvus summarize_file path=sample.bin stixPath=case/sample.stix.json
```

- Writes a STIX 2.1 bundle of the file, its members and the network indicators found.
