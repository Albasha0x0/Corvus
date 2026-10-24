# Documentation

## Use

| Page | Covers |
|---|---|
| [Installation](installation.md) | Install scripts, clients, plugins, .NET tool, updating and removing |
| [Configuration](configuration.md) | Every server option, environment variable and security switch |
| [Features](features.md) | What each area reads and shows, by tool |
| [Tool reference](tools.md) | Every tool's arguments and output (generated) |
| [Command line](cli.md) | Running tools from a terminal or a script |
| [Errors](errors.md) | Error codes and their `Next:` lines (generated) |
| [Troubleshooting](troubleshooting.md) | Common problems and fixes |
| [FAQ](faq.md) | Network use, what runs, supported formats |

## Learn

Guides on the sample in `samples/Notes`:
[first session](guides/1-first-session.md) · [decode and patch](guides/2-decode-and-patch.md) ·
[new build](guides/3-new-build.md).

Showcases: a question about a real library, answered step by step.

- [Decompile, rebuild, run](showcase/round-trip.md)
- [Inside a single-file app](showcase/single-file.md)
- [Where SQLite makes its random numbers](showcase/sqlite-random.md)
- [A Json.NET error traced to its code](showcase/json-reference-loop.md)
- [What NLog's attributes declare](showcase/attribute-arguments.md)
- [A crypto table in an array initializer](showcase/fieldrva-table.md)
- [IL with the source lines of its build](showcase/source-lines.md)

Every step in the guides and showcases is checked by a test.

Recipes: Corvus with other security tools.
[Dependency-Track](recipes/dependency-track.md) · [Velociraptor](recipes/velociraptor.md) ·
[GuardDog](recipes/guarddog.md) · [Package gate](recipes/package-gate.md).

## Contracts and formats

| Page | Covers |
|---|---|
| [Saving](saving.md) | What `save_assembly` keeps byte-for-byte and reports (generated) |
| [Simplification](simplify.md) | What `simplify_methods` changes and its reason codes (generated) |
| [Native editing](native-editing.md) | Native annotations and patches |
| [Live inspection](live-inspection.md) | Process inspection and live sessions |
| [Engine databases](engine-databases.md) | IDA and Ghidra databases: identity, reuse, cache |
| [Normalized IL hash](il-hash.md) | The method-body hash used across builds |
| [Migration reasons](migration-reasons.md) | Codes for names and patches carried to a new build (generated) |
| [Result limitations](limitations.md) | The `limitations` ids in result provenance (generated) |
| [Error schema](error.schema.json), [result schemas](schemas/) | JSON Schemas of errors and structured results |

## Project

| Page | Covers |
|---|---|
| [Contributing](../CONTRIBUTING.md) | Build, test, add a tool, commit and release |
| [Testing](testing.md) | Test sets, layout, test data, guard and generated-document tests |
| [Native reliability](native-maturity.md) | Sweeps, large images, tested engine versions, agreement with other tools |
| [Known issues](known-issues.md) | Known limits and open issues with a workaround |
| [Release notes](release-notes.md) | Changes by version |
| [Security](../SECURITY.md) | Trust model and reporting |
