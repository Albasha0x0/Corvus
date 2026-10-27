# Corvus

MCP server for reverse engineering .NET assemblies and native PE, ELF and Mach-O binaries.

- Decompile, search, trace, compare builds and patch.
- IDA and Ghidra are optional decompilers.
- Nothing is uploaded; by default nothing is executed.

## Install

```sh
dotnet tool install -g CorvusRE
corvus install
```

- `corvus install` registers the server with the MCP clients it finds.
- Without installing: `dnx CorvusRE --yes`.

## Links

- [Documentation, tool reference and self-contained builds](https://github.com/Albasha0x0/Corvus)
- [Release notes](https://github.com/Albasha0x0/Corvus/blob/main/docs/release-notes.md)

<!-- mcp-name: io.github.Albasha0x0/corvus -->
