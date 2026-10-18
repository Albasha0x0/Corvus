# Corvus

Reverse-engineering MCP server for AI agents: decompile, search, trace, compare and patch .NET assemblies and native
PE, ELF and Mach-O binaries. IDA and Ghidra are optional decompilers. Nothing is uploaded, and by default nothing is executed.

Corvus is under active development; changes are listed in the
[release notes](https://github.com/Albasha0x0/Corvus/blob/main/docs/release-notes.md).

## Install

```sh
dotnet tool install -g CorvusRE
corvus install
```

`corvus install` registers the server with the MCP clients it finds. Without installing: `dnx CorvusRE --yes`.

Documentation, the tool reference and the self-contained builds that need no .NET:
https://github.com/Albasha0x0/Corvus

<!-- mcp-name: io.github.Albasha0x0/corvus -->
