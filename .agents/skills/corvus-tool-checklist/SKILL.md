---
name: corvus-tool-checklist
description: "Add or change a Corvus MCP tool or parameter with every registration, contract row, doc and test the guard tests require. Use when designing a new tool, a new parameter, action or view, or when deciding whether a feature needs a tool at all."
---

# Tool checklist

First decide whether the feature needs a new tool. Prefer, in order: a value of an existing parameter, an action or
`view` of an existing tool, a new parameter, and only then a new tool. Each new tool is paid for in every client's
catalog (`corvus-catalog-audit`).

Design:

- A tool is a `[McpServerTool]` method in `src/Corvus/Tools` that wraps a service call in `ToolSupport.Read`, `Write`
  or `Edit`; the logic lives in a service under `src/Corvus/Services`.
- Results are bounded: a list pages with `offset`, `limit` and `hasMore`; long text is kept for `read_result`.
- Errors the agent acts on are a `ToolError` with a code from `docs/errors.md` and a `Next:` step.
- A reader that could not see something reports it as unknown or partial, never as absent, and names the limit.
- A closed string parameter has a value set; an `engine` parameter always has one.
- A parameter naming a file the tool writes is listed in `tests/Corvus.Tests/ContractSweepData`.
- A capability that runs or attaches to a program stays behind its existing opt-in, off by default.

Registration (`CONTRIBUTING.md`, "Adding or changing a tool"):

1. `src/Corvus/Mcp/Contract`: effects, value sets, contract row (output and latency class, profiles, dryRun policy,
   list sort key).
2. `tests/Corvus.Tests/ContractSweepData`: written-file parameters.
3. `src/Corvus/Core/Toolsets.cs`: the tool in exactly one family.
4. `src/Corvus/Mcp/Guide.cs`: the tool named in the core or a topic.
5. `docs/features.md`: a tool table row; the tool count there, in `README.md` and in `README.*.md`.
6. Tests: the tool's own, one focused test per behaviour, and a case in `McpProtocolTests.ToolCases`.

Then run `./test.ps1` and the guard tests (`CatalogAuditTests`, `ReadmeSyncTests`, `TranslatedReadmeTests`,
`SkillTests`), and regenerate generated docs with `CORVUS_UPDATE_DOCS=1`.
