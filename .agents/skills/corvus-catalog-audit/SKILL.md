---
name: corvus-catalog-audit
description: "Check that the Corvus tool catalog stays within its size ceilings and per-tool limits, and read a failure of the catalog guard tests. Use after changing a tool, parameter or description, or when CatalogAuditTests, OutputSchemaTransformTests or a ratchet fails."
---

# Catalog audit

The tool catalog is what every client loads before the first call; its size is a cost paid on every session.

Run the guard tests:

```
dotnet test tests/Corvus.Tests --filter "FullyQualifiedName~CatalogAuditTests|FullyQualifiedName~OutputSchemaTransformTests|FullyQualifiedName~ReadmeSyncTests|FullyQualifiedName~SchemaDocsTests"
```

What they hold (`tests/Corvus.Tests/Contract/CatalogAuditTests.cs`):

- The model-facing catalog (names, descriptions, input schemas) and the whole `tools/list` response stay under their
  byte ceilings; the lean and core profiles have their own tool counts and byte ceilings.
- A tool description is at most 600 bytes, a parameter description 160, an output schema 4 KiB.
- Every tool has a family in `src/Corvus/Core/Toolsets.cs` and a contract row in `src/Corvus/Mcp/Contract`.
- Input schemas are flat objects with portable patterns and no null defaults.

When a ceiling fails, shrink the change: shorter descriptions, an enum instead of prose, a parameter folded into an
existing one, a view of an existing tool instead of a new tool. A ceiling is raised only deliberately, with the
measured figure and the reason recorded beside the constant.

Ratchets (`tests/Corvus.Tests/Ratchets/<name>.txt`, `tests/Corvus.Tests/Support/Ratchet.cs`) list today's
violations of a newer rule; the list may only shrink. A new violation fails: fix it, never add it to the list. A
listed entry that now complies also fails until it is removed: run once with `CORVUS_UPDATE_RATCHETS=1`.

A description change also changes generated docs: run the tests once with `CORVUS_UPDATE_DOCS=1` and commit
`docs/tools.md`, `docs/schemas` and `skills/corvus`.
