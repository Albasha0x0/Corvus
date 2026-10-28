# Error results

<!-- Generated from Core/ToolError.cs and Mcp/ErrorResult.cs by ErrorContractTests; run the tests with CORVUS_UPDATE_DOCS=1 to update. -->

A failed tool call returns a result with `isError: true`, no `structuredContent` and two text blocks:

1. `Error (<code>[, retryable]) in <tool>: <message>`, then `Next: <step>` on a second line.
2. The marker `error (json): ` (after a blank line) followed by the same error as one line of JSON:
   `{ "code", "retryable", "message", "next", "partial", "details" }`, described by
   [error.schema.json](error.schema.json).
   - `retryable`: repeating the same call can succeed without changing its arguments.
   - `next`: the next step that can succeed; never empty. Without a specific one, the code's default below.
   - `partial`: results produced before the failure (matches found before a time limit, files written), or null.
     Above 4,000 tokens it is kept for `read_result` (`details.partialResultId`).
   - `details`: further machine-readable facts (the parameter, limits, candidates, a kept result id), or null.
     `details.retryAfterMs` appears only on `conflict`, `timeout`, `provider_unavailable`:
     an engine restarting or a busy server, a database lock held by another process, a timed-out call whose work still runs.

The error is always the first block. Workspace notices (`[workspace] ...`) follow the two blocks. An error larger than
the response limit keeps its code; its message is cut and the full text is kept for `read_result` (`details.resultId`).
Text quoted from the analyzed file is escaped: a line of it that starts like a server marker (`Error (`, `Next:`,
`[More:`, `[End:`, `[workspace]`) gets `\u2063` in front, and invisible and control characters are written as `\uXXXX`.

| Code | Meaning | Retryable | Default next step |
|---|---|---|---|
| `failed` | Not classified. | no | read the message for the cause, change the arguments or the target, and call again |
| `invalid_argument` | An argument is missing, malformed, out of range or outside its value set, a parameter is not declared, or an output path lies outside the output roots or in a refused place. | no | fix the argument the message names; `corvus describe &lt;tool>` or the tool's input schema lists its parameters, types and ranges |
| `not_found` | The named symbol, address, file, entry or kept result does not exist. | no | check the name, address or path: list_assemblies shows what is loaded, search_symbols and list_functions find names, and a relative path resolves against the server's working directory |
| `ambiguous` | A name matches several things and the call needs one; the candidates are listed. | no | call again with one of the candidates (a full name, a token, or the assembly or image parameter) |
| `not_loaded` | The call needs a loaded target that is not loaded (or was unloaded meanwhile). | no | load_assembly path=&lt;file> loads it (a target parameter also takes the file's path); list_assemblies shows what is loaded |
| `unsupported` | The target kind, architecture or construct is not handled. | no | summarize_file names the kind of the target and the tools that read it |
| `malformed_input` | The input is corrupt or not of the expected format. | no | check that the file is complete and of the expected kind; summarize_file reports what it is |
| `limit_exceeded` | A size or count limit was reached; an oversized result is kept for read_result. | no | narrow the call (a smaller limit, a filter, one member instead of a type); a kept result is paged with read_result |
| `conflict` | The change conflicts with the current state (stale edit, existing file, failed compile, a database another process holds). | no | read the current state and repeat the change against it; for an existing output file pass overwrite=true or another path |
| `changed_on_disk` | The file changed on disk since it was loaded; writing would lose those changes. | no | reload_assembly reads the file on disk (in-memory edits are dropped), or save to another path |
| `io_error` | Reading or writing a file failed. | yes | check that the path is reachable and not locked by another program, then call again |
| `timeout` | The operation or the call took longer than its time limit; partial holds what was done. | yes | narrow the call (one member instead of a type, a smaller limit or scope); partial holds what finished |
| `cancelled` | The server cancelled the work (the target was unloaded, reloaded or superseded). | yes | call again; if the target was unloaded or reloaded, list_assemblies shows what is loaded |
| `provider_unavailable` | An external engine (IDA, a reference pack download) is missing or failed, or the server is busy. | yes | server_status names the missing engine or download and how to enable it; when details.retryAfterMs is given, retry after it |
| `access_denied` | The operating system refused access (another user's or a protected process, missing privileges). | no | pick a target this user may read, or run the server with the rights it needs |
| `internal` | An unexpected exception; the message names its type. Please report it. | no | retry once; if it repeats, report it with the tool and its arguments (server_status shows the version) |
