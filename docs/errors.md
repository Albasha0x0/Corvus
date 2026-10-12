# Error results

<!-- Generated from Core/ToolError.cs and Mcp/ErrorResult.cs by ErrorContractTests; run the tests with CORVUS_UPDATE_DOCS=1 to update. -->

A failed tool call returns a result with `isError: true`, no `structuredContent` and two text blocks:

1. `Error (<code>[, retryable]) in <tool>: <message>`, then `Next: <step>` on a second line when a next step is known.
2. The marker `error (json): ` (after a blank line) followed by the same error as one line of JSON:
   `{ "code", "retryable", "message", "next", "partial", "details" }`.
   - `retryable`: repeating the same call can succeed without changing its arguments.
   - `next`: the next step that can succeed, or null.
   - `partial`: results produced before the failure (matches found before a time limit, files written), or null;
     over 32,000 characters it is dropped and `details.partialOmittedChars` gives its size.
   - `details`: further machine-readable facts (the parameter, limits, candidates, a kept result id), or null.

An error larger than the response limit keeps its code; its message is cut and the full text is kept for
`read_result` (`details.resultId`). Workspace notices (`[workspace] ...`) may precede the two blocks.

| Code | Meaning | Retryable |
|---|---|---|
| `failed` | Not classified. | no |
| `invalid_argument` | An argument is missing, malformed, out of range or outside its value set, or a parameter is not declared. | no |
| `not_found` | The named symbol, address, file, entry or kept result does not exist. | no |
| `ambiguous` | A name matches several things and the call needs one; the candidates are listed. | no |
| `not_loaded` | The call needs a loaded target that is not loaded (or was unloaded meanwhile). | no |
| `unsupported` | The target kind, architecture or construct is not handled. | no |
| `malformed_input` | The input is corrupt or not of the expected format. | no |
| `limit_exceeded` | A size or count limit was reached; an oversized result is kept for read_result. | no |
| `conflict` | The change conflicts with the current state (stale edit, existing file, failed compile). | no |
| `changed_on_disk` | The file changed on disk since it was loaded; writing would lose those changes. | no |
| `io_error` | Reading or writing a file failed. | yes |
| `timeout` | The operation or the call took longer than its time limit; partial holds what was done. | yes |
| `cancelled` | The server cancelled the work (the target was unloaded, reloaded or superseded). | yes |
| `provider_unavailable` | An external engine (IDA, a reference pack download) is missing or failed, or the server is busy (retry after details.retryAfterMs). | yes |
| `access_denied` | The operating system refused access (another user's or a protected process, missing privileges). | no |
| `internal` | An unexpected exception; the message names its type. Please report it. | no |
