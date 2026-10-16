# Result limitations

<!-- Generated from Core/Limitations.cs by ErrorContractTests; run the tests with CORVUS_UPDATE_DOCS=1 to update. -->

A result whose coverage is not complete names why in the `limitations` list of its provenance record
(`_meta["corvus/provenance"]`). The list uses only these ids; details are in the result's text. A record that says it
stopped early (`truncated`, `cut`, `incomplete`, or a `partial` reason) has coverage `partial` too.

Function results also name their facets (`pseudocode`, `callers`, `callees`, `xrefs`, `strings`, `cfg`) as `available`
or `unavailable: why`, in the provenance and in the record's `coverage.facets`. Comparisons of kept results
(`oldResult` / `newResult`) report what a side does not show as `unknown`: a page of a longer result, a result that is
not complete, or a facet either side lacks; never as equal, removed, added or changed.

| Id | Meaning |
|---|---|
| `analysis-partial` | The engine's analysis had not finished; functions, references or types it finds later are missing. |
| `engine-profile-standard` | The engine database was built with the standard analysis profile; the full profile can find more. |
| `index-building` | The code index was still being built; references from code not yet indexed are missing. |
| `regex-timeouts` | The pattern ran out of time on some inputs; those inputs were skipped. |
| `row-cap` | A scan or collection cap stopped before the end of the input; counts are lower bounds. |
| `time-limit` | The call's time limit stopped the work; the result holds what finished. |
| `transformed-names` | Names are transformed or compiler-generated; matches by name are unreliable. |
| `no-pdb` | No symbol file was loaded; names, types and boundaries are recovered, not read. |
| `heuristic-boundaries` | Function starts and ends come from heuristics, not from symbols or unwind data. |
| `indirect-calls` | Calls through pointers, virtual slots or reflection are not resolved to their targets. |
| `unresolved-references` | Referenced assemblies or modules were not found; types and calls into them are unresolved. |
| `architecture-undecoded` | The built-in engine does not decode this instruction set; code facts come from metadata and symbols only. |
| `encrypted-metadata` | Metadata is encrypted or packed; only the part that could be read is reflected. |
