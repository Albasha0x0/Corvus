---
name: corvus-release-notes
description: "Write the docs/release-notes.md section for a new Corvus version from the commits since the previous tag. Use before running release.ps1, or when asked to draft or review release notes."
---

# Release notes

`release.ps1 -Version X.Y.Z` refuses a release whose version is not the first `## X.Y.Z` section of
`docs/release-notes.md`; write the section first.

1. The previous tag: `git describe --tags --abbrev=0`. The commits: `git log <tag>..origin/main --format='%h %s%n%b'`.
2. Open with `## X.Y.Z` and one line: the tool and prompt counts (from `docs/features.md`) and what changed in the
   catalog since the last release.
3. `### Highlights`: 3-4 one-line bullets, each a task a developer can now do ("Compare a binary's file bytes with
   IDA's memory"), not a mechanism.
4. `### Breaking changes`: one entry per commit with `!` after its scope or a `BREAKING CHANGE:` footer. Each names the
   tools, then a `Before:` and an `After:` call; add the setting that restores the old behaviour when one exists.
5. `### Changes` (`feat`, `perf`) and `### Fixes` (`fix`): `- **Area:** one sentence. [hash](https://github.com/Albasha0x0/Corvus/commit/hash)`.
   Skip `test`, `ci`, `chore` and `refactor` commits unless a user sees the effect.
6. An engine or platform item states its verified scope from the commit's `Verified:` paragraph (runtime and engine
   versions, operating systems, architectures) and what is not supported, from its `Not verified:` line.
7. An upgrade effect that needs no action but changes behaviour once (a cache read again, an index rebuilt) gets one
   line under Changes.

Before citing a hash, check that it is on main and its subject is the one described:
`git merge-base --is-ancestor <hash> origin/main && git log -1 --format=%s <hash>`.

Wording: lead with the point, one fact per sentence, vendor terms for every concept, no marketing.
`DocFactsTests` and `ReleaseScriptTests` check the file; run them after editing.
