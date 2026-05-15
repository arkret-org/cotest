---
name: file names use domain paths, not sequential SN prefixes
description: Organize tests/docs by spec domain (identity/, encryption/, messaging/, etc.) with descriptive filenames. Don't prefix with sequential numbers like S7, S23 — they're opaque and break when reorganized.
type: feedback
---

When creating tests or scenario docs:

- **Mirror the spec's directory layout.** contrix-spec uses `identity/`, `crypto-media/` (encryption), `models/` (split into messaging/spaces/kanban/documents/etc by domain), `sync/`, `authz/`, `discovery/`, `governance/`, etc. The e2e suite uses the same domains.
- **Filenames describe content, no numbers.** `identity/onboarding.spec.ts`, not `s7-account-onboarding.spec.ts`. The path itself is the identifier.
- **Cross-references in docs use paths.** "see identity/multi-device" not "see S10". When files move, refs stay valid (or are easy to grep-find).
- **Path-based filtering in playwright `--grep`.** `-Grep "kanban/"` runs everything in that domain. `-Grep "messaging/triad-collaboration"` runs one scenario.

**Why:** 2026-05-15 user feedback: "这个 s23 等前缀什么意思? 是否我们应该有跟好的命名或者分类的方式去组织代码和文件名称?" Sequential numbers are useful only as initial communication shorthand during planning; they ossify into noise once N > ~10 because numbers don't convey domain or priority.

**How to apply:**
- When adding a new e2e scenario, decide its domain first, then drop the doc + spec into `e2e/scenarios/<domain>/<name>.md` and `e2e/tests/<domain>/<name>.spec.ts`. Use kebab-case, no number prefix.
- If you find yourself wanting to write "S31" or similar, instead invent a `<domain>/<descriptive-name>` and add it to the appropriate domain bucket in `e2e/scenarios/catalog.md`.
- In doc bodies, refer to other scenarios by path token (e.g., `(见 identity/multi-device)`), not by old S# tokens.
- `test.describe()` titles should NOT start with `S#` — they show up in playwright output and the path already identifies the scenario.
