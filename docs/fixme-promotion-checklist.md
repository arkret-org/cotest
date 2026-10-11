# Fixme Promotion Checklist

Use this checklist before converting any Playwright `test.fixme(...)` to
`test(...)`. Promotion is local-only: do not publish packages, create releases,
push tags, or open remote CI-only follow-ups as evidence.

Empty callback bodies are forbidden. `npm run check:fixme` must pass before
promotion or demotion work is considered complete.

## Required Evidence

| Evidence | Requirement |
|---|---|
| Feature id | A backing local feature or gap id such as `coland#messages-reactions`, `inkson#chat-polls`, `coauth#device-auth`, `cotest#mimi-facade`, or `GAP-P3-074`. |
| Single-spec pass | One command that ran only the promoted spec or an even narrower grep, recorded exactly enough to rerun locally. |
| Regression artifact | One screenshot, HAR, trace, zip, or artifact directory from the passing run. |

## Promotion Strand

1. Confirm the existing fixme has `@blocking-on`, `@user-promise`, and
   `@expected-live-by` metadata.
2. Run the single-spec command locally and keep its run artifact path.
3. Promote through `scripts/promote-fixme.ps1`, passing `-FeatureId`,
   `-PassedSpecCommand`, and `-EvidencePath`.
4. Commit the promotion together with the evidence reference in the relevant
   todo/report document.

Example:

```powershell
.\scripts\promote-fixme.ps1 `
  -SpecPath e2e\tests\extensions\mimi-federation.spec.ts:57 `
  -FeatureId cotest#mimi-facade `
  -PassedSpecCommand 'npx playwright test --config playwright.config.ts --project chromium --grep "mock-mimi-facade"' `
  -EvidencePath artifacts\latest\joint-e2e\playwright-report `
  -NewBody @'
async ({ page, request }) => {
  // promoted body
}
'@
```
