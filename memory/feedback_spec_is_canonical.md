---
name: spec is the canonical source, not the current frontend
description: When e2e tests and the yougen frontend diverge, the spec/protocol decides what's correct — assume tests were drafted against a stale or invented concept and trace it back to the protocol before "fixing" either side
type: feedback
---

When an e2e test references a route, testid, or concept that the yougen frontend doesn't have, do NOT assume the frontend regressed. Check the contrix-spec / protocol first — the test may have been written against a concept that never existed in the spec.

Concrete example: `gotoProduct()` → `/product` route → `product-panel` testid was sprinkled across most joint e2e specs. yougen has no `/product` route. The user clarified: "应该以 spec 为基准, /product 本身不对. 协议里面没有这个东西."

**Why:** Treating yougen's current routes as the source of truth lets stale or invented test concepts ratchet themselves into the frontend. The protocol (`../contrix-spec`) is authoritative; yougen and cotest both serve it.

**How to apply:**
- Before adjusting tests OR the frontend to reconcile a mismatch, grep `../contrix-spec` for the disputed term.
- If the term has no spec presence, the test/helper is wrong — rewrite it against a spec-defined concept, don't add the missing route to yougen.
- If you're tempted to add a route/testid to make a test pass, stop and confirm spec coverage first.
